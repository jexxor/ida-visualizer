"""Map overlays and offset translation."""

from array import array
from bisect import bisect_left
from visualizer_engine.geometry import (
    BLACK,
    CHANGED,
    GLOBAL_GAP,
    INSPECTION_RANGE_OUTLINES,
    NEW_REGION,
    RenderCancelled,
    UNCOMPARABLE,
    UNREADABLE,
    _INSPECTION_RANGE_FILLS,
    curve_index_at,
    curve_point_at,
)

def delta_only_pixels(pixels):
    """Hide entropy background in a rendered delta, retaining comparison states."""
    colors = array("I")
    colors.frombytes(pixels)
    for index, color in enumerate(colors):
        if color not in (CHANGED, UNREADABLE, UNCOMPARABLE, NEW_REGION, GLOBAL_GAP):
            colors[index] = BLACK
    return colors.tobytes()


def new_region_pixels(pixels):
    """First-seen process region without file backing; never claim byte diff."""
    colors = array("I")
    colors.frombytes(pixels)
    for index, color in enumerate(colors):
        if color == UNCOMPARABLE:
            colors[index] = NEW_REGION
    return colors.tobytes()


def inspection_pixel_span(frame, start, stop):
    """Hilbert-index interval whose displayed original offsets fall in [start, stop)."""
    cells = frame.side * frame.side
    if stop <= start:
        return 0, 0
    if frame.sampled and frame.sample_offsets:
        count = len(frame.sample_offsets)
        low = bisect_left(frame.sample_offsets, start)
        high = bisect_left(frame.sample_offsets, stop)
        return ((low * cells + count - 1) // count,
                (high * cells + count - 1) // count)
    width = frame.stop - frame.start
    low = max(0, min(width, start - frame.start))
    high = max(0, min(width, stop - frame.start))
    return ((low * cells + width - 1) // width,
            (high * cells + width - 1) // width)


def inspection_map_overlay(frame, start, stop, cancelled=None, focus=None):
    """Outline inspected footprint, tint its 64-KiB focus; use displayed offsets."""
    first, end = inspection_pixel_span(frame, start, stop)
    side = frame.side
    pixels = array("I", [0]) * (side * side)
    mask = bytearray(side * side)
    focused = bytearray(side * side)
    focus_first, focus_end = (inspection_pixel_span(frame, *focus)
                              if focus is not None else (0, 0))
    if focus_first <= first and focus_end >= end and end - first > side * side // 2:
        focus_first = focus_end = 0  # Full-screen analysis: outline, do not wash out map.
    for index in range(first, end):
        if (index & 1023) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        x, y = curve_point_at(side, index)
        mask[y * side + x] = 1
        if focus_first <= index < focus_end:
            focused[y * side + x] = 1
    for index, selected in enumerate(mask):
        if (index & 4095) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        if not selected:
            continue
        x, y = index % side, index // side
        edge = (not x or not y or x == side - 1 or y == side - 1
                or not mask[index - 1] or not mask[index + 1]
                or not mask[index - side] or not mask[index + side])
        pixels[index] = (0xBF66E7C9 if edge else
                         0x587DE6BB if focused[index] else 0x0E7DE6BB)
    return pixels.tobytes(), end - first


def inspection_ranges_overlay(frame, ranges, cancelled=None, selected_scale=None):
    """Map exact windows to displayed pixels; optionally isolate one scale."""
    if len(ranges) != 4:
        raise ValueError("Inspector needs four scale windows")
    if selected_scale is not None and not 0 <= selected_scale < 4:
        raise ValueError("Invalid inspection scale")
    spans = [inspection_pixel_span(frame, low, high) for low, high in ranges]
    active = (selected_scale,) if selected_scale is not None else range(4)
    side, cells = frame.side, frame.side * frame.side
    flags = bytearray(cells)
    pixels = array("I", [0]) * cells
    for index in range(min(spans[scale][0] for scale in active),
                       max(spans[scale][1] for scale in active)):
        if (index & 1023) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        membership = sum(1 << scale for scale in active
                         for first, end in (spans[scale],)
                         if first <= index < end)
        if membership:
            x, y = curve_point_at(side, index)
            flags[y * side + x] = membership
    for index, membership in enumerate(flags):
        if (index & 4095) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        if not membership:
            continue
        x, y = index % side, index // side
        for scale in range(4):
            bit = 1 << scale
            if not membership & bit:
                continue
            edge = (not x or not y or x == side - 1 or y == side - 1
                    or not flags[index - 1] & bit or not flags[index + 1] & bit
                    or not flags[index - side] & bit or not flags[index + side] & bit)
            pixels[index] = (INSPECTION_RANGE_OUTLINES[scale] if edge else
                             _INSPECTION_RANGE_FILLS[scale])
            break
    return pixels.tobytes(), tuple(end - first for first, end in spans)


def offset_at(frame, x, y):
    if not (0 <= x < frame.side and 0 <= y < frame.side):
        return None
    index = curve_index_at(frame.side, x, y)
    if frame.sampled and frame.sample_offsets:
        count = len(frame.sample_offsets)
        return frame.sample_offsets[index * count // (frame.side * frame.side)]
    return frame.start + index * (frame.stop - frame.start) // (frame.side * frame.side)


def curve_index_for_offset(frame, offset):
    """Place IDA cursor on displayed sample, not an unrelated pixel in its bin."""
    total = frame.side * frame.side
    if frame.sampled and frame.sample_offsets:
        samples = frame.sample_offsets
        pos = min(len(samples) - 1, bisect_left(samples, offset))
        if pos and abs(samples[pos - 1] - offset) <= abs(samples[pos] - offset):
            pos -= 1
        return min(total - 1, (2 * pos + 1) * total // (2 * len(samples)))
    return min(total - 1, max(0, (offset - frame.start) * total // (frame.stop - frame.start)))


def tile_file_offset(frame, tile_index, tile_side=8):
    """Representative file offset of a Hilbert-aligned map tile."""
    if (frame.side % tile_side != 0 or tile_side < 1
            or tile_side & (tile_side - 1)
            or not 0 <= tile_index < (frame.side // tile_side) ** 2):
        raise ValueError("Invalid Hilbert tile")
    pixel_index = tile_index * tile_side * tile_side + tile_side * tile_side // 2
    if frame.sampled and frame.sample_offsets:
        bin_index = pixel_index * len(frame.sample_offsets) // (frame.side * frame.side)
        return frame.sample_offsets[bin_index]
    return frame.start + pixel_index * (frame.stop - frame.start) // (frame.side * frame.side)


def delta_tile_masks(frame, tile_side=8):
    """Mark every map tile touching a shifted VA block, including sampled maps."""
    grid = frame.side // tile_side
    up, down = bytearray(grid * grid), bytearray(grid * grid)
    if not frame.entropy_shifts:
        return up, down
    ends = [shift[1] for shift in frame.entropy_shifts]
    pixels = frame.side * frame.side
    count = len(frame.sample_offsets)
    for tile in range(grid * grid):
        first, last = tile * tile_side * tile_side, (tile + 1) * tile_side * tile_side
        if frame.sampled and count:
            low = max(frame.start, frame.sample_offsets[first * count // pixels] - 16)
            high = min(frame.stop, frame.sample_offsets[(last - 1) * count // pixels] + 16)
        else:
            span = frame.stop - frame.start
            low = frame.start + first * span // pixels
            high = frame.start + (last * span + pixels - 1) // pixels
        x, y = curve_point_at(grid, tile)
        for index in range(bisect_left(ends, low + 1), len(frame.entropy_shifts)):
            begin, stop, delta = frame.entropy_shifts[index]
            if begin >= high:
                break
            (up if delta > 0 else down)[y * grid + x] = 1
    return up, down


def is_unmapped_tile(frame, tile_index, get_ea, badaddr, tile_side=8):
    """Check a representative tile byte plus exact viewport boundaries."""
    count = (frame.side // tile_side) ** 2
    if get_ea(tile_file_offset(frame, tile_index, tile_side)) == badaddr:
        return True
    if tile_index == 0 and get_ea(frame.start) == badaddr:
        return True
    if tile_index == count - 1 and get_ea(frame.stop - 1) == badaddr:
        return True
    return False


def unmapped_boundary_segments(mask, grid_side, tile_side=8):
    """Expose only outer edges of unmapped tiles, not red grid lines inside them."""
    if grid_side <= 0 or len(mask) != grid_side * grid_side:
        raise ValueError("Invalid unmapped mask")
    edges = []
    for y in range(grid_side):
        for x in range(grid_side):
            index = y * grid_side + x
            if not mask[index]:
                continue
            left, right = x * tile_side, (x + 1) * tile_side
            top, bottom = y * tile_side, (y + 1) * tile_side
            if x == 0 or not mask[index - 1]:
                edges.append((left, top, left, bottom))
            if x == grid_side - 1 or not mask[index + 1]:
                edges.append((right, top, right, bottom))
            if y == 0 or not mask[index - grid_side]:
                edges.append((left, top, right, top))
            if y == grid_side - 1 or not mask[index + grid_side]:
                edges.append((left, bottom, right, bottom))
    return edges
