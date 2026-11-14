"""Layout and rendering across debugger regions."""

import math

from array import array
from collections import Counter
from pathlib import Path
from visualizer_engine.geometry import (
    CHANGED,
    GLOBAL_GAP,
    NEW_REGION,
    RenderCancelled,
    SIDE,
    UNCOMPARABLE,
    UNREADABLE,
    clamp_range,
    curve_index_at,
    curve_point_at,
    hilbert_pixels,
)
from visualizer_engine.models import GlobalFrame
from visualizer_engine.native import _native_entropy_deltas
from visualizer_engine.palette import Entropy
from visualizer_engine.snapshots import _verified_file_page, common_va_snapshots, iter_file_baseline

def same_region_overlap(first, second):
    """Only offer snapshots of the same mapped region with comparable VA bytes."""
    if (first is second or first.start >= second.stop
            or second.start >= first.stop):
        return False
    if first.mapping and second.mapping:
        return (first.mapping[:2] == second.mapping[:2]
                or (first.mapping[0] == second.mapping[0]
                    and first.mapping[2] == second.mapping[2]))
    return first.region == second.region


def global_layout(snapshots, side=SIDE, priorities=None):
    """Assign whole tiles; retain verified changed regions before unchanged ones."""
    if side < 8 or side & (side - 1):
        raise ValueError("Global map side must be a power of two >= 8")
    snapshots = sorted(snapshots, key=lambda item: (item.start, item.stop, item.region))
    if not snapshots:
        raise ValueError("No snapshots for global map")
    if len({snapshot.serial for snapshot in snapshots}) != 1:
        raise ValueError("Global map needs snapshots from one debugger stop")
    capacity = (side // 8) ** 2
    maximum = (capacity + 1) // 2
    omitted = max(0, len(snapshots) - maximum)
    if omitted and priorities:
        changed = sorted((item for item in snapshots if id(item) in priorities),
                         key=lambda item: (len(item.data), item.start))
        chosen = changed[:maximum]
        chosen.extend(item for item in snapshots if id(item) not in priorities)
        snapshots = sorted(chosen[:maximum], key=lambda item: (item.start, item.stop, item.region))
    else:
        snapshots = snapshots[:maximum]
    available = capacity - len(snapshots) + 1
    extra = available - len(snapshots)
    weights = [math.sqrt(len(snapshot.data)) for snapshot in snapshots]
    total = sum(weights)
    portions = [extra * weight / total for weight in weights]
    sizes = [1 + int(amount) for amount in portions]
    leftovers = extra - sum(size - 1 for size in sizes)
    for index in sorted(range(len(sizes)), key=lambda i: portions[i] % 1, reverse=True)[:leftovers]:
        sizes[index] += 1
    regions, indices = [], [-1] * capacity
    at = 0
    for snapshot, size in zip(snapshots, sizes):
        regions.append((at, at + size, snapshot))
        indices[at:at + size] = [len(regions) - 1] * size
        at += size + 1
    return tuple(regions), tuple(indices), omitted


def iter_global_file_samples(snapshots, side, path, file_offset_for_ea):
    """Map verified samples; first check small regions exactly to prioritize changes.

    All IDB file-offset calls stay on IDA's UI thread. The special 'changed'
    entry carries an exact VA, not a sampled color guess.
    """
    snapshots = tuple(snapshots)
    priority = {}
    path = Path(path)
    file_size = path.stat().st_size
    for snapshot in snapshots:
        if len(snapshot.data) > 4096:
            continue
        changed = False
        for offset, original, valid in iter_file_baseline(
                path, snapshot.start, len(snapshot.data), file_offset_for_ea):
            now = snapshot.data[offset:offset + len(original)]
            known = snapshot.valid[offset:offset + len(original)]
            first = next((index for index, (a, b, x, y) in enumerate(
                zip(now, original, known, valid)) if x and y and a != b), None)
            if first is not None:
                address = snapshot.start + offset + first
                priority[id(snapshot)] = address
                yield (id(snapshot), "changed"), address
                changed = True
                break
        if not changed:
            yield (id(snapshot), "probed"), None  # Yield between IDB-bound page probes.
    regions, _, _ = global_layout(snapshots, side, priority)
    with path.open("rb") as stream:
        for first, end, snapshot in regions:
            page_cache = {}
            cells = (end - first) * 64
            count = min(8192, max(1, cells // 32))
            for index in range(count):
                pos = (2 * index + 1) * len(snapshot.data) // (2 * count)
                size = min(32, len(snapshot.data))
                begin = max(0, min(pos - size // 2, len(snapshot.data) - size))
                if not all(snapshot.valid[begin:begin + size]):
                    yield (id(snapshot), index), (bytes(size), bytes(size))
                    continue  # Unread RAM cannot be a verified file difference.
                ea = snapshot.start + begin
                data, validity = bytearray(), bytearray()
                for page in range(ea & ~4095, ea + size, 4096):
                    if page not in page_cache:
                        low = max(page, snapshot.start)
                        high = min(page + 4096, snapshot.stop)
                        page_cache[page] = (low, *_verified_file_page(
                            stream, file_size, low, high - low, file_offset_for_ea))
                        yield (id(snapshot), "page", page), None  # Bound IDB work per UI turn.
                    low, original, valid = page_cache[page]
                    offset = max(ea, page) - low
                    width = min(ea + size, page + 4096) - max(ea, page)
                    data.extend(original[offset:offset + width])
                    validity.extend(valid[offset:offset + width])
                yield (id(snapshot), index), (bytes(data), bytes(validity))


def global_hit(frame, x, y):
    """Return snapshot and real VA; separators have no invented address."""
    if not (0 <= x < frame.side and 0 <= y < frame.side):
        return None
    index = curve_index_at(frame.side, x, y)
    tile = index // 64
    region_index = frame.tile_regions[tile]
    if region_index < 0:
        return None
    first, end, snapshot = frame.regions[region_index]
    local = index - first * 64
    ea = snapshot.start + local * len(snapshot.data) // ((end - first) * 64)
    return snapshot, min(ea, snapshot.stop - 1)


def global_bookmark_position(frame, address):
    """Map a bookmarked VA to its captured region and nearest Hilbert cell."""
    for first, end, snapshot in frame.regions:
        if snapshot.start <= address < snapshot.stop:
            cells = (end - first) * 64
            index = first * 64 + min(cells - 1,
                                     (address - snapshot.start) * cells // len(snapshot.data))
            return snapshot, curve_point_at(frame.side, index)
    return None


def global_boundary_segments(frame):
    """Show every region's border and all separator tiles in map coordinates."""
    grid = frame.side // 8
    owners = [-1] * (grid * grid)
    for tile, owner in enumerate(frame.tile_regions):
        x, y = curve_point_at(grid, tile)
        owners[y * grid + x] = owner
    edges = []
    for y in range(grid):
        for x in range(grid):
            owner = owners[y * grid + x]
            if owner < 0:
                continue
            left, right = x * 8, (x + 1) * 8
            top, bottom = y * 8, (y + 1) * 8
            if x == 0 or owners[y * grid + x - 1] != owner:
                edges.append((left, top, left, bottom))
            if x == grid - 1 or owners[y * grid + x + 1] != owner:
                edges.append((right, top, right, bottom))
            if y == 0 or owners[(y - 1) * grid + x] != owner:
                edges.append((left, top, right, top))
            if y == grid - 1 or owners[(y + 1) * grid + x] != owner:
                edges.append((left, bottom, right, bottom))
    return edges


def global_delta_tile_masks(frame):
    grid = frame.side // 8
    up, down = bytearray(grid * grid), bytearray(grid * grid)
    shifts = {}
    for region, start, stop, delta in frame.entropy_shifts:
        shifts.setdefault(region, []).append((start, stop, delta))
    for region_index, (first, end, snapshot) in enumerate(frame.regions):
        cells = (end - first) * 64
        for tile in range(first, end):
            low = snapshot.start + (tile - first) * 64 * len(snapshot.data) // cells
            high = snapshot.start + ((tile - first + 1) * 64 * len(snapshot.data) + cells - 1) // cells
            for start, stop, delta in shifts.get(region_index, ()):
                if start < high and low < stop:
                    x, y = curve_point_at(grid, tile)
                    (up if delta > 0 else down)[y * grid + x] = 1
    return up, down


def first_comparable_change(current, baseline, cancelled=None, start=None, stop=None):
    """First verified changed VA across overlapping readable captures; no sampling."""
    low = max(current.start, baseline.start, current.start if start is None else start)
    high = min(current.stop, baseline.stop, current.stop if stop is None else stop)
    for address in range(low, high, 65536):
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        size = min(65536, high - address)
        a, b = address - current.start, address - baseline.start
        now, old = current.data[a:a + size], baseline.data[b:b + size]
        current_valid = current.valid[a:a + size]
        baseline_valid = baseline.valid[b:b + size]
        for index, (x, y, known_x, known_y) in enumerate(
                zip(now, old, current_valid, baseline_valid)):
            if known_x and known_y and x != y:
                return address + index
    return None


def render_global_snapshots(snapshots, side=SIDE, comparisons=None,
                             file_samples=None, cancelled=None):
    """Bounded Hilbert map over disjoint captured VA regions of one stop."""
    snapshots = tuple(snapshots)
    if comparisons is not None:
        candidates = tuple(comparisons)
    else:
        candidates = ()
    priorities = {key[0]: value for key, value in (file_samples or {}).items()
                  if key[1] == "changed"}
    baselines = {}
    if comparisons is not None:
        for snapshot in snapshots:
            if cancelled is not None and cancelled():
                raise RenderCancelled()
            matches = [old for old in candidates if same_region_overlap(snapshot, old)]
            if matches:
                baseline = max(matches, key=lambda old: min(snapshot.stop, old.stop)
                               - max(snapshot.start, old.start))
                baselines[id(snapshot)] = baseline
                address = first_comparable_change(snapshot, baseline, cancelled)
                if address is not None:
                    priorities[id(snapshot)] = address
    regions, tile_regions, omitted = global_layout(snapshots, side, priorities)
    included = {id(snapshot) for _, _, snapshot in regions}
    omitted_changes = sum(key not in included for key in priorities)
    points, _ = hilbert_pixels(side)
    pixels = array("I", [GLOBAL_GAP]) * (side * side)
    shifts = []
    for region_index, (first, end, snapshot) in enumerate(regions):
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        baseline = baselines.get(id(snapshot))
        if baseline is not None:
            now, before = common_va_snapshots(snapshot, baseline)
            shifts.extend((region_index, low, high, delta) for low, high, delta in
                          entropy_delta_regions(now, before))
        cells = (end - first) * 64
        count = min(8192, max(1, cells // 32))
        colors = array("I")
        for sample in range(count):
            pos = (2 * sample + 1) * len(snapshot.data) // (2 * count)
            size = min(32, len(snapshot.data))
            begin = max(0, min(pos - size // 2, len(snapshot.data) - size))
            data = snapshot.data[begin:begin + size]
            valid = snapshot.valid[begin:begin + size]
            if not all(valid):
                color = UNREADABLE
            elif file_samples is not None:
                other = file_samples.get((id(snapshot), sample))
                if other is None or not all(other[1]):
                    color = NEW_REGION if snapshot.new_region else UNCOMPARABLE
                else:
                    if data != other[0]:
                        color = CHANGED
                        if id(snapshot) not in priorities:
                            difference = next(i for i, (x, y) in enumerate(zip(data, other[0]))
                                              if x != y)
                            priorities[id(snapshot)] = snapshot.start + begin + difference
                    else:
                        color = Entropy(data).color(size // 2)
            elif comparisons is not None:
                ea = snapshot.start + begin
                if baseline is None or ea < baseline.start or ea + size > baseline.stop:
                    color = NEW_REGION if snapshot.new_region else UNCOMPARABLE
                else:
                    offset = ea - baseline.start
                    other_valid = baseline.valid[offset:offset + size]
                    if not all(other_valid):
                        color = UNCOMPARABLE
                    else:
                        old_data = baseline.data[offset:offset + size]
                        color = CHANGED if data != old_data else Entropy(data).color(size // 2)
            else:
                color = Entropy(data).color(size // 2)
            colors.append(color)
        for local in range(cells):
            if (local & 1023) == 0 and cancelled is not None and cancelled():
                raise RenderCancelled()
            pixels[points[first * 64 + local]] = colors[local * count // cells]
    marks = tuple((index, priorities[id(snapshot)])
                  for index, (_, _, snapshot) in enumerate(regions)
                  if id(snapshot) in priorities)
    return GlobalFrame(pixels.tobytes(), side, regions[0][2].serial,
                       regions, tile_regions, tuple(shifts), omitted, marks, omitted_changes)


def entropy_delta_regions(current, baseline, start=None, stop=None,
                           block_size=4096, threshold_bits=0.5):
    """Find entropy shifts in VA-aligned blocks, independent of viewport."""
    if (current.start != baseline.start or current.stop != baseline.stop
            or block_size < 512):
        raise ValueError("Incompatible entropy comparison")
    start, stop = clamp_range(current.start if start is None else start,
                              current.stop if stop is None else stop,
                              current.start, current.stop)
    aligned_start = start // block_size * block_size
    data_start = max(current.start, aligned_start)
    data_stop = min(current.stop, (stop + block_size - 1) // block_size * block_size)
    prefix = data_start - aligned_start
    offset = data_start - current.start
    length = data_stop - data_start
    pad = bytes(prefix)
    native = _native_entropy_deltas(
        pad + current.data[offset:offset + length], pad + current.valid[offset:offset + length],
        pad + baseline.data[offset:offset + length], pad + baseline.valid[offset:offset + length],
        block_size)
    if native is not None:
        return tuple((max(start, address), min(stop, address + block_size), delta)
                      for index, delta in enumerate(native)
                      for address in (aligned_start + index * block_size,)
                      if not math.isnan(delta) and abs(delta) >= threshold_bits)
    shifts = []
    for address in range(aligned_start, stop, block_size):
        begin = max(current.start, address)
        end = min(current.stop, address + block_size)
        offset = begin - current.start
        length = end - address
        now = current.data[offset:offset + end - begin]
        then = baseline.data[offset:offset + end - begin]
        valid = current.valid[offset:offset + end - begin]
        other_valid = baseline.valid[offset:offset + end - begin]
        pairs = [(a, b) for a, b, x, y in zip(now, then, valid, other_valid) if x and y]
        if len(pairs) < max(512, (length * 3 + 3) // 4):
            continue
        a_counts = Counter(a for a, _ in pairs)
        b_counts = Counter(b for _, b in pairs)
        n = len(pairs)
        def shannon(counts):
            return math.log2(n) - sum(count * math.log2(count) for count in counts.values()) / n
        difference = shannon(a_counts) - shannon(b_counts)
        if abs(difference) >= threshold_bits:
            shifts.append((max(start, address), min(stop, end), difference))
    return tuple(shifts)
