"""File and snapshot map rendering and overviews."""

import threading

from array import array
from collections import OrderedDict
from pathlib import Path
from visualizer_engine.geometry import (
    BLACK,
    CHANGED,
    EXACT_LIMIT,
    MAX_SEQUENTIAL_SAMPLE_BYTES,
    RenderCancelled,
    SIDE,
    UNCOMPARABLE,
    UNREADABLE,
    clamp_range,
    hilbert_pixels,
)
from visualizer_engine.global_map import entropy_delta_regions, first_comparable_change
from visualizer_engine.models import Frame
from visualizer_engine.native import _native_debug_pixels, _native_pixels
from visualizer_engine.palette import Entropy

_SAMPLE_CACHE = OrderedDict()
_SAMPLE_CACHE_LIMIT = 16384
_SAMPLE_LOCK = threading.Lock()


def _sample_count(span, side):
    count = min(side * side // 4, 8192)
    if span > 64 * (1 << 20):
        count = min(count, 2048)
    if span > 1 << 30:
        count = min(count, 1024)
    return max(1, count)


def _sample_positions(start, stop, count):
    """Use stable file-aligned buckets so neighboring viewports reuse samples."""
    span = stop - start
    spacing = max(32, span // count)
    grid = 1 << (spacing.bit_length() - 1)
    for index in range(count):
        center = start + (2 * index + 1) * span // (2 * count)
        yield max(start, min(stop - 1, center // grid * grid))


def _sample_block(stream, signature, file_size, position):
    key = (*signature, position)
    with _SAMPLE_LOCK:
        block = _SAMPLE_CACHE.get(key)
        if block is not None:
            _SAMPLE_CACHE.move_to_end(key)
            return block
    block_start = max(0, min(position - 16, file_size - 32))
    stream.seek(block_start)
    block = stream.read(32)
    with _SAMPLE_LOCK:
        _SAMPLE_CACHE[key] = block
        _SAMPLE_CACHE.move_to_end(key)
        if len(_SAMPLE_CACHE) > _SAMPLE_CACHE_LIMIT:
            _SAMPLE_CACHE.popitem(last=False)
    return block


def render_file(path, start, stop, side=SIDE, cancelled=None):
    """Exact rendering up to 1 MiB; bounded 32-byte sampling above it."""
    path = Path(path)
    stat = path.stat()
    file_size = stat.st_size
    start, stop = clamp_range(start, stop, 0, file_size)
    span = stop - start
    with path.open("rb") as stream:
        if span <= EXACT_LIMIT:
            stream.seek(start)
            data = stream.read(span)
            if cancelled is not None and cancelled():
                raise RenderCancelled()
            native = _native_pixels(data, side)
            if native is not None:
                return Frame(native, side, start, stop, False)
            points, _ = hilbert_pixels(side)
            pixels = array("I", [BLACK]) * (side * side)
            entropy = Entropy(data)
            last_index, color = -1, BLACK
            for index, pixel in enumerate(points):
                if (index & 1023) == 0 and cancelled is not None and cancelled():
                    raise RenderCancelled()
                source_index = index * len(data) // len(points)
                if source_index != last_index:
                    color = entropy.color(source_index)
                    last_index = source_index
                pixels[pixel] = color
            sampled = False
        else:
            count = _sample_count(span, side)
            blocks = bytearray()
            positions = tuple(_sample_positions(start, stop, count))
            # Small zoomed-out regions are faster as one sequential read, not
            # thousands of file seeks (especially on HDDs/network shares).
            if span <= MAX_SEQUENTIAL_SAMPLE_BYTES:
                base = max(0, start - 16)
                stream.seek(base)
                nearby = stream.read(min(file_size - base, stop - base + 16))
            else:
                nearby = None
                signature = (str(path.resolve()), file_size, stat.st_ino,
                             stat.st_mtime_ns, stat.st_ctime_ns)
            for index, position in enumerate(positions):
                if (index & 255) == 0 and cancelled is not None and cancelled():
                    raise RenderCancelled()
                block_start = max(0, min(position - 16, file_size - 32))
                if nearby is not None:
                    block = nearby[block_start - base:block_start - base + 32]
                else:
                    block = _sample_block(stream, signature, file_size, position)
                blocks.extend(block)
            if cancelled is not None and cancelled():
                raise RenderCancelled()
            native = _native_pixels(bytes(blocks), side, sampled=True, count=count)
            if native is not None:
                return Frame(native, side, start, stop, True, positions)
            points, _ = hilbert_pixels(side)
            colors = array("I", (Entropy(blocks[index * 32:(index + 1) * 32]).color(16)
                                 for index in range(count)))
            pixels = array("I", [BLACK]) * (side * side)
            for index, pixel in enumerate(points):
                if (index & 1023) == 0 and cancelled is not None and cancelled():
                    raise RenderCancelled()
                pixels[pixel] = colors[index * count // len(points)]
            sampled = True
    return Frame(pixels.tobytes(), side, start, stop, sampled,
                 positions if sampled else ())


def render_snapshot(snapshot, start=None, stop=None, side=SIDE, compare=None,
                     cancelled=None):
    """Render paused process memory; unreadable or uncomparable bytes stay distinct."""
    start, stop = clamp_range(snapshot.start if start is None else start,
                              snapshot.stop if stop is None else stop,
                              snapshot.start, snapshot.stop)
    if compare is not None and (compare.start != snapshot.start
                                or compare.stop != snapshot.stop):
        raise ValueError("Comparison snapshot has a different address range")
    at = start - snapshot.start
    length = stop - start
    shifts = (entropy_delta_regions(snapshot, compare, start, stop)
              if compare is not None else ())
    first_change = (first_comparable_change(snapshot, compare, cancelled, start, stop)
                    if compare is not None else None)
    if length <= EXACT_LIMIT:
        data = snapshot.data[at:at + length]
        valid = snapshot.valid[at:at + length]
        if compare is not None:
            other = start - compare.start
            baseline = compare.data[other:other + length]
            baseline_valid = compare.valid[other:other + length]
        else:
            baseline = baseline_valid = None
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        native = _native_debug_pixels(data, valid, side, baseline, baseline_valid)
        if native is not None:
            return Frame(native, side, start, stop, False,
                         entropy_shifts=shifts, first_change=first_change)
        points, _ = hilbert_pixels(side)
        colors = array("I", [BLACK]) * (side * side)
        entropy = Entropy(data)
        n = min(32, length)
        for index, pixel in enumerate(points):
            if (index & 1023) == 0 and cancelled is not None and cancelled():
                raise RenderCancelled()
            source = index * length // len(points)
            begin = max(0, min(source - n // 2, length - n))
            if not valid[source]:
                color = UNREADABLE
            elif baseline is not None and not baseline_valid[source]:
                color = UNCOMPARABLE
            elif baseline is not None and data[source] != baseline[source]:
                color = CHANGED
            elif not all(valid[begin:begin + n]):
                color = BLACK  # Source is readable; local entropy window is not.
            else:
                color = entropy.color(source)
            colors[pixel] = color
        return Frame(colors.tobytes(), side, start, stop, False,
                     entropy_shifts=shifts, first_change=first_change)

    count = _sample_count(length, side)
    positions = tuple(_sample_positions(start, stop, count))
    blocks, valid_blocks = bytearray(), bytearray()
    baseline_blocks = bytearray() if compare is not None else None
    baseline_valid_blocks = bytearray() if compare is not None else None
    for index, position in enumerate(positions):
        if (index & 255) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        begin = max(snapshot.start, min(position - 16, snapshot.stop - 32))
        offset = begin - snapshot.start
        blocks.extend(snapshot.data[offset:offset + 32])
        valid_blocks.extend(snapshot.valid[offset:offset + 32])
        if compare is not None:
            other = begin - compare.start
            baseline_blocks.extend(compare.data[other:other + 32])
            baseline_valid_blocks.extend(compare.valid[other:other + 32])
    base = bytes(baseline_blocks) if baseline_blocks is not None else None
    base_valid = bytes(baseline_valid_blocks) if baseline_valid_blocks is not None else None
    native = _native_debug_pixels(bytes(blocks), bytes(valid_blocks), side,
                                  base, base_valid, sampled=True, count=count)
    if native is not None:
        return Frame(native, side, start, stop, True, positions, shifts, first_change)
    points, _ = hilbert_pixels(side)
    sampled_colors = array("I")
    for index in range(count):
        begin = index * 32
        chunk = blocks[begin:begin + 32]
        valid_chunk = valid_blocks[begin:begin + 32]
        if not all(valid_chunk):
            color = UNREADABLE
        elif base is not None and not all(base_valid[begin:begin + 32]):
            color = UNCOMPARABLE
        elif base is not None and chunk != base[begin:begin + 32]:
            color = CHANGED
        else:
            color = Entropy(chunk).color(16)
        sampled_colors.append(color)
    pixels = array("I", [BLACK]) * (side * side)
    for index, pixel in enumerate(points):
        if (index & 1023) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        pixels[pixel] = sampled_colors[index * count // len(points)]
    return Frame(pixels.tobytes(), side, start, stop, True, positions, shifts, first_change)


def entropy_overview_chunks(path, bins=1024, chunk_size=64, start=0, stop=None):
    """Yield entropy strips for a file range, paintable in small increments."""
    path = Path(path)
    size = path.stat().st_size
    if size <= 0 or bins <= 0 or chunk_size <= 0:
        raise ValueError("Empty file or preview")
    start, stop = clamp_range(start, size if stop is None else stop, 0, size)
    span = stop - start
    colors = array("I")
    with path.open("rb") as stream:
        for index in range(bins):
            center = min(stop - 1, start + (2 * index + 1) * span // (2 * bins))
            block_start = max(0, min(center - 16, size - 32))
            stream.seek(block_start)
            block = stream.read(32)
            colors.append(Entropy(block).color(center - block_start))
            if len(colors) == chunk_size:
                yield index + 1 - len(colors), colors.tobytes()
                colors = array("I")
    if colors:
        yield bins - len(colors), colors.tobytes()


def snapshot_overview_chunks(snapshot, bins=1024, chunk_size=64, start=None, stop=None):
    start, stop = clamp_range(snapshot.start if start is None else start,
                              snapshot.stop if stop is None else stop,
                              snapshot.start, snapshot.stop)
    colors = array("I")
    for index in range(bins):
        center = min(stop - 1, start + (2 * index + 1) * (stop - start) // (2 * bins))
        begin = max(snapshot.start, min(center - 16, snapshot.stop - 32)) - snapshot.start
        data = snapshot.data[begin:begin + 32]
        valid = snapshot.valid[begin:begin + 32]
        color = Entropy(data).color(center - snapshot.start - begin) if all(valid) else UNREADABLE
        colors.append(color)
        if len(colors) == chunk_size:
            yield index + 1 - len(colors), colors.tobytes()
            colors = array("I")
    if colors:
        yield bins - len(colors), colors.tobytes()
