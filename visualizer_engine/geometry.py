"""Map coordinates, ranges, and shared rendering values."""

import ctypes

from array import array
from functools import lru_cache
from visualizer_engine.native import native_renderer

SIDE = 512


EXACT_LIMIT = 1 << 20


MAX_SEQUENTIAL_SAMPLE_BYTES = 64 << 20


BLACK = 0xFF000000


GLOBAL_GAP = 0xFF222C35


UNREADABLE = 0xFF9AA2AA


UNCOMPARABLE = 0xFF376CA8


CHANGED = 0xFFFFB64C


NEW_REGION = 0xFFB781EB


INSPECTION_RANGE_OUTLINES = (0xEFFF9AD5, 0xEF8EA7FF, 0xEFFFF0A2, 0xEF65D8BB)


_INSPECTION_RANGE_FILLS = (0x6BFF9AD5, 0x518EA7FF, 0x3CFFF0A2, 0x0E65D8BB)


ORDER_LAGS = (2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)


ORDER_WINDOW = 8192


COMPRESSIBLE_MIN_ENTROPY = 7.6


COMPRESSIBLE_MAX_RATIO = 0.55


ORDER_SUPPORT_MIN_EFFECT = 0.25


ORDER_SUPPORT_MAX_P = 0.02


class RenderCancelled(Exception):
    """Viewport moved while this frame was rendering."""


def clamp_range(low, high, minimum, maximum):
    if maximum <= minimum:
        raise ValueError("Empty range")
    low = max(minimum, min(int(low), maximum - 1))
    return low, max(low + 1, min(int(high), maximum))


def move_range(low, high, delta, minimum, maximum):
    length = high - low
    low = max(minimum, min(low + int(delta), maximum - length))
    return low, low + length


def remap_nested(old_outer, inner, new_outer):
    """Keep a relative viewport at the same fraction of the absolute range."""
    old_low, old_high = old_outer
    new_low, new_high = new_outer
    span = old_high - old_low
    if span <= 0:
        raise ValueError("Empty absolute range")
    new_span = new_high - new_low
    low = new_low + (inner[0] - old_low) * new_span // span
    high = new_low + ((inner[1] - old_low) * new_span + span - 1) // span
    return clamp_range(low, high, new_low, new_high)


def zoom_range(low, high, minimum, maximum, anchor, inward):
    length = high - low
    if inward:
        new_length = max(1, min(length - 1, length * 4 // 5)) if length > 1 else 1
    else:
        new_length = min(maximum - minimum, max(length + 1, (length * 5 + 3) // 4))
    anchor = max(low, min(anchor, high - 1))
    new_low = anchor - (anchor - low) * new_length // length
    new_low = max(minimum, min(new_low, maximum - new_length))
    return new_low, new_low + new_length


def focus_domain(outer, inner):
    """Show a short zoom range within a useful local context on second slider."""
    minimum, maximum = outer
    low, high = inner
    context = min(maximum - minimum, (high - low) * 8)
    if context == maximum - minimum:
        return outer
    center = (low + high) // 2
    start = max(minimum, min(center - context // 2, maximum - context))
    return start, start + context


@lru_cache(maxsize=4)
def hilbert_pixels(side):
    """Curve index -> pixel and inverse; orientation matches Hilbert.java."""
    if side < 2 or side & (side - 1):
        raise ValueError("Map side must be a power of two")
    points = array("I", [0])
    width = 1
    while width < side:
        next_width = width * 2
        quadrant = array("I")
        for pixel in points:
            x, y = pixel % width, pixel // width
            quadrant.append(x * next_width + y)
        for pixel in points:
            x, y = pixel % width, pixel // width
            quadrant.append(y * next_width + x + width)
        for pixel in points:
            x, y = pixel % width, pixel // width
            quadrant.append((y + width) * next_width + x + width)
        for pixel in points:
            x, y = pixel % width, pixel // width
            quadrant.append((next_width - 1 - x) * next_width + width - 1 - y)
        points = quadrant
        width = next_width
    inverse = array("I", [0]) * (side * side)
    for index, pixel in enumerate(points):
        inverse[pixel] = index
    return points, inverse


def curve_index_at(side, x, y):
    if not (0 <= x < side and 0 <= y < side):
        return None
    lib = native_renderer()
    if lib is not None:
        index = ctypes.c_uint32()
        if lib.visualizer_hilbert_index(side, x, y, ctypes.byref(index)) != 0:
            raise ValueError("Native Hilbert inverse failed")
        return index.value
    return hilbert_pixels(side)[1][y * side + x]


def curve_point_at(side, index):
    if not 0 <= index < side * side:
        return None
    lib = native_renderer()
    if lib is not None:
        x, y = ctypes.c_uint32(), ctypes.c_uint32()
        if lib.visualizer_hilbert_point(side, index, ctypes.byref(x), ctypes.byref(y)) != 0:
            raise ValueError("Native Hilbert point failed")
        return x.value, y.value
    pixel = hilbert_pixels(side)[0][index]
    return pixel % side, pixel // side
