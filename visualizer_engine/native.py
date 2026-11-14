"""Optional native renderer and its C ABI."""

import ctypes
import os
import sys

from functools import lru_cache
from pathlib import Path

_native_error = None


@lru_cache(maxsize=1)
def native_renderer():
    """Load optional C ABI library from beside the plugin, without linking Qt."""
    global _native_error
    extension = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    filename = ("visualizer" if sys.platform == "win32" else "libvisualizer") + extension
    path = Path(os.environ.get("VISUALIZER_NATIVE_LIB") or Path(__file__).resolve().parent.parent / filename)
    if not path.is_file():
        _native_error = f"{path.name} not found"
        return None
    try:
        lib = ctypes.CDLL(str(path))
        ptr = ctypes.POINTER(ctypes.c_uint32)
        lib.visualizer_render_entropy.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ptr)
        lib.visualizer_render_entropy.restype = ctypes.c_int
        lib.visualizer_render_entropy_blocks.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ptr)
        lib.visualizer_render_entropy_blocks.restype = ctypes.c_int
        lib.visualizer_hilbert_index.argtypes = (ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ptr)
        lib.visualizer_hilbert_index.restype = ctypes.c_int
        lib.visualizer_hilbert_point.argtypes = (ctypes.c_uint32, ctypes.c_uint32, ptr, ptr)
        lib.visualizer_hilbert_point.restype = ctypes.c_int
        lib.visualizer_render_debug.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_uint32, ptr)
        lib.visualizer_render_debug.restype = ctypes.c_int
        lib.visualizer_render_debug_blocks.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_uint32, ptr)
        lib.visualizer_render_debug_blocks.restype = ctypes.c_int
        lib.visualizer_entropy_deltas.argtypes = (
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_double))
        lib.visualizer_entropy_deltas.restype = ctypes.c_int
        _native_error = None
        return lib
    except (OSError, AttributeError) as exc:
        _native_error = str(exc)
        return None


def renderer_status():
    return "C++" if native_renderer() is not None else f"Python ({_native_error})"


def _native_pixels(data, side, sampled=False, count=0):
    lib = native_renderer()
    if lib is None:
        return None
    pixels = (ctypes.c_uint32 * (side * side))()
    source = ctypes.create_string_buffer(data)
    if sampled:
        result = lib.visualizer_render_entropy_blocks(source, count, side, pixels)
    else:
        result = lib.visualizer_render_entropy(source, len(data), side, pixels)
    if result != 0:
        raise ValueError(f"Native entropy renderer failed ({result})")
    return ctypes.string_at(pixels, side * side * 4)


def _native_debug_pixels(data, valid, side, compare=None, compare_valid=None,
                         sampled=False, count=0):
    lib = native_renderer()
    if lib is None:
        return None
    pixels = (ctypes.c_uint32 * (side * side))()
    buffers = [ctypes.create_string_buffer(value) if value is not None else None
               for value in (data, valid, compare, compare_valid)]
    if sampled:
        result = lib.visualizer_render_debug_blocks(
            *buffers, count, side, pixels)
    else:
        result = lib.visualizer_render_debug(
            *buffers, len(data), side, pixels)
    if result != 0:
        raise ValueError(f"Native debug renderer failed ({result})")
    return ctypes.string_at(pixels, side * side * 4)


def _native_entropy_deltas(current, current_valid, baseline, baseline_valid,
                           block_size):
    lib = native_renderer()
    if lib is None:
        return None
    length = len(current)
    output = (ctypes.c_double * ((length + block_size - 1) // block_size))()
    buffers = [ctypes.create_string_buffer(value) for value in
               (current, current_valid, baseline, baseline_valid)]
    result = lib.visualizer_entropy_deltas(*buffers, length, block_size, output)
    if result != 0:
        raise ValueError(f"Native entropy delta failed ({result})")
    return output
