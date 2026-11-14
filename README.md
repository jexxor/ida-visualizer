# IDA Visualizer

Visualizer explores a binary's entropy as a Hilbert map inside IDA. It can
compare the original file with captured debugger memory, inspect byte ranges,
and show evidence found in the file or memory snapshots.

## How the code flows

1. IDA loads `visualizer.py`, which exposes `PLUGIN_ENTRY` from
   `visualizer_ui/plugin.py`.
2. The plugin opens `EntropyMap` in `visualizer_ui/panel.py`. Its constructor
   builds the controls and starts the first file render.
3. `visualizer_ui/session.py` collects debugger regions and stores each stop in
   `SnapshotHistory`. The capture view selects regions and stops.
4. The view state chooses a file or memory source and a byte range. The render
   view submits work to `visualizer_engine`, then paints the returned frame.
5. The inspection, byte diff, and findings views use the same selected source
   and frame. Small Qt widgets live in `visualizer_ui/widget_*.py`.

`visualizer_core.py` is the Qt-free public API. Its implementation is split by
responsibility under `visualizer_engine/`: geometry, snapshots, rendering,
overlays, inspection, and findings. `native/entropy.cpp` builds the optional
C++ renderer; Python rendering remains available when the library is absent.

## Native build

Build with CMake 3.16+ and a C++17 compiler:

```sh
cmake -S native -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The resulting library is `build/libvisualizer.so` on Linux or
`build/Release/visualizer.dll` with the Visual Studio generator on Windows.
Put it beside `visualizer.py` to enable the C++ renderer.

## Local installation

Copy `visualizer.py`, `visualizer_core.py`, both `visualizer_*` directories, and
optionally the native library into IDA's `plugins` directory. The current UI
uses the IDA 9.3 Python API and PySide6.

The entropy map was adapted from cantordust-ng (Apache-2.0, Battelle Memorial
Institute). See `LICENSE` for the license text.

Every push to `main` builds Linux and Windows packages and publishes a GitHub
Release tagged `v0.1.<workflow run number>`. Each package contains the Python
plugin, the platform's native library, this README, and `LICENSE`.
