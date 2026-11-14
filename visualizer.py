"""IDA entry point for the Visualizer plugin."""

from pathlib import Path
import sys

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from visualizer_ui.plugin import PLUGIN_ENTRY
