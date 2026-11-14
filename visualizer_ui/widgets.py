"""Small Qt widgets used by the panel and auxiliary docks."""

from visualizer_ui.widget_common import (
    byte_diff_focus_text,
    data_color,
    format_byte_diff,
    view_colors,
    visual_ink,
    wheel_units,
)
from visualizer_ui.widget_diff import ByteHistogram, DiffHexView, DiffRibbon
from visualizer_ui.widget_findings import EvidenceLanes
from visualizer_ui.widget_inspection import InspectionProfile, inspection_profile_data
from visualizer_ui.widget_map import MapCanvas
from visualizer_ui.widget_slider import EntropySlider