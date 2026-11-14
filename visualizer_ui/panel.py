"""Main dock and plugin form assembly."""

import ida_dbg
import ida_kernwin

from PySide6 import QtCore, QtWidgets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from visualizer_core import (
    BLACK,
    CHANGED,
    EXACT_LIMIT,
    NEW_REGION,
    UNCOMPARABLE,
    UNREADABLE,
    renderer_status,
)
from visualizer_ui.byte_views import ByteViewsMixin
from visualizer_ui.capture_view import CaptureViewMixin
from visualizer_ui.constants import (
    DELTA_DOWN,
    DELTA_FILE,
    DELTA_STORED,
    DELTA_UP,
    RAM_STOP,
)
from visualizer_ui.findings_view import FindingsViewMixin
from visualizer_ui.inspection_view import InspectionViewMixin
from visualizer_ui.render_view import RenderViewMixin
from visualizer_ui.session import RenderSignal
from visualizer_ui.view_state import ViewStateMixin
from visualizer_ui.widgets import EntropySlider, MapCanvas

class EntropyMap(
    ByteViewsMixin,
    FindingsViewMixin,
    InspectionViewMixin,
    CaptureViewMixin,
    ViewStateMixin,
    RenderViewMixin,
    QtWidgets.QWidget,
):
    def __init__(self, parent, path, idb_path, session):
        super().__init__(parent)
        self._init_state(path, idb_path, session)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self._build_source_controls(layout)
        self._build_stop_controls(layout)
        self._build_legend(layout)
        self._build_range_controls(layout)
        self._connect_ui(layout)
        self._start()

    def _init_state(self, path, idb_path, session):
        """Set the file, capture, worker, and view state before making widgets."""
        self.session = session
        self.path = Path(path)
        self.idb_path = idb_path
        self.file_size = self.path.stat().st_size
        self.mode = "File"
        self.global_mode = False
        self.global_follow_latest = False
        self.follow_previous_baseline = True
        self.global_baseline_generation = 0
        self.global_file_key = None
        self.global_file_samples = None
        self.global_pending_key = None
        self.global_sample_iterator = None
        self.domain = 0, self.file_size
        self.absolute_range = 0, min(EXACT_LIMIT, self.file_size)
        self.selection = self.absolute_range
        self.file_ranges = self.absolute_range, self.selection
        self.relative_domain = self.absolute_range
        self.snapshot = None
        self.baseline = None
        self.history = session.history
        self.tracked_regions = session.tracked_regions
        self.tracking_initialized = False
        self.new_regions = set()
        self.regions = []
        self.active_regions = ()
        self.stop_serial = 0
        self.baseline_generation = 0
        self.baseline_iterator = None
        self.closed = False
        self.generation = 0
        self.ui_ready = False
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="visualizer-entropy")
        self.absolute_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="visualizer-file-entropy")
        self.relative_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="visualizer-window-entropy")
        self.finding_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="visualizer-findings")
        self.inspection_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="visualizer-inspection")
        self.inspection_generation = 0
        self.inspection_future = None
        self.inspection_requested_frame = None
        self.inspection_result_frame = None
        self.inspection_overlay_cache = None
        self.inspection_focus_generation = 0
        self.inspection_focus_future = None
        self.inspection_focus_cache = {}
        self.inspection_show_ranges = False
        self.inspection_range_checkbox = None
        self.render_source_key = None
        self.pending_inspection_offset = None
        self.finding_generation = 0
        self.finding_future = None
        self.findings = []
        self._finding_restore = None
        self.finding_view_key = None
        self.finding_completed_scope = None
        self.finding_saved = {}
        self.finding_jump_target = None
        self.finding_jump_pending = False
        self.finding_form = None
        self.finding_panel = None
        self.finding_list = None
        self.finding_lanes = None
        self.finding_scroll = None
        self.finding_focus = None
        self.finding_details = None
        self.selected_finding_index = None
        self.finding_scope = None
        self.finding_full_scan = None
        self.mark_finding = None
        self.inspector_form = None
        self.diff_form = None
        self.diff_address = None
        self.diff_title = None
        self.diff_text = None
        self.diff_all_bytes_font = None
        self.diff_ribbon = None
        self.diff_window = None
        self.diff_focus = None
        self.diff_summary = None
        self.diff_prev_button = None
        self.diff_next_button = None
        self.inspection_title = None
        self.inspection_scales = None
        self.inspection_facts = None
        self.inspection_histogram = None
        self.inspection_profile = None
        self.inspection_details = None
        self.overview_started = False
        self.absolute_generation = 0
        self.absolute_pixels = bytearray(b"\x00\x00\x00\xFF" * 1024)
        self.relative_pixels = bytearray(b"\x00\x00\x00\xFF" * 1024)
        self.relative_generation = 0
        self.relative_future = None
        self.absolute_future = None
        self.future = None
        self._wheel_pending = {"relative": 0, "absolute": 0}
        self.result = RenderSignal(self)
        self.result.ready.connect(self._rendered)
        self.result.overview_ready.connect(self._overview_rendered)
        self.result.findings_ready.connect(self._findings_rendered)
        self.result.inspection_ready.connect(self._inspection_rendered)
        self.result.inspection_focus_ready.connect(self._inspection_focus_rendered)
        self.raw_dialog = None
        self.bookmarks = {}
        self.bookmarks_loaded = False
        self.outline_generation = 0


    def _build_source_controls(self, layout):
        source_row = QtWidgets.QHBoxLayout()
        self.source_picker = QtWidgets.QComboBox()
        self.source_picker.addItems(("File", RAM_STOP, DELTA_FILE, DELTA_STORED))
        self.source_picker.currentTextChanged.connect(self._source_changed)
        self.region_picker = QtWidgets.QComboBox()
        self.region_picker.setMinimumWidth(210)
        self.region_picker.currentIndexChanged.connect(self._region_changed)
        self.track_button = QtWidgets.QToolButton()
        self.track_button.setText("Track…")
        self.track_button.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.track_button.setPopupMode(QtWidgets.QToolButton.ToolButtonPopupMode.InstantPopup)
        self.track_menu = QtWidgets.QMenu(self.track_button)
        self.track_button.setMenu(self.track_menu)
        self.track_button.setToolTip("Choose regions to capture on each debugger pause")
        self.global_button = QtWidgets.QPushButton("Global Map")
        self.global_button.setCheckable(True)
        self.global_button.setToolTip("Show all captured regions of one debugger stop")
        self.global_button.toggled.connect(self._global_changed)
        self.finding_button = QtWidgets.QPushButton("Findings")
        self.finding_button.setCheckable(True)
        self.finding_button.setToolTip("Ranked evidence from file and captured debugger stops")
        self.finding_button.toggled.connect(self._toggle_findings)
        self.inspector_button = QtWidgets.QPushButton("Inspector")
        self.inspector_button.setCheckable(True)
        self.inspector_button.setToolTip("Open dockable byte statistics")
        self.inspector_button.toggled.connect(self._toggle_inspector)
        self.diff_button = QtWidgets.QPushButton("Byte Diff")
        self.diff_button.setCheckable(True)
        self.diff_button.setToolTip("Show exact A and B bytes side by side for a delta map hit")
        self.diff_button.toggled.connect(self._toggle_byte_diff)
        self.diff_button.setVisible(False)
        self.entropy_eye = QtWidgets.QToolButton()
        self.entropy_eye.setText("👁")
        self.entropy_eye.setToolButtonStyle(QtCore.Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.entropy_eye.setFixedWidth(36)
        self.entropy_eye.setCheckable(True)
        self.entropy_eye.setChecked(True)
        self.entropy_eye.setToolTip("Hide entropy background in delta map")
        self.entropy_eye.toggled.connect(self._entropy_visibility_changed)
        self.region_picker.setVisible(False)
        self.track_button.setVisible(True)
        self.global_button.setVisible(False)
        self.entropy_eye.setVisible(False)
        source_row.addWidget(self.source_picker)
        source_row.addWidget(self.region_picker, 1)
        source_row.addWidget(self.track_button)
        source_row.addWidget(self.global_button)
        source_row.addWidget(self.finding_button)
        source_row.addWidget(self.inspector_button)
        source_row.addWidget(self.diff_button)
        source_row.addWidget(self.entropy_eye)
        layout.addLayout(source_row)

    def _build_stop_controls(self, layout):
        self.global_bar = QtWidgets.QWidget(self)
        global_row = QtWidgets.QHBoxLayout(self.global_bar)
        global_row.setContentsMargins(0, 0, 0, 0)
        self.global_base_label = QtWidgets.QLabel("A · stop")
        self.global_base_picker = QtWidgets.QComboBox()
        self.global_base_picker.currentIndexChanged.connect(self._base_stop_changed)
        global_row.addWidget(self.global_base_label)
        global_row.addWidget(self.global_base_picker, 1)
        global_row.addWidget(QtWidgets.QLabel("B · stop"))
        self.global_stop_picker = QtWidgets.QComboBox()
        self.global_stop_picker.currentIndexChanged.connect(self._global_stop_changed)
        global_row.addWidget(self.global_stop_picker, 1)
        self.global_bar.setVisible(False)
        layout.addWidget(self.global_bar)
        self.canvas = MapCanvas(self)
        layout.addWidget(self.canvas, 1)


    def _build_legend(self, layout):
        self.delta_legend = QtWidgets.QWidget(self)
        legend = QtWidgets.QGridLayout(self.delta_legend)
        legend.setContentsMargins(4, 0, 4, 0)
        legend.setHorizontalSpacing(12)
        for index, (text, color, outline) in enumerate((
                ("Changed byte", CHANGED, False),
                ("RAM read failed", UNREADABLE, False),
                ("No baseline", UNCOMPARABLE, False),
                ("New region", NEW_REGION, False),
                ("Entropy ↑", DELTA_UP, True),
                ("Entropy ↓", DELTA_DOWN, True),
                ("Unchanged", BLACK, False))):
            item = QtWidgets.QWidget(self.delta_legend)
            row = QtWidgets.QHBoxLayout(item)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(4)
            swatch = QtWidgets.QLabel(item)
            swatch.setFixedSize(14, 14)
            rgb = f"#{color & 0xFFFFFF:06X}" if isinstance(color, int) else color
            swatch.setStyleSheet((f"background: #000000; border: 2px solid {rgb};"
                                  if outline else f"background: {rgb}; border: 1px solid #888888;"))
            row.addWidget(swatch)
            row.addWidget(QtWidgets.QLabel(text, item))
            legend.addWidget(item, 0 if index < 3 else 1,
                             index if index < 3 else index - 3)
            if text == "Unchanged":
                self.unchanged_legend = item
                item.setVisible(not self.entropy_eye.isChecked())
        self.delta_legend.setVisible(False)
        layout.addWidget(self.delta_legend)


    def _build_range_controls(self, layout):
        self.absolute_bar = QtWidgets.QWidget(self)
        absolute_row = QtWidgets.QHBoxLayout(self.absolute_bar)
        absolute_row.setContentsMargins(0, 0, 0, 0)
        self.absolute_label = QtWidgets.QLabel("File")
        self.absolute_label.setFixedWidth(50)
        self.absolute_slider = EntropySlider(0, self.file_size, *self.absolute_range, parent=self)
        absolute_row.addWidget(self.absolute_label)
        absolute_row.addStretch(1)
        absolute_row.addWidget(self.absolute_slider, 5)
        absolute_row.addStretch(1)
        layout.addWidget(self.absolute_bar)

        self.relative_bar = QtWidgets.QWidget(self)
        relative_row = QtWidgets.QHBoxLayout(self.relative_bar)
        relative_row.setContentsMargins(0, 0, 0, 0)
        label = QtWidgets.QLabel("Zoom")
        label.setFixedWidth(50)
        self.relative_slider = EntropySlider(*self.relative_domain, *self.selection, parent=self)
        relative_row.addWidget(label)
        relative_row.addStretch(1)
        relative_row.addWidget(self.relative_slider, 5)
        relative_row.addStretch(1)
        layout.addWidget(self.relative_bar)


    def _connect_ui(self, layout):
        self.status = QtWidgets.QLabel()
        layout.addWidget(self.status)
        self.bookmark_refresh = QtCore.QTimer(self)
        self.bookmark_refresh.setSingleShot(True)
        self.bookmark_refresh.timeout.connect(self.refresh_bookmarks)
        self.outline_refresh = QtCore.QTimer(self)
        self.outline_refresh.setSingleShot(True)
        self.outline_refresh.timeout.connect(self.refresh_mapping)
        self.absolute_slider.rangeChanged.connect(self._absolute_changed)
        self.relative_slider.rangeChanged.connect(self._relative_changed)
        self.ui_ready = True

    def _start(self):
        self.session.attach(self)
        self._refresh_regions()
        if (ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP
                and not self.session.tracking_configured
                and not any(self.session.history.for_stop(serial)
                            for serial in self.session.history.stops)):
            self.session.track_prompt_pending = True
            generation = self.session.generation
            QtCore.QTimer.singleShot(0, lambda: self.session.offer_track_setup(generation))
        self.status.setText(f"Entropy · {renderer_status()} · drag slider to explore; wheel to zoom")
        self.render()

    def shutdown(self):
        self.closed = True
        self.inspection_generation += 1
        if self.inspection_future is not None:
            self.inspection_future.cancel()
        self.inspection_executor.shutdown(wait=False, cancel_futures=True)
        self.finding_generation += 1
        if self.finding_future is not None:
            self.finding_future.cancel()
        self.finding_executor.shutdown(wait=False, cancel_futures=True)
        self.session.detach(self)
        self.global_sample_iterator = None
        self.outline_generation += 1
        self.bookmark_refresh.stop()
        self.outline_refresh.stop()
        self.generation += 1
        if self.future is not None:
            self.future.cancel()
        self.executor.shutdown(wait=False, cancel_futures=True)
        if self.relative_future is not None:
            self.relative_future.cancel()
        self.absolute_executor.shutdown(wait=False, cancel_futures=True)
        self.relative_executor.shutdown(wait=False, cancel_futures=True)
        if self.inspector_form is not None:
            self.inspector_form.Close(0)
        if self.diff_form is not None:
            self.diff_form.Close(0)
        if self.finding_form is not None:
            self.finding_form.Close(0)
        if self.raw_dialog is not None:
            self.raw_dialog.close()


class VisualizerForm(ida_kernwin.PluginForm):
    def __init__(self, path, idb_path, session):
        super().__init__()
        self.path = path
        self.idb_path = idb_path
        self.session = session
        self.panel = None

    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        self.panel = EntropyMap(parent, self.path, self.idb_path, self.session)
        layout = QtWidgets.QVBoxLayout(parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.panel)

    def OnClose(self, form):
        if self.panel:
            self.panel.shutdown()
            self.panel = None
