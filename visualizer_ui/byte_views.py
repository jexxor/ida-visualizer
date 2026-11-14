"""Byte inspector and diff dock behavior."""

import ida_registry
import sys

from PySide6 import QtCore, QtGui, QtWidgets
from dataclasses import replace
from visualizer_core import (
    Frame,
    INSPECTION_RANGE_OUTLINES,
    byte_diff_changes,
    byte_diff_window,
)
from visualizer_ui.constants import (
    ALL_BYTES_FONT_SETTING,
    DELTA_FILE,
    DELTA_STORED,
    FONT_REGISTRY_KEY,
)
from visualizer_ui.forms import ByteDiffForm
from visualizer_ui.widgets import (
    ByteHistogram,
    DiffHexView,
    DiffRibbon,
    InspectionProfile,
    byte_diff_focus_text,
    format_byte_diff,
)

class ByteViewsMixin:
    def _create_inspector_widget(self, widget):
        self.inspector = widget
        layout = QtWidgets.QVBoxLayout(widget)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)
        header = QtWidgets.QHBoxLayout()
        self.inspection_title = QtWidgets.QLabel(widget)
        self.inspection_title.setWordWrap(True)
        header.addWidget(self.inspection_title, 1)
        self.inspection_range_checkbox = QtWidgets.QCheckBox("Show sample ranges", widget)
        self.inspection_range_checkbox.setToolTip(
            "Show all four measured windows; click a profile scale to isolate one")
        self.inspection_range_checkbox.setChecked(self.inspection_show_ranges)
        self.inspection_range_checkbox.toggled.connect(self._toggle_sample_ranges)
        header.addWidget(self.inspection_range_checkbox)
        layout.addLayout(header)
        scroll = QtWidgets.QScrollArea(widget)
        scroll.setWidgetResizable(True)
        scroll.viewport().setBackgroundRole(QtGui.QPalette.ColorRole.Window)
        scroll.viewport().setAutoFillBackground(True)
        content = QtWidgets.QWidget(scroll)
        content_layout = QtWidgets.QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        self.inspection_profile = InspectionProfile(content)
        self.inspection_profile.scaleClicked.connect(self._inspect_scale_clicked)
        content_layout.addWidget(self.inspection_profile)
        details_toggle = QtWidgets.QPushButton("Exact measures ▸", content)
        details_toggle.setCheckable(True)
        self.inspection_details = QtWidgets.QWidget(widget)
        detailed = QtWidgets.QVBoxLayout(self.inspection_details)
        detailed.setContentsMargins(0, 0, 0, 0)
        detailed.addWidget(QtWidgets.QLabel("Entropy by scale · bits/byte", widget))
        self.inspection_scales = self._inspection_table(
            widget, ("Window", "Exact source range", "Known/span", "H / cap", "Map px"), 132)
        detailed.addWidget(self.inspection_scales)
        detailed.addWidget(QtWidgets.QLabel("Composition · order controls · comparison", widget))
        self.inspection_facts = self._inspection_table(
            widget, ("Measure", "Observed", "Shuffled / baseline", "Basis / effect"), 218)
        detailed.addWidget(self.inspection_facts)
        self.inspection_details.setVisible(False)
        details_toggle.toggled.connect(lambda checked: (
            self.inspection_details.setVisible(checked),
            details_toggle.setText("Exact measures ▾" if checked else "Exact measures ▸")))
        content_layout.addWidget(details_toggle)
        content_layout.addWidget(self.inspection_details)
        self.inspection_histogram = ByteHistogram(content)
        self.inspection_histogram.byteClicked.connect(self._histogram_clicked)
        content_layout.addWidget(QtWidgets.QLabel(
            "Byte histogram · log frequency · click a column", content))
        content_layout.addWidget(self.inspection_histogram)
        content_layout.addStretch(1)
        scroll.setWidget(content)
        layout.addWidget(scroll, 1)
        self._clear_inspection()

    def _create_diff_widget(self, widget):
        layout = QtWidgets.QVBoxLayout(widget)
        layout.setContentsMargins(6, 4, 6, 4)
        self.diff_title = QtWidgets.QLabel(widget)
        self.diff_title.setWordWrap(True)
        layout.addWidget(self.diff_title)
        self.diff_ribbon = DiffRibbon(widget)
        self.diff_ribbon.byteClicked.connect(self._select_diff_byte)
        self.diff_ribbon.byteHovered.connect(self._preview_diff_byte)
        layout.addWidget(self.diff_ribbon)
        self.diff_summary = QtWidgets.QLabel(widget)
        layout.addWidget(self.diff_summary)
        self.diff_focus = QtWidgets.QLabel(widget)
        self.diff_focus.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.diff_focus)
        changes_row = QtWidgets.QHBoxLayout()
        self.diff_prev_button = QtWidgets.QPushButton("← change", widget)
        self.diff_next_button = QtWidgets.QPushButton("change →", widget)
        for button, direction in ((self.diff_prev_button, -1),
                                  (self.diff_next_button, 1)):
            button.setToolTip("Navigate verified changes inside this 256-byte window")
            button.clicked.connect(lambda checked=False, step=direction: self._step_byte_change(step))
            changes_row.addWidget(button)
        layout.addLayout(changes_row)
        controls = QtWidgets.QHBoxLayout()
        for title, direction in (("← 256 B", -1), ("256 B →", 1)):
            button = QtWidgets.QPushButton(title, widget)
            button.clicked.connect(lambda checked=False, step=direction: self._page_byte_diff(step))
            controls.addWidget(button)
        layout.addLayout(controls)
        self.diff_text = DiffHexView(widget)
        self.diff_text.setReadOnly(True)
        self.diff_text.setOpenLinks(False)
        self.diff_text.setOpenExternalLinks(False)
        self.diff_text.byteMoved.connect(self._move_diff_cursor)
        self.diff_text.anchorClicked.connect(self._diff_hex_clicked)
        self.diff_text.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.diff_text.customContextMenuRequested.connect(self._diff_hex_menu)
        self._apply_all_bytes_font(self._load_all_bytes_font())
        self.diff_text.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.diff_text, 1)
        self._clear_byte_diff()

    def _clear_byte_diff(self, message="Open a delta region to compare bytes"):
        if getattr(self, "diff_title", None) is not None:
            self.diff_title.setText(message)
            self.diff_text.clear()
        self.diff_window = None
        if getattr(self, "diff_ribbon", None) is not None:
            self.diff_ribbon.set_window(None)
            self.diff_summary.clear()
            self.diff_focus.clear()
            self.diff_prev_button.setEnabled(False)
            self.diff_next_button.setEnabled(False)

    def _diff_closed(self, form):
        if self.diff_form is not form:
            return
        self.diff_form = self.diff_title = self.diff_text = None
        self.diff_ribbon = self.diff_focus = self.diff_summary = None
        self.diff_prev_button = self.diff_next_button = None
        self.diff_window = None
        self.diff_address = None
        self._uncheck(self.diff_button)

    def _toggle_byte_diff(self, checked):
        if not checked:
            if self.diff_form is not None:
                self.diff_form.Close(0)
            return
        self.diff_form = ByteDiffForm(self)
        self.diff_form.Show("Visualizer: Byte Diff", options=self._aux_options())
        if self.diff_title is None:
            self._uncheck(self.diff_button)
            self.diff_form = None
            return
        if self.diff_address is None and not self.global_mode:
            low, high = self.selection
            focus = self.canvas.hover_offset
            if focus is None or not low <= focus < high:
                focus = self.canvas.cursor_offset
            self.diff_address = focus if focus is not None and low <= focus < high else low
        self._refresh_byte_diff()
        self.diff_text.setFocus()

    def _page_byte_diff(self, direction):
        snapshot = self._current_snapshot()
        if snapshot is None or self.diff_address is None or self.global_mode:
            return
        self.diff_address = max(snapshot.start, min(self.diff_address + direction * 256,
                                                    snapshot.stop - 1))
        self._refresh_byte_diff()

    @staticmethod
    def _load_all_bytes_font():
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        saved = ida_registry.reg_read_string(ALL_BYTES_FONT_SETTING, FONT_REGISTRY_KEY)
        if saved:
            restored = QtGui.QFont()
            if restored.fromString(saved) and (restored.pointSizeF() > 0
                                                or restored.pixelSize() > 0):
                return restored
        return font

    def _apply_all_bytes_font(self, font, persist=False):
        self.diff_all_bytes_font = QtGui.QFont(font)
        self.diff_text.setFont(self.diff_all_bytes_font)
        self.diff_text.document().setDefaultFont(self.diff_all_bytes_font)
        if persist:
            ida_registry.reg_write_string(ALL_BYTES_FONT_SETTING,
                                          self.diff_all_bytes_font.toString(), FONT_REGISTRY_KEY)
        window = self.diff_window
        if window is not None:
            palette = self.diff_text.palette()
            color = palette.color(QtGui.QPalette.ColorRole.Text).name()
            self.diff_text.setHtml(format_byte_diff(window, color, self.diff_all_bytes_font))
            if hasattr(self.diff_text, "scrollToAnchor"):
                self.diff_text.scrollToAnchor(f"byte-{window.focus:X}")

    def _choose_all_bytes_font(self):
        dialog = QtWidgets.QFontDialog(self.diff_text)
        dialog.setCurrentFont(self.diff_all_bytes_font)
        dialog.setWindowTitle("Visualizer: All bytes font")
        dialog.setOption(QtWidgets.QFontDialog.FontDialogOption.MonospacedFonts)
        if sys.platform == "darwin":
            dialog.setOption(QtWidgets.QFontDialog.FontDialogOption.DontUseNativeDialog)
        try:
            if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                self._apply_all_bytes_font(dialog.selectedFont(), persist=True)
        finally:
            dialog.deleteLater()

    def _diff_hex_menu(self, position):
        browser = self.diff_text
        if browser is None:
            return
        menu = browser.createStandardContextMenu(position)
        menu.addSeparator()
        font_action = menu.addAction("Font…")
        try:
            if menu.exec(browser.viewport().mapToGlobal(position)) is font_action:
                self._choose_all_bytes_font()
        finally:
            menu.deleteLater()

    def _diff_hex_clicked(self, url):
        link = url.toString()
        if not link.startswith("va:"):
            return
        try:
            address = int(link[3:], 16)
        except ValueError:
            return
        self._select_diff_byte(address)

    def _move_diff_cursor(self, step):
        window = self.diff_window
        snapshot = self._current_snapshot() if window is not None else None
        if snapshot is None:
            return
        address = window.focus + step
        if not snapshot.start <= address < snapshot.stop:
            return
        if not window.start <= address < window.stop:
            self.diff_address = address
            self._refresh_byte_diff()
            if self.diff_window is None or not self.diff_window.start <= address < self.diff_window.stop:
                return
        self._select_diff_byte(address)

    def _preview_diff_byte(self, address):
        window = self.diff_window
        if self.diff_focus is None or window is None:
            return
        if address is None or not window.start <= address < window.stop:
            address = window.focus
            hint = ""
        else:
            hint = (" · release to select" if self.diff_ribbon.dragging else
                    " · click to select")
        self.diff_focus.setText(byte_diff_focus_text(window, address) + hint)

    def _step_byte_change(self, direction):
        window = self.diff_window
        if window is None:
            return
        changes = byte_diff_changes(window)
        candidates = (address for address in (reversed(changes) if direction < 0 else changes)
                      if (address < window.focus if direction < 0 else address > window.focus))
        address = next(candidates, None)
        if address is not None:
            self._select_diff_byte(address)

    def _select_diff_byte(self, address):
        window = self.diff_window
        if window is None or not window.start <= address < window.stop:
            return
        snapshot = self._current_snapshot()
        compare = (self._detail_comparison(self.mode, snapshot)
                   if snapshot is not None else None)
        expected = self._detail_source_key(self.mode, snapshot, compare)
        if (snapshot is None or compare is None or not self._same_detail_source(
                getattr(self.canvas, "frame_source_key", None), expected)):
            self._clear_byte_diff("Selected stop pair is no longer available")
            return
        self.diff_address = address
        self._present_diff_window(replace(window, focus=address), snapshot, compare)
        if self.domain[0] <= address < self.domain[1]:
            if not self.selection[0] <= address < self.selection[1]:
                self._focus_finding_range(address)
            else:
                self.canvas.cursor_offset = address
                self.canvas.update()
                self.absolute_slider.cursor_offset = address
                self.absolute_slider.update()
                if self.inspector_button.isChecked():
                    self.inspect_offset(address)
        self.show_offset(address)
        if hasattr(self.diff_text, "setFocus"):
            self.diff_text.setFocus()

    def _present_diff_window(self, window, snapshot, compare):
        self.diff_window = window
        a = "original file" if self.mode == DELTA_FILE else f"stop #{compare.serial}"
        self.diff_title.setText(
            f"A: {a} → B: stop #{snapshot.serial} · VA 0x{window.start:X}–0x{window.stop - 1:X}")
        text_color = (self.diff_text.palette().color(QtGui.QPalette.ColorRole.Text).name()
                      if hasattr(self.diff_text, "palette") else None)
        self.diff_text.setHtml(format_byte_diff(
            window, text_color, getattr(self, "diff_all_bytes_font", None)))
        if hasattr(self.diff_text, "scrollToAnchor"):
            self.diff_text.scrollToAnchor(f"byte-{window.focus:X}")
        if getattr(self, "diff_ribbon", None) is None:
            return
        changes = byte_diff_changes(window)
        unread = sum(not known for known in window.after_valid)
        no_baseline = sum(a_valid == 0 and b_valid != 0 for a_valid, b_valid in zip(
            window.before_valid, window.after_valid))
        self.diff_summary.setText(
            f"Δ {len(changes):,} · paired {window.comparable:,}"
            f" · no A {no_baseline:,} · unread B {unread:,}")
        self.diff_focus.setText(byte_diff_focus_text(window, window.focus))
        self.diff_ribbon.set_window(window)
        self.diff_prev_button.setEnabled(any(address < window.focus for address in changes))
        self.diff_next_button.setEnabled(any(address > window.focus for address in changes))

    def _refresh_byte_diff(self):
        if self.diff_title is None:
            return
        if self.global_mode or self.mode not in (DELTA_FILE, DELTA_STORED):
            self._clear_byte_diff()
            return
        snapshot = self._current_snapshot()
        if snapshot is None:
            self._clear_byte_diff("Select a captured stop B")
            return
        compare = self._detail_comparison(self.mode, snapshot)
        if self.mode == DELTA_FILE and compare is None:
            self._clear_byte_diff("Waiting for verified original-file pages…")
            return
        if self.mode == DELTA_STORED and compare is None:
            self._clear_byte_diff("No matching VA for selected stop A")
            return
        frame = self.canvas.frame
        expected = self._detail_source_key(self.mode, snapshot, compare)
        if (not isinstance(frame, Frame)
                or not self._same_detail_source(
                    getattr(self.canvas, "frame_source_key", None), expected)):
            self._clear_byte_diff("Waiting for map frame at selected stop pair…")
            return
        focus = self.diff_address
        if focus is None or not snapshot.start <= focus < snapshot.stop:
            focus = max(snapshot.start, min(self.selection[0], snapshot.stop - 1))
        self.diff_address = focus
        try:
            window = byte_diff_window(snapshot, compare, focus)
        except (OSError, ValueError) as exc:
            self._clear_byte_diff(f"Byte diff failed: {exc}")
            return
        self._present_diff_window(window, snapshot, compare)

    @staticmethod
    def _inspection_table(parent, headers, height):
        table = QtWidgets.QTableWidget(0, len(headers), parent)
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().hide()
        table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(height)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        return table

    @staticmethod
    def _set_inspection_rows(table, rows):
        table.setRowCount(len(rows))
        for row, fields in enumerate(rows):
            for column, text in enumerate(fields):
                item = QtWidgets.QTableWidgetItem(str(text))
                if column == 0 and len(fields) == 5 and row < len(INSPECTION_RANGE_OUTLINES):
                    if hasattr(item, "setForeground"):
                        item.setForeground(QtGui.QBrush(QtGui.QColor(
                            f"#{INSPECTION_RANGE_OUTLINES[row] & 0xFFFFFF:06X}")))
                table.setItem(row, column, item)
