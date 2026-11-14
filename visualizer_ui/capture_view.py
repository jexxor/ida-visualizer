"""Debugger region tracking and capture UI."""

import ida_dbg
import ida_kernwin

from PySide6 import QtCore, QtWidgets
from visualizer_ui.session import process_regions

class CaptureViewMixin:
    def _refresh_regions(self):
        previous = (self.regions[self.region_picker.currentIndex()]
                    if 0 <= self.region_picker.currentIndex() < len(self.regions) else None)
        active = process_regions()
        self.active_regions = tuple(active) if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP else ()
        saved = {snapshot.mapping for snapshot in self.history.snapshots if snapshot.mapping}
        track_candidates = sorted(set(active) | saved)
        if self.mode != "File":
            regions = sorted({snapshot.mapping for snapshot in self.history.for_stop(
                self.global_stop_picker.currentData()) if snapshot.mapping})
        else:
            regions = track_candidates
        self.regions = regions
        focus = ida_kernwin.get_screen_ea()
        self.region_picker.blockSignals(True)
        self.region_picker.clear()
        chosen = -1
        for index, (start, stop, name) in enumerate(regions):
            flag = ("NEW · " if (start, stop, name) in self.new_regions else
                    "saved · " if (start, stop, name) not in self.active_regions else "")
            self.region_picker.addItem(f"{flag}{name[-32:]}  0x{start:X}–0x{stop - 1:X}")
            if start <= focus < stop:
                chosen = index
        if previous in regions and (previous in self.active_regions or chosen < 0):
            chosen = regions.index(previous)
        if regions:
            self.region_picker.setCurrentIndex(max(0, chosen))
        self.region_picker.blockSignals(False)
        self.session.resolve_tracking(self.active_regions)
        self.tracked_regions.intersection_update(track_candidates)
        if track_candidates and not self.tracking_initialized:
            if not self.session.tracking_configured:
                focus_region = next((region for region in track_candidates
                                     if region[0] <= focus < region[1]), track_candidates[0])
                self.tracked_regions.add(focus_region)
            self.tracking_initialized = True
        self.track_menu.clear()
        select_all = self.track_menu.addAction("Select all regions")
        select_all.setEnabled(bool(self.active_regions or track_candidates))
        select_all.triggered.connect(
            lambda checked=False, candidates=tuple(self.active_regions or track_candidates):
            self._set_tracked_regions(candidates, candidates))
        clear_all = self.track_menu.addAction("Clear tracking")
        clear_all.triggered.connect(
            lambda checked=False, candidates=tuple(track_candidates):
            self._set_tracked_regions(candidates, ()))
        self.track_menu.addSeparator()
        for region in track_candidates:
            start, stop, name = region
            action = self.track_menu.addAction(f"{name[-32:]}  0x{start:X}–0x{stop - 1:X}")
            action.setCheckable(True)
            action.setChecked(region in self.tracked_regions)
            action.toggled.connect(lambda checked, key=region: self._tracking_changed(key, checked))
        return bool(track_candidates)

    def _tracking_changed(self, region, checked):
        self.session.track(region, checked, self.active_regions or self.regions)

    def _set_tracked_regions(self, regions, selected):
        self.session.configure_tracking(regions, selected)
        QtCore.QTimer.singleShot(0, self._refresh_regions)

    def prompt_track_regions(self, regions):
        """Ask which debugger regions to capture before the first stop scan."""
        if self.closed or not regions:
            return False
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Visualizer: Track debugger regions")
        dialog.resize(570, 420)
        layout = QtWidgets.QVBoxLayout(dialog)
        layout.addWidget(QtWidgets.QLabel(
            "Select regions to capture on every debugger stop:", dialog))
        choices = QtWidgets.QListWidget(dialog)
        checked = QtCore.Qt.CheckState.Checked
        unchecked = QtCore.Qt.CheckState.Unchecked
        for start, stop, name in regions:
            item = QtWidgets.QListWidgetItem(
                f"{name[-48:]}  0x{start:X}–0x{stop - 1:X}", choices)
            item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(checked if ((start, stop, name) in self.tracked_regions
                                           or self.session.region_rule((start, stop, name), regions)
                                           in self.session.track_rules)
                               else unchecked)
        layout.addWidget(choices)
        row = QtWidgets.QHBoxLayout()
        def mark_all(state):
            for index in range(choices.count()):
                choices.item(index).setCheckState(state)
        for label, state in (("Select all", checked), ("Clear all", unchecked)):
            button = QtWidgets.QPushButton(label, dialog)
            button.clicked.connect(lambda selected=False, value=state: mark_all(value))
            row.addWidget(button)
        layout.addLayout(row)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel, parent=dialog)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return False
        selected = [region for index, region in enumerate(regions)
                    if choices.item(index).checkState() == checked]
        self.session.configure_tracking(regions, selected)
        self._refresh_regions()
        self.status.setText(f"Tracking {len(selected)} regions on debugger stops")
        return True

    def debugger_stopped(self):
        self.session.sync_panel()
        if not self.closed:
            self._refresh_regions()
            if self.mode != "File":
                self.status.setText(f"Stop #{self.stop_serial}: capturing tracked regions...")

    def debugger_capture_completed(self, snapshot):
        if self.closed or self.mode == "File":
            return
        index = self.region_picker.currentIndex()
        if (not self.global_mode and snapshot.serial == self.global_stop_picker.currentData()
                and 0 <= index < len(self.regions)
                and self.regions[index] == snapshot.mapping):
            self._select_stop_snapshot(snapshot)

    def debugger_capture_finished(self):
        if self.closed or self.mode == "File":
            return
        previous = self.global_stop_picker.currentData()
        self._refresh_global_stops()
        if self.global_follow_latest:
            self._select_latest_captured_stop()
            self._refresh_global_stops()
            if self.global_stop_picker.currentData() is not None:
                self.global_follow_latest = False
        selected = self.global_stop_picker.currentData()
        if selected != previous or selected == self.stop_serial:
            self._stop_selection_changed()

    def debugger_session_reset(self):
        self._clear_inspection()
        self.diff_address = None
        self._clear_byte_diff()
        for picker in (self.global_stop_picker, self.global_base_picker):
            picker.blockSignals(True)
            if picker.count():
                picker.setCurrentIndex(0)
            picker.blockSignals(False)
        self.global_follow_latest = True
        self.follow_previous_baseline = False
        self.finding_generation += 1
        self.findings = []
        self.selected_finding_index = None
        self.finding_view_key = None
        self.finding_completed_scope = None
        self.finding_saved.clear()
        self.finding_jump_target = None
        self.finding_jump_pending = False
        self._finding_restore = None
        if hasattr(self.canvas, "set_finding"):
            self.canvas.set_finding(None)
        if self.finding_list is not None:
            self.finding_list.clear()
            self.mark_finding.setEnabled(False)
        self.baseline_generation += 1
        self.generation += 1
        self.global_baseline_generation += 1
        self.global_file_key = self.global_file_samples = self.global_pending_key = None
        self.global_sample_iterator = None
        self.stop_serial = 0
        self.new_regions.clear()
        self.tracking_initialized = False
        self.snapshot = self.baseline = None
        self.regions = []
        self.active_regions = ()
        self.region_picker.blockSignals(True)
        self.region_picker.clear()
        self.region_picker.blockSignals(False)
        self.track_menu.clear()
        self._refresh_global_stops()
        if not self.closed:
            self._refresh_regions()
        if not self.closed and self.mode != "File":
            self.canvas.frame = self.canvas.image = None
            self.canvas.update()
            self.status.setText("New debugger session; waiting for a paused snapshot")
