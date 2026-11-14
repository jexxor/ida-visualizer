"""Evidence detection and findings navigation."""

import ida_idaapi
import ida_idc
import ida_kernwin
import ida_loader
import ida_segment

from PySide6 import QtCore, QtGui, QtWidgets
from visualizer_core import (
    EXACT_LIMIT,
    RenderCancelled,
    file_findings,
    ram_findings,
)
from visualizer_ui.constants import DELTA_FILE, DELTA_STORED, RAM_STOP
from visualizer_ui.forms import FindingsForm
from visualizer_ui.widgets import EvidenceLanes

class FindingsViewMixin:
    def _create_findings_widget(self, widget):
        self.finding_panel = widget
        layout = QtWidgets.QVBoxLayout(widget)
        layout.setContentsMargins(4, 2, 4, 2)
        header = QtWidgets.QHBoxLayout()
        header.addWidget(QtWidgets.QLabel(
            "Findings · select an address marker to navigate", widget))
        header.addStretch(1)
        self.finding_full_scan = QtWidgets.QCheckBox("Scan entire file", widget)
        self.finding_full_scan.setToolTip(
            "Visit every file byte; large scans run in background and can be cancelled")
        self.finding_full_scan.setVisible(self.mode == "File")
        self.finding_full_scan.toggled.connect(lambda checked: self.refresh_findings())
        header.addWidget(self.finding_full_scan)
        layout.addLayout(header)
        self.finding_scope = QtWidgets.QLabel(widget)
        self.finding_scope.setWordWrap(True)
        layout.addWidget(self.finding_scope)
        hint = QtWidgets.QLabel(
            "Top 64 · blank ≠ clean · ◯ sampled · bands = bounded evidence", widget)
        hint.setWordWrap(True)
        hint.setToolTip("Bands do not mean every byte changed. Amber = byte diff; red/cyan = "
                        "entropy shift; purple = executable; mint = validated object. "
                        "Only ranked findings appear; see scan coverage above.")
        layout.addWidget(hint)
        self.finding_lanes = EvidenceLanes(widget)
        self.finding_lanes.activated.connect(self._select_finding)
        lanes_scroll = QtWidgets.QScrollArea(widget)
        lanes_scroll.setWidgetResizable(True)
        lanes_scroll.viewport().setBackgroundRole(QtGui.QPalette.ColorRole.Window)
        lanes_scroll.viewport().setAutoFillBackground(True)
        lanes_scroll.setWidget(self.finding_lanes)
        self.finding_scroll = lanes_scroll
        layout.addWidget(lanes_scroll, 1)
        navigation = QtWidgets.QHBoxLayout()
        back = QtWidgets.QPushButton("◀", widget)
        back.clicked.connect(lambda checked=False: self._step_finding(-1))
        navigation.addWidget(back)
        self.finding_focus = QtWidgets.QLabel("Select a marker to inspect evidence", widget)
        self.finding_focus.setWordWrap(True)
        navigation.addWidget(self.finding_focus, 1)
        forward = QtWidgets.QPushButton("▶", widget)
        forward.clicked.connect(lambda checked=False: self._step_finding(1))
        navigation.addWidget(forward)
        layout.addLayout(navigation)
        details_toggle = QtWidgets.QPushButton("Exact evidence ▸", widget)
        details_toggle.setCheckable(True)
        layout.addWidget(details_toggle)
        self.finding_list = QtWidgets.QTreeWidget(widget)
        self.finding_list.setHeaderLabels(("Priority", "Finding", "Address", "Evidence"))
        self.finding_list.itemClicked.connect(self._open_finding)
        self.finding_list.setVisible(False)
        details_toggle.toggled.connect(lambda checked: (
            self.finding_list.setVisible(checked),
            details_toggle.setText("Exact evidence ▾" if checked else "Exact evidence ▸")))
        layout.addWidget(self.finding_list)
        self.finding_details = details_toggle
        self.mark_finding = QtWidgets.QPushButton("Mark selected in IDA…", widget)
        self.mark_finding.setEnabled(False)
        self.mark_finding.clicked.connect(self._mark_finding)
        layout.addWidget(self.mark_finding)

    @staticmethod
    def _uncheck(button):
        button.blockSignals(True)
        button.setChecked(False)
        button.blockSignals(False)

    @staticmethod
    def _aux_options():
        return (ida_kernwin.PluginForm.WOPN_PERSIST
                | getattr(ida_kernwin.PluginForm, "WOPN_DP_RIGHT", 0))

    def _findings_closed(self, form):
        if self.finding_form is not form:
            return
        self.finding_generation += 1
        if self.finding_future is not None:
            self.finding_future.cancel()
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
        self.findings = []
        self._finding_restore = None
        self.finding_view_key = None
        self.finding_completed_scope = None
        getattr(self, "finding_saved", {}).clear()
        self.finding_jump_target = None
        self.finding_jump_pending = False
        if getattr(self, "canvas", None) is not None and hasattr(self.canvas, "set_finding"):
            self.canvas.set_finding(None)
        self._uncheck(self.finding_button)

    def _toggle_findings(self, checked):
        if checked:
            self.finding_form = FindingsForm(self)
            self.finding_form.Show("Visualizer: Findings",
                                   options=self._aux_options())
            self.refresh_findings()
        else:
            self.finding_generation += 1
            if self.finding_future is not None:
                self.finding_future.cancel()
            if self.finding_form is not None:
                self.finding_form.Close(0)

    @staticmethod
    def _finding_identity(finding):
        return (finding.kind, finding.source, finding.address,
                finding.snapshot.serial if finding.snapshot else None)

    def _finding_context(self):
        if self.mode == "File":
            return ("File",), "File offsets"
        stop_id = self.global_stop_picker.currentData()
        if self.mode == DELTA_FILE:
            if self.global_mode:
                return ((self.mode, stop_id, "global"),
                        f"Global stop #{stop_id} · sampled file comparison")
            snapshot = self.snapshot
            name = snapshot.region if snapshot is not None else "select a captured region"
            serial = snapshot.serial if snapshot is not None else stop_id
            return ((self.mode, stop_id, "detail", id(snapshot)),
                    f"Region {name} · stop #{serial} · exact file comparison")
        current = tuple(id(item) for item in self.history.for_stop(stop_id))
        if self.mode == DELTA_STORED:
            base_stop = self.global_base_picker.currentData()
            baseline = tuple(id(item) for item in self.history.for_stop(base_stop))
            return ((self.mode, base_stop, stop_id, baseline, current),
                    f"All captured regions · A #{base_stop} → B #{stop_id}")
        return (self.mode, stop_id, current), f"All captured regions · stop #{stop_id}"

    def refresh_findings(self):
        if self.closed or self.finding_panel is None or not self.finding_button.isChecked():
            return
        scope, scope_label = self._finding_context()
        if (self.mode in (RAM_STOP, DELTA_STORED)
                and scope == getattr(self, "finding_completed_scope", None)):
            return  # Same captured stop pair, even when switching Global/detail map.
        selected = self._selected_finding()
        previous_scope = getattr(self, "finding_view_key", None)
        saved = getattr(self, "finding_saved", None)
        if saved is None:
            saved = self.finding_saved = {}
        if selected is not None and previous_scope is not None:
            saved[previous_scope] = self._finding_identity(selected)
        self.finding_view_key = scope
        self.finding_completed_scope = None
        self.finding_scope_label = scope_label
        target = getattr(self, "finding_jump_target", None)
        entering_target = (getattr(self, "finding_jump_pending", False)
                           and self.mode == DELTA_FILE and not self.global_mode
                           and target is not None and self.snapshot is target[0])
        self._finding_restore = None if entering_target else saved.get(scope)
        self.finding_generation += 1
        generation = self.finding_generation
        if self.finding_future is not None:
            self.finding_future.cancel()
        self.finding_list.clear()
        self.findings = []
        self.selected_finding_index = None
        if getattr(self, "finding_lanes", None) is not None:
            self.finding_lanes.set_evidence((), self.file_size,
                                            empty_text="Scanning captured bytes…")
            self.finding_focus.setText("Scanning " + scope_label + "…")
        if getattr(self, "canvas", None) is not None and hasattr(self.canvas, "set_finding"):
            self.canvas.set_finding(None)
        self.mark_finding.setEnabled(False)
        self.finding_scope.setText(scope_label + " · scanning captured bytes…")
        mode, path, signal = self.mode, self.path, self.result
        full_scan = self.finding_full_scan.isChecked()
        snapshots = tuple(self.history.for_stop(self.global_stop_picker.currentData()))
        baseline = (self.baseline if mode == DELTA_FILE and not self.global_mode else None)
        selected = self.snapshot
        if mode == DELTA_FILE:
            if not self.global_mode:
                if (selected is None or baseline is None or baseline.serial != selected.serial
                        or baseline.start != selected.start):
                    self.finding_scope.setText(scope_label + " · waiting for verified file baseline")
                    if getattr(self, "finding_lanes", None) is not None:
                        self.finding_lanes.set_evidence(
                            (), self.file_size, empty_text="Waiting for verified file baseline…")
                    return
                snapshots = (selected,)
            elif snapshots:
                try:
                    stat = path.stat()
                except OSError as exc:
                    self.finding_scope.setText(scope_label + f" · file comparison failed: {exc}")
                    return
                key = (self.global_stop_picker.currentData(), self.render_side(),
                       tuple(id(item) for item in snapshots), stat.st_size, stat.st_mtime_ns)
                if self.global_file_key != key or self.global_file_samples is None:
                    self.finding_scope.setText(scope_label + " · mapping original file samples…")
                    if getattr(self, "finding_lanes", None) is not None:
                        self.finding_lanes.set_evidence(
                            (), self.file_size, empty_text="Mapping verified file samples…")
                    return
        samples = (self.global_file_samples if mode == DELTA_FILE and self.global_mode else None)
        comparisons = (tuple(self.history.for_stop(self.global_base_picker.currentData()))
                        if mode == DELTA_STORED else ())
        side = self.render_side()

        def worker():
            try:
                cancel = lambda: self.closed or generation != self.finding_generation
                findings = (file_findings(path, max_scan=None if full_scan else 64 << 20,
                                          cancelled=cancel) if mode == "File" else
                            ram_findings(snapshots, baseline, samples, side, comparisons,
                                         cancelled=cancel))
                error = None
            except RenderCancelled:
                return
            except (OSError, RuntimeError, ValueError) as exc:
                findings, error = [], str(exc)
            try:
                signal.findings_ready.emit(generation, findings, error)
            except RuntimeError:
                pass

        self.finding_future = self.finding_executor.submit(worker)

    @QtCore.Slot(int, object, object)
    def _findings_rendered(self, generation, findings, error):
        if (self.closed or generation != self.finding_generation
                or self.finding_panel is None or not self.finding_button.isChecked()):
            return
        if error:
            self.finding_scope.setText("Scan failed")
            if getattr(self, "finding_lanes", None) is not None:
                self.finding_lanes.set_evidence((), self.file_size,
                                                empty_text="Findings scan failed")
            self.status.setText("Findings scan failed: " + error)
            return
        self.findings = findings
        self.finding_completed_scope = getattr(self, "finding_view_key", None)
        self.selected_finding_index = None
        if getattr(self, "finding_scope", None) is not None:
            scope_label = getattr(self, "finding_scope_label", "")
            self.finding_scope.setText((scope_label + " · " if scope_label else "")
                                       + getattr(findings, "coverage", "Selected findings"))
        for index, finding in enumerate(findings):
            item = QtWidgets.QTreeWidgetItem((str(finding.score), finding.kind,
                                              ("File+" if finding.source == "File" else "VA ")
                                              + f"0x{finding.address:X}", finding.evidence))
            item.setData(0, QtCore.Qt.ItemDataRole.UserRole, index)
            self.finding_list.addTopLevelItem(item)
            key = self._finding_identity(finding)
            if key == getattr(self, "_finding_restore", None):
                self.finding_list.setCurrentItem(item)
                self.selected_finding_index = index
                self.mark_finding.setEnabled(self._finding_ea(finding) is not None)
        requested = getattr(self, "_finding_restore", None)
        target = getattr(self, "finding_jump_target", None)
        target_in_scope = (target is not None and getattr(self, "finding_jump_pending", False)
                           and self.mode == DELTA_FILE and not self.global_mode
                           and self.snapshot is target[0])
        if findings and self.selected_finding_index is None and target_in_scope:
            snapshot, address = target
            matching = [(index, finding) for index, finding in enumerate(findings)
                        if finding.snapshot is snapshot and finding.address == address]
            if matching:
                self.selected_finding_index = max(matching, key=lambda item: item[1].score)[0]
            elif (snapshot.start <= address < snapshot.stop
                    and self.baseline is not None and self.baseline.start <= address < self.baseline.stop):
                offset = address - snapshot.start
                base_offset = address - self.baseline.start
                if (snapshot.valid[offset] and self.baseline.valid[base_offset]
                        and snapshot.data[offset] != self.baseline.data[base_offset]):
                    candidates = [(index, finding) for index, finding in enumerate(findings)
                                  if finding.snapshot is snapshot and finding.kind in (
                                      "RAM differs from file", "Bytes changed")]
                    if candidates:
                        self.selected_finding_index = min(
                            candidates, key=lambda item: (-item[1].score,
                                                          abs(item[1].address - address)))[0]
        if (findings and self.selected_finding_index is None
                and requested is None and not target_in_scope):
            self.selected_finding_index = 0
        if self.selected_finding_index is not None:
            if hasattr(self.finding_list, "setCurrentItem"):
                self.finding_list.setCurrentItem(
                    self.finding_list.topLevelItem(self.selected_finding_index))
            self.mark_finding.setEnabled(self._finding_ea(
                findings[self.selected_finding_index]) is not None)
        self._finding_restore = None
        if getattr(self, "finding_lanes", None) is not None:
            self.finding_lanes.set_evidence(findings, self.file_size, self.selected_finding_index)
            if self.selected_finding_index is not None:
                self._show_finding_selection(findings[self.selected_finding_index])
            else:
                self.finding_focus.setText(
                    (f"No finding at selected VA 0x{target[1]:X} · choose a marker"
                     if target_in_scope else
                     "Previous finding is no longer in this scope · choose a marker"
                     if requested is not None else
                     "Select a marker · points = evidence anchors"
                     " · bands = bounded evidence · hollow = sampled"))
        if getattr(self, "canvas", None) is not None and hasattr(self.canvas, "set_finding"):
            self.canvas.set_finding(
                findings[self.selected_finding_index] if self.selected_finding_index is not None
                else None)
        if target_in_scope:
            self.finding_jump_pending = False
        if not findings:
            self.status.setText("No findings in scanned bounds; absence is not proof of clean data")

    def _selected_finding(self):
        index = getattr(self, "selected_finding_index", None)
        if isinstance(index, int) and 0 <= index < len(self.findings):
            return self.findings[index]
        if self.finding_list is None:
            return None
        item = self.finding_list.currentItem()
        if item is None:
            return None
        index = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
        return self.findings[index] if isinstance(index, int) and 0 <= index < len(self.findings) else None

    def _show_finding_selection(self, finding):
        index = getattr(self, "selected_finding_index", None)
        if getattr(self, "finding_focus", None) is not None:
            source = (f"File+0x{finding.address:X}" if finding.source == "File" else
                      f"VA 0x{finding.address:X} · stop #{finding.snapshot.serial}"
                      if finding.snapshot is not None else f"VA 0x{finding.address:X}")
            target = getattr(self, "finding_jump_target", None)
            origin = (f" · opened from VA 0x{target[1]:X}"
                      if (self.mode == DELTA_FILE and not self.global_mode and target is not None
                          and target[0] is finding.snapshot and target[1] != finding.address) else "")
            self.finding_focus.setText(f"{index + 1}/{len(self.findings)} · {finding.kind}"
                                       f" · {source} · priority {finding.score}{origin}")
            self.finding_focus.setToolTip(finding.evidence)
        if getattr(self, "finding_lanes", None) is not None:
            self.finding_lanes.selected = index
            self.finding_lanes.update()
            if getattr(self, "finding_scroll", None) is not None:
                for row, lane in enumerate(self.finding_lanes.lanes):
                    if index in lane.indices:
                        width = max(1, lane.stop - lane.start)
                        address = max(lane.start, min(finding.address, lane.stop - 1))
                        x = 12 + round(max(1, self.finding_lanes.width() - 24)
                                       * (address - lane.start) / width)
                        self.finding_scroll.ensureVisible(x, 46 + row * 64, 20, 32)
                        break
        if getattr(self, "canvas", None) is not None and hasattr(self.canvas, "set_finding"):
            self.canvas.set_finding(finding)

    def _select_finding(self, index):
        if not 0 <= index < len(self.findings):
            return
        self.selected_finding_index = index
        item = self.finding_list.topLevelItem(index)
        self.finding_list.setCurrentItem(item)
        self._open_finding(item, 0)

    def _step_finding(self, direction):
        if self.findings:
            current = self.selected_finding_index
            first = current if current is not None else (0 if direction < 0 else -1)
            self._select_finding((first + direction) % len(self.findings))

    def _select_finding_at(self, address, snapshot):
        for index, finding in enumerate(self.findings):
            if (finding.address == address and
                    (finding.source == "File" and self.mode == "File" or
                     finding.source == "RAM" and finding.snapshot is snapshot)):
                self.selected_finding_index = index
                if self.finding_list is not None:
                    self.finding_list.setCurrentItem(self.finding_list.topLevelItem(index))
                self._show_finding_selection(finding)
                self.mark_finding.setEnabled(self._finding_ea(finding) is not None)
                return

    def _focus_finding_range(self, address):
        """Bring a finding into the actual map window, preserving source address domain."""
        if self.global_mode or not hasattr(self, "selection"):
            return
        inspecting = (getattr(self, "inspector_button", None) is not None
                      and self.inspector_button.isChecked())
        if self.selection[0] <= address < self.selection[1]:
            if inspecting:
                self.inspect_offset(address)
            return
        if not self.domain[0] <= address < self.domain[1]:
            return
        width = min(EXACT_LIMIT, self.selection[1] - self.selection[0],
                    self.domain[1] - self.domain[0])
        begin = max(self.domain[0], min(address - width // 2, self.domain[1] - width))
        if not self.absolute_range[0] <= begin or begin + width > self.absolute_range[1]:
            absolute_width = min(max(EXACT_LIMIT, width), self.domain[1] - self.domain[0])
            absolute_begin = max(self.domain[0], min(address - absolute_width // 2,
                                                    self.domain[1] - absolute_width))
            self._set_data_domain(self.domain, (absolute_begin, absolute_begin + absolute_width),
                                  (begin, begin + width))
            self._switch_overviews()
            self.queue_render()
        else:
            self._set_relative(begin, begin + width)
        if inspecting:
            self.pending_inspection_offset = address

    def _finding_ea(self, finding):
        if ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path:
            return None
        ea = (ida_loader.get_fileregion_ea(finding.address)
              if finding.source == "File" else finding.address)
        if ea is None or ea == ida_idaapi.BADADDR or ea < 0:
            return None
        if finding.source == "RAM" and ida_segment.getseg(ea) is None:
            return None
        return ea

    def _open_finding(self, item, column):
        if item is not None:
            index = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
            if isinstance(index, int):
                self.selected_finding_index = index
        finding = self._selected_finding()
        if finding is None:
            return
        self._show_finding_selection(finding)
        self._finding_restore = (finding.kind, finding.source, finding.address,
                                 finding.snapshot.serial if finding.snapshot else None)
        ea = self._finding_ea(finding)
        self.mark_finding.setEnabled(ea is not None)
        if finding.source == "RAM" and finding.snapshot is not None:
            if self.global_mode or self.snapshot is not finding.snapshot:
                self.open_global_hit((finding.snapshot, finding.address))
            else:
                self._focus_finding_range(finding.address)
            if getattr(self, "diff_button", None) is not None and self.diff_button.isChecked():
                self.diff_address = finding.address
                self._refresh_byte_diff()
            if ea is None or not ida_kernwin.jumpto(ea):
                self.status.setText(f"VA 0x{finding.address:X} has no IDA listing address"
                                    " · select debugger region to inspect RAM")
        elif finding.source == "File":
            self._focus_finding_range(finding.address)
            if ea is not None:
                ida_kernwin.jumpto(ea)
            else:
                self.show_raw(finding.address)

    def _mark_finding(self):
        finding = self._selected_finding()
        ea = self._finding_ea(finding) if finding is not None else None
        if ea is None or not ida_kernwin.jumpto(ea):
            self.status.setText("No IDA listing address to bookmark")
            return
        try:
            if any(ida_idc.get_marked_pos(slot) == ea for slot in range(1024)):
                self.status.setText(f"IDA bookmark already exists at 0x{ea:X}")
                return
            slot = next((slot for slot in range(1024)
                         if ida_idc.get_marked_pos(slot) == ida_idaapi.BADADDR), None)
            if slot is None:
                self.status.setText("No free IDA bookmark slots")
                return
            ida_idc.mark_position(ea, 0, 0, 0, slot, "Visualizer: " + finding.kind)
            if ida_idc.get_marked_pos(slot) != ea:
                self.status.setText("IDA did not create the bookmark")
                return
        except (RuntimeError, ValueError) as exc:
            self.status.setText(f"IDA bookmark failed: {exc}")
            return
        self.status.setText(f"Marked in IDA at 0x{ea:X} · {finding.kind}")
        self.refresh_bookmarks()
