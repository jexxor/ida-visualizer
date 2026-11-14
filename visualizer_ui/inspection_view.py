"""Inspection navigation and map overlays."""

import ida_idaapi
import ida_kernwin
import ida_loader
import math

from PySide6 import QtCore, QtGui, QtWidgets
from visualizer_core import (
    Frame,
    GlobalFrame,
    RenderCancelled,
    curve_point_at,
    inspect_file,
    inspect_snapshot,
    inspection_ranges_overlay,
    is_unmapped_tile,
    raw_hex_preview,
    snapshot_hex_preview,
    unmapped_boundary_segments,
)
from visualizer_ui.forms import ByteInspectorForm
from visualizer_ui.session import collect_ida_bookmarks

class InspectionViewMixin:
    def _inspector_closed(self, form):
        if self.inspector_form is not form:
            return
        self._clear_inspection()
        self.inspector_form = None
        self.inspector = None
        self.inspection_title = None
        self.inspection_scales = None
        self.inspection_facts = None
        self.inspection_range_checkbox = None
        self.inspection_histogram = None
        self.inspection_profile = None
        self.inspection_details = None
        self._uncheck(self.inspector_button)

    def _toggle_inspector(self, checked):
        if not checked:
            if self.inspector_form is not None:
                self.inspector_form.Close(0)
            return
        self.inspector_form = ByteInspectorForm(self)
        self.inspector_form.Show("Visualizer: Byte Inspector",
                                 options=self._aux_options())
        if self.inspection_title is None:
            self._uncheck(self.inspector_button)
            self.inspector_form = None
            return
        if self.global_mode:
            self._clear_inspection()
            return
        low, high = self.selection
        focus = self.canvas.hover_offset
        if focus is None or not low <= focus < high:
            focus = self.canvas.cursor_offset
        if focus is None or not low <= focus < high:
            focus = low + (high - low) // 2
        self.inspect_offset(focus)

    def _clear_inspection(self):
        self.pending_inspection_offset = None
        self.inspection_requested_frame = None
        self.inspection_result_frame = None
        self.inspection_overlay_cache = None
        self.inspection_focus_generation = getattr(self, "inspection_focus_generation", 0) + 1
        future = getattr(self, "inspection_focus_future", None)
        if future is not None:
            future.cancel()
        self.inspection_focus_cache = {}
        if getattr(self, "inspection_generation", None) is not None:
            self.inspection_generation += 1
            if self.inspection_future is not None:
                self.inspection_future.cancel()
        if getattr(self, "inspection_title", None) is None:
            return
        self.inspection_title.setText("Open a region to inspect bytes" if self.global_mode
                                      else "Click a map byte to inspect")
        self.inspection_scales.setRowCount(0)
        self.inspection_facts.setRowCount(0)
        self.inspection_histogram.bins = (0,) * 256
        self.inspection_histogram.selected_byte = None
        self.inspection_histogram.update()
        if getattr(self, "inspection_profile", None) is not None:
            self.inspection_profile.set_inspection(None)
        self.canvas.inspection_overlay = None
        self.canvas.inspection_overlay_frame = None
        self.canvas.update()

    def _toggle_sample_ranges(self, checked):
        self.inspection_show_ranges = checked
        if getattr(self, "inspection_profile", None) is not None:
            self.inspection_profile.selected_scale = None
            self.inspection_profile.update()
        if not checked:
            self.canvas.inspection_overlay = None
            self.canvas.inspection_overlay_frame = None
            self.canvas.update()
        elif self.inspection_overlay_cache is not None:
            self._display_inspection_overlay(*self.inspection_overlay_cache)

    def _inspect_scale_clicked(self, index):
        profile = self.inspection_profile
        if (profile is None or profile.info is None or
                self.inspection_result_frame is not self.canvas.frame):
            return
        low, high = profile.info.ranges[index]
        if self.inspection_range_checkbox.isChecked():
            self.inspection_range_checkbox.setChecked(False)
        profile.selected_scale = index
        profile.update()
        frame = self.canvas.frame
        cached = self.inspection_focus_cache.get(index)
        if cached is not None:
            self._paint_inspection_overlay(frame, cached)
        else:
            self.inspection_focus_generation += 1
            generation = self.inspection_focus_generation
            previous = self.inspection_focus_future
            if previous is not None:
                previous.cancel()
            self.canvas.inspection_overlay = None
            self.canvas.inspection_overlay_frame = None
            self.canvas.update()
            inspection_generation = self.inspection_generation
            ranges, signal = profile.info.ranges, self.result

            def worker():
                try:
                    cancelled = lambda: (self.closed or generation != self.inspection_focus_generation
                                         or inspection_generation != self.inspection_generation)
                    overlay, _ = inspection_ranges_overlay(
                        frame, ranges, cancelled, selected_scale=index)
                except RenderCancelled:
                    return
                except (OSError, RuntimeError, ValueError):
                    return
                try:
                    signal.inspection_focus_ready.emit(inspection_generation, index, frame, overlay)
                except RuntimeError:
                    pass

            self.inspection_focus_future = self.inspection_executor.submit(worker)
        self.status.setText(
            f"{('File+' if self.mode == 'File' else 'VA ')}0x{low:X}–0x{high - 1:X}"
            f" · {('32 B', '4 KiB', '64 KiB', '1 MiB')[index]} exact source window"
            f" · {profile.highlighted[index]:,} displayed map pixels")

    @QtCore.Slot(int, int, object, object)
    def _inspection_focus_rendered(self, generation, index, frame, overlay):
        if (self.closed or generation != self.inspection_generation
                or frame is not self.canvas.frame
                or frame is not self.inspection_result_frame):
            return
        self.inspection_focus_cache[index] = overlay
        if (self.inspection_profile is not None
                and self.inspection_profile.selected_scale == index
                and not self.inspection_show_ranges):
            self._paint_inspection_overlay(frame, overlay)

    def _histogram_clicked(self, value):
        bins = self.inspection_histogram.bins
        self.status.setText(f"Byte 0x{value:02X} ({value}) · histogram: "
                            f"{bins[value]:,}/{sum(bins):,} readable bytes")

    def _inspect_pending(self, frame):
        address = self.pending_inspection_offset
        if (address is None or not self.inspector_button.isChecked()
                or not frame.start <= address < frame.stop
                or (frame.start, frame.stop) != self.selection):
            return
        self.pending_inspection_offset = None
        self.inspect_offset(address, map_sampled=frame.sampled)

    def inspect_offset(self, offset, map_sampled=None):
        """Analyze original bytes off the UI thread; discard obsolete inspections."""
        if self.closed or ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path:
            return
        frame = self.canvas.frame
        low, high = self.selection
        if not low <= offset < high:
            return
        mode = self.mode
        snapshot = self._current_snapshot() if mode != "File" else None
        if mode != "File" and snapshot is None:
            self._clear_inspection()
            return
        compare = self._detail_comparison(mode, snapshot)
        expected_key = self._detail_source_key(mode, snapshot, compare)
        if not isinstance(frame, Frame) or (frame.start, frame.stop) != (low, high):
            self._clear_inspection()
            self.pending_inspection_offset = offset
            if self.inspection_title is not None:
                self.inspection_title.setText("Waiting for map frame at selected range…")
            return
        if not self._same_detail_source(
                getattr(self.canvas, "frame_source_key", None), expected_key):
            self._clear_inspection()
            self.pending_inspection_offset = offset
            if self.inspection_title is not None:
                self.inspection_title.setText("Waiting for map frame at selected stop pair…")
            return
        map_sampled = frame.sampled
        source = (f"File+0x{offset:X}" if mode == "File" else
                  f"stop #{snapshot.serial} · VA 0x{offset:X} (RAM B)")
        self._clear_inspection()
        generation = self.inspection_generation
        self.inspection_requested_frame = frame
        self.inspection_title.setText(f"Analyzing {source}…")
        path, signal, inspected_frame = self.path, self.result, frame

        def worker():
            try:
                cancel = lambda: self.closed or generation != self.inspection_generation
                info = (inspect_file(path, low, high, offset, map_sampled, cancel) if mode == "File" else
                        inspect_snapshot(snapshot, low, high, offset, map_sampled, compare, cancel))
                overlay, highlighted = (inspection_ranges_overlay(
                    inspected_frame, info.ranges, cancel)
                    if isinstance(inspected_frame, Frame)
                    else (None, (0, 0, 0, 0)))
                payload = info, inspected_frame, overlay, highlighted
                error = None
            except RenderCancelled:
                return
            except (OSError, ValueError, RuntimeError) as exc:
                payload, error = None, str(exc)
            try:
                signal.inspection_ready.emit(generation, payload, source, error)
            except RuntimeError:
                pass

        self.inspection_future = self.inspection_executor.submit(worker)

    @QtCore.Slot(int, object, object, object)
    def _inspection_rendered(self, generation, payload, source, error):
        if self.closed or generation != self.inspection_generation:
            return
        if error:
            self.inspection_title.setText("Inspection failed: " + error)
            self.status.setText("Inspection failed: " + error)
            return
        info, frame, overlay, highlighted = payload
        if frame is not self.canvas.frame:
            return
        self.inspection_result_frame = frame
        self.inspection_title.setText(f"Bytes · {source} · 0x{info.start:X}–0x{info.stop - 1:X}")
        scales = []
        for (size, actual, readable, entropy), (begin, end), map_pixels in zip(
                info.scales, info.ranges, highlighted):
            name = {32: "32 B", 4096: "4 KiB", 65536: "64 KiB", 1 << 20: "1 MiB"}[size]
            value = f"{entropy:.2f}" if entropy is not None else "n/a"
            ceiling = min(8, math.log2(readable)) if readable else 0
            scales.append((name, f"0x{begin:X}–0x{end - 1:X}",
                           f"{readable:,}/{actual:,} B", f"{value}/{ceiling:.2f}",
                           f"{map_pixels:,}"))
        self._set_inspection_rows(self.inspection_scales, scales)
        facts = []
        known = info.readable

        def add(name, observed, baseline="", basis=""):
            facts.append((name, observed, baseline, basis))

        for name, count, basis in (
                ("Zero 00", info.zeros, "fraction of readable bytes"),
                ("ASCII text", info.text, "printable + TAB/CR/LF"),
                ("High-bit 80–FF", info.high_bit, "fraction of readable bytes")):
            value = f"{count:,} ({count / known:.1%})" if known else "n/a"
            add(name, value, basis=basis)
        add("Distinct bytes", f"{info.distinct}/256", basis=f"{known:,} known bytes")
        add("Longest identical run", f"{info.longest_run:,} B", basis="unread gaps split runs")
        add("zlib size / input", f"{info.zlib_ratio:.1%}" if info.zlib_ratio is not None
            else "n/a", basis="whole window readable" if info.zlib_ratio is not None
            else "unread byte: compression not measured")
        add("Adjacent H · 64 KiB",
            f"{info.digram_entropy:.2f}/16 bits" if info.digram_entropy is not None else "n/a",
            basis=f"{info.adjacent_pairs:,} known neighboring pairs")
        order = info.order
        if order is None:
            add("Shuffled order control", "insufficient data", basis="need ≥512 adjacent known pairs")
        else:
            add("Order sample", f"{order.readable:,}/{order.examined:,} B",
                f"{order.permutations} shuffles", "up to 8 KiB; each readable run shuffled separately")
            add("Adjacent H · control", f"{order.entropy:.2f}/16 bits",
                f"mean {order.shuffled_entropy:.2f}",
                f"Δ {order.entropy_effect:+.2f} bits · p={order.entropy_p:.3f}"
                f" · {order.adjacent_pairs:,} pairs")
            if order.lag is not None:
                add(f"Strongest lag · {order.lag} B",
                    f"{order.lag_matches:,}/{order.lag_pairs:,}"
                    f" ({order.lag_matches / order.lag_pairs:.1%})",
                    f"expected {order.lag_expected:.1%}",
                    f"excess {order.lag_effect:+.1%} · p={order.lag_p:.3f}"
                    f" (max over {order.lags_tested} lags)")
            if order.compression_p is not None:
                add("zlib · control", f"{order.compression_ratio:.1%}",
                    f"mean {order.shuffled_compression:.1%}",
                    f"Δ {order.shuffled_compression - order.compression_ratio:+.1%}"
                    f" · p={order.compression_p:.3f}")
        comp = info.comparison
        if comp is None:
            if self.mode.startswith("Δ"):
                add("A/B comparison", "not measured", basis="baseline pending or no matching VA")
        else:
            add(f"Changed vs {comp.label}", f"{comp.changed:,}/{comp.comparable:,} B",
                basis=(f"first VA 0x{comp.first_changed:X}" if comp.first_changed is not None
                       else "only valid paired bytes"))
            if comp.comparable:
                add("Comparable H · B", f"{comp.current_entropy:.2f}",
                    f"A {comp.baseline_entropy:.2f}", "bits/byte on same paired positions")
        add("Inspector coverage", f"{known:,}/{info.examined:,} B", "exact",
            "unread excluded" if known != info.examined else "all bytes readable")
        add("Map coverage", f"{highlighted[-1]:,} pixels",
            "sampled" if info.map_sampled else "exact",
            ("no displayed samples in inspected interval" if not highlighted[-1] else
             "pixel counts by scale above; unread RAM excluded from statistics"))
        self._set_inspection_rows(self.inspection_facts, facts)
        self.inspection_histogram.bins = info.histogram
        self.inspection_histogram.update()
        if getattr(self, "inspection_profile", None) is not None:
            self.inspection_profile.set_inspection(info, highlighted, self.mode.startswith("Δ"))
        self.inspection_overlay_cache = frame, overlay
        self._display_inspection_overlay(frame, overlay)

    def _display_inspection_overlay(self, frame, overlay):
        if (not self.inspection_show_ranges or overlay is None
                or frame is not self.canvas.frame):
            return
        self._paint_inspection_overlay(frame, overlay)

    def _paint_inspection_overlay(self, frame, overlay):
        image = QtGui.QImage(overlay, frame.side, frame.side, frame.side * 4,
                             QtGui.QImage.Format.Format_ARGB32)
        self.canvas.inspection_overlay = image.copy()
        self.canvas.inspection_overlay_frame = frame
        self.canvas.update()

    def _start_unmapped_outline(self, frame):
        self.outline_generation += 1
        generation = self.outline_generation
        self.canvas.unmapped_overlay = None
        grid = frame.side // 8
        mask = bytearray(grid * grid)
        QtCore.QTimer.singleShot(0, lambda: self._outline_step(frame, generation, mask, 0))

    def _outline_step(self, frame, generation, mask, index):
        if (self.closed or generation != self.outline_generation
                or frame is not self.canvas.frame
                or ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path):
            return
        grid = frame.side // 8
        end = min(len(mask), index + 128)  # Bounded IDB work per UI turn.
        for tile_index in range(index, end):
            if is_unmapped_tile(frame, tile_index, ida_loader.get_fileregion_ea,
                                ida_idaapi.BADADDR):
                x, y = curve_point_at(grid, tile_index)
                mask[y * grid + x] = 1
        if end < len(mask):
            QtCore.QTimer.singleShot(0, lambda: self._outline_step(frame, generation, mask, end))
            return
        if not any(mask):
            return
        overlay = QtGui.QImage(frame.side, frame.side, QtGui.QImage.Format.Format_ARGB32)
        overlay.fill(QtCore.Qt.GlobalColor.transparent)
        painter = QtGui.QPainter(overlay)
        painter.setPen(QtGui.QPen(QtGui.QColor(255, 45, 45, 230), 1))
        for x0, y0, x1, y1 in unmapped_boundary_segments(mask, grid):
            painter.drawLine(min(x0, frame.side - 1), min(y0, frame.side - 1),
                             min(x1, frame.side - 1), min(y1, frame.side - 1))
        painter.end()
        self.canvas.unmapped_overlay = overlay
        self.canvas.update()

    def refresh_bookmarks(self):
        if self.closed:
            return
        if ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path:
            self.bookmarks = {}
        else:
            self.bookmarks = collect_ida_bookmarks(self.file_size if self.mode == "File" else None)
        self.bookmarks_loaded = True
        self.canvas.set_bookmarks(self.bookmarks)

    def refresh_mapping(self):
        if not self.closed and self.mode == "File" and self.canvas.frame is not None:
            self._start_unmapped_outline(self.canvas.frame)

    def show_offset(self, offset):
        if ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path:
            self.status.setText("Map belongs to another IDA database; reopen Visualizer")
            return
        if self.mode != "File":
            snapshot = self._current_snapshot()
            if snapshot is None or not snapshot.start <= offset < snapshot.stop:
                self.status.setText("Address is outside debugger snapshot")
                return
            readable = snapshot.valid[offset - snapshot.start] != 0
            partial_sample = False
            frame = self.canvas.frame
            if readable and frame is not None and not isinstance(frame, GlobalFrame) and frame.sampled:
                begin = max(snapshot.start, min(offset - 16, snapshot.stop - 32))
                partial_sample = not all(snapshot.valid[begin - snapshot.start:
                                                        begin - snapshot.start + 32])
            self.status.setText(f"RAM stop #{snapshot.serial} · VA 0x{offset:X}"
                                + (" · not read in snapshot" if not readable else
                                   " · 32-byte sample includes bytes not read" if partial_sample else ""))
            return
        ea = ida_loader.get_fileregion_ea(offset)
        address = (f"IDA 0x{ea:X}" if ea != ida_idaapi.BADADDR
                   else "unmapped in IDA; click to inspect original bytes")
        self.status.setText(f"File+0x{offset:X} → {address}")

    def jump_to_offset(self, offset):
        if ida_loader.get_path(ida_loader.PATH_TYPE_IDB) != self.idb_path:
            self.status.setText("Map belongs to another IDA database; reopen Visualizer")
            return
        if self.mode != "File":
            snapshot = self._current_snapshot()
            if snapshot is None or not snapshot.start <= offset < snapshot.stop:
                return
            if not snapshot.valid[offset - snapshot.start] or not ida_kernwin.jumpto(offset):
                self.show_raw(offset)
            else:
                self.show_offset(offset)
            return
        ea = ida_loader.get_fileregion_ea(offset)
        if ea == ida_idaapi.BADADDR:
            self.show_raw(offset)
        else:
            ida_kernwin.jumpto(ea)
            self.show_offset(offset)

    def show_raw(self, offset):
        try:
            context = (raw_hex_preview(self.path, offset) if self.mode == "File"
                       else snapshot_hex_preview(self._current_snapshot(), offset))
        except (OSError, ValueError) as exc:
            self.status.setText(str(exc))
            return
        if self.raw_dialog is None:
            self.raw_dialog = QtWidgets.QDialog(self)
            self.raw_dialog.resize(740, 270)
            box = QtWidgets.QVBoxLayout(self.raw_dialog)
            self.raw_text = QtWidgets.QPlainTextEdit(self.raw_dialog)
            self.raw_text.setFont(QtGui.QFont("monospace"))
            self.raw_text.setReadOnly(True)
            box.addWidget(self.raw_text)
        self.raw_text.setPlainText(context)
        self.raw_dialog.setWindowTitle("Visualizer: Original file bytes" if self.mode == "File"
                                       else "Visualizer: RAM snapshot bytes")
        self.raw_dialog.show()
        self.raw_dialog.raise_()
        self.status.setText((f"File+0x{offset:X} has no IDA address; showing original bytes"
                             if self.mode == "File" else f"RAM VA 0x{offset:X} · snapshot hex viewer"))
