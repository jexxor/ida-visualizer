"""Asynchronous map rendering and presentation."""

import ida_kernwin
import ida_loader

from PySide6 import QtCore, QtGui
from visualizer_core import (
    EXACT_LIMIT,
    GlobalFrame,
    RenderCancelled,
    SIDE,
    common_va_snapshots,
    delta_only_pixels,
    delta_tile_masks,
    global_boundary_segments,
    global_delta_tile_masks,
    new_region_pixels,
    render_file,
    render_global_snapshots,
    render_snapshot,
    renderer_status,
    same_region_overlap,
    unmapped_boundary_segments,
)
from visualizer_ui.constants import (
    DELTA_DOWN,
    DELTA_FILE,
    DELTA_STORED,
    DELTA_UP,
)

class RenderViewMixin:
    def queue_render(self, adjusting=False, preserve_inspection=False):
        if not self.closed:
            self._clear_byte_diff("Waiting for map frame at selected stop pair…")
            pending = self.pending_inspection_offset if preserve_inspection else None
            if getattr(self, "inspector_button", None) is not None and self.inspector_button.isChecked():
                self._clear_inspection()
                if pending is not None:
                    self.pending_inspection_offset = pending
            self.generation += 1
            if self.future is not None:
                self.future.cancel()
            if not adjusting:
                self.render()

    def render_side(self):
        return 256 if min(self.canvas.width(), self.canvas.height()) < 420 else SIDE

    @staticmethod
    def _detail_source_key(mode, snapshot, compare):
        """Identify bytes behind a detail frame, including the selected A baseline."""
        return mode, snapshot, compare

    @staticmethod
    def _same_detail_source(first, second):
        return (first is not None and second is not None
                and first[0] == second[0]
                and first[1] is second[1] and first[2] is second[2])

    def _detail_comparison(self, mode, snapshot):
        if mode == DELTA_FILE:
            return self.baseline
        if mode == DELTA_STORED:
            old = [item for item in self.history.for_stop(self.global_base_picker.currentData())
                   if same_region_overlap(item, snapshot)]
            if old:
                return max(old, key=lambda item: min(snapshot.stop, item.stop)
                           - max(snapshot.start, item.start))
        return None

    def _display_frame(self, frame):
        pixels = frame.pixels
        if (not isinstance(frame, GlobalFrame) and self.mode == DELTA_FILE
                and self.snapshot is not None
                and self.snapshot.new_region and self.baseline is not None):
            pixels = new_region_pixels(pixels)
        if self.mode.startswith("Δ") and not self.entropy_eye.isChecked():
            pixels = delta_only_pixels(pixels)
        image = QtGui.QImage(pixels, frame.side, frame.side, frame.side * 4,
                             QtGui.QImage.Format.Format_ARGB32)
        self.canvas.image = image.copy()
        self.canvas.update()

    def _entropy_visibility_changed(self, checked):
        self.entropy_eye.setToolTip(("Hide" if checked else "Show")
                                    + " entropy background in delta map")
        self.unchanged_legend.setVisible(not checked)
        if self.mode.startswith("Δ") and self.canvas.frame is not None:
            self._display_frame(self.canvas.frame)

    def render(self):
        if self.closed:
            return
        if self.global_mode:
            self._render_global()
            return
        mode = self.mode
        snapshot = self._current_snapshot() if mode != "File" else None
        if mode != "File" and snapshot is None:
            self.status.setText("Select a stop with captured regions under Track…")
            return
        source_snapshot = snapshot
        comparison = self._detail_comparison(mode, snapshot)
        if mode == DELTA_STORED:
            if comparison is None:
                self._clear_detail_map(f"No matching VA for {snapshot.region} at stop A")
                return
            snapshot, compare = common_va_snapshots(snapshot, comparison)
        elif mode == DELTA_FILE:
            if comparison is None:
                self.status.setText("Comparing RAM with original file pages...")
                return
            compare = comparison
        else:
            compare = None
        self.generation += 1
        generation = self.generation
        self.render_source_key = (generation, self._detail_source_key(
            mode, source_snapshot, comparison))
        low, high = self.selection
        side = self.render_side()
        path, signal = self.path, self.result
        def worker():
            try:
                cancel = lambda: self.closed or generation != self.generation
                frame = (render_file(path, low, high, side, cancelled=cancel)
                         if mode == "File" else
                         render_snapshot(snapshot, low, high, side, compare=compare,
                                         cancelled=cancel))
            except RenderCancelled:
                return
            except Exception as exc:
                frame, error = None, str(exc)
            else:
                error = None
            try:
                signal.ready.emit(generation, frame, error)
            except RuntimeError:
                pass

        self.future = self.executor.submit(worker)

    def _render_global(self):
        stop_id = self.global_stop_picker.currentData()
        snapshots = self.history.for_stop(stop_id)
        if not snapshots:
            coverage = self.history.stop_coverage(stop_id)
            message = (f"Stop #{stop_id}: {coverage[0].reason or 'no completed regions'}"
                       if coverage is not None else
                       "Select a debugger stop with captured tracked regions")
            self._clear_global_map(message)
            return
        side = self.render_side()
        mode = self.mode
        comparisons = None
        samples = None
        if mode == DELTA_STORED:
            base_stop = self.global_base_picker.currentData()
            if base_stop is None or base_stop == stop_id:
                self._clear_global_map("Choose a different baseline stop A for global comparison")
                return
            comparisons = self.history.for_stop(base_stop)
        elif mode == DELTA_FILE:
            try:
                stat = self.path.stat()
            except OSError as exc:
                self.status.setText(f"Global file comparison failed: {exc}")
                return
            key = (stop_id, side, tuple(id(item) for item in snapshots),
                   stat.st_size, stat.st_mtime_ns)
            if self.global_file_key != key:
                if self.global_pending_key != key:
                    self._clear_global_map("Mapping original file samples for global comparison...")
                    self._start_global_file_baseline(snapshots, side, key)
                return
            samples = self.global_file_samples
        self.generation += 1
        generation = self.generation
        signal = self.result

        def worker():
            try:
                frame = render_global_snapshots(
                    snapshots, side, comparisons=comparisons, file_samples=samples,
                    cancelled=lambda: self.closed or generation != self.generation)
            except RenderCancelled:
                return
            except Exception as exc:
                frame, error = None, str(exc)
            else:
                error = None
            try:
                signal.ready.emit(generation, frame, error)
            except RuntimeError:
                pass

        self.future = self.executor.submit(worker)

    def _clear_global_map(self, message):
        self.generation += 1
        self.render_source_key = None
        if getattr(self, "inspection_title", None) is not None:
            self._clear_inspection()
        self.canvas.frame = self.canvas.image = None
        self.canvas.frame_source_key = None
        self.render_source_key = None
        self.canvas.unmapped_overlay = self.canvas.delta_overlay = None
        self.canvas.update()
        self._clear_byte_diff(message)
        self.status.setText(message)

    def _stop_coverage_text(self, serial):
        coverage = self.history.stop_coverage(serial)
        if coverage is None:
            return ""
        record, uncovered = coverage
        return ((" · capture in progress" if not record.finished else "")
                + (f" · {uncovered:,} VA bytes not captured" if uncovered else "")
                + (f" · {record.reason}" if record.reason else ""))

    @QtCore.Slot(int, object, object)
    def _rendered(self, generation, frame, error):
        if self.closed or generation != self.generation:
            return
        if error:
            if (self.pending_inspection_offset is not None
                    and self.inspection_title is not None):
                self._clear_inspection()
                self.inspection_title.setText("Map render failed; choose a byte after retry")
            self.status.setText("Render failed: " + error)
            return
        if ((self.inspection_result_frame is not None
             and self.inspection_result_frame is not frame)
                or (self.inspection_requested_frame is not None
                    and self.inspection_requested_frame is not frame)):
            self._clear_inspection()
        if isinstance(frame, GlobalFrame):
            self._clear_byte_diff()
            self.render_source_key = None
            self.canvas.frame_source_key = None
            self.canvas.frame = frame
            self._display_frame(frame)
            self.canvas.set_changes(frame)
            if hasattr(self.canvas, "set_finding"):
                self.canvas.set_finding(self._selected_finding())
            if not self.bookmarks_loaded:
                self.refresh_bookmarks()
            else:
                self.canvas.set_bookmarks(self.bookmarks)
            self._draw_global_boundaries(frame)
            self._draw_entropy_deltas(frame)
            self.canvas.cursor_offset = None
            self.absolute_slider.cursor_offset = None
            self.canvas.update()
            self.status.setText(
                f"Global stop #{frame.stop_id} · {len(frame.regions)} captured regions"
                + (f" · {sum(snapshot.missing_bytes for _, _, snapshot in frame.regions):,} bytes not read"
                   if any(snapshot.missing_bytes for _, _, snapshot in frame.regions) else "")
                + (f" · {frame.omitted} regions exceed map capacity" if frame.omitted else "")
                + (f" · {frame.omitted_changes} verified changed regions omitted"
                   if frame.omitted_changes else "")
                + (f" · {len(frame.change_marks)} exact changed VA pins" if frame.change_marks else "")
                + self._stop_coverage_text(frame.stop_id)
                + (f" · entropy shifts: {len(frame.entropy_shifts)}"
                   if self.mode == DELTA_STORED else "")
                + (" · sampled file diff (open region for entropy shifts)"
                   if self.mode == DELTA_FILE else "")
                + " · click region for detail")
            return
        self._start_overviews()  # First map paints before file-wide sampling.
        request = getattr(self, "render_source_key", None)
        self.canvas.frame_source_key = (request[1] if request is not None
                                        and request[0] == generation else None)
        self.canvas.frame = frame
        self._display_frame(frame)
        self.canvas.set_changes(frame)
        if hasattr(self.canvas, "set_finding"):
            self.canvas.set_finding(self._selected_finding())
        if self.mode == "File":
            self.canvas.delta_overlay = None
            self._start_unmapped_outline(frame)
            if not self.bookmarks_loaded:
                self.refresh_bookmarks()
            else:
                self.canvas.set_bookmarks(self.bookmarks)
            ea = ida_kernwin.get_screen_ea()
            offset = ida_loader.get_fileregion_offset(ea)
            cursor_offset = offset if 0 <= offset < self.file_size else None
        else:
            self.outline_generation += 1
            self.canvas.unmapped_overlay = None
            if not self.bookmarks_loaded:
                self.refresh_bookmarks()
            else:
                self.canvas.set_bookmarks(self.bookmarks)
            self._draw_entropy_deltas(frame)
            ea = ida_kernwin.get_screen_ea()
            cursor_offset = ea if frame.start <= ea < frame.stop else None
        self.canvas.cursor_offset = cursor_offset
        self.absolute_slider.cursor_offset = cursor_offset
        self.absolute_slider.update()
        self.canvas.update()
        mode = "sampled" if frame.sampled else "exact"
        if self.mode == "File":
            self.status.setText(f"{renderer_status()} · file 0x{frame.start:X}–0x{frame.stop - 1:X} "
                                f"({frame.stop - frame.start:,} bytes) · {mode}")
        else:
            current = self._current_snapshot()
            has_comparison = self.mode.startswith("Δ")
            pair = (f"Stop A #{self.global_base_picker.currentData()} → B #{current.serial}"
                    if self.mode == DELTA_STORED else f"RAM stop #{current.serial}")
            self.status.setText(f"{pair} · VA 0x{frame.start:X}–0x{frame.stop - 1:X}"
                                + (f" · {current.missing_bytes:,} bytes not read"
                                   if current.missing_bytes else "")
                                + (f" · verified change VA 0x{frame.first_change:X}"
                                   if frame.first_change is not None else
                                   " · no verified byte change in view" if has_comparison else "")
                                + (f" · entropy shifts: {len(frame.entropy_shifts)}" if has_comparison else "")
                                + (" · newly seen region" if current.new_region else "")
                                 + (f" · {len(self.new_regions)} newly seen regions this pause"
                                    if self.new_regions and not current.new_region else "")
                                 + self._stop_coverage_text(current.serial))
        self._inspect_pending(frame)
        if getattr(self, "diff_title", None) is not None:
            self._refresh_byte_diff()

    def _draw_entropy_deltas(self, frame):
        self.canvas.delta_overlay = None
        if not frame.entropy_shifts:
            return
        grid = frame.side // 8
        up, down = (global_delta_tile_masks(frame) if isinstance(frame, GlobalFrame)
                    else delta_tile_masks(frame))
        overlay = QtGui.QImage(frame.side, frame.side, QtGui.QImage.Format.Format_ARGB32)
        overlay.fill(QtCore.Qt.GlobalColor.transparent)
        painter = QtGui.QPainter(overlay)
        for mask, color in ((up, QtGui.QColor(DELTA_UP)),
                            (down, QtGui.QColor(DELTA_DOWN))):
            color.setAlpha(220)
            painter.setPen(QtGui.QPen(color, 2))
            for x0, y0, x1, y1 in unmapped_boundary_segments(mask, grid):
                painter.drawLine(min(x0, frame.side - 1), min(y0, frame.side - 1),
                                 min(x1, frame.side - 1), min(y1, frame.side - 1))
        painter.end()
        self.canvas.delta_overlay = overlay

    def _draw_global_boundaries(self, frame):
        overlay = QtGui.QImage(frame.side, frame.side, QtGui.QImage.Format.Format_ARGB32)
        overlay.fill(QtCore.Qt.GlobalColor.transparent)
        painter = QtGui.QPainter(overlay)
        painter.setPen(QtGui.QPen(QtGui.QColor(190, 200, 205, 200), 1))
        for x0, y0, x1, y1 in global_boundary_segments(frame):
            painter.drawLine(min(x0, frame.side - 1), min(y0, frame.side - 1),
                             min(x1, frame.side - 1), min(y1, frame.side - 1))
        painter.end()
        self.canvas.unmapped_overlay = overlay

    def show_global_hit(self, hit):
        snapshot, address = hit
        readable = snapshot.valid[address - snapshot.start] != 0
        self.status.setText(f"Global · stop #{snapshot.serial} · {snapshot.region} · VA 0x{address:X}"
                            + (" · not read" if not readable else "")
                            + " · click for detail")

    def open_global_hit(self, hit):
        snapshot, address = hit
        self.finding_jump_target = snapshot, address
        self.finding_jump_pending = True
        self.diff_address = address
        was_global = self.global_mode
        self._select_stop_snapshot(snapshot)
        self.global_button.setChecked(False)
        if not was_global and getattr(self, "finding_panel", None) is not None:
            self.refresh_findings()
        if self.domain[0] <= address < self.domain[1]:
            width = min(EXACT_LIMIT, self.domain[1] - self.domain[0])
            low = max(self.domain[0], min(address - width // 2, self.domain[1] - width))
            self._set_data_domain(self.domain, self.domain, (low, low + width))
            self._switch_overviews()
            self.queue_render()
        self.show_offset(address)
        if self.inspector_button.isChecked():
            self.pending_inspection_offset = address
