"""Source selection, ranges, and overview state."""

import ida_dbg
import ida_kernwin
import ida_loader

from PySide6 import QtCore, QtGui, QtWidgets
from datetime import datetime
from visualizer_core import (
    EXACT_LIMIT,
    MemorySnapshot,
    clamp_range,
    common_va_snapshots,
    entropy_overview_chunks,
    focus_domain,
    iter_file_baseline,
    iter_global_file_samples,
    remap_nested,
    same_region_overlap,
    snapshot_overview_chunks,
    zoom_range,
)
from visualizer_ui.constants import DELTA_FILE, DELTA_STORED

class ViewStateMixin:
    def _current_snapshot(self):
        return self.snapshot

    def _sync_global_controls(self):
        active = self.global_mode and self.mode != "File"
        if getattr(self, "diff_button", None) is not None:
            self.diff_button.setVisible(self.mode in (DELTA_FILE, DELTA_STORED))
        self.global_button.setVisible(self.mode != "File")
        self.region_picker.setVisible(not active and self.mode != "File")
        self.track_button.setVisible(not active)
        self.global_bar.setVisible(self.mode != "File")
        self.global_base_label.setVisible(self.mode == DELTA_STORED)
        self.global_base_picker.setVisible(self.mode == DELTA_STORED)
        self.absolute_bar.setVisible(not active)
        self.relative_bar.setVisible(not active)

    def _global_changed(self, checked):
        self.global_mode = checked
        if checked:
            self.finding_jump_pending = False
        self.canvas.frame = self.canvas.image = None
        self.canvas.frame_source_key = None
        self.canvas.update()
        if checked:
            self._wheel_pending = {"relative": 0, "absolute": 0}
        self._sync_global_controls()
        if checked:
            self._refresh_global_stops()
            if getattr(self, "finding_panel", None) is not None:
                self.refresh_findings()
            self.queue_render()
        else:
            self.global_baseline_generation += 1
            self.global_pending_key = self.global_sample_iterator = None
            self._source_changed(self.mode)

    def _refresh_global_stops(self):
        current = self.global_stop_picker.currentData()
        baseline = self.global_base_picker.currentData()
        stops = sorted(self.history.stops, reverse=True)

        def populate(picker, selected, placeholder, options):
            picker.blockSignals(True)
            picker.clear()
            picker.addItem(placeholder, None)
            for stop_id in options:
                group = self.history.for_stop(stop_id)
                stamp = datetime.fromtimestamp(self.history.stops[stop_id].captured_at).strftime("%H:%M:%S")
                coverage = self.history.stop_coverage(stop_id)
                state = (" · partial" if coverage and
                         (coverage[1] or coverage[0].reason) else
                         " · capturing" if coverage and not coverage[0].finished else "")
                picker.addItem(f"Stop #{stop_id} · {stamp} · {len(group)} regions{state}", stop_id)
                if stop_id == selected:
                    picker.setCurrentIndex(picker.count() - 1)
            if selected is not None and selected not in options:
                picker.addItem(f"Stop #{selected} · unavailable", selected)
                picker.setCurrentIndex(picker.count() - 1)
            picker.blockSignals(False)
        populate(self.global_stop_picker, current, "Choose stop B…", stops)
        current = self.global_stop_picker.currentData()
        alternatives = [stop for stop in stops if stop != current]
        populate(self.global_base_picker, baseline, "Choose stop A…", alternatives)
        if current is not None and self.follow_previous_baseline and baseline is None:
            older = next((stop for stop in alternatives
                          if stop < current and self.history.for_stop(stop)), None)
            self.global_base_picker.blockSignals(True)
            self.global_base_picker.setCurrentIndex(
                alternatives.index(older) + 1 if older is not None else 0)
            self.global_base_picker.blockSignals(False)

    def _global_stop_changed(self, index=None):
        if self.closed or self.mode == "File":
            return
        self.global_follow_latest = False
        self.follow_previous_baseline = False
        self.global_baseline_generation += 1
        self.global_file_key = self.global_file_samples = None
        self.global_pending_key = None
        self.global_sample_iterator = None
        self._refresh_global_stops()
        self._stop_selection_changed()

    def _select_latest_captured_stop(self):
        for index in range(1, self.global_stop_picker.count()):
            if self.history.for_stop(self.global_stop_picker.itemData(index)):
                self.global_stop_picker.blockSignals(True)
                self.global_stop_picker.setCurrentIndex(index)
                self.global_stop_picker.blockSignals(False)
                break

    def _base_stop_changed(self, index=None):
        if self.closed or self.mode != DELTA_STORED:
            return
        self.follow_previous_baseline = False
        self._stop_selection_changed()

    def _stop_selection_changed(self):
        if self.global_mode:
            if getattr(self, "finding_panel", None) is not None:
                self.refresh_findings()
            self.queue_render()
            return
        self._refresh_regions()
        stop_id = self.global_stop_picker.currentData()
        group = self.history.for_stop(stop_id)
        if not group:
            self.snapshot = self.baseline = None
            if getattr(self, "finding_panel", None) is not None:
                self.refresh_findings()
            self._clear_detail_map(f"Stop #{stop_id}: no captured regions")
            return
        previous = self.snapshot
        candidates = [item for item in group if previous is not None
                      and item.mapping == previous.mapping]
        current = next((item for item in candidates if item.start <= previous.start < item.stop),
                       None) if candidates else None
        if current is None:
            focus = ida_kernwin.get_screen_ea()
            current = next((item for item in group if item.start <= focus < item.stop), group[0])
        self._select_stop_snapshot(current)
        if getattr(self, "finding_panel", None) is not None:
            self.refresh_findings()

    def _clear_detail_map(self, message):
        self.generation += 1
        self.render_source_key = None
        if getattr(self, "inspection_title", None) is not None:
            self._clear_inspection()
        self.canvas.frame = self.canvas.image = None
        self.canvas.frame_source_key = None
        self.canvas.unmapped_overlay = self.canvas.delta_overlay = None
        self.canvas.update()
        self._clear_byte_diff(message)
        self.status.setText(message)

    def _select_stop_snapshot(self, snapshot):
        previous = self.snapshot
        self.snapshot = snapshot
        if snapshot.mapping in self.regions:
            self.region_picker.blockSignals(True)
            self.region_picker.setCurrentIndex(self.regions.index(snapshot.mapping))
            self.region_picker.blockSignals(False)
        self.baseline_generation += 1
        self.baseline = None
        if self.global_mode:
            return
        if self.mode == DELTA_STORED:
            old = [item for item in self.history.for_stop(self.global_base_picker.currentData())
                   if same_region_overlap(item, snapshot)]
            if not old:
                self._clear_detail_map(f"No matching VA for {snapshot.region} at stop A")
                return
            baseline = max(old, key=lambda item: min(snapshot.stop, item.stop)
                           - max(snapshot.start, item.start))
            now, _ = common_va_snapshots(snapshot, baseline)
            domain = now.start, now.stop
            if self.domain != domain:
                width = min(EXACT_LIMIT, now.stop - now.start)
                focus = ida_kernwin.get_screen_ea()
                low = max(now.start, min(focus - width // 2, now.stop - width))
                self._set_data_domain(domain, domain, (low, low + width))
                self._switch_overviews()
            self.queue_render()
            return
        self._show_snapshot(snapshot, reset=previous is None or
                            (previous.start, previous.stop) != (snapshot.start, snapshot.stop))
        if self.mode == DELTA_FILE:
            self._start_baseline()

    def _start_global_file_baseline(self, snapshots, side, key):
        self.global_baseline_generation += 1
        generation = self.global_baseline_generation
        self.global_pending_key = key
        self.global_sample_iterator = iter_global_file_samples(
            snapshots, side, self.path, ida_loader.get_fileregion_offset)
        self.global_sample_buffer = {}
        self.global_priority_pending = True
        self.status.setText("Mapping original file samples for global comparison...")
        QtCore.QTimer.singleShot(0, lambda: self._global_file_step(generation, key))

    def _global_file_step(self, generation, key):
        if (self.closed or not self.global_mode or self.mode != DELTA_FILE
                or generation != self.global_baseline_generation
                or key != self.global_pending_key):
            return
        try:
            for _ in range(8 if self.global_priority_pending else 128):
                sample, value = next(self.global_sample_iterator)
                self.global_sample_buffer[sample] = value
                if isinstance(sample[1], int):
                    self.global_priority_pending = False
                if sample[1] == "page":
                    break  # One full-page IDB mapping verification per UI turn.
        except StopIteration:
            self.global_file_samples = self.global_sample_buffer
            self.global_file_key = key
            self.global_pending_key = None
            self.global_sample_iterator = None
            self.refresh_findings()
            self.queue_render()
            return
        except (OSError, RuntimeError, ValueError) as exc:
            self.global_pending_key = None
            self.global_sample_iterator = None
            if getattr(self, "finding_panel", None) is not None:
                self.finding_scope.setText(f"Global stop · file mapping failed: {exc}")
                if getattr(self, "finding_lanes", None) is not None:
                    self.finding_lanes.set_evidence(
                        (), self.file_size, empty_text="Verified file mapping failed")
            self.status.setText(f"Global file comparison failed: {exc}")
            return
        QtCore.QTimer.singleShot(0, lambda: self._global_file_step(generation, key))

    def _set_data_domain(self, domain, absolute, selected):
        self._wheel_pending = {"relative": 0, "absolute": 0}
        self.domain = domain
        self.absolute_range = clamp_range(*absolute, *domain)
        self.selection = clamp_range(*selected, *self.absolute_range)
        self.relative_domain = focus_domain(self.absolute_range, self.selection)
        self.absolute_label.setText("File" if self.mode == "File" else "RAM")
        kind = "File" if self.mode == "File" else "VA"
        self.absolute_slider.address_kind = kind
        self.relative_slider.address_kind = kind
        self.absolute_slider.set_range(*self.absolute_range, minimum=domain[0], maximum=domain[1])
        self.relative_slider.set_range(*self.selection,
                                       minimum=self.relative_domain[0],
                                       maximum=self.relative_domain[1])
        self.canvas.hover_offset = None
        self.outline_generation += 1
        self.canvas.unmapped_overlay = None
        self.canvas.delta_overlay = None

    def _switch_overviews(self):
        self.absolute_generation += 1
        self.relative_generation += 1
        if self.absolute_future is not None:
            self.absolute_future.cancel()
        if self.relative_future is not None:
            self.relative_future.cancel()
        self.overview_started = False
        self.absolute_pixels[:] = b"\x00\x00\x00\xFF" * 1024
        self.relative_pixels[:] = b"\x00\x00\x00\xFF" * 1024
        for slider in (self.absolute_slider, self.relative_slider):
            slider.image = None
            slider.update()

    def _source_changed(self, text):
        if self.closed:
            return
        if self.mode != text:
            self.render_source_key = None
            self.finding_jump_pending = False
        if getattr(self, "finding_full_scan", None) is not None:
            self.finding_full_scan.setVisible(text == "File")
        if getattr(self, "inspection_title", None) is not None:
            self._clear_inspection()
        if self.mode != text:
            self.diff_address = None
        self._clear_byte_diff()
        self._wheel_pending = {"relative": 0, "absolute": 0}
        self.generation += 1
        prior_mode = self.mode
        if self.global_mode and prior_mode != text:
            self.global_baseline_generation += 1
            self.global_pending_key = None
            self.global_sample_iterator = None
        if text == "File":
            if self.global_mode:
                self.global_button.blockSignals(True)
                self.global_button.setChecked(False)
                self.global_button.blockSignals(False)
                self.global_mode = False
                self.global_baseline_generation += 1
                self.global_file_key = self.global_file_samples = None
                self.global_pending_key = None
                self.global_sample_iterator = None
            self.baseline_generation += 1
            self.mode = "File"
            self.region_picker.setVisible(False)
            self.entropy_eye.setVisible(False)
            self.delta_legend.setVisible(False)
            self._sync_global_controls()
            absolute, selected = self.file_ranges
            self._set_data_domain((0, self.file_size), absolute, selected)
            self._switch_overviews()
            self.bookmarks_loaded = False
            self.canvas.frame = self.canvas.image = None
            self.canvas.frame_source_key = None
            if getattr(self, "finding_panel", None) is not None:
                self.refresh_findings()
            self.queue_render()
            return
        if self.mode == "File":
            self.file_ranges = self.absolute_range, self.selection
        self.mode = text
        self.bookmarks_loaded = False
        if not self.session.tracking_configured:
            self.session.enabled = True
            if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
                self.session.track_prompt_pending = True
                generation = self.session.generation
                QtCore.QTimer.singleShot(0, lambda: self.session.offer_track_setup(generation))
        if self.global_stop_picker.currentData() is None:
            self.global_follow_latest = True
        if text.startswith("Δ") and prior_mode != text:
            self.global_mode = True
            self.canvas.frame = self.canvas.image = None
            self.canvas.frame_source_key = None
            self.canvas.update()
            self.global_button.blockSignals(True)
            self.global_button.setChecked(True)
            self.global_button.blockSignals(False)
            if self.global_base_picker.currentData() is None:
                self.follow_previous_baseline = True
        self.entropy_eye.setVisible(text.startswith("Δ"))
        self.delta_legend.setVisible(text.startswith("Δ"))
        self._sync_global_controls()
        self._refresh_global_stops()
        if self.global_follow_latest:
            self._select_latest_captured_stop()
            self._refresh_global_stops()
            if self.global_stop_picker.currentData() is not None:
                self.global_follow_latest = False
        self.follow_previous_baseline = False
        self._stop_selection_changed()

    def _region_changed(self, index):
        if self.closed or self.mode == "File" or not 0 <= index < len(self.regions):
            return
        region = self.regions[index]
        group = [item for item in self.history.for_stop(self.global_stop_picker.currentData())
                 if item.mapping == region]
        if not group:
            self._clear_detail_map(f"Region {region[2]} was not captured at this stop")
            return
        focus = ida_kernwin.get_screen_ea()
        snapshot = next((item for item in group if item.start <= focus < item.stop), group[0])
        self._select_stop_snapshot(snapshot)

    def _show_snapshot(self, snapshot, reset):
        domain = snapshot.start, snapshot.stop
        if reset or self.domain != domain:
            focus = ida_kernwin.get_screen_ea()
            width = min(EXACT_LIMIT, snapshot.stop - snapshot.start)
            low = max(snapshot.start, min(focus - width // 2, snapshot.stop - width))
            selected = low, low + width
            self._set_data_domain(domain, domain, selected)
        self._switch_overviews()
        self.canvas.frame = self.canvas.image = None
        self.canvas.set_bookmarks({})
        self.queue_render()

    def _start_baseline(self):
        snapshot = self.snapshot
        if snapshot is None or self.mode != DELTA_FILE:
            return
        self.baseline_generation += 1
        generation = self.baseline_generation
        self.baseline_data = bytearray(len(snapshot.data))
        self.baseline_valid = bytearray(len(snapshot.data))
        self.baseline_iterator = iter_file_baseline(
            self.path, snapshot.start, len(snapshot.data), ida_loader.get_fileregion_offset)
        self.status.setText("Comparing captured RAM with file-backed IDA pages...")
        QtCore.QTimer.singleShot(0, lambda: self._baseline_step(generation, snapshot))

    def _baseline_step(self, generation, snapshot):
        if self.closed or generation != self.baseline_generation or self.snapshot is not snapshot:
            return
        try:
            for _ in range(16):
                offset, data, valid = next(self.baseline_iterator)
                self.baseline_data[offset:offset + len(data)] = data
                self.baseline_valid[offset:offset + len(valid)] = valid
        except StopIteration:
            self.baseline = MemorySnapshot(snapshot.start, bytes(self.baseline_data),
                                           bytes(self.baseline_valid), "file baseline", snapshot.serial)
            self.refresh_findings()
            self.queue_render(preserve_inspection=True)
            return
        except (OSError, RuntimeError, ValueError) as exc:
            if self.pending_inspection_offset is not None and self.inspection_title is not None:
                self._clear_inspection()
                self.inspection_title.setText(f"File baseline failed: {exc}")
            if getattr(self, "finding_panel", None) is not None:
                self.finding_scope.setText(f"Region {snapshot.region} · file baseline failed: {exc}")
                if getattr(self, "finding_lanes", None) is not None:
                    self.finding_lanes.set_evidence(
                        (), self.file_size, empty_text="Verified file baseline failed")
            self.status.setText(f"File comparison failed: {exc}")
            return
        QtCore.QTimer.singleShot(0, lambda: self._baseline_step(generation, snapshot))

    def _start_overviews(self):
        if not self.overview_started and not self.closed:
            self.overview_started = True
            source = None if self.mode == "File" else self._current_snapshot()
            self.absolute_future = self.absolute_executor.submit(
                self._build_overview, "absolute", self.absolute_generation,
                *self.domain, source)
            self._schedule_relative_overview()

    def _build_overview(self, which, generation, low, high, snapshot):
        try:
            chunks = (entropy_overview_chunks(self.path, start=low, stop=high)
                      if snapshot is None else snapshot_overview_chunks(snapshot, start=low, stop=high))
            for start, pixels in chunks:
                if (self.closed or generation != (self.relative_generation
                                                   if which == "relative" else self.absolute_generation)):
                    return
                self.result.overview_ready.emit(which, generation, start, pixels)
        except (OSError, ValueError, RuntimeError):
            pass  # Gray track remains usable if file changes or view closes.

    @QtCore.Slot(str, int, int, object)
    def _overview_rendered(self, which, generation, start, pixels):
        if (self.closed or generation != (self.relative_generation
                                          if which == "relative" else self.absolute_generation)):
            return
        buffer = self.absolute_pixels if which == "absolute" else self.relative_pixels
        slider = self.absolute_slider if which == "absolute" else self.relative_slider
        buffer[start * 4:start * 4 + len(pixels)] = pixels
        image = QtGui.QImage(buffer, 1024, 1, 1024 * 4, QtGui.QImage.Format.Format_ARGB32)
        slider.image = image.copy()
        slider.update()

    def _schedule_relative_overview(self):
        if not self.overview_started or self.closed:
            return
        self.relative_generation += 1
        if self.relative_future is not None:
            self.relative_future.cancel()
        self.relative_slider.image = None  # Never show colors from the previous absolute range.
        self.relative_pixels[:] = b"\x00\x00\x00\xFF" * 1024
        self.relative_slider.update()
        low, high = self.relative_domain
        source = None if self.mode == "File" else self._current_snapshot()
        self.relative_future = self.relative_executor.submit(
            self._build_overview, "relative", self.relative_generation, low, high, source)

    def _refresh_relative_domain(self, refresh_overview):
        new_domain = focus_domain(self.absolute_range, self.selection)
        changed = new_domain != self.relative_domain
        self.relative_domain = new_domain
        self.relative_slider.set_range(*self.selection,
                                       minimum=self.relative_domain[0],
                                       maximum=self.relative_domain[1])
        if changed and refresh_overview:
            self._schedule_relative_overview()

    def _absolute_changed(self, low, high, adjusting):
        previous = self.absolute_range
        self.absolute_range = low, high
        self.selection = remap_nested(previous, self.selection, self.absolute_range)
        self._refresh_relative_domain(False)
        if adjusting:
            self.relative_generation += 1  # Ignore old colors until release.
            if self.relative_future is not None:
                self.relative_future.cancel()
            self.relative_slider.image = None
            self.relative_slider.update()
        else:
            self._schedule_relative_overview()
        self.queue_render(adjusting)

    def _relative_changed(self, low, high, adjusting):
        self.selection = low, high
        if not adjusting:
            self._refresh_relative_domain(True)
        self.queue_render(adjusting)

    def _set_relative(self, low, high):
        low, high = clamp_range(low, high, *self.absolute_range)
        self.selection = low, high
        self._refresh_relative_domain(True)
        self.queue_render()

    def wheel_zoom(self, anchor, units, absolute=False):
        if self.closed or self.global_mode:
            return
        key = "absolute" if absolute else "relative"
        low, high = self.absolute_range if absolute else self.selection
        minimum, maximum = self.domain if absolute else self.absolute_range
        pending = max(-1920, min(1920, self._wheel_pending[key] + units))
        notches = pending // 120 if pending >= 0 else -((-pending) // 120)
        self._wheel_pending[key] = pending - notches * 120
        if not notches:
            return
        updated = low, high
        for _ in range(abs(notches)):
            next_range = zoom_range(*updated, minimum, maximum, anchor, notches > 0)
            if next_range == updated:
                self._wheel_pending[key] = 0
                break
            updated = next_range
        if updated == (low, high):
            return
        if absolute:
            self.absolute_slider._set(*updated, adjusting=False)
        else:
            self._set_relative(*updated)

    def zoom_at(self, offset, inward):
        selection = zoom_range(*self.selection, *self.absolute_range, offset, inward)
        if selection != self.selection:
            self._set_relative(*selection)

    def slider_menu(self, slider, position):
        menu = QtWidgets.QMenu(self)
        if slider is self.absolute_slider:
            fit = menu.addAction("Show entire file")
            reset = menu.addAction("Reset to 1 MiB")
        else:
            fit = menu.addAction("Fit relative to absolute")
            reset = None
        exact = menu.addAction("Enter exact range…")
        action = menu.exec(position)
        if action == fit and slider is self.absolute_slider:
            selected = self.selection
            slider._set(*self.domain, False)
            self._set_relative(*selected)
        elif action == fit:
            self._set_relative(*self.absolute_range)
        elif action == reset:
            length = min(EXACT_LIMIT, self.domain[1] - self.domain[0])
            center = (slider.low + slider.high) // 2
            start = max(self.domain[0], min(center - length // 2, self.domain[1] - length))
            slider._set(start, start + length, False)
        elif action == exact:
            slider._ask_range()
