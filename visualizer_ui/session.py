"""IDA debugger capture and bookmark adapters."""

import ida_dbg
import ida_idaapi
import ida_idc
import ida_idd
import ida_kernwin
import ida_loader
import ida_moves
import ida_segment
import time

from PySide6 import QtCore
from visualizer_core import (
    DiskSnapshotStore,
    MemorySnapshot,
    SnapshotHistory,
    debugger_regions,
    disjoint_regions,
    iter_memory_chunks,
    snapshot_bounds,
)
from visualizer_ui.constants import MAX_CAPTURE_WINDOW, MAX_PAUSE_BYTES

def process_regions():
    """Discover process mappings; some debuggers cannot report a memory map."""
    regions = []
    for query in (ida_idd.dbg_get_memory_info, ida_dbg.get_manual_regions):
        try:
            regions = debugger_regions(query())
        except (AttributeError, RuntimeError, TypeError, ValueError):
            pass
        if regions:
            break
    if not regions:
        modules, segments = [], []
        try:
            module = ida_idd.modinfo_t()
            more = ida_dbg.get_first_module(module)
            while more:
                modules.extend(debugger_regions([(module.base, module.base + module.size,
                                                   module.name)]))
                more = ida_dbg.get_next_module(module)
        except (AttributeError, RuntimeError, TypeError, ValueError):
            pass
        try:
            for index in range(ida_segment.get_segm_qty()):
                segment = ida_segment.getnseg(index)
                if segment is not None:
                    segments.extend(debugger_regions([(
                        segment.start_ea, segment.end_ea,
                        ida_segment.get_segm_name(segment))]))
        except (AttributeError, RuntimeError, TypeError, ValueError):
            pass
        regions = disjoint_regions(modules, segments)
    else:
        regions = disjoint_regions(regions)
    # A freshly unpacked allocation may have no IDB segment or module yet.
    if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
        focus = ida_kernwin.get_screen_ea()
        if (0 <= focus < ida_idaapi.BADADDR
                and not any(start <= focus < stop for start, stop, _ in regions)):
            page = focus & ~4095
            try:
                if ida_idd.dbg_read_memory(focus, 1) is not None:
                    regions.append((page, page + 4096, "current page"))
            except (AttributeError, RuntimeError, TypeError, ValueError):
                pass
    return sorted(regions)


def debugger_execute_permissions(regions):
    """Use only permissions supplied by debugger on this stop, never IDB guesses."""
    try:
        mappings = ida_idd.dbg_get_memory_info() or ()
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return {}
    result = {}
    for region in regions:
        matching = [item for item in mappings
                    if (getattr(item, "start_ea", -1) <= region[0]
                        and region[1] <= getattr(item, "end_ea", -1)
                        and isinstance(getattr(item, "perm", None), int))]
        if len(matching) == 1:
            result[region] = bool(matching[0].perm & ida_segment.SEGPERM_EXEC)
    return result


def collect_ida_bookmarks(file_size=None):
    """IDA listing bookmarks as file offsets, or as virtual addresses for RAM."""
    found = {}

    def add(ea, description):
        if ea is None or ea < 0 or ea == ida_idaapi.BADADDR:
            return
        if file_size is None:
            found.setdefault(ea, str(description))
        else:
            offset = ida_loader.get_fileregion_offset(ea)
            if offset is not None and 0 <= offset < file_size:
                found.setdefault(offset, str(description))

    viewers = 0
    for suffix in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        viewer = ida_kernwin.find_widget("IDA View-" + suffix)
        if viewer is None:
            continue
        viewers += 1
        try:
            for location, description in ida_moves.bookmarks_t(viewer):
                place = ida_kernwin.place_t_as_idaplace_t(location.place())
                if place is not None:
                    add(place.ea, description)
        except (AttributeError, RuntimeError, TypeError):
            continue  # Other listing types can use a non-address place_t.
    if not viewers:
        try:
            for slot in range(1024):
                ea = ida_idc.get_marked_pos(slot)
                if ea != ida_idaapi.BADADDR:
                    add(ea, ida_idc.get_mark_comment(slot) or "IDA bookmark")
        except (AttributeError, RuntimeError, TypeError, ValueError):
            pass  # Older IDA may lack legacy mark slots; listing bookmarks still work.
    return found


class RenderSignal(QtCore.QObject):
    ready = QtCore.Signal(int, object, object)
    overview_ready = QtCore.Signal(str, int, int, object)
    findings_ready = QtCore.Signal(int, object, object)
    inspection_ready = QtCore.Signal(int, object, object, object)
    inspection_focus_ready = QtCore.Signal(int, int, object, object)


class CaptureSession:
    """Debugger-stop capture survives switching sources and closing the form."""

    def __init__(self):
        self.history = SnapshotHistory()
        self.tracked_regions = set()
        self.track_rules = set()
        self.tracking_configured = False
        self.enabled = False
        self.panel = None
        self.stop_serial = 0
        self.pause_time = None
        self.stop_active = False
        self.pending_stop = False
        self.track_prompt_pending = False
        self.observed_regions = None
        self.new_regions = set()
        self.generation = 0
        self.running = False
        self.cancelled_store = None

    @staticmethod
    def region_rule(region, regions):
        start, stop, name = region
        if name in ("memory", "current page"):
            return "va", start, stop, name
        similar = [item for item in regions
                   if item[2] == name and item[1] - item[0] == stop - start]
        return "named", name, stop - start, similar.index(region)

    def resolve_tracking(self, regions):
        self.tracked_regions.intersection_update(regions)
        for region in regions:
            if self.region_rule(region, regions) in self.track_rules:
                self.tracked_regions.add(region)
        # An IDB section (e.g. .data) can be reported by the debugger under
        # its module name instead. Resolve its current rebased IDB address.
        if regions and self.track_rules:
            try:
                segments = [ida_segment.getnseg(index)
                            for index in range(ida_segment.get_segm_qty())]
                for kind, name, size, rank in self.track_rules:
                    if kind != "named":
                        continue
                    matching = [segment for segment in segments if segment is not None
                                and ida_segment.get_segm_name(segment) == name
                                and segment.end_ea - segment.start_ea == size]
                    if rank < len(matching):
                        ea = matching[rank].start_ea
                        for region in regions:
                            if region[0] <= ea < region[1]:
                                self.tracked_regions.add(region)
            except (AttributeError, RuntimeError, TypeError, ValueError):
                pass

    def track(self, region, checked, regions):
        self.tracking_configured = True
        if region not in regions:
            regions = sorted((*regions, region))
        rule = self.region_rule(region, regions)
        if checked:
            self.track_rules.add(rule)
            self.tracked_regions.add(region)
        else:
            self.track_rules.discard(rule)
            self.tracked_regions.discard(region)
        self.enabled = bool(self.track_rules)

    def configure_tracking(self, regions, selected):
        """Apply a dialog selection as one explicit tracking configuration."""
        selected = set(selected)
        self.track_rules.clear()
        self.tracked_regions.clear()
        self.tracking_configured = True
        for region in regions:
            if region in selected:
                self.track_rules.add(self.region_rule(region, regions))
                self.tracked_regions.add(region)
        self.enabled = bool(self.track_rules)
        self.track_prompt_pending = False

    def offer_track_setup(self, generation=None):
        if (generation is not None and generation != self.generation
                or not self.track_prompt_pending or self.panel is None):
            return
        regions = process_regions()
        if regions and hasattr(self.panel, "prompt_track_regions"):
            self.resolve_tracking(regions)
            self.track_prompt_pending = False
            self.panel.prompt_track_regions(regions)

    def attach(self, panel):
        self.panel = panel
        self.sync_panel()

    def detach(self, panel):
        if self.panel is panel:
            self.panel = None

    def sync_panel(self):
        panel = self.panel
        if panel is not None and not panel.closed:
            panel.stop_serial = self.stop_serial
            panel.new_regions = set(self.new_regions)

    def reset(self):
        self.generation += 1
        self.running = False
        if getattr(self, "store", None) is not None:
            self.store.stream.close()
        self.store = None
        if self.cancelled_store is not None:
            self.cancelled_store.stream.close()
            self.cancelled_store = None
        self.history.clear()
        self.tracked_regions.clear()
        self.stop_serial = 0
        self.pending_stop = False
        self.pause_time = None
        self.stop_active = False
        self.observed_regions = None
        self.new_regions.clear()
        if self.panel is not None:
            self.panel.debugger_session_reset()
            self.sync_panel()
            self.track_prompt_pending = not self.tracking_configured
            if self.track_prompt_pending:
                generation = self.generation
                QtCore.QTimer.singleShot(0, lambda: self.offer_track_setup(generation))
        else:
            self.track_prompt_pending = False

    def note_stop(self):
        if self.pending_stop:
            self.history.finish_stop(self.stop_serial, "superseded before capture began")
        if self.running:
            self.history.finish_stop(self.stop_serial, "superseded before capture completed")
            self.cancelled_store = getattr(self, "store", None)
            self.store = None
        self.generation += 1
        self.running = False
        self.stop_serial += 1
        self.pause_time = time.time()
        self.stop_active = True
        self.pending_stop = True
        self.history.begin_stop(self.stop_serial, self.pause_time, (), 0)
        return self.generation

    def stopped(self, generation=None):
        if generation is not None and generation != self.generation:
            return
        if not self.pending_stop:
            self.note_stop()
        self.pending_stop = False
        generation = self.generation
        if self.cancelled_store is not None:
            self.cancelled_store.stream.close()
            self.cancelled_store = None
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            self.history.finish_stop(self.stop_serial, "resumed before capture began")
            self.sync_panel()
            self._notify_finished()
            return
        regions = None
        if self.track_prompt_pending and self.panel is not None:
            regions = process_regions()
            if regions and hasattr(self.panel, "prompt_track_regions"):
                self.resolve_tracking(regions)
                self.track_prompt_pending = False
                self.panel.prompt_track_regions(regions)
        if not self.tracking_configured or not self.enabled:
            reason = ("tracking not configured" if not self.tracking_configured
                      else "tracking not enabled")
            self.history.finish_stop(self.stop_serial, reason)
            self.sync_panel()
            if self.panel is not None:
                self.panel.debugger_stopped()
            return
        if regions is None:
            regions = process_regions()
        self.resolve_tracking(regions)
        old = self.observed_regions
        self.new_regions = ({region for region in regions
                             if not any(start <= region[0] and region[1] <= stop
                                        for start, stop, _ in old)}
                            if old is not None else set())
        self.observed_regions = tuple(regions)
        self.execute_permissions = debugger_execute_permissions(regions)
        chosen = [region for region in regions
                  if region in self.tracked_regions or region in self.new_regions]
        chosen.sort(key=lambda region: region not in self.new_regions)
        remaining, jobs = MAX_PAUSE_BYTES, []
        for region in chosen:
            start, stop, _ = region
            if remaining < min(MAX_CAPTURE_WINDOW, stop - start):
                continue
            previous = self.history.for_region(region)
            if stop - start > remaining:
                recent = previous[0] if previous else None
                if recent is not None and start <= recent.start < recent.stop <= stop:
                    windows = [(recent.start, recent.stop)]
                else:
                    windows = [snapshot_bounds(region, ida_kernwin.get_screen_ea(),
                                               min(MAX_CAPTURE_WINDOW, remaining))]
            else:
                windows = [(low, min(stop, low + MAX_CAPTURE_WINDOW))
                           for low in range(start, stop, MAX_CAPTURE_WINDOW)]
            for low, high in windows:
                jobs.append((low, high, region))
                remaining -= high - low
        self.history.begin_stop(self.stop_serial, self.pause_time, chosen, len(jobs))
        self.sync_panel()
        if self.panel is not None:
            self.panel.debugger_stopped()
        self.jobs = iter(jobs)
        self.running = bool(jobs)
        if jobs:
            self._start_job(generation)
        else:
            self.history.finish_stop(self.stop_serial, "no tracked regions available")
            self._notify_finished()

    def _start_job(self, generation):
        if generation != self.generation:
            return
        try:
            low, high, self.mapping = next(self.jobs)
        except StopIteration:
            self.running = False
            self.store = None
            self.history.finish_stop(self.stop_serial)
            self._notify_finished()
            return
        try:
            self.store = DiskSnapshotStore(high - low)
        except OSError as exc:
            self._abort(f"storage failed: {exc}")
            return
        self.bounds = low, high
        self.missing = 0
        self.iterator = iter_memory_chunks(ida_idd.dbg_read_memory, low, high - low)
        QtCore.QTimer.singleShot(0, lambda: self._step(generation))

    def _step(self, generation):
        if generation != self.generation:
            return
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            self._abort("resumed before capture completed")
            return
        store = self.store
        try:
            offset, data, valid = next(self.iterator)
        except StopIteration:
            if generation != self.generation:
                return
            low, high = self.bounds
            data, valid = store.views()
            snapshot = MemorySnapshot(low, data, valid, self.mapping[2],
                                       self.stop_serial, self.pause_time, self.mapping,
                                       self.mapping in self.new_regions, self.missing,
                                       self.execute_permissions.get(self.mapping))
            self.history.add(snapshot)
            self.store = None  # Completed views own the temporary file.
            if self.panel is not None:
                self.panel.debugger_capture_completed(snapshot)
            QtCore.QTimer.singleShot(0, lambda: self._start_job(generation))
            return
        except (OSError, RuntimeError, ValueError) as exc:
            if generation == self.generation:
                self._abort(f"debugger read failed: {exc}")
            return
        if generation != self.generation:
            return
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            self._abort("resumed during capture")
            return
        self.missing += valid.count(0)
        try:
            store.write(offset, data, valid)
        except OSError as exc:
            self._abort(f"storage failed: {exc}")
            return
        QtCore.QTimer.singleShot(0, lambda: self._step(generation))

    def _abort(self, reason):
        self.running = False
        if getattr(self, "store", None) is not None:
            self.store.stream.close()
        self.store = None
        self.history.finish_stop(self.stop_serial, reason)
        self._notify_finished()

    def _notify_finished(self):
        if self.panel is not None:
            self.panel.debugger_capture_finished()

    def exited(self):
        if self.running:
            self._abort("process exited before capture completed")
        self.generation += 1
        if self.cancelled_store is not None:
            self.cancelled_store.stream.close()
            self.cancelled_store = None
        if self.pending_stop:
            self.history.finish_stop(self.stop_serial, "process exited before capture began")
            self.pending_stop = False
        self.stop_active = False
        self.sync_panel()
