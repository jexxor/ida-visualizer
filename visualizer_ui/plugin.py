"""IDA hooks and plugin lifecycle."""

import ida_dbg
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_nalt

from PySide6 import QtCore
from pathlib import Path
from visualizer_ui.constants import TITLE
from visualizer_ui.panel import VisualizerForm
from visualizer_ui.session import CaptureSession

class CursorHook(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def screen_ea_changed(self, ea, prev_ea):
        form = self.plugin.form
        if form and form.panel:
            current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) == form.idb_path
            panel = form.panel
            if panel.mode == "File":
                offset = ida_loader.get_fileregion_offset(ea) if current else -1
                cursor_offset = offset if current and 0 <= offset < panel.file_size else None
            else:
                snapshot = panel._current_snapshot()
                cursor_offset = (ea if current and snapshot is not None
                                 and snapshot.start <= ea < snapshot.stop else None)
            form.panel.canvas.cursor_offset = cursor_offset
            form.panel.absolute_slider.cursor_offset = cursor_offset
            form.panel.absolute_slider.update()
            if not current:
                form.panel.outline_generation += 1
                form.panel.canvas.unmapped_overlay = None
                form.panel.bookmarks = {}
                form.panel.bookmarks_loaded = False
                form.panel.canvas.set_bookmarks({})
            elif not getattr(panel, "bookmarks_loaded", True):
                panel.bookmark_refresh.start(0)
            form.panel.canvas.update()


class DatabaseHook(ida_idp.IDB_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def bookmark_changed(self, index, pos, desc, op):
        form = self.plugin.form
        if form and form.panel:
            form.panel.bookmark_refresh.start(0)  # Query IDA after its update completes.
        return 0

    def _segments_changed(self):
        form = self.plugin.form
        if form and form.panel:
            form.panel.outline_refresh.start(0)
        return 0

    def segm_added(self, segment):
        return self._segments_changed()

    def segm_deleted(self, start_ea, end_ea, flags):
        return self._segments_changed()

    def segm_start_changed(self, segment, old_start):
        return self._segments_changed()

    def segm_end_changed(self, segment, old_end):
        return self._segments_changed()

    def allsegs_moved(self, info):
        return self._segments_changed()


class DebugHook(ida_dbg.DBG_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def dbg_suspend_process(self):
        generation = self.plugin.session.note_stop()
        QtCore.QTimer.singleShot(0, lambda: self.plugin.session.stopped(generation))

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.plugin.session.reset()

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.dbg_process_start(pid, tid, ea, name, base, size)

    def dbg_process_exit(self, pid, tid, ea, code):
        self.plugin.session.exited()

    def dbg_process_detach(self, pid, tid, ea):
        self.dbg_process_exit(pid, tid, ea, 0)


class VisualizerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Entropy Hilbert map of original file bytes"
    help = "Entropy map with native C++ renderer and two linked entropy sliders"
    wanted_name = TITLE
    wanted_hotkey = "Ctrl-Alt-V"

    def init(self):
        self.form = None
        self.session = CaptureSession()
        self.hooks = CursorHook(self)
        self.hooks.hook()
        self.database_hooks = DatabaseHook(self)
        self.database_hooks.hook()
        self.debug_hooks = DebugHook(self)
        self.debug_hooks.hook()
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        path = ida_nalt.get_input_file_path()
        if not path or not Path(path).is_file():
            path = ida_kernwin.ask_file(0, "*", "Select original binary for Visualizer")
        if not path or not Path(path).is_file() or not Path(path).stat().st_size:
            ida_kernwin.warning("Visualizer needs a nonempty input binary")
            return
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or path
        if self.form and (self.form.path != path or self.form.idb_path != idb_path):
            if self.form.panel:
                self.form.Close(0)
            self.session.exited()
            self.session = CaptureSession()
            self.form = None
        if not self.form or not self.form.panel:
            self.form = VisualizerForm(path, idb_path, self.session)
        self.form.Show(TITLE, options=ida_kernwin.PluginForm.WOPN_PERSIST)

    def term(self):
        self.session.exited()
        self.debug_hooks.unhook()
        self.database_hooks.unhook()
        self.hooks.unhook()
        if self.form and self.form.panel:
            self.form.Close(0)


def PLUGIN_ENTRY():
    return VisualizerPlugin()
