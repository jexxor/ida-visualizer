"""Interactive Hilbert map canvas."""

import ida_kernwin

from PySide6 import QtCore, QtGui, QtWidgets
from visualizer_core import (
    Frame,
    GlobalFrame,
    curve_index_for_offset,
    curve_point_at,
    global_bookmark_position,
    global_hit,
    offset_at,
)
from visualizer_ui.widget_common import wheel_units

class MapCanvas(QtWidgets.QWidget):
    def __init__(self, panel):
        super().__init__(panel)
        self.panel = panel
        self.frame = None
        self.image = None
        self.unmapped_overlay = None
        self.delta_overlay = None
        self.inspection_overlay = None
        self.inspection_overlay_frame = None
        self.cursor_offset = None
        self.hover_offset = None
        self.bookmark_points = []
        self.change_points = []
        self.finding_point = None
        self.finding_frame = None
        self.setMinimumSize(256, 256)
        self.setMouseTracking(True)
        self.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding,
                           QtWidgets.QSizePolicy.Policy.Expanding)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if (getattr(self.panel, "ui_ready", False) and self.frame is not None
                and self.frame.side != self.panel.render_side()):
            self.panel.queue_render()

    def _rect(self):
        size = min(self.width(), self.height())
        return QtCore.QRect((self.width() - size) // 2,
                            (self.height() - size) // 2, size, size)

    def _offset(self, position):
        frame, rect = self.frame, self._rect()
        if frame is None or not rect.contains(position):
            return None
        x = min(frame.side - 1, (position.x() - rect.x()) * frame.side // rect.width())
        y = min(frame.side - 1, (position.y() - rect.y()) * frame.side // rect.height())
        if isinstance(frame, GlobalFrame):
            return global_hit(frame, x, y)
        return offset_at(frame, x, y)

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.fillRect(self.rect(), QtGui.QColor(20, 20, 20))
        rect = self._rect()
        if self.image is not None:
            painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform, False)
            painter.drawImage(rect, self.image)
        if self.unmapped_overlay is not None:
            painter.drawImage(rect, self.unmapped_overlay)
        if self.delta_overlay is not None:
            painter.drawImage(rect, self.delta_overlay)
        if self.inspection_overlay is not None and self.inspection_overlay_frame is self.frame:
            painter.drawImage(rect, self.inspection_overlay)
        frame = self.frame
        if frame is not None and getattr(self, "change_points", ()):
            scale = rect.width() / frame.side
            painter.setPen(QtGui.QPen(QtGui.QColor(20, 25, 29), 2))
            painter.setBrush(QtGui.QColor(255, 224, 100))
            for px, py, _, _ in self.change_points:
                painter.drawEllipse(QtCore.QPointF(rect.x() + (px + 0.5) * scale,
                                                   rect.y() + (py + 0.5) * scale), 5, 5)
        if frame is getattr(self, "finding_frame", None) and getattr(self, "finding_point", None):
            px, py, _, _ = self.finding_point
            scale = rect.width() / frame.side
            painter.setPen(QtGui.QPen(QtGui.QColor("#FFFFFF"), 2))
            painter.setBrush(QtCore.Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QtCore.QPointF(rect.x() + (px + 0.5) * scale,
                                               rect.y() + (py + 0.5) * scale), 8, 8)
        if frame and self.bookmark_points:
            scale = rect.width() / frame.side
            painter.setPen(QtGui.QPen(QtGui.QColor(20, 20, 20), 1))
            painter.setBrush(QtGui.QColor(255, 168, 43))
            for px, py, _, _ in self.bookmark_points:
                painter.drawEllipse(QtCore.QPointF(rect.x() + (px + 0.5) * scale,
                                                   rect.y() + (py + 0.5) * scale), 3, 3)
        if (frame and not isinstance(frame, GlobalFrame) and self.cursor_offset is not None
                and frame.start <= self.cursor_offset < frame.stop):
            index = curve_index_for_offset(frame, self.cursor_offset)
            x_index, y_index = curve_point_at(frame.side, index)
            scale = rect.width() / frame.side
            x = rect.x() + (x_index + 0.5) * scale
            y = rect.y() + (y_index + 0.5) * scale
            painter.setPen(QtGui.QPen(QtGui.QColor(255, 230, 85), 2))
            painter.setBrush(QtCore.Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QtCore.QPointF(x, y), 6, 6)
        painter.end()

    def set_bookmarks(self, bookmarks):
        frame = self.frame
        points = []
        if isinstance(frame, GlobalFrame):
            for address, desc in bookmarks.items():
                mapped = global_bookmark_position(frame, address)
                if mapped is not None:
                    _, (x, y) = mapped
                    points.append((x, y, address, desc))
        elif frame is not None:
            for offset, desc in bookmarks.items():
                if frame.start <= offset < frame.stop:
                    index = curve_index_for_offset(frame, offset)
                    x, y = curve_point_at(frame.side, index)
                    points.append((x, y, offset, desc))
        self.bookmark_points = points
        self.update()

    def set_changes(self, frame):
        points = []
        if isinstance(frame, GlobalFrame):
            for region_index, address in frame.change_marks:
                snapshot = frame.regions[region_index][2]
                mapped = global_bookmark_position(frame, address)
                if mapped is not None:
                    x, y = mapped[1]
                    points.append((x, y, snapshot, address))
        elif isinstance(frame, Frame) and frame.first_change is not None:
            index = curve_index_for_offset(frame, frame.first_change)
            x, y = curve_point_at(frame.side, index)
            points.append((x, y, self.panel.snapshot, frame.first_change))
        self.change_points = points
        self.update()

    def set_finding(self, finding):
        frame = self.frame
        point = None
        if finding is not None and isinstance(frame, GlobalFrame) and finding.source == "RAM":
            mapped = global_bookmark_position(frame, finding.address)
            if mapped is not None and mapped[0] is finding.snapshot:
                point = (*mapped[1], finding.address, finding.snapshot)
        elif finding is not None and isinstance(frame, Frame) and frame.start <= finding.address < frame.stop:
            if (finding.source == "File" and self.panel.mode == "File"
                    or finding.source == "RAM" and self.panel.snapshot is finding.snapshot
                    and self.panel.mode != "File"):
                index = curve_index_for_offset(frame, finding.address)
                point = (*curve_point_at(frame.side, index), finding.address, finding.snapshot)
        self.finding_point = point
        self.finding_frame = frame
        self.update()

    def _finding_near(self, pos):
        if (getattr(self, "frame", None) is None
                or self.frame is not getattr(self, "finding_frame", None)
                or not getattr(self, "finding_point", None)):
            return None
        rect = self._rect()
        scale = rect.width() / self.frame.side
        px, py, address, snapshot = self.finding_point
        x, y = rect.x() + (px + 0.5) * scale, rect.y() + (py + 0.5) * scale
        return (address, snapshot) if (pos.x() - x) ** 2 + (pos.y() - y) ** 2 <= 100 else None

    def _change_near(self, pos):
        if getattr(self, "frame", None) is None or not getattr(self, "change_points", ()):
            return None
        rect = self._rect()
        scale = rect.width() / self.frame.side
        for px, py, snapshot, address in self.change_points:
            x = rect.x() + (px + 0.5) * scale
            y = rect.y() + (py + 0.5) * scale
            if (pos.x() - x) ** 2 + (pos.y() - y) ** 2 <= 100:
                return snapshot, address
        return None

    def _bookmark_near(self, pos):
        if self.frame is None or not self.bookmark_points:
            return None
        rect = self._rect()
        scale = rect.width() / self.frame.side
        for px, py, offset, desc in self.bookmark_points:
            x = rect.x() + (px + 0.5) * scale
            y = rect.y() + (py + 0.5) * scale
            if (pos.x() - x) ** 2 + (pos.y() - y) ** 2 <= 64:
                return offset, desc
        return None

    def mouseMoveEvent(self, event):
        pos = event.position().toPoint()
        offset = self._offset(pos)
        if self.panel.global_mode:
            changed = self._change_near(pos)
            bookmark = self._bookmark_near(pos)
            finding = self._finding_near(pos)
            if changed is not None:
                self.panel.status.setText(f"Changed byte · VA 0x{changed[1]:X}"
                                          " · click for exact detail")
            elif bookmark is not None:
                self.panel.status.setText(f"IDA bookmark: {bookmark[1]} · VA 0x{bookmark[0]:X}")
            elif finding is not None:
                self.panel.status.setText(f"Selected finding · VA 0x{finding[0]:X}"
                                          " · click for exact detail")
            elif offset is None:
                self.panel.status.setText("Global map · gap between captured regions")
            else:
                self.panel.show_global_hit(offset)
            return
        changed = self._change_near(pos)
        if offset is not None or changed is not None:
            finding = self._finding_near(pos)
            self.hover_offset = (finding[0] if finding is not None else
                                 changed[1] if changed is not None else offset)
            bookmark = self._bookmark_near(pos)
            if bookmark is not None:
                bookmarked_offset, desc = bookmark
                self.hover_offset = bookmarked_offset
                location = (f"File+0x{bookmarked_offset:X}" if self.panel.mode == "File"
                            else f"VA 0x{bookmarked_offset:X}")
                self.panel.status.setText(f"IDA bookmark: {desc} · {location}")
                return
            if finding is not None:
                self.panel.status.setText(f"Selected finding · "
                                          f"{('File+' if self.panel.mode == 'File' else 'VA ')}"
                                          f"0x{finding[0]:X} · click for exact detail")
                return
            if changed is not None:
                self.panel.status.setText(f"Verified changed byte · VA 0x{changed[1]:X}"
                                          " · click for exact detail")
                return
            self.panel.show_offset(offset)

    def mousePressEvent(self, event):
        pos = event.position().toPoint()
        bookmark = self._bookmark_near(pos)
        finding = self._finding_near(pos)
        changed = self._change_near(pos)
        offset = self._offset(pos)
        if self.panel.global_mode:
            if event.button() == QtCore.Qt.MouseButton.LeftButton:
                changed = self._change_near(pos)
                if changed is not None:
                    self.panel.open_global_hit(changed)
                elif bookmark is not None:
                    mapped = global_bookmark_position(self.frame, bookmark[0])
                    if mapped is not None:
                        self.panel.open_global_hit((mapped[0], bookmark[0]))
                elif finding is not None:
                    self.panel.open_global_hit((finding[1], finding[0]))
                    if hasattr(self.panel, "_select_finding_at"):
                        self.panel._select_finding_at(finding[0], finding[1])
                elif offset is not None:
                    self.panel.open_global_hit(offset)
                    if hasattr(self.panel, "_select_finding_at"):
                        self.panel._select_finding_at(offset[1], offset[0])
            return
        if offset is None and finding is None and changed is None:
            return
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            selected = (bookmark[0] if bookmark else finding[0] if finding else
                        changed[1] if changed else offset)
            if bookmark is not None and self.panel.mode != "File":
                if ida_kernwin.jumpto(selected):
                    self.panel.show_offset(selected)
                else:
                    self.panel.show_raw(selected)
            else:
                self.panel.jump_to_offset(selected)
            if self.panel.inspector_button.isChecked():
                self.panel.inspect_offset(selected)
            if (getattr(self.panel, "diff_button", None) is not None
                    and self.panel.diff_button.isChecked()):
                self.panel.diff_address = selected
                self.panel._refresh_byte_diff()
            if hasattr(self.panel, "_select_finding_at"):
                self.panel._select_finding_at(selected, None if self.panel.mode == "File"
                                               else self.panel.snapshot)
        elif event.button() == QtCore.Qt.MouseButton.RightButton:
            menu = QtWidgets.QMenu(self)
            zoom_in = menu.addAction("Zoom in here")
            zoom_out = menu.addAction("Zoom out here")
            action = menu.exec(event.globalPosition().toPoint())
            if action == zoom_in:
                self.panel.zoom_at(offset, True)
            elif action == zoom_out:
                self.panel.zoom_at(offset, False)

    def wheelEvent(self, event):
        if self.panel.global_mode:
            event.ignore()
            return
        offset = self._offset(event.position().toPoint())
        units = wheel_units(event)
        if offset is not None and units:
            self.panel.wheel_zoom(offset, units)
            event.accept()
        else:
            super().wheelEvent(event)
