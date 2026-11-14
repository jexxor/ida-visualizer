"""Byte histogram and difference views."""

import math

from PySide6 import QtCore, QtGui, QtWidgets
from collections import Counter
from visualizer_core import (
    CHANGED,
    UNCOMPARABLE,
    UNREADABLE,
    byte_diff_state,
)
from visualizer_ui.widget_common import data_color, view_colors, visual_ink

class ByteHistogram(QtWidgets.QWidget):
    """Log-scaled byte frequencies (0x00 to 0xFF), not map colors."""

    byteClicked = QtCore.Signal(int)

    def __init__(self, parent):
        super().__init__(parent)
        self.bins = (0,) * 256
        self.selected_byte = None
        self.setMinimumWidth(256)
        self.setFixedHeight(60)
        self.setToolTip("Byte frequency by value 00–FF · logarithmic height")

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        background, text, _, highlight = view_colors(self)
        painter.fillRect(self.rect(), background)
        peak = max(self.bins)
        if peak:
            painter.setPen(data_color("#5ACCE6", background))
            scale = math.log1p(peak)
            for value, count in enumerate(self.bins):
                if count:
                    x = value * (self.width() - 1) // 255
                    bar = max(1, round(math.log1p(count) / scale * (self.height() - 4)))
                    painter.drawLine(x, self.height() - 2, x, self.height() - 2 - bar)
        if self.selected_byte is not None:
            x = self.selected_byte * (self.width() - 1) // 255
            painter.setPen(QtGui.QPen(highlight if highlight != background else text, 2))
            painter.drawLine(x, 0, x, self.height() - 1)
        painter.end()

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            x = event.position().x()
            if 0 <= x < self.width():
                value = min(255, max(0, round(x * 255 / max(1, self.width() - 1))))
                self.selected_byte = value
                self.update()
                self.byteClicked.emit(value)
                event.accept()
                return
        super().mousePressEvent(event)


class DiffHexView(QtWidgets.QTextBrowser):
    """Keep keyboard navigation on the selected byte, not Qt's text cursor."""

    byteMoved = QtCore.Signal(int)

    def keyPressEvent(self, event):
        if event.modifiers() == QtCore.Qt.KeyboardModifier.NoModifier:
            steps = {QtCore.Qt.Key.Key_Left: -1, QtCore.Qt.Key.Key_Right: 1,
                     QtCore.Qt.Key.Key_Up: -16, QtCore.Qt.Key.Key_Down: 16}
            step = steps.get(event.key())
            if step is not None:
                self.byteMoved.emit(step)
                event.accept()
                return
        super().keyPressEvent(event)


class DiffRibbon(QtWidgets.QWidget):
    """Exact byte states; hover previews VA, drag scrubs, release selects."""

    byteClicked = QtCore.Signal(object)  # Python VA may exceed Qt's signed 32-bit int.
    byteHovered = QtCore.Signal(object)

    def __init__(self, parent):
        super().__init__(parent)
        self.window = None
        self.states = ()
        self.hover_index = None
        self.preview_index = None
        self.dragging = False
        self.setMinimumHeight(50)
        self.setMouseTracking(True)

    def set_window(self, window):
        self.window = window
        self.states = (tuple(byte_diff_state(window, index)
                             for index in range(window.stop - window.start))
                       if window is not None else ())
        self.hover_index = self.preview_index = None
        self.dragging = False
        if window is None:
            self.unsetCursor()
        else:
            self.setCursor(QtCore.Qt.CursorShape.PointingHandCursor)
        self.update()

    def _bucket(self, x):
        if self.window is None:
            return None
        x = int(x)  # QMouseEvent.position() is QPointF, even at integral screen pixels.
        width = max(1, self.width() - 16)
        if not 8 <= x < 8 + width:
            return None
        length = len(self.states)
        start = min(length - 1, (x - 8) * length // width)
        stop = min(length, max(start + 1, (x - 7) * length // width))
        return start, stop

    def _index_at(self, x):
        bucket = self._bucket(max(8, min(x, self.width() - 9)))
        if bucket is None:
            return None
        start, stop = bucket
        return next(index for state in ("changed", "unread", "no baseline", "same")
                    for index in range(start, stop) if self.states[index] == state)

    def _preview(self, index, force=False):
        if force or index != self.hover_index:
            self.hover_index = index
            self.byteHovered.emit(self.window.start + index if index is not None else None)
            self.update()

    def mouseMoveEvent(self, event):
        bucket = self._bucket(event.position().x())
        if self.dragging and self.window is not None:
            self.preview_index = self._index_at(event.position().x())
            self._preview(self.preview_index)
            event.accept()
            return
        if bucket is not None:
            start, stop = bucket
            counts = Counter(self.states[start:stop])
            self.setToolTip(
                f"VA 0x{self.window.start + start:X}–0x{self.window.start + stop - 1:X}"
                + " · " + " · ".join(f"{state}: {counts[state]}" for state in
                                      ("changed", "unread", "no baseline", "same") if counts[state]))
            self._preview(self._index_at(event.position().x()))
            event.accept()
            return
        if self.window is not None:
            self._preview(None)
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        if self.window is not None and event.button() == QtCore.Qt.MouseButton.LeftButton:
            self.dragging = True
            self.preview_index = self._index_at(event.position().x())
            self._preview(self.preview_index, force=True)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        if self.dragging and event.button() == QtCore.Qt.MouseButton.LeftButton:
            index = self._index_at(event.position().x()) if self.window is not None else None
            self.dragging = False
            self.preview_index = None
            if index is not None:
                self.byteClicked.emit(self.window.start + index)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def leaveEvent(self, event):
        if self.window is not None and not self.dragging:
            self._preview(None)
        super().leaveEvent(event)

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        background, text, base, highlight = view_colors(self)
        painter.fillRect(self.rect(), background)
        if self.window is None:
            painter.setPen(text)
            painter.drawText(8, 18, "Open a delta region to compare captured bytes")
            painter.end()
            return
        length, width = len(self.states), max(1, self.width() - 16)
        painter.setPen(text)
        painter.drawText(8, 15, f"0x{self.window.start:X}")
        last = f"0x{self.window.stop - 1:X}"
        painter.drawText(max(8, self.width() - 8 - painter.fontMetrics().horizontalAdvance(last)),
                         15, last)
        painter.fillRect(8, 22, width, 13,
                         visual_ink(text, 35) if base == background else base)
        colors = {"changed": f"#{CHANGED & 0xFFFFFF:06X}",
                  "unread": f"#{UNREADABLE & 0xFFFFFF:06X}",
                  "no baseline": f"#{UNCOMPARABLE & 0xFFFFFF:06X}"}
        for x in range(width):
            start = min(length - 1, x * length // width)
            stop = min(length, max(start + 1, (x + 1) * length // width))
            states = set(self.states[start:stop])
            for state in ("changed", "unread", "no baseline"):
                if state in states:
                    painter.fillRect(8 + x, 22, 1, 13, data_color(colors[state], background))
                    break
            if len(states) > 1:
                painter.fillRect(8 + x, 30, 1, 5, visual_ink(text, 170))
        focus_x = 8 + (self.window.focus - self.window.start) * width // length
        painter.setPen(QtGui.QPen(highlight, 2))
        painter.drawLine(focus_x, 19, focus_x, 39)
        active = self.preview_index if self.dragging else self.hover_index
        if active is not None:
            hover_x = 8 + active * width // length
            painter.fillRect(hover_x - 2, 20, 5, 17, visual_ink(highlight, 65))
            painter.setPen(QtGui.QPen(text, 1))
            painter.drawLine(hover_x, 18, hover_x, 40)
        painter.end()
