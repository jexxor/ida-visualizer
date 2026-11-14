"""Entropy range slider."""

from PySide6 import QtCore, QtGui, QtWidgets
from visualizer_core import clamp_range, move_range
from visualizer_ui.constants import TITLE
from visualizer_ui.widget_common import wheel_units

class EntropySlider(QtWidgets.QWidget):
    """Compact horizontal entropy range with narrow resize handles."""

    rangeChanged = QtCore.Signal(object, object, bool)  # Preserve 64-bit offsets.

    def __init__(self, minimum, maximum, low, high, parent):
        super().__init__(parent)
        self.minimum, self.maximum = minimum, maximum
        self.low, self.high = clamp_range(low, high, minimum, maximum)
        self.image = None
        self.cursor_offset = None  # Only File slider receives IDA's current location.
        self.address_kind = "File"
        self.drag = None
        self.anchor = None
        self.drag_offset = 0
        self.setFixedHeight(36)
        self.setMinimumWidth(220)
        self.setMaximumWidth(620)
        self.setMouseTracking(True)
        self.setToolTip("Drag thin handles: resize · Drag selection: pan · Wheel: zoom")

    def set_range(self, low, high, minimum=None, maximum=None):
        if minimum is not None:
            self.minimum = minimum
        if maximum is not None:
            self.maximum = maximum
        self.low, self.high = clamp_range(low, high, self.minimum, self.maximum)
        self.setToolTip(f"0x{self.low:X}–0x{self.high:X} ({self.high - self.low:,} bytes)")
        self.update()

    def _track(self):
        return max(1, self.width() - 24)

    def _x(self, value):
        return 12 + (value - self.minimum) * self._track() // (self.maximum - self.minimum)

    def _value(self, x):
        pixel = max(0, min(self._track(), int(x) - 12))
        return self.minimum + pixel * (self.maximum - self.minimum) // self._track()

    def _handles(self):
        return self._x(self.low), self._x(self.high)

    def _set(self, low, high, adjusting):
        low, high = clamp_range(low, high, self.minimum, self.maximum)
        if (low, high) != (self.low, self.high):
            self.low, self.high = low, high
            self.setToolTip(f"0x{low:X}–0x{high:X} ({high - low:,} bytes)")
            self.rangeChanged.emit(low, high, adjusting)
            self.update()

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.fillRect(self.rect(), QtGui.QColor(25, 25, 25))
        track = QtCore.QRect(12, 6, self._track(), self.height() - 12)
        if self.image is not None:
            painter.setRenderHint(QtGui.QPainter.RenderHint.SmoothPixmapTransform, False)
            painter.drawImage(track, self.image)
        else:
            painter.fillRect(track, QtGui.QColor(65, 70, 78))
        low, high = self._handles()
        painter.setPen(QtCore.Qt.PenStyle.NoPen)
        painter.fillRect(QtCore.QRect(low, track.y(), max(1, high - low), track.height()),
                         QtGui.QColor(55, 155, 225, 65))
        painter.setBrush(QtGui.QColor(255, 213, 83))
        mid = self.height() // 2
        if high - low < 14:
            # Short staggered grips remain distinct when positions overlap.
            painter.drawRoundedRect(QtCore.QRect(low - 3, mid - 11, 6, 10), 2, 2)
            painter.drawRoundedRect(QtCore.QRect(high - 3, mid + 1, 6, 10), 2, 2)
        else:
            for x in (low, high):
                painter.drawRoundedRect(QtCore.QRect(x - 2, mid - 7, 4, 14), 1, 1)
        if self.cursor_offset is not None and self.minimum <= self.cursor_offset < self.maximum:
            marker_x = self._x(self.cursor_offset)
            painter.setPen(QtGui.QPen(QtGui.QColor(35, 245, 230), 1))
            painter.drawLine(marker_x, track.y(), marker_x, track.y() + track.height())
        painter.end()

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.RightButton:
            self.parent().slider_menu(self, event.globalPosition().toPoint())
            return
        if event.button() != QtCore.Qt.MouseButton.LeftButton:
            return
        x = event.position().x()
        low, high = self._handles()
        near_low, near_high = abs(x - low) <= 7, abs(x - high) <= 7
        if near_low and near_high:
            self.drag = "low" if event.position().y() < self.height() // 2 else "high"
            self.drag_offset = (self.low if self.drag == "low" else self.high) - self._value(x)
        elif near_low:
            self.drag = "low"
            self.drag_offset = self.low - self._value(x)
        elif near_high:
            self.drag = "high"
            self.drag_offset = self.high - self._value(x)
        else:
            self.drag = "move"
            if not low <= x <= high:
                center = self._value(x)
                self._set(*move_range(self.low, self.high,
                                      center - (self.low + self.high) // 2,
                                      self.minimum, self.maximum), adjusting=True)
        self.anchor = self._value(x), self.low, self.high

    def mouseMoveEvent(self, event):
        if self.drag is None:
            self.setToolTip(f"{self.address_kind} 0x{self._value(event.position().x()):X}")
            return
        value = self._value(event.position().x())
        origin, low, high = self.anchor
        if self.drag == "low":
            self._set(min(value + self.drag_offset, self.high - 1), self.high, True)
        elif self.drag == "high":
            self._set(self.low, max(value + self.drag_offset, self.low + 1), True)
        else:
            self._set(*move_range(low, high, value - origin,
                                  self.minimum, self.maximum), adjusting=True)

    def mouseReleaseEvent(self, event):
        if self.drag is not None:
            self.drag = None
            self.rangeChanged.emit(self.low, self.high, False)

    def wheelEvent(self, event):
        units = wheel_units(event)
        if units:
            self.parent().wheel_zoom(self._value(event.position().x()), units,
                                     absolute=self is not self.parent().relative_slider)
            event.accept()

    def mouseDoubleClickEvent(self, event):
        self._ask_range()

    def _ask_range(self):
        is_relative = self is self.parent().relative_slider
        minimum, maximum = (self.parent().absolute_range if is_relative
                            else (self.minimum, self.maximum))
        text, accepted = QtWidgets.QInputDialog.getText(
            self, "Visualizer range", "Start:End (hex, end exclusive):",
            text=f"{self.low:X}:{self.high:X}")
        if accepted:
            try:
                low, high = (int(part.strip().removeprefix("0x"), 16)
                             for part in text.split(":"))
                if not minimum <= low < high <= maximum:
                    raise ValueError()
            except ValueError:
                QtWidgets.QMessageBox.warning(self, TITLE, "Invalid hexadecimal range")
                return
            if is_relative:
                self.parent()._set_relative(low, high)
            else:
                self._set(low, high, False)
