"""Byte inspection profile."""

import math

from PySide6 import QtCore, QtGui, QtWidgets
from visualizer_ui.widget_common import data_color, view_colors, visual_ink

def inspection_profile_data(info):
    """Four nested exact windows and disjoint byte categories on the largest one."""
    windows = tuple((name, actual, known, entropy,
                     min(8, math.log2(known)) if known else 0, bounds)
                    for (name, (requested, actual, known, entropy), bounds) in zip(
                        ("32 B", "4 KiB", "64 KiB", "1 MiB"), info.scales, info.ranges))
    other = info.readable - info.zeros - info.text - info.high_bit
    categories = (("00", info.zeros), ("Text", info.text),
                  ("80–FF", info.high_bit), ("Other", other),
                  ("Not read", info.examined - info.readable))
    return windows, categories


class InspectionProfile(QtWidgets.QWidget):
    """Small-multiple exact byte statistics; map colors keep their own meaning."""

    scaleClicked = QtCore.Signal(int)
    COLORS = ("#FF9AD5", "#8EA7FF", "#FFF0A2", "#65D8BB")
    CATEGORIES = ("#92A5B8", "#73CEA2", "#BC92DF", "#53647A", "#7B858F")

    def __init__(self, parent):
        super().__init__(parent)
        self.info = None
        self.highlighted = (0, 0, 0, 0)
        self.selected_scale = None
        self.expect_comparison = False
        self.setMinimumHeight(282)
        self.setToolTip("Click a scale to show the measured windows on the map")

    def set_inspection(self, info, highlighted=(0, 0, 0, 0), expect_comparison=False):
        self.info = info
        self.highlighted = highlighted
        self.selected_scale = None
        self.expect_comparison = expect_comparison
        self.update()

    def mousePressEvent(self, event):
        row = int((event.position().y() - 26) // 37)
        if (self.info is not None and event.button() == QtCore.Qt.MouseButton.LeftButton
                and 0 <= row < 4 and 26 <= event.position().y() < 174):
            self.selected_scale = row
            self.update()
            self.scaleClicked.emit(row)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        row = int((event.position().y() - 26) // 37)
        if self.info is not None and 0 <= row < 4 and 26 <= event.position().y() < 174:
            name, actual, known, entropy, ceiling, (low, high) = inspection_profile_data(
                self.info)[0][row]
            self.setToolTip(f"{name} · 0x{low:X}–0x{high - 1:X}"
                            f" · {known:,}/{actual:,} readable · H {entropy if entropy is not None else 'n/a'}"
                            f" / cap {ceiling:.2f} · {self.highlighted[row]:,} map pixels")
        elif self.info is not None and 188 <= event.position().y() < 230:
            categories = inspection_profile_data(self.info)[1]
            self.setToolTip("Exact largest window · " + " · ".join(
                f"{name}: {count:,} B" for name, count in categories))
        elif self.info is not None and self.info.comparison is not None:
            comp = self.info.comparison
            self.setToolTip(f"{comp.changed:,}/{comp.comparable:,} valid paired bytes differ"
                            f" across {self.info.examined:,} inspected B bytes")
        else:
            self.setToolTip("Click a scale to highlight its measured windows")
        super().mouseMoveEvent(event)

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        background, text, base, highlight = view_colors(self)
        muted = visual_ink(text, 175)
        track = visual_ink(text, 38) if base == background else base
        painter.fillRect(self.rect(), background)
        if self.info is None:
            painter.setPen(muted)
            painter.drawText(10, 28, "Click a map byte to see its visual profile")
            painter.end()
            return
        windows, categories = inspection_profile_data(self.info)
        x, width = 75, max(16, self.width() - 190)
        painter.setPen(text)
        painter.drawText(x, 17, "Shannon H · 0–8 bits/byte")
        for index, (label, actual, known, entropy, ceiling, bounds) in enumerate(windows):
            top = 26 + index * 37
            color = data_color(self.COLORS[index], background)
            if self.selected_scale == index:
                painter.fillRect(2, top - 2, self.width() - 4, 34, visual_ink(highlight, 45))
            painter.setPen(color)
            painter.drawText(7, top + 11, label)
            painter.fillRect(x, top, width, 12, track)
            if entropy is not None:
                painter.fillRect(x, top, round(width * entropy / 8), 12, color)
            if 0 < ceiling < 8:
                painter.setPen(QtGui.QPen(text, 1))
                limit = x + round(width * ceiling / 8)
                painter.drawLine(limit, top - 2, limit, top + 13)
            painter.setPen(text)
            painter.drawText(x + width + 6, top + 11,
                             f"{entropy:.2f}/{ceiling:.2f}" if entropy is not None else "n/a")
            painter.fillRect(x, top + 17, width, 4, track)
            painter.fillRect(x, top + 17, round(width * known / max(1, actual)), 4, color)
            painter.drawText(x + width + 6, top + 25, f"{known / max(1, actual):.0%} read")
        painter.setPen(text)
        painter.drawText(7, 188, f"Composition · exact {self.info.examined:,} B")
        total = max(1, self.info.examined)
        bar_x, bar_width = 7, max(1, self.width() - 14)
        for index, (_, count) in enumerate(categories):
            right = 7 + round(bar_width * sum(part for _, part in categories[:index + 1]) / total)
            color = (visual_ink(text, 100) if index == 4 else
                     data_color(self.CATEGORIES[index], background))
            painter.fillRect(bar_x, 195, right - bar_x, 14, color)
            bar_x = right
        legend = " · ".join(f"{name} {count / total:.0%}" for name, count in categories if count)
        painter.setPen(muted)
        painter.drawText(7, 225, painter.fontMetrics().elidedText(
            legend, QtCore.Qt.TextElideMode.ElideRight, max(1, self.width() - 14)))
        comp = self.info.comparison
        if comp is not None and comp.comparable:
            painter.fillRect(7, 234, bar_width, 8, track)
            painter.fillRect(7, 234, round(bar_width * comp.changed / comp.comparable), 8,
                             data_color("#FFB64C", background))
            painter.drawText(7, 255, f"A→B · {comp.changed:,}/{comp.comparable:,}"
                                     f" paired changed ({comp.changed / comp.comparable:.1%})")
            if comp.current_entropy is not None and comp.baseline_entropy is not None:
                painter.drawText(7, 274, f"Comparable H · A {comp.baseline_entropy:.2f}"
                                         f" → B {comp.current_entropy:.2f} bits/B")
        elif comp is not None:
            painter.drawText(7, 250, "A→B · no comparable bytes")
        elif self.expect_comparison:
            painter.drawText(7, 250, "A→B · baseline pending or unavailable")
        painter.end()
