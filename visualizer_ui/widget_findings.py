"""Evidence lane visualization."""

from PySide6 import QtCore, QtGui, QtWidgets
from collections import Counter
from visualizer_core import finding_lanes, finding_verified_span
from visualizer_ui.constants import DELTA_DOWN, DELTA_UP
from visualizer_ui.widget_common import data_color, view_colors, visual_ink

class EvidenceLanes(QtWidgets.QWidget):
    """Ranked finding anchors on separate file/stop/region address axes."""

    activated = QtCore.Signal(int)

    def __init__(self, parent):
        super().__init__(parent)
        self.findings = ()
        self.lanes = ()
        self.selected = None
        self.points = []
        self.setMouseTracking(True)
        self.setMinimumWidth(280)
        self.set_evidence((), 1)

    @staticmethod
    def evidence_color(finding):
        kind = finding.kind
        if "changed" in kind.lower() or "differs" in kind.lower():
            return "#FFB64C"
        if "Entropy transition" in kind:
            return DELTA_DOWN if "Δ -" in finding.evidence else DELTA_UP
        if "executable" in kind:
            return "#B781EB"
        if kind.startswith("Validated "):
            return "#65D8BB"
        return "#8EA7FF"

    def set_evidence(self, findings, file_size, selected=None, empty_text=None):
        self.findings = tuple(findings)
        self.lanes = finding_lanes(self.findings, file_size)
        self.selected = selected
        self.empty_text = empty_text or "No ranked findings in scanned bounds"
        self.points = []
        self.setFixedHeight(max(95, len(self.lanes) * 64 + 12))
        self.update()

    def _near(self, position, advance=False):
        near = [(abs(position.x() - x), index, x, y) for x, y, index in self.points
                if abs(position.x() - x) <= 10 and abs(position.y() - y) <= 12]
        if not near:
            return None
        _, first, x, y = min(near)
        stacked = sorted(index for px, py, index in self.points if (px, py) == (x, y))
        if advance and self.selected in stacked and len(stacked) > 1:
            return stacked[(stacked.index(self.selected) + 1) % len(stacked)]
        if not advance and self.selected in stacked:
            return self.selected
        return first

    def mouseMoveEvent(self, event):
        index = self._near(event.position())
        if index is not None:
            finding = self.findings[index]
            location = (f"File+0x{finding.address:X}" if finding.source == "File" else
                        f"VA 0x{finding.address:X} · stop #{finding.snapshot.serial}"
                        if finding.snapshot is not None else f"VA 0x{finding.address:X}")
            point = next((x, y) for x, y, current in self.points if current == index)
            overlapping = sum((x, y) == point for x, y, _ in self.points) > 1
            self.setToolTip(f"{finding.kind} · {location} · {finding.evidence}"
                            + (" · click again to cycle overlapping markers" if overlapping else ""))
        else:
            self.setToolTip("Points mark anchors; bands show bounded evidence, not changed bytes")
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            index = self._near(event.position(), advance=True)
            if index is not None:
                self.activated.emit(index)
                event.accept()
                return
        super().mousePressEvent(event)

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        background, text, _, highlight = view_colors(self)
        muted = visual_ink(text, 165)
        painter.fillRect(self.rect(), background)
        if not self.lanes:
            painter.setPen(muted)
            painter.drawText(12, 30, self.empty_text)
            painter.end()
            return
        x0, span = 12, max(1, self.width() - 24)
        self.points = []
        for row, lane in enumerate(self.lanes):
            y = 46 + row * 64
            if self.selected in lane.indices:
                painter.fillRect(2, y - 43, self.width() - 4, 62,
                                 visual_ink(highlight, 30))
            painter.setPen(text)
            painter.drawText(12, y - 24, painter.fontMetrics().elidedText(
                lane.label, QtCore.Qt.TextElideMode.ElideRight, span))
            painter.setPen(muted)
            painter.drawLine(x0, y, x0 + span, y)
            painter.drawText(x0, y + 19, f"0x{lane.start:X}")
            right = f"0x{lane.stop - 1:X}"
            painter.drawText(x0 + span - painter.fontMetrics().horizontalAdvance(right), y + 19, right)
            width = max(1, lane.stop - lane.start)
            if self.selected in lane.indices:
                address = max(lane.start, min(self.findings[self.selected].address, lane.stop - 1))
                focus_x = x0 + round(span * (address - lane.start) / width)
                painter.setPen(QtGui.QPen(visual_ink(highlight, 160), 1,
                                         QtCore.Qt.PenStyle.DashLine))
                painter.drawLine(focus_x, y - 14, focus_x, y + 14)
            selected_point = None
            for index in reversed(lane.indices):
                finding = self.findings[index]
                address = max(lane.start, min(finding.address, lane.stop - 1))
                x = x0 + round(span * (address - lane.start) / width)
                color = data_color(self.evidence_color(finding), background)
                verified = finding_verified_span(finding)
                if verified is not None:
                    end = min(lane.stop, verified[1])
                    if end > address:
                        x_end = x0 + round(span * (end - lane.start) / width)
                        painter.setPen(QtGui.QPen(color, 5))
                        painter.drawLine(x, y, max(x + 1, x_end), y)
                sampled = "(sampled)" in finding.kind
                painter.setPen(QtGui.QPen(color, 2))
                painter.setBrush(QtCore.Qt.BrushStyle.NoBrush if sampled else color)
                painter.drawEllipse(QtCore.QPointF(x, y), 5, 5)
                if index == self.selected:
                    selected_point = x, y
                self.points.append((x, y, index))
            for (point_x, point_y), count in Counter(
                    (point_x, point_y) for point_x, point_y, _ in self.points
                    if point_y == y).items():
                if count > 1:
                    painter.setPen(text)
                    painter.drawText(point_x + 7, point_y - 6, str(count))
            if selected_point is not None:
                painter.setPen(QtGui.QPen(highlight, 2))
                painter.setBrush(QtCore.Qt.BrushStyle.NoBrush)
                painter.drawEllipse(QtCore.QPointF(*selected_point), 9, 9)
        painter.end()
