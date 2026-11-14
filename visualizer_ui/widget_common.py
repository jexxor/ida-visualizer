"""Shared formatting and interaction helpers."""

from PySide6 import QtGui
from html import escape
from visualizer_core import byte_diff_state

def view_colors(widget):
    """Use dock's native palette for surfaces/text; retain data-encoding hues."""
    palette = widget.palette()
    role = QtGui.QPalette.ColorRole
    return (palette.color(role.Window), palette.color(role.WindowText),
            palette.color(role.Base), palette.color(role.Highlight))


def visual_ink(color, alpha=255):
    ink = QtGui.QColor(color)
    ink.setAlpha(alpha)
    return ink


def data_color(value, background):
    color = QtGui.QColor(value)
    return color.darker(155) if background.lightness() > 160 else color


def format_byte_diff(window, text_color=None, font=None):
    """Side-by-side original bytes; every hex/ASCII cell links to its exact VA."""
    style = "white-space:pre;"
    if font is None:
        style += "font-family:monospace;"
    else:
        family = escape(font.family().replace("\\", "\\\\").replace("'", "\\'"), quote=True)
        style += f"font-family:'{family}';font-weight:{int(font.weight())};"
        if font.italic():
            style += "font-style:italic;"
        if font.pointSizeF() > 0:
            style += f"font-size:{font.pointSizeF():g}pt;"
        elif font.pixelSize() > 0:
            style += f"font-size:{font.pixelSize()}px;"
    rows = [f'<pre style="{style}">']
    for base in range(0, window.stop - window.start, 16):
        address = window.start + base
        lines = []
        for label, data, valid, missing in (("A", window.before, window.before_valid, "??"),
                                            ("B", window.after, window.after_valid, "--")):
            hex_bytes, ascii_bytes = [], []
            for index in range(base, min(base + 16, window.stop - window.start)):
                known = bool(valid[index])
                value = data[index]
                hex_text = f"{value:02X}" if known else missing
                ascii_text = escape(chr(value)) if known and 32 <= value < 127 else (
                    "." if known else "?" if label == "A" else "-")
                changed = bool(window.before_valid[index] and window.after_valid[index]
                               and window.before[index] != window.after[index])
                if changed:
                    style = 'background-color:#805122; color:#ffffff; text-decoration:none;'
                elif not known:
                    style = ('color:#9daab5; text-decoration:none;' if label == "B" else
                             'color:#7299db; text-decoration:none;')
                else:
                    style = ((f'color:{text_color}; ' if text_color is not None else '')
                             + 'text-decoration:none;')
                if window.start + index == window.focus:
                    style = 'background-color:#2869A7; color:#ffffff; text-decoration:underline;'
                byte_address = window.start + index
                hex_text = (f'<a name="byte-{byte_address:X}" href="va:{byte_address:X}" style="{style}">'
                            f'{hex_text}</a>' if label == "A" else
                            f'<a href="va:{byte_address:X}" style="{style}">{hex_text}</a>')
                ascii_text = f'<a href="va:{byte_address:X}" style="{style}">{ascii_text}</a>'
                hex_bytes.append(hex_text)
                ascii_bytes.append(ascii_text)
            # Pad the final (possibly partial) row before the ASCII column.
            hex_bytes.extend(["  "] * (16 - len(hex_bytes)))
            lines.append(f'{"0x" + format(address, "016X") if label == "A" else " " * 18}'
                         f' {label}  {" ".join(hex_bytes)}  |{"".join(ascii_bytes)}|')
        rows.extend(lines)
        rows.append("")
    rows.append("</pre>")
    return "\n".join(rows)


def byte_diff_focus_text(window, address):
    index = address - window.start
    before = f"{window.before[index]:02X}" if window.before_valid[index] else "??"
    after = f"{window.after[index]:02X}" if window.after_valid[index] else "--"
    return f"VA 0x{address:X} · A {before} → B {after} · {byte_diff_state(window, index)}"


def wheel_units(event):
    """Accumulate touchpad pixels or wheel angles into discrete notches."""
    pixels = event.pixelDelta().y() if hasattr(event, "pixelDelta") else 0
    return int(pixels * 2 if pixels else event.angleDelta().y())
