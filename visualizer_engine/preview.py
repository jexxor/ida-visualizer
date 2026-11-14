"""Raw file and memory hex previews."""

from pathlib import Path

def raw_hex_preview(path, offset):
    """File context for bytes whose file offset has no IDA address."""
    path = Path(path)
    size = path.stat().st_size
    if not 0 <= offset < size:
        raise ValueError("Offset exceeds input file")
    start = max(0, offset - 64) // 16 * 16
    with path.open("rb") as stream:
        stream.seek(start)
        data = stream.read(min(size - start, offset + 128 - start))
    lines = [f"Original file · offset 0x{offset:X} / 0x{size:X}"]
    for row in range(0, len(data), 16):
        chunk = data[row:row + 16]
        hex_bytes = " ".join(f"[{byte:02X}]" if start + row + i == offset else f" {byte:02X} "
                             for i, byte in enumerate(chunk))
        ascii_bytes = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{start + row:012X}: {hex_bytes:79s} {ascii_bytes}")
    return "\n".join(lines)


def snapshot_hex_preview(snapshot, address):
    """Display RAM bytes without claiming missing pages contain zeros."""
    if not snapshot.start <= address < snapshot.stop:
        raise ValueError("Address is outside debugger snapshot")
    start = max(snapshot.start, address - 64) // 16 * 16
    start = max(snapshot.start, start)
    stop = min(snapshot.stop, address + 128)
    lines = [f"RAM stop #{snapshot.serial} · VA 0x{address:X}"]
    for base in range(start, stop, 16):
        values = snapshot.data[base - snapshot.start:base - snapshot.start + min(16, stop - base)]
        valid = snapshot.valid[base - snapshot.start:base - snapshot.start + len(values)]
        hex_bytes = " ".join(
            (f"[{byte:02X}]" if base + index == address else f" {byte:02X} ")
            if valid[index] else " ?? "
            for index, byte in enumerate(values))
        ascii_bytes = "".join(chr(byte) if is_valid and 32 <= byte < 127 else "."
                              for byte, is_valid in zip(values, valid))
        lines.append(f"{base:012X}: {hex_bytes:79s} {ascii_bytes}")
    return "\n".join(lines)
