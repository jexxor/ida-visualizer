"""Snapshot storage and memory capture helpers."""

import tempfile
import threading

from dataclasses import dataclass
from pathlib import Path
from visualizer_engine.models import MemorySnapshot

class DiskSnapshotStore:
    """Temporary-file backing for bulk process captures; removed on release."""

    def __init__(self, length):
        self.length = length
        self.stream = tempfile.TemporaryFile()
        self.stream.truncate(2 * length)
        self.lock = threading.Lock()

    def write(self, offset, data, valid):
        with self.lock:
            for base, value in ((0, data), (self.length, valid)):
                self.stream.seek(base + offset)
                self.stream.write(value)

    def read(self, offset, length):
        with self.lock:
            self.stream.seek(offset)
            return self.stream.read(length)

    def views(self):
        return (DiskBytes(self, 0, self.length),
                DiskBytes(self, self.length, self.length))


class DiskBytes:
    """Bytes-like read-only slice of a disk-backed snapshot."""

    def __init__(self, store, offset, length):
        self.store, self.offset, self.length = store, offset, length

    def __len__(self):
        return self.length

    def __bytes__(self):
        return self.store.read(self.offset, self.length)

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(self.length)
            if step != 1:
                return self.store.read(self.offset, self.length)[key]
            return self.store.read(self.offset + start, max(0, stop - start))
        index = int(key)
        if index < 0:
            index += self.length
        if not 0 <= index < self.length:
            raise IndexError(index)
        return self.store.read(self.offset + index, 1)[0]


@dataclass
class StopRecord:
    serial: int
    captured_at: float
    expected_regions: tuple = ()
    planned: int = 0
    completed: int = 0
    finished: bool = False
    reason: str = ""


class SnapshotHistory:
    """Bounded snapshots across regions, newest first per region in the UI."""

    def __init__(self, max_bytes=256 << 20, max_disk_bytes=2 << 30):
        self.max_bytes = max_bytes
        self.max_disk_bytes = max_disk_bytes
        self.snapshots = []
        self.bytes_used = 0
        self.disk_bytes = 0
        self.stops = {}

    def begin_stop(self, serial, captured_at, regions, jobs):
        record = self.stops.setdefault(serial, StopRecord(serial, captured_at))
        record.expected_regions = tuple(dict.fromkeys((*record.expected_regions, *regions)))
        record.planned += jobs
        record.finished = False
        record.reason = ""
        if len(self.stops) > 256:
            retained = {item.serial for item in self.snapshots}
            for old_serial in sorted(self.stops):
                if len(self.stops) <= 256:
                    break
                if old_serial not in retained and old_serial != serial:
                    self.stops.pop(old_serial)
        return record

    def finish_stop(self, serial, reason=""):
        record = self.stops.get(serial)
        if record is not None:
            record.finished = True
            record.reason = reason

    def stop_coverage(self, serial):
        record = self.stops.get(serial)
        if record is None:
            return None
        group = self.for_stop(serial)
        uncovered = 0
        for start, stop, mapping_name in record.expected_regions:
            intervals = sorted((max(start, item.start), min(stop, item.stop))
                               for item in group if item.mapping == (start, stop, mapping_name)
                               and item.start < stop and item.stop > start)
            end = start
            for low, high in intervals:
                uncovered += max(0, low - end)
                end = max(end, high)
            uncovered += stop - end
        return record, uncovered

    def add(self, snapshot):
        self.snapshots.append(snapshot)
        self.bytes_used += self._resident_size(snapshot)
        if isinstance(snapshot.data, DiskBytes):
            self.disk_bytes += 2 * len(snapshot.data)
        record = self.stops.setdefault(snapshot.serial, StopRecord(snapshot.serial,
                                                                  snapshot.captured_at))
        record.completed += 1
        while (len(self.snapshots) > 1
               and (self.bytes_used > self.max_bytes or self.disk_bytes > self.max_disk_bytes)
               and self.snapshots[0].serial != snapshot.serial):
            old_stop = self.snapshots[0].serial
            while self.snapshots and self.snapshots[0].serial == old_stop:
                self._drop_oldest()
            self.stops.pop(old_stop, None)

    def _drop_oldest(self):
        oldest = self.snapshots.pop(0)
        self.bytes_used -= self._resident_size(oldest)
        if isinstance(oldest.data, DiskBytes):
            self.disk_bytes -= 2 * len(oldest.data)

    @staticmethod
    def _resident_size(snapshot):
        return 0 if isinstance(snapshot.data, DiskBytes) else 2 * len(snapshot.data)

    def for_region(self, mapping):
        return [snapshot for snapshot in reversed(self.snapshots)
                if snapshot.mapping == mapping]

    def for_stop(self, stop_id):
        latest = {}
        for snapshot in self.snapshots:
            if snapshot.serial == stop_id:
                latest[snapshot.mapping, snapshot.start, snapshot.stop] = snapshot
        return sorted(latest.values(), key=lambda item: (item.start, item.stop, item.region))

    def clear(self):
        self.snapshots.clear()
        self.bytes_used = 0
        self.disk_bytes = 0
        self.stops.clear()


def common_va_snapshots(current, baseline):
    """Clip two arbitrary captures to their common VA interval."""
    start, stop = max(current.start, baseline.start), min(current.stop, baseline.stop)
    if start >= stop:
        raise ValueError("Snapshots have no overlapping virtual addresses")

    def crop(snapshot):
        low, high = start - snapshot.start, stop - snapshot.start
        valid = snapshot.valid[low:high]
        return MemorySnapshot(start, snapshot.data[low:high], valid,
                              snapshot.region, snapshot.serial, snapshot.captured_at,
                              snapshot.mapping, snapshot.new_region,
                              valid.count(0))

    return crop(current), crop(baseline)


def _verified_file_page(stream, file_size, ea, size, file_offset_for_ea):
    """Use the same whole-page linearity rule in Global and detail views."""
    first = file_offset_for_ea(ea)
    last = file_offset_for_ea(ea + size - 1)
    if (first is None or last is None or first < 0 or first + size > file_size
            or last != first + size - 1):
        return bytes(size), bytes(size)
    if any(file_offset_for_ea(ea + index) != first + index
           for index in range(1, size - 1)):
        return bytes(size), bytes(size)
    stream.seek(first)
    chunk = stream.read(size)
    return (chunk, b"\x01" * size) if len(chunk) == size else (bytes(size), bytes(size))


def debugger_regions(info):
    """Normalize IDA debugger memory configuration to (start, end, name)."""
    if info is None:
        return []
    if isinstance(info, tuple) and len(info) >= 2 and isinstance(info[0], int):
        info = [info]
    regions = []
    for item in info:
        if hasattr(item, "start_ea"):
            start, stop = int(item.start_ea), int(item.end_ea)
            name = getattr(item, "name", "")
        else:
            if len(item) < 2:
                continue
            start, stop = int(item[0]), int(item[1])
            name = item[2] if len(item) > 2 else ""
        if 0 <= start < stop:
            regions.append((start, stop, str(name or "memory")))
    return sorted(regions)


def disjoint_regions(regions, preferred=()):
    """Give specific mappings priority; retain only uncovered module intervals."""
    by_size = lambda region: (region[1] - region[0], region[0], region[2])
    ordered = sorted(preferred, key=by_size) + sorted(regions, key=by_size)
    result = []
    for start, stop, name in ordered:
        pending = [(start, stop)]
        for taken_start, taken_stop, _ in result:
            remainder = []
            for low, high in pending:
                if high <= taken_start or taken_stop <= low:
                    remainder.append((low, high))
                else:
                    if low < taken_start:
                        remainder.append((low, taken_start))
                    if taken_stop < high:
                        remainder.append((taken_stop, high))
            pending = remainder
            if not pending:
                break
        clipped = pending != [(start, stop)]
        for low, high in pending:
            result.append((low, high, f"{name} [other]" if clipped else name))
    return sorted(result)


def snapshot_bounds(region, focus, limit=16 << 20):
    start, stop = region[:2]
    if stop - start <= limit:
        return start, stop
    if not start <= focus < stop:
        focus = start + limit // 2
    focus = max(start, min(int(focus), stop - 1))
    low = max(start, min(focus - limit // 2, stop - limit))
    return low, low + limit


def _recover_memory_range(read_memory, address, size, data, valid, at, payload, page_size):
    """Retry at smaller sizes without assuming single-byte reads are supported."""
    copied = min(len(payload), size) if payload else 0
    if copied:
        data[at:at + copied] = payload[:copied]
        valid[at:at + copied] = b"\x01" * copied
    if copied == size:
        return
    address, at, size = address + copied, at + copied, size - copied
    if size <= 4:
        for index in range(size):
            byte = read_memory(address + index, 1)
            if byte:
                data[at + index] = byte[0]
                valid[at + index] = 1
        return
    step = (size + 3) // 4
    if size < page_size:
        readable = False
        # Probe every quarter at multiple sizes. A debugger may accept 256B
        # reads but reject both a 4KiB page and single-byte requests.
        for probe_size in dict.fromkeys((step, min(step, 64), 1)):
            for index in range(0, size, step):
                count = min(probe_size, size - index)
                piece = read_memory(address + index, count)
                if piece:
                    n = min(len(piece), count)
                    data[at + index:at + index + n] = piece[:n]
                    valid[at + index:at + index + n] = b"\x01" * n
                    readable = True
            if readable:
                break
        if not readable:
            return
    for index in range(0, size, step):
        count = min(step, size - index)
        if all(valid[at + index:at + index + count]):
            continue
        piece = read_memory(address + index, count)
        _recover_memory_range(read_memory, address + index, count,
                              data, valid, at + index, piece, page_size)


def iter_memory_chunks(read_memory, start, length, chunk_size=65536, page_size=4096):
    """Read chunks, retry failed pages adaptively; retain per-byte validity."""
    if start < 0 or length <= 0 or chunk_size <= 0 or page_size <= 0:
        raise ValueError("Invalid debugger memory range")
    for offset in range(0, length, chunk_size):
        size = min(chunk_size, length - offset)
        data = bytearray(size)
        valid = bytearray(size)
        payload = read_memory(start + offset, size)
        copied = min(len(payload), size) if payload else 0
        if copied:
            data[:copied] = payload[:copied]
            valid[:copied] = b"\x01" * copied
        if copied < size:
            at = copied
            while at < size:
                address = start + offset + at
                count = min(page_size - address % page_size, size - at)
                piece = read_memory(address, count)
                _recover_memory_range(read_memory, address, count, data, valid, at,
                                      piece, page_size)
                at += count
        yield offset, bytes(data), bytes(valid)


def iter_file_baseline(path, start, length, file_offset_for_ea, page_size=4096):
    """Compare only pages whose EA-to-file mapping is provably linear."""
    path = Path(path)
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        for offset in range(0, length, page_size):
            size = min(page_size - (start + offset) % page_size, length - offset)
            ea = start + offset
            chunk, valid = _verified_file_page(stream, file_size, ea, size, file_offset_for_ea)
            yield offset, chunk, valid
