"""Evidence detection in files and debugger snapshots."""

import io
import os
import zipfile
import zlib

from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from visualizer_engine.geometry import (
    COMPRESSIBLE_MAX_RATIO,
    COMPRESSIBLE_MIN_ENTROPY,
    ORDER_SUPPORT_MAX_P,
    ORDER_SUPPORT_MIN_EFFECT,
    ORDER_WINDOW,
    RenderCancelled,
    SIDE,
)
from visualizer_engine.global_map import entropy_delta_regions, global_layout, same_region_overlap
from visualizer_engine.inspection import OrderBaseline, _shannon, calibrate_byte_order
from visualizer_engine.models import MemorySnapshot

@dataclass(frozen=True)
class Finding:
    score: int
    kind: str
    address: int
    source: str  # "File" or "RAM"; never conflate file offsets and virtual addresses.
    evidence: str
    snapshot: MemorySnapshot | None = field(default=None, repr=False, compare=False)
    extent: int = 0
    order: OrderBaseline | None = field(default=None, repr=False, compare=False)


class FindingResults(list):
    """Ranked findings plus actual scan coverage; empty results are not clean verdicts."""

    def __init__(self, items=(), coverage=""):
        super().__init__(items)
        self.coverage = coverage


@dataclass(frozen=True)
class FindingLane:
    """One address domain; file offsets and per-stop RAM VAs never share an axis."""
    label: str
    start: int
    stop: int
    indices: tuple
    source: str
    serial: int | None


def finding_lanes(findings, file_size):
    """Group ranked evidence by file or captured stop and process region."""
    groups = {}
    for index, finding in enumerate(findings):
        snapshot = finding.snapshot
        if finding.source == "File":
            key = ("File", None, None)
            label, start, stop = "File offsets", 0, max(1, file_size)
        else:
            mapping = (snapshot.mapping if snapshot is not None and snapshot.mapping else
                       (snapshot.start, snapshot.stop, snapshot.region) if snapshot is not None else
                       (finding.address, finding.address + 1, "RAM"))
            key = ("RAM", snapshot.serial if snapshot is not None else None, mapping)
            label = f"Stop #{key[1]} · {mapping[2]}" if key[1] is not None else mapping[2]
            start, stop = mapping[:2]
            if snapshot is not None:
                start, stop = min(start, snapshot.start), max(stop, snapshot.stop)
        if key not in groups:
            groups[key] = [label, start, stop, [], key[0], key[1]]
        groups[key][3].append(index)
    lanes = [FindingLane(label, start, stop, tuple(indices), source, serial)
             for label, start, stop, indices, source, serial in groups.values()]
    return tuple(sorted(lanes, key=lambda lane: (lane.source != "File",
                                                     -(lane.serial or 0), lane.start)))


def finding_verified_span(finding):
    """Measured object or block bounds, never a claim every byte changed."""
    if finding.extent > 0 and (finding.kind.startswith("Validated ") or finding.kind in (
            "High entropy, compressible",
            "Entropy transition across stops")):
        return finding.address, finding.address + finding.extent
    return None


def _verified_zip(data, pos):
    """Central directory, local headers and every entry CRC must be checkable."""
    if pos + 30 > len(data):
        return None
    eocd = data.find(b"PK\x05\x06", pos + 30, min(len(data), pos + (2 << 20)))
    while eocd >= 0:
        if eocd + 22 <= len(data):
            end = eocd + 22 + int.from_bytes(data[eocd + 20:eocd + 22], "little")
            if end <= len(data) and end - pos <= 2 << 20:
                try:
                    with zipfile.ZipFile(io.BytesIO(data[pos:end])) as archive:
                        entries = archive.infolist()
                        if (entries and len(entries) <= 128 and entries[0].header_offset == 0
                                and sum(item.file_size for item in entries) <= 8 << 20
                                and not any(item.flag_bits & 1 for item in entries)):
                            for item in entries:
                                with archive.open(item) as stream:
                                    while stream.read(65536):
                                        pass  # ZipExtFile verifies CRC when drained.
                            return end
                except (OSError, ValueError, RuntimeError, EOFError,
                        zipfile.BadZipFile, NotImplementedError, zlib.error):
                    pass
        eocd = data.find(b"PK\x05\x06", eocd + 1, min(len(data), pos + (2 << 20)))
    return None


def _verified_objects(data):
    """Recognize complete bounded PNG/gzip/ZIP streams; magic alone never qualifies."""
    signature = b"\x89PNG\r\n\x1a\n"
    objects = []
    at = 0
    attempts = 0
    while at < len(data) and attempts < 64:
        candidates = [(pos, name) for pos, name in (
            (data.find(signature, at), "PNG"),
            (data.find(b"\x1f\x8b\x08", at), "gzip"),
            (data.find(b"PK\x03\x04", at), "ZIP")) if pos >= 0]
        if not candidates:
            break
        pos, name = min(candidates)
        attempts += 1
        end = None
        if name == "PNG":
            offset, image_data, row_size, height = pos + len(signature), bytearray(), 0, 0
            seen_data, after_data, palette = False, False, False
            while offset + 12 <= min(len(data), pos + (2 << 20)):
                length = int.from_bytes(data[offset:offset + 4], "big")
                if length > 2 << 20 or offset + 12 + length > len(data):
                    break
                tag = data[offset + 4:offset + 8]
                payload = data[offset + 8:offset + 8 + length]
                crc = int.from_bytes(data[offset + 8 + length:offset + 12 + length], "big")
                if zlib.crc32(tag + payload) != crc:
                    break
                if (tag == b"IHDR" and offset != pos + 8
                        or tag not in (b"IHDR", b"PLTE", b"IDAT", b"IEND")
                        and not tag[0] & 0x20):  # Unknown critical chunk.
                    break
                if offset == pos + 8:
                    if tag != b"IHDR" or length != 13:
                        break
                    width = int.from_bytes(payload[:4], "big")
                    height = int.from_bytes(payload[4:8], "big")
                    depth, color = payload[8:10]
                    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color)
                    if (not width or not height or channels is None
                            or depth != 8 or payload[10:13] != b"\x00\x00\x00"):
                        break  # Supported subset: noninterlaced 8-bit PNG.
                    row_size = 1 + width * channels
                    if row_size * height > 8 << 20:
                        break
                if tag == b"PLTE":
                    if seen_data or palette or not length or length > 768 or length % 3:
                        break
                    palette = True
                if tag == b"IDAT":
                    if after_data or not row_size or (color == 3 and not palette):
                        break
                    seen_data = True
                    image_data.extend(payload)
                elif seen_data:
                    after_data = True
                offset += 12 + length
                if tag == b"IEND":
                    if not length and image_data and row_size:
                        try:
                            unpack = zlib.decompressobj()
                            pixels = unpack.decompress(image_data, (8 << 20) + 1)
                            if (unpack.eof and not unpack.unused_data
                                    and len(pixels) == row_size * height
                                    and all(pixels[row * row_size] <= 4
                                            for row in range(height))):
                                end = offset
                        except zlib.error:
                            pass
                    break
        elif name == "gzip":
            try:
                unpack = zlib.decompressobj(wbits=31)
                chunk = data[pos:pos + (2 << 20)]
                output = unpack.decompress(chunk, (8 << 20) + 1)
                if unpack.eof and len(output) <= 8 << 20:
                    end = pos + len(chunk) - len(unpack.unused_data)
            except zlib.error:
                pass
        else:
            end = _verified_zip(data, pos)
        if end is not None and end > pos:
            objects.append((pos, end, name))
            at = end
        else:
            at = pos + 1
    return objects


def _compressible_findings(data, source, base=0, snapshot=None):
    results = []
    for offset in range(0, len(data) - 4095, 65536):
        chunk = data[offset:offset + 65536]
        if len(chunk) < 4096:
            continue
        entropy = _shannon(Counter(chunk), len(chunk))
        if entropy >= COMPRESSIBLE_MIN_ENTROPY:
            ratio = len(zlib.compress(chunk)) / len(chunk)
        else:
            ratio = 1.0
        if ratio <= COMPRESSIBLE_MAX_RATIO:
            results.append(Finding(60, "High entropy, compressible", base + offset, source,
                                   f"{len(chunk):,} exact bytes · H {entropy:.2f} bits/byte"
                                   f" · zlib {ratio:.1%} of input", snapshot, len(chunk)))
    return results


def _coalesce_compressible(results):
    """One finding per contiguous anomalous run; keep first exact byte as anchor."""
    grouped = []
    for item in sorted((item for item in results if item.kind == "High entropy, compressible"),
                       key=lambda finding: (finding.source, finding.address)):
        if (grouped and item.kind == "High entropy, compressible"
                and grouped[-1].kind == item.kind
                and grouped[-1].source == item.source
                and grouped[-1].snapshot is item.snapshot
                and grouped[-1].address + grouped[-1].extent == item.address):
            previous = grouped[-1]
            grouped[-1] = replace(previous, extent=previous.extent + item.extent,
                                  evidence=f"{previous.extent + item.extent:,} contiguous bytes"
                                  f" · H ≥{COMPRESSIBLE_MIN_ENTROPY:.1f} bits/byte,"
                                  f" zlib ≤{COMPRESSIBLE_MAX_RATIO:.0%} per window"
                                  " · adjacent windows measured independently")
        else:
            grouped.append(item)
    return grouped + [item for item in results if item.kind != "High entropy, compressible"]


def _calibrate_compressible_findings(results, read, cancelled=None):
    """Rank top candidates by measured order effect, never by raw entropy alone."""
    selected = sorted((item for item in results if item.kind == "High entropy, compressible"),
                      key=lambda item: (-item.extent, item.address))[:8]
    replacements = {}
    for finding in selected:
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        length = min(ORDER_WINDOW, finding.extent)
        sample = read(finding, length)
        if len(sample) != length:
            raise OSError("Inspection source changed during findings scan")
        stats = calibrate_byte_order(sample, permutations=63, cancelled=cancelled)
        if stats is None or stats.compression_p is None:
            continue
        effect = stats.shuffled_compression - stats.compression_ratio
        corroborated = (effect >= ORDER_SUPPORT_MIN_EFFECT
                        and stats.compression_p <= ORDER_SUPPORT_MAX_P)
        replacements[id(finding)] = replace(
            finding, score=64 if corroborated else finding.score, order=stats,
            evidence=finding.evidence
            + f" · shuffled control {length:,} B: zlib {stats.compression_ratio:.1%}"
            + f" vs {stats.shuffled_compression:.1%}, Δ {effect:+.1%}"
            + f" (p={stats.compression_p:.3f}, 63 shuffles)"
            + (" · corroborated order effect" if corroborated else
               " · order effect not resolved"))
    return [replacements.get(id(finding), finding) for finding in results]


def _file_scan_ranges(length, budget):
    """Full coverage up to budget; otherwise first/last plus spread windows."""
    if length <= 0 or budget <= 0:
        return ()
    if length <= budget:
        return ((0, length),)
    width = min(4 << 20, budget)
    count = max(1, budget // width)
    starts = ([0] if count == 1 else
              [(length - width) * index // (count - 1) for index in range(count)])
    regions = []
    for start in starts:
        if regions and start <= regions[-1][1]:
            regions[-1] = regions[-1][0], max(regions[-1][1], start + width)
        else:
            regions.append((start, start + width))
    return tuple(regions)


def file_findings(path, max_scan=64 << 20, cancelled=None):
    """Distributed scan with 2-MiB overlaps; max_scan=None visits entire file."""
    path = Path(path)
    stamp = path.stat()
    length = stamp.st_size
    ranges = _file_scan_ranges(length, length if max_scan is None else max_scan)
    results, seen = [], set()
    with path.open("rb") as stream:
        if os.fstat(stream.fileno()).st_size != length:
            raise OSError("Input file changed during findings scan")
        for region_start, region_end in ranges:
            structures = []
            for start in range(region_start, region_end, 2 << 20):
                if cancelled is not None and cancelled():
                    raise RenderCancelled()
                stream.seek(start)
                requested = min(4 << 20, region_end - start)
                data = stream.read(requested)
                if len(data) != requested:
                    raise OSError("Input file changed during findings scan")
                for low, high, name in _verified_objects(data):
                    address = start + low
                    if address in seen:
                        continue
                    seen.add(address)
                    structures.append((address, start + high, name))
            for start, end, name in sorted(structures):
                results.append(Finding(65, f"Validated {name}", start, "File",
                                       f"0x{start:X}–0x{end - 1:X} · parsed and checksummed",
                                       extent=end - start))
            for start in range(region_start, region_end, 2 << 20):
                if cancelled is not None and cancelled():
                    raise RenderCancelled()
                stream.seek(start)
                requested = min(2 << 20, region_end - start)
                data = stream.read(requested)
                if len(data) != requested:
                    raise OSError("Input file changed during findings scan")
                results.extend(_compressible_findings(data, "File", start))
        results = _coalesce_compressible(results)
        def read_candidate(finding, size):
            stream.seek(finding.address)
            return stream.read(size)
        results = _calibrate_compressible_findings(results, read_candidate, cancelled)
        current = os.fstat(stream.fileno())
        if (current.st_size, current.st_mtime_ns) != (stamp.st_size, stamp.st_mtime_ns):
            raise OSError("Input file changed during findings scan")
    scanned = sum(stop - start for start, stop in ranges)
    coverage = (f"File: {scanned:,}/{length:,} bytes visited"
                + (" (complete)" if scanned == length else
                   f" ({len(ranges)} distributed windows; gaps not scanned)"))
    return FindingResults(sorted(results, key=lambda item: (-item.score, item.address))[:64],
                          coverage)


def ram_findings(snapshots, baseline=None, file_samples=None, side=SIDE,
                 comparisons=(), cancelled=None):
    """Scan captured B-stop windows; comparisons use only valid overlapping VA."""
    results = []
    scanned, analyzed, comparable_total, compared_span = 0, 0, 0, 0
    for snapshot in snapshots:
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        if snapshot.new_region and snapshot.executable is True:
            results.append(Finding(100, "New executable RAM region", snapshot.start, "RAM",
                                   f"stop #{snapshot.serial} · debugger reported execute permission"
                                   f" · {len(snapshot.data):,} captured bytes", snapshot))
        previous = [item for item in comparisons if same_region_overlap(snapshot, item)]
        if previous:
            old = max(previous, key=lambda item: min(snapshot.stop, item.stop)
                      - max(snapshot.start, item.start))
            start, stop = max(snapshot.start, old.start), min(snapshot.stop, old.stop)
            shifts = []
            paired, different, first_difference = 0, 0, None
            low = start
            while low < stop:
                if cancelled is not None and cancelled():
                    raise RenderCancelled()
                high = min(stop, (low // (1 << 20) + 1) * (1 << 20))
                a, b = low - snapshot.start, low - old.start
                current = MemorySnapshot(low, snapshot.data[a:a + high - low],
                                         snapshot.valid[a:a + high - low], snapshot.region,
                                         snapshot.serial)
                prior = MemorySnapshot(low, old.data[b:b + high - low],
                                       old.valid[b:b + high - low], old.region, old.serial)
                for index, (x, y, known_x, known_y) in enumerate(zip(
                        current.data, prior.data, current.valid, prior.valid)):
                    if known_x and known_y:
                        paired += 1
                        if x != y:
                            different += 1
                            if first_difference is None:
                                first_difference = low + index
                shifts.extend(entropy_delta_regions(current, prior))
                compared_span += high - low
                low = high
            if shifts:
                for address, end, delta in sorted(shifts, key=lambda item: -abs(item[2]))[:4]:
                    results.append(Finding(75 + min(5, int(abs(delta))),
                                           "Entropy transition across stops", address, "RAM",
                                           f"stop #{old.serial} → #{snapshot.serial}"
                                           f" · Δ {delta:+.2f} bits/byte in VA-aligned 4 KiB"
                                           " · at least 75% comparable", snapshot, end - address))
            if different:
                results.append(Finding(35, "Bytes changed", first_difference, "RAM",
                                       f"stop #{old.serial} → #{snapshot.serial}"
                                       f" · {different:,}/{paired:,} readable paired bytes differ"
                                       " · entire captured VA overlap", snapshot,
                                       stop - first_difference))
        length = len(snapshot.data)
        scanned += length
        for pos in range(0, length, 65536):
            if cancelled is not None and cancelled():
                raise RenderCancelled()
            width = min(65536, length - pos)
            valid = snapshot.valid[pos:pos + width]
            if width < 4096:
                continue
            if all(valid):
                analyzed += width
                results.extend(_compressible_findings(snapshot.data[pos:pos + width],
                                                      "RAM", snapshot.start + pos, snapshot))
            elif any(valid):
                at = 0
                while at < width:
                    while at < width and not valid[at]:
                        at += 1
                    end = valid.find(b"\x00", at)
                    if end < 0:
                        end = width
                    if end - at >= 4096:
                        analyzed += end - at
                        results.extend(_compressible_findings(snapshot.data[pos + at:pos + end],
                                                              "RAM", snapshot.start + pos + at,
                                                              snapshot))
                    at = end + 1
        if (baseline is not None and baseline.region == "file baseline"
                and baseline.serial == snapshot.serial
                and snapshot.start < baseline.stop and baseline.start < snapshot.stop):
            low, high = max(snapshot.start, baseline.start), min(snapshot.stop, baseline.stop)
            run = None
            file_changed, file_compared, file_first = 0, 0, None
            for address in range(low, high, 4096):
                if cancelled is not None and cancelled():
                    raise RenderCancelled()
                width = min(4096, high - address)
                a, b = address - snapshot.start, address - baseline.start
                now, old = snapshot.data[a:a + width], baseline.data[b:b + width]
                now_valid = snapshot.valid[a:a + width]
                old_valid = baseline.valid[b:b + width]
                checked = sum(bool(x and y) for x, y in zip(now_valid, old_valid))
                comparable_total += checked
                file_compared += checked
                changed = sum(x and y and current != prior for x, y, current, prior in zip(
                    now_valid, old_valid, now, old))
                if changed:
                    first = next(i for i, (x, y, current, prior) in enumerate(zip(
                        now_valid, old_valid, now, old)) if x and y and current != prior)
                    file_changed += changed
                    if file_first is None:
                        file_first = address + first
                    if run is None:
                        run = [address + first, address + width, checked, changed, 1]
                    else:
                        run[1], run[2], run[3], run[4] = (address + width, run[2] + checked,
                                                            run[3] + changed, run[4] + 1)
                elif run is not None:
                    results.append(Finding(80 + min(10, run[3] * 10 // run[2]),
                                           "RAM differs from file", run[0], "RAM",
                                           f"{run[3]:,}/{run[2]:,} comparable bytes differ"
                                           f" across {run[4]} consecutive 4-KiB pages"
                                           " · verified linear file mapping", snapshot,
                                           run[1] - run[0]))
                    run = None
            if run is not None:
                results.append(Finding(80 + min(10, run[3] * 10 // run[2]),
                                       "RAM differs from file", run[0], "RAM",
                                       f"{run[3]:,}/{run[2]:,} comparable bytes differ"
                                       f" across {run[4]} consecutive 4-KiB pages"
                                       " · verified linear file mapping", snapshot,
                                       run[1] - run[0]))
            if file_changed:
                results.append(Finding(35, "Bytes changed", file_first, "RAM",
                                       f"RAM stop #{snapshot.serial} vs verified file"
                                       f" · {file_changed:,}/{file_compared:,} readable paired bytes differ",
                                       snapshot, high - file_first))
    results = _coalesce_compressible(results)
    def read_candidate(finding, size):
        offset = finding.address - finding.snapshot.start
        return finding.snapshot.data[offset:offset + size]
    results = _calibrate_compressible_findings(results, read_candidate, cancelled)
    if file_samples is not None and snapshots:
        # Sample indices belong to the prioritized layout used when collecting
        # them. Recomputing the VA-only layout shifts sample positions and can
        # invent differences in a completely unchanged region.
        priorities = {key[0]: address for key, address in file_samples.items()
                      if key[1] == "changed" and address is not None}
        regions, _, _ = global_layout(snapshots, side, priorities)
        for first, end, snapshot in regions:
            cells = (end - first) * 64
            count = min(8192, max(1, cells // 32))
            samples, changed, first_change, bytes_changed, bytes_checked = 0, 0, None, 0, 0
            for index in range(count):
                if cancelled is not None and cancelled():
                    raise RenderCancelled()
                original = file_samples.get((id(snapshot), index))
                if original is None or not all(original[1]):
                    continue
                size = len(original[0])
                pos = (2 * index + 1) * len(snapshot.data) // (2 * count)
                begin = max(0, min(pos - size // 2, len(snapshot.data) - size))
                if all(snapshot.valid[begin:begin + size]):
                    samples += 1
                    bytes_checked += size
                    observed = snapshot.data[begin:begin + size]
                    difference = sum(a != b for a, b in zip(observed, original[0]))
                    if difference:
                        changed += 1
                        bytes_changed += difference
                        if first_change is None:
                            first_index = next(i for i, (a, b) in enumerate(zip(
                                observed, original[0])) if a != b)
                            first_change = snapshot.start + begin + first_index
            if changed:
                results.append(Finding(70 + min(5, changed * 5 // samples),
                                       "RAM differs from file (sampled)",
                                       first_change, "RAM",
                                       f"{changed:,}/{samples:,} verified samples differ"
                                       " · up to 32 B each; unsampled VA not compared", snapshot))
                results.append(Finding(20, "Bytes changed (sampled)", first_change, "RAM",
                                       f"{bytes_changed:,}/{bytes_checked:,} checked sample bytes differ"
                                       " · sample windows can overlap; other VA untested", snapshot))
            comparable_total += bytes_checked
    coverage = (f"RAM: {scanned:,} captured bytes visited across {len(snapshots)} windows"
                f" · {analyzed:,} contiguous readable bytes (≥4 KiB) analyzed for composition"
                + (f" · {comparable_total:,} paired bytes checked"
                   if baseline is not None or file_samples is not None else "")
                + (f" · {compared_span:,} overlapping VA bytes evaluated for A/B entropy"
                   if comparisons else "")
                + " · unread bytes excluded")
    return FindingResults(sorted(results, key=lambda item: (-item.score, item.address))[:64],
                          coverage)
