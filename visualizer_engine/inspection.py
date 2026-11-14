"""Byte inspection, comparison, and order analysis."""

import hashlib
import math
import random
import zlib

from collections import Counter
from dataclasses import dataclass, replace
from visualizer_engine.geometry import ORDER_LAGS, ORDER_WINDOW, RenderCancelled

@dataclass(frozen=True)
class ByteDiffWindow:
    """Exact A/B bytes at VA; zero validity never means a known zero byte."""
    start: int
    stop: int
    focus: int
    before: bytes
    before_valid: bytes
    after: bytes
    after_valid: bytes
    comparable: int
    changed: int


def byte_diff_window(current, baseline, address, size=256):
    """Read a bounded B window, aligned to 16 bytes away from capture edges."""
    if not current.start <= address < current.stop or size <= 0:
        raise ValueError("Diff address outside B snapshot")
    length = min(size, current.stop - current.start)
    start = max(current.start, min((address - length // 2) & ~15,
                                   current.stop - length))
    stop = start + length
    after = bytes(current.data[start - current.start:stop - current.start])
    after_valid = bytes(current.valid[start - current.start:stop - current.start])
    before = bytearray(length)
    before_valid = bytearray(length)
    if baseline is not None:
        low, high = max(start, baseline.start), min(stop, baseline.stop)
        if low < high:
            before[low - start:high - start] = baseline.data[
                low - baseline.start:high - baseline.start]
            before_valid[low - start:high - start] = baseline.valid[
                low - baseline.start:high - baseline.start]
    comparable = changed = 0
    for a, av, b, bv in zip(before, before_valid, after, after_valid):
        if av and bv:
            comparable += 1
            changed += a != b
    return ByteDiffWindow(start, stop, address, bytes(before), bytes(before_valid),
                          after, after_valid, comparable, changed)


def byte_diff_state(window, index):
    """A verified change requires two readable bytes at the same VA."""
    if not window.after_valid[index]:
        return "unread"
    if not window.before_valid[index]:
        return "no baseline"
    return "changed" if window.before[index] != window.after[index] else "same"


def byte_diff_changes(window):
    """Exact changed VAs in this window; never include unread/unknown bytes."""
    return tuple(window.start + index for index in range(window.stop - window.start)
                 if byte_diff_state(window, index) == "changed")


@dataclass(frozen=True)
class ByteInspection:
    """Exact local bytes around one map hit; map_sampled describes only the map."""
    start: int
    stop: int
    examined: int
    readable: int
    scales: tuple  # (requested size, actual size, readable bytes, bits/byte or None)
    histogram: tuple  # 256 bins for the largest local window, readable bytes only.
    zeros: int
    text: int
    zlib_ratio: float | None
    map_sampled: bool
    distinct: int = 0
    high_bit: int = 0
    longest_run: int = 0
    digram_entropy: float | None = None
    adjacent_pairs: int = 0
    comparison: "ByteComparison | None" = None
    order: "OrderBaseline | None" = None
    ranges: tuple = ()  # Exact half-open windows for scales above, same order.


@dataclass(frozen=True)
class ByteComparison:
    label: str
    comparable: int
    changed: int
    first_changed: int | None
    current_entropy: float | None  # Computed on the SAME comparable positions.
    baseline_entropy: float | None


@dataclass(frozen=True)
class OrderBaseline:
    """Conditional shuffled-byte null; p-values describe order, not randomness."""
    examined: int
    readable: int
    adjacent_pairs: int
    permutations: int
    entropy: float
    shuffled_entropy: float
    entropy_effect: float  # shuffled H - observed H, bits per adjacent pair.
    entropy_p: float  # lower-tail, with +1 Monte Carlo correction.
    lag: int | None
    lag_matches: int
    lag_pairs: int
    lag_expected: float  # expected equality fraction, given run histograms.
    lag_effect: float  # observed - expected equality fraction.
    lag_p: float  # max-lag null, corrected for searching multiple lags.
    lags_tested: int
    compression_ratio: float | None
    shuffled_compression: float | None
    compression_p: float | None


def _shannon(counts, size):
    return (max(0.0, -sum((n / size) * math.log2(n / size) for n in counts.values()))
            if size else None)


def _pair_entropy(runs):
    counts = Counter((a << 8) | b for run in runs for a, b in zip(run, run[1:]))
    return _shannon(counts, sum(counts.values()))


def _readable_runs(data, valid):
    runs, at = [], 0
    while at < len(data):
        while at < len(data) and not valid[at]:
            at += 1
        end = at
        while end < len(data) and valid[end]:
            end += 1
        if end > at:
            runs.append(bytes(data[at:end]))
        at = end + 1
    return runs


def calibrate_byte_order(data, valid=None, permutations=127, cancelled=None):
    """Shuffle each readable run, preserving histograms and unknown-byte gaps.

    Lag tail compares observed BEST excess to shuffled BEST excess, so testing
    multiple periods cannot make a spurious small single-lag p-value.
    """
    if valid is None:
        valid = b"\x01" * len(data)
    if len(data) != len(valid) or not 1 <= permutations <= 255:
        raise ValueError("Invalid order-calibration input")
    if len(data) > ORDER_WINDOW:
        raise ValueError("Order-calibration window exceeds 8 KiB")
    runs = _readable_runs(data, valid)
    readable = sum(map(len, runs))
    pairs = sum(max(0, len(run) - 1) for run in runs)
    if pairs < 512:
        return None
    run_expectations = []
    for run in runs:
        n = len(run)
        counts = Counter(run)
        run_expectations.append(sum(count * (count - 1) for count in counts.values())
                                / (n * (n - 1)) if n > 1 else 0.0)
    eligible = {}
    for lag in ORDER_LAGS:
        comparable = sum(max(0, len(run) - lag) for run in runs)
        if comparable < 512:
            continue
        expectation = sum((len(run) - lag) * expected
                          for run, expected in zip(runs, run_expectations)
                          if len(run) > lag) / comparable
        eligible[lag] = comparable, expectation

    def lag_matches_for(parts, lag):
        return sum(sum(a == b for a, b in zip(run, run[lag:]))
                   for run in parts if len(run) > lag)

    def lag_scores(parts):
        return {lag: (lag_matches_for(parts, lag) / comparable - expected)
                for lag, (comparable, expected) in eligible.items()}

    observed_entropy = _pair_entropy(runs)
    observed_scores = lag_scores(runs)
    lag = max(observed_scores, key=observed_scores.get) if observed_scores else None
    lag_effect = observed_scores[lag] if lag is not None else 0.0
    lag_pairs, lag_expected = eligible[lag] if lag is not None else (0, 0.0)
    lag_matches = lag_matches_for(runs, lag) if lag is not None else 0
    whole = readable == len(data)
    compression = len(zlib.compress(data)) / len(data) if whole else None
    # A seed derived from order would change the null with the observation.
    # Run lengths and multisets are invariant under the tested permutations.
    sorted_runs = [bytearray(sorted(run)) for run in runs]
    seed_material = b"".join(len(run).to_bytes(4, "little") + bytes(run)
                             for run in sorted_runs)
    seed = int.from_bytes(hashlib.blake2b(seed_material, digest_size=8).digest(), "little")
    rng = random.Random(seed)
    null_entropies, null_lags, null_compressions = [], [], []
    for _ in range(permutations):
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        shuffled = [bytearray(run) for run in sorted_runs]
        for run in shuffled:
            rng.shuffle(run)
        null_entropies.append(_pair_entropy(shuffled))
        if lag is not None:
            null_lags.append(max(lag_scores(shuffled).values()))
        if whole:
            null_compressions.append(
                len(zlib.compress(shuffled[0])) / len(shuffled[0]))
    mean_entropy = sum(null_entropies) / permutations
    mean_compression = (sum(null_compressions) / permutations if whole else None)
    return OrderBaseline(
        len(data), readable, pairs, permutations, observed_entropy, mean_entropy,
        mean_entropy - observed_entropy,
        (1 + sum(value <= observed_entropy + 1e-12 for value in null_entropies))
        / (permutations + 1),
        lag, lag_matches, lag_pairs, lag_expected, lag_effect,
        ((1 + sum(value >= lag_effect - 1e-12 for value in null_lags))
         / (permutations + 1) if lag is not None else 1.0),
        len(eligible), compression, mean_compression,
        ((1 + sum(value <= compression + 1e-12 for value in null_compressions))
         / (permutations + 1) if whole else None))


def _byte_relations(data, valid, cancelled=None):
    """Only adjacent *known* bytes; gaps never create imaginary digrams."""
    if cancelled is not None and cancelled():
        raise RenderCancelled()
    runs = _readable_runs(data, valid)
    pairs = Counter((a << 8) | b for run in runs for a, b in zip(run, run[1:]))
    count = sum(pairs.values())
    return _shannon(pairs, count), count


def inspect_bytes(read, start, stop, anchor, map_sampled=False, cancelled=None):
    """Inspect 32 B to 1 MiB of exact bytes, clipped to selected source bounds.

    read(offset, size) returns (data, validity); validity=0 excludes unknown RAM.
    No interpolation from sampled map pixels is used for these measurements.
    """
    if not start <= anchor < stop:
        raise ValueError("Inspection address outside selected range")
    if cancelled is not None and cancelled():
        raise RenderCancelled()
    size = min(1 << 20, stop - start)
    low = max(start, min(anchor - size // 2, stop - size))
    data, valid = read(low, size)
    if len(data) != size or len(valid) != size:
        raise ValueError("Incomplete inspection read")
    scales, ranges = [], []
    for requested in (32, 4096, 65536, 1 << 20):
        if cancelled is not None and cancelled():
            raise RenderCancelled()
        width = min(requested, size)
        begin = max(low, min(anchor - width // 2, low + size - width)) - low
        ranges.append((low + begin, low + begin + width))
        sample = bytes(value for value, known in
                       zip(data[begin:begin + width], valid[begin:begin + width]) if known)
        scales.append((requested, width, len(sample), _shannon(Counter(sample), len(sample))))
    known = bytes(value for value, is_valid in zip(data, valid) if is_valid)
    counts = Counter(known)
    histogram = tuple(counts.get(value, 0) for value in range(256))
    text = sum(counts.get(value, 0) for value in (*range(0x20, 0x7F), 9, 10, 13))
    local_size = min(65536, size)
    local = max(0, min(anchor - local_size // 2 - low, size - local_size))
    digram, pairs = _byte_relations(
        data[local:local + local_size], valid[local:local + local_size], cancelled)
    calibration_size = min(ORDER_WINDOW, local_size)
    calibration_at = max(local, min(anchor - calibration_size // 2 - low,
                                    local + local_size - calibration_size))
    order = calibrate_byte_order(data[calibration_at:calibration_at + calibration_size],
                                 valid[calibration_at:calibration_at + calibration_size],
                                 cancelled=cancelled)
    # Runs on the full inspected window; relationship on the local 64-KiB window.
    longest, run, previous = 0, 0, None
    for index, (value, is_valid) in enumerate(zip(data, valid)):
        if (index & 16383) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        if is_valid:
            run = run + 1 if value == previous else 1
            longest = max(longest, run)
            previous = value
        else:
            run, previous = 0, None
    # Joining disjoint readable runs would invent adjacency and compressibility.
    if cancelled is not None and cancelled():
        raise RenderCancelled()
    ratio = len(zlib.compress(data)) / size if len(known) == size else None
    return ByteInspection(low, low + size, size, len(known), tuple(scales), histogram,
                          counts.get(0, 0), text, ratio, map_sampled,
                          distinct=len(counts),
                          high_bit=sum(counts.get(value, 0) for value in range(128, 256)),
                          longest_run=longest, digram_entropy=digram, adjacent_pairs=pairs,
                          order=order, ranges=tuple(ranges))


def inspect_file(path, start, stop, anchor, map_sampled=False, cancelled=None):
    """Read original file bytes, never IDB patches or map samples."""
    with open(path, "rb") as stream:
        return inspect_bytes(lambda offset, size: _inspect_file_read(stream, offset, size),
                             start, stop, anchor, map_sampled, cancelled)


def _inspect_file_read(stream, offset, size):
    stream.seek(offset)
    return stream.read(size), b"\x01" * size


def inspect_snapshot(snapshot, start, stop, anchor, map_sampled=False, compare=None,
                     cancelled=None):
    """Read captured RAM and its validity mask, including disk-backed snapshots."""
    start, stop = max(start, snapshot.start), min(stop, snapshot.stop)
    result = inspect_bytes(lambda offset, size: (
        snapshot.data[offset - snapshot.start:offset - snapshot.start + size],
        snapshot.valid[offset - snapshot.start:offset - snapshot.start + size]),
        start, stop, anchor, map_sampled, cancelled)
    if compare is None:
        return result
    low, high = max(result.start, compare.start), min(result.stop, compare.stop)
    if low >= high:
        return replace(result, comparison=ByteComparison(
            "original file" if compare.region == "file baseline" else f"stop #{compare.serial}",
            0, 0, None, None, None))
    a, b = low - snapshot.start, low - compare.start
    length = high - low
    now, old = snapshot.data[a:a + length], compare.data[b:b + length]
    mask_a, mask_b = snapshot.valid[a:a + length], compare.valid[b:b + length]
    current_counts, baseline_counts = Counter(), Counter()
    comparable, changed, first = 0, 0, None
    for index, (x, y, v, w) in enumerate(zip(now, old, mask_a, mask_b)):
        if (index & 16383) == 0 and cancelled is not None and cancelled():
            raise RenderCancelled()
        if not v or not w:
            continue
        comparable += 1
        current_counts[x] += 1
        baseline_counts[y] += 1
        if x != y:
            changed += 1
            if first is None:
                first = low + index
    label = "original file" if compare.region == "file baseline" else f"stop #{compare.serial}"
    return replace(result, comparison=ByteComparison(
        label, comparable, changed, first,
        _shannon(current_counts, comparable), _shannon(baseline_counts, comparable)))
