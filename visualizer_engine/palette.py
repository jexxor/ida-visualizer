"""Entropy colors for map rendering."""

import math

from collections import Counter
from visualizer_engine.geometry import BLACK

class Entropy:
    """Incremental 32-byte Shannon entropy and ColorEntropy.java palette."""

    def __init__(self, data):
        self.data = data
        self.size = min(32, len(data))
        self.start = 0
        self.counts = [0] * 256
        for byte in data[:self.size]:
            self.counts[byte] += 1
        self.terms = [0.0] + [n * math.log(n) for n in range(1, 33)]
        self.total = sum(self.terms[n] for n in self.counts)
        self.log_base = math.log(max(2, self.size))

    def color(self, index):
        if self.size < 2:
            return BLACK
        start = max(0, min(index - self.size // 2, len(self.data) - self.size))
        counts, terms = self.counts, self.terms
        if start - self.start >= self.size:
            # Skip distant samples without iterating through all intervening bytes.
            counts[:] = [0] * 256
            histogram = Counter(self.data[start:start + self.size])
            for byte, count in histogram.items():
                counts[byte] = count
            self.total = sum(terms[count] for count in histogram.values())
            self.start = start
        while self.start < start:
            outgoing = self.data[self.start]
            count = counts[outgoing]
            self.total += terms[count - 1] - terms[count]
            counts[outgoing] = count - 1
            incoming = self.data[self.start + self.size]
            count = counts[incoming]
            self.total += terms[count + 1] - terms[count]
            counts[incoming] = count + 1
            self.start += 1
        e = max(0.0, min(1.0, (math.log(self.size) - self.total / self.size) / self.log_base))
        red = int(255 * max(0, 4 * (e - 0.5) - 4 * (e - 0.5) ** 2) ** 4) if e > 0.5 else 0
        blue = int(255 * e ** 2)
        return 0xFF000000 | red << 16 | blue
