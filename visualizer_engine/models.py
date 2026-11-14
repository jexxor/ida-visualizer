"""Immutable map and memory snapshot data."""

from dataclasses import dataclass

@dataclass(frozen=True)
class Frame:
    pixels: bytes
    side: int
    start: int
    stop: int
    sampled: bool
    sample_offsets: tuple = ()
    entropy_shifts: tuple = ()
    first_change: int | None = None  # Verified VA in this viewport, not a sampled guess.


@dataclass(frozen=True)
class GlobalFrame:
    pixels: bytes
    side: int
    stop_id: int
    regions: tuple  # (first tile, end tile, MemorySnapshot)
    tile_regions: tuple  # Hilbert tile index -> region number, or -1 for gap.
    entropy_shifts: tuple = ()  # (region number, VA start, VA end, delta)
    omitted: int = 0
    change_marks: tuple = ()  # (region index, exact changed VA), not sampled pixels.
    omitted_changes: int = 0


@dataclass(frozen=True)
class MemorySnapshot:
    """Paused process bytes; valid=0 means not read, never a known zero byte."""
    start: int
    data: bytes
    valid: bytes
    region: str
    serial: int  # Debugger stop number, shared by every capture at that stop.
    captured_at: float = 0.0
    mapping: tuple = ()
    new_region: bool = False
    missing_bytes: int = 0  # Bytes for which debugger supplied no data.
    executable: bool | None = None  # Permission observed at this debugger stop.

    def __post_init__(self):
        if self.start < 0 or not self.data or len(self.data) != len(self.valid):
            raise ValueError("Invalid debugger snapshot")

    @property
    def stop(self):
        return self.start + len(self.data)
