"""Stable Qt-free API used by the IDA plugin.

The entropy map was adapted from cantordust-ng (Apache-2.0,
Battelle Memorial Institute).
"""

from visualizer_engine.geometry import (
    BLACK,
    CHANGED,
    COMPRESSIBLE_MAX_RATIO,
    COMPRESSIBLE_MIN_ENTROPY,
    EXACT_LIMIT,
    GLOBAL_GAP,
    INSPECTION_RANGE_OUTLINES,
    MAX_SEQUENTIAL_SAMPLE_BYTES,
    NEW_REGION,
    ORDER_LAGS,
    ORDER_SUPPORT_MAX_P,
    ORDER_SUPPORT_MIN_EFFECT,
    ORDER_WINDOW,
    RenderCancelled,
    SIDE,
    UNCOMPARABLE,
    UNREADABLE,
    clamp_range,
    curve_index_at,
    curve_point_at,
    focus_domain,
    hilbert_pixels,
    move_range,
    remap_nested,
    zoom_range,
)

from visualizer_engine.native import (
    native_renderer,
    renderer_status,
)

from visualizer_engine.render import (
    entropy_overview_chunks,
    render_file,
    render_snapshot,
    snapshot_overview_chunks,
)

from visualizer_engine.palette import (
    Entropy,
)

from visualizer_engine.models import (
    Frame,
    GlobalFrame,
    MemorySnapshot,
)

from visualizer_engine.inspection import (
    ByteComparison,
    ByteDiffWindow,
    ByteInspection,
    OrderBaseline,
    byte_diff_changes,
    byte_diff_state,
    byte_diff_window,
    calibrate_byte_order,
    inspect_bytes,
    inspect_file,
    inspect_snapshot,
)

from visualizer_engine.findings import (
    Finding,
    FindingLane,
    FindingResults,
    file_findings,
    finding_lanes,
    finding_verified_span,
    ram_findings,
)

from visualizer_engine.snapshots import (
    DiskBytes,
    DiskSnapshotStore,
    SnapshotHistory,
    StopRecord,
    common_va_snapshots,
    debugger_regions,
    disjoint_regions,
    iter_file_baseline,
    iter_memory_chunks,
    snapshot_bounds,
)

from visualizer_engine.global_map import (
    entropy_delta_regions,
    first_comparable_change,
    global_bookmark_position,
    global_boundary_segments,
    global_delta_tile_masks,
    global_hit,
    global_layout,
    iter_global_file_samples,
    render_global_snapshots,
    same_region_overlap,
)

from visualizer_engine.overlays import (
    curve_index_for_offset,
    delta_only_pixels,
    delta_tile_masks,
    inspection_map_overlay,
    inspection_pixel_span,
    inspection_ranges_overlay,
    is_unmapped_tile,
    new_region_pixels,
    offset_at,
    tile_file_offset,
    unmapped_boundary_segments,
)

from visualizer_engine.preview import (
    raw_hex_preview,
    snapshot_hex_preview,
)
