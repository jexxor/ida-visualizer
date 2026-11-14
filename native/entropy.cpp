// Native renderer for the visualizer IDA plugin. No Qt or IDA SDK dependency.
// Adapted from cantordust-ng (Apache-2.0, Battelle Memorial Institute).
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#ifdef _WIN32
#define VISUALIZER_EXPORT extern "C" __declspec(dllexport)
#else
#define VISUALIZER_EXPORT extern "C" __attribute__((visibility("default")))
#endif

namespace {
constexpr uint32_t black = 0xff000000u;
constexpr uint32_t unreadable = 0xff9aa2aau;
constexpr uint32_t uncomparable = 0xff376ca8u;
constexpr uint32_t changed = 0xffffb64cu;

std::vector<uint32_t> hilbert_pixels(uint32_t side)
{
  std::vector<uint32_t> points{0};
  for ( uint32_t width = 1; width < side; width *= 2 )
  {
    const uint32_t next_width = width * 2;
    std::vector<uint32_t> next;
    next.reserve(points.size() * 4);
    for ( uint32_t pixel : points )
    {
      const uint32_t x = pixel % width, y = pixel / width;
      next.push_back(x * next_width + y);
    }
    for ( uint32_t pixel : points )
    {
      const uint32_t x = pixel % width, y = pixel / width;
      next.push_back(y * next_width + x + width);
    }
    for ( uint32_t pixel : points )
    {
      const uint32_t x = pixel % width, y = pixel / width;
      next.push_back((y + width) * next_width + x + width);
    }
    for ( uint32_t pixel : points )
    {
      const uint32_t x = pixel % width, y = pixel / width;
      next.push_back((next_width - 1 - x) * next_width + width - 1 - y);
    }
    points.swap(next);
  }
  return points;
}

bool valid_side(uint32_t side)
{
  return side >= 2 && side <= 2048 && (side & (side - 1)) == 0;
}

uint32_t hilbert_index(uint32_t side, uint32_t x, uint32_t y)
{
  uint32_t index = 0;
  while ( side > 1 )
  {
    const uint32_t half = side / 2;
    const uint32_t quarter = half * half;
    uint32_t quadrant;
    if ( x < half && y < half )
    {
      quadrant = 0;
      std::swap(x, y);
    }
    else if ( x >= half && y < half )
    {
      quadrant = 1;
      x -= half;
    }
    else if ( x >= half )
    {
      quadrant = 2;
      x -= half;
      y -= half;
    }
    else
    {
      quadrant = 3;
      const uint32_t old_x = x;
      x = side - 1 - y;
      y = half - 1 - old_x;
    }
    index += quadrant * quarter;
    side = half;
  }
  return index;
}

void hilbert_point(uint32_t side, uint32_t index, uint32_t &x, uint32_t &y)
{
  if ( side == 1 )
  {
    x = y = 0;
    return;
  }
  const uint32_t half = side / 2;
  const uint32_t quadrant = index / (half * half);
  hilbert_point(half, index % (half * half), x, y);
  switch ( quadrant )
  {
    case 0: std::swap(x, y); break;
    case 1: x += half; break;
    case 2: x += half; y += half; break;
    case 3:
    {
      const uint32_t old_x = x;
      x = half - 1 - y;
      y = side - 1 - old_x;
      break;
    }
  }
}

class entropy_cursor_t
{
  const uint8_t *data;
  size_t length;
  size_t sample_size;
  size_t start = 0;
  std::array<unsigned, 256> counts{};
  std::array<double, 33> terms{};
  double total = 0;
  double log_base;
  double log_size;

  void rebuild(size_t position)
  {
    counts.fill(0);
    for ( size_t i = position; i < position + sample_size; ++i )
      ++counts[data[i]];
    total = 0;
    for ( unsigned count : counts )
      total += terms[count];
    start = position;
  }

public:
  entropy_cursor_t(const uint8_t *source, size_t size)
    : data(source), length(size), sample_size(std::min<size_t>(32, size)),
      log_base(std::log(double(std::max<size_t>(2, sample_size)))),
      log_size(sample_size ? std::log(double(sample_size)) : 0)
  {
    for ( unsigned i = 1; i < terms.size(); ++i )
      terms[i] = i * std::log(double(i));
    if ( sample_size != 0 )
      rebuild(0);
  }

  uint32_t color(size_t index)
  {
    if ( sample_size < 2 )
      return black;
    const size_t desired = std::min(length - sample_size,
                                    index < sample_size / 2 ? 0 : index - sample_size / 2);
    if ( desired - start >= sample_size )
      rebuild(desired);
    while ( start < desired )
    {
      const unsigned outgoing = data[start];
      unsigned count = counts[outgoing];
      total += terms[count - 1] - terms[count];
      counts[outgoing] = count - 1;
      const unsigned incoming = data[start + sample_size];
      count = counts[incoming];
      total += terms[count + 1] - terms[count];
      counts[incoming] = count + 1;
      ++start;
    }
    const double e = std::clamp((log_size - total / sample_size) / log_base, 0.0, 1.0);
    const double v = e - 0.5;
    const int red = e > 0.5 ? int(255 * std::pow(std::max(0.0, 4 * v - 4 * v * v), 4)) : 0;
    const int blue = int(255 * e * e);
    return black | (uint32_t(red) << 16) | uint32_t(blue);
  }
};
} // namespace

// Coordinate lookup without building Python's full inverse Hilbert table.
VISUALIZER_EXPORT int visualizer_hilbert_index(uint32_t side, uint32_t x, uint32_t y,
                               uint32_t *out_index) noexcept
{
  if ( out_index == nullptr || !valid_side(side) || x >= side || y >= side )
    return -1;
  *out_index = hilbert_index(side, x, y);
  return 0;
}

VISUALIZER_EXPORT int visualizer_hilbert_point(uint32_t side, uint32_t index,
                               uint32_t *out_x, uint32_t *out_y) noexcept
{
  if ( out_x == nullptr || out_y == nullptr || !valid_side(side)
    || index >= side * side )
    return -1;
  hilbert_point(side, index, *out_x, *out_y);
  return 0;
}

// Caller allocates side*side uint32_t pixels. ARGB32 integer layout matches
// QImage::Format_ARGB32 on IDA's little-endian x86-64 platforms.
VISUALIZER_EXPORT int visualizer_render_entropy(const uint8_t *data, size_t length,
                                uint32_t side, uint32_t *pixels) noexcept
{
  if ( data == nullptr || length == 0 || pixels == nullptr || !valid_side(side) )
    return -1;
  try
  {
    const auto points = hilbert_pixels(side);
    entropy_cursor_t entropy(data, length);
    size_t previous = length;
    uint32_t color = black;
    for ( size_t i = 0; i < points.size(); ++i )
    {
      const size_t source_index = i * length / points.size();
      if ( source_index != previous )
      {
        color = entropy.color(source_index);
        previous = source_index;
      }
      pixels[points[i]] = color;
    }
    return 0;
  }
  catch ( ... )
  {
    return -2;
  }
}

// blocks contains count successive 32-byte samples centered on a source byte.
VISUALIZER_EXPORT int visualizer_render_entropy_blocks(const uint8_t *blocks, size_t count,
                                       uint32_t side, uint32_t *pixels) noexcept
{
  if ( blocks == nullptr || count == 0 || pixels == nullptr || !valid_side(side) )
    return -1;
  try
  {
    const auto points = hilbert_pixels(side);
    std::vector<uint32_t> colors;
    colors.reserve(count);
    for ( size_t i = 0; i < count; ++i )
    {
      entropy_cursor_t entropy(blocks + i * 32, 32);
      colors.push_back(entropy.color(16));
    }
    for ( size_t i = 0; i < points.size(); ++i )
      pixels[points[i]] = colors[i * count / points.size()];
    return 0;
  }
  catch ( ... )
  {
    return -2;
  }
}

// Paused debugger snapshot. Invalid memory stays gray, never looks like zeros.
// compare/compare_valid may both be nullptr for a plain RAM view.
VISUALIZER_EXPORT int visualizer_render_debug(const uint8_t *data, const uint8_t *valid,
        const uint8_t *compare, const uint8_t *compare_valid,
        size_t length, uint32_t side, uint32_t *pixels) noexcept
{
  if ( data == nullptr || valid == nullptr || pixels == nullptr || length == 0
    || !valid_side(side) || (compare == nullptr) != (compare_valid == nullptr) )
    return -1;
  try
  {
    const auto points = hilbert_pixels(side);
    std::vector<uint32_t> missing(length + 1);
    for ( size_t i = 0; i < length; ++i )
      missing[i + 1] = missing[i] + (valid[i] == 0);
    entropy_cursor_t entropy(data, length);
    const size_t n = std::min<size_t>(32, length);
    size_t previous = length;
    uint32_t color = black;
    for ( size_t i = 0; i < points.size(); ++i )
    {
      const size_t at = i * length / points.size();
      if ( at != previous )
      {
        const size_t begin = std::min(length - n, at < n / 2 ? 0 : at - n / 2);
        if ( valid[at] == 0 )
          color = unreadable;
        else if ( compare != nullptr && compare_valid[at] == 0 )
          color = uncomparable;
        else if ( compare != nullptr && data[at] != compare[at] )
          color = changed;
        else if ( missing[begin + n] != missing[begin] )
          color = black; // Readable source; entropy window contains missing bytes.
        else
          color = entropy.color(at);
        previous = at;
      }
      pixels[points[i]] = color;
    }
    return 0;
  }
  catch ( ... )
  {
    return -2;
  }
}

// Blocks of 32 bytes sampled from a large debugged memory range.
VISUALIZER_EXPORT int visualizer_render_debug_blocks(const uint8_t *blocks,
        const uint8_t *valid_blocks, const uint8_t *compare_blocks,
        const uint8_t *compare_valid_blocks, size_t count,
        uint32_t side, uint32_t *pixels) noexcept
{
  if ( blocks == nullptr || valid_blocks == nullptr || pixels == nullptr || count == 0
    || !valid_side(side) || (compare_blocks == nullptr) != (compare_valid_blocks == nullptr) )
    return -1;
  try
  {
    const auto points = hilbert_pixels(side);
    std::vector<uint32_t> colors;
    colors.reserve(count);
    for ( size_t i = 0; i < count; ++i )
    {
      const size_t begin = i * 32;
      bool readable = true, comparable = true, different = false;
      for ( size_t b = 0; b < 32; ++b )
      {
        readable &= valid_blocks[begin + b] != 0;
        if ( compare_blocks != nullptr )
        {
          comparable &= compare_valid_blocks[begin + b] != 0;
          different |= blocks[begin + b] != compare_blocks[begin + b];
        }
      }
      if ( !readable )
        colors.push_back(unreadable);
      else if ( !comparable )
        colors.push_back(uncomparable);
      else if ( different )
        colors.push_back(changed);
      else
      {
        entropy_cursor_t entropy(blocks + begin, 32);
        colors.push_back(entropy.color(16));
      }
    }
    for ( size_t i = 0; i < points.size(); ++i )
      pixels[points[i]] = colors[i * count / points.size()];
    return 0;
  }
  catch ( ... )
  {
    return -2;
  }
}

// Shannon bits/byte change per aligned block; NaN means insufficient
// comparable data. Analysis stays native even for multi-megabyte snapshots.
VISUALIZER_EXPORT int visualizer_entropy_deltas(const uint8_t *current,
        const uint8_t *current_valid, const uint8_t *baseline,
        const uint8_t *baseline_valid, size_t length, uint32_t block_size,
        double *out_values) noexcept
{
  if ( current == nullptr || current_valid == nullptr || baseline == nullptr
    || baseline_valid == nullptr || out_values == nullptr
    || length == 0 || block_size < 512 )
    return -1;
  try
  {
    const size_t blocks = (length + block_size - 1) / block_size;
    for ( size_t block = 0; block < blocks; ++block )
    {
      const size_t start = block * block_size;
      const size_t stop = std::min(length, start + block_size);
      std::array<unsigned, 256> now{}, before{};
      unsigned count = 0;
      for ( size_t at = start; at < stop; ++at )
      {
        if ( current_valid[at] && baseline_valid[at] )
        {
          ++now[current[at]];
          ++before[baseline[at]];
          ++count;
        }
      }
      if ( count < 512 || size_t(count) * 4 < (stop - start) * 3 )
      {
        out_values[block] = std::numeric_limits<double>::quiet_NaN();
        continue;
      }
      double sum_now = 0, sum_before = 0;
      for ( size_t value = 0; value < 256; ++value )
      {
        if ( now[value] )
          sum_now += now[value] * std::log2(double(now[value]));
        if ( before[value] )
          sum_before += before[value] * std::log2(double(before[value]));
      }
      out_values[block] = (sum_before - sum_now) / count;
    }
    return 0;
  }
  catch ( ... )
  {
    return -2;
  }
}
