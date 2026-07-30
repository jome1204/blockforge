#ifndef BLOCKFORGE_INTERNAL_H
#define BLOCKFORGE_INTERNAL_H

#include "blockforge/filesystem.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>

namespace blockforge::internal {

inline bool fail(Error &error, ErrorCode code, uint64_t offset,
                 std::string message) {
  error.code = code;
  error.offset = offset;
  error.message = std::move(message);
  return false;
}

inline uint16_t le16(const uint8_t *data) {
  return static_cast<uint16_t>(data[0]) |
         static_cast<uint16_t>(static_cast<uint16_t>(data[1]) << 8);
}

inline uint32_t le32(const uint8_t *data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}

inline uint64_t le64(const uint8_t *data) {
  return static_cast<uint64_t>(le32(data)) |
         (static_cast<uint64_t>(le32(data + 4)) << 32);
}

inline void append16(std::vector<uint8_t> &output, uint16_t value) {
  output.push_back(static_cast<uint8_t>(value));
  output.push_back(static_cast<uint8_t>(value >> 8));
}

inline void append32(std::vector<uint8_t> &output, uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8)
    output.push_back(static_cast<uint8_t>(value >> shift));
}

inline void append64(std::vector<uint8_t> &output, uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8)
    output.push_back(static_cast<uint8_t>(value >> shift));
}

inline void patch32(std::vector<uint8_t> &output, size_t offset,
                    uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8)
    output[offset + shift / 8] = static_cast<uint8_t>(value >> shift);
}

inline void patch64(std::vector<uint8_t> &output, size_t offset,
                    uint64_t value) {
  for (unsigned shift = 0; shift < 64; shift += 8)
    output[offset + shift / 8] = static_cast<uint8_t>(value >> shift);
}

inline void append_string(std::vector<uint8_t> &output,
                          std::string_view value) {
  append32(output, static_cast<uint32_t>(value.size()));
  output.insert(output.end(), value.begin(), value.end());
}

inline std::string normalize_name(std::string_view name) {
  std::string result(name);
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char value) {
                   return static_cast<char>(std::tolower(value));
                 });
  return result;
}

inline uint64_t ceil_divide(uint64_t value, uint64_t divisor) {
  return value == 0 ? 0 : 1 + (value - 1) / divisor;
}

inline uint32_t aligned_directory_length(size_t name_size) {
  uint64_t raw = 16 + name_size;
  return static_cast<uint32_t>((raw + 7) & ~uint64_t{7});
}

} // namespace blockforge::internal

#endif
