#include "blockforge/filesystem.h"
#include <cstddef>
#include <cstdint>
#include <string>

namespace {
uint32_t read32(const uint8_t *data) {
  return static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24);
}
uint64_t read64(const uint8_t *data) {
  return static_cast<uint64_t>(read32(data)) |
         (static_cast<uint64_t>(read32(data + 4)) << 32);
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 17 || size > 8 * 1024 * 1024)
    return 0;
  uint32_t image_size = read32(data);
  if (image_size > size - 4)
    return 0;
  size_t position = 4 + image_size;
  if (position >= size)
    return 0;
  uint8_t path_size = data[position++];
  if (path_size > size - position || size - position - path_size < 12)
    return 0;
  std::string path(reinterpret_cast<const char *>(data + position), path_size);
  position += path_size;
  uint64_t offset = read64(data + position);
  position += 8;
  uint32_t length = read32(data + position);
  blockforge::Limits limits;
  limits.max_image_bytes = 8 * 1024 * 1024;
  limits.max_file_bytes = 2 * 1024 * 1024;
  blockforge::Filesystem filesystem(limits);
  blockforge::MountOptions options;
  options.read_only = true;
  options.allow_dirty = true;
  options.replay_journal = false;
  blockforge::Error error;
  if (filesystem.mount(data + 4, image_size, options, error)) {
    length = std::min<uint32_t>(length, 256 * 1024);
    (void)filesystem.read(path, offset, length);
    (void)filesystem.stat(path, true, error);
  }
  return 0;
}
