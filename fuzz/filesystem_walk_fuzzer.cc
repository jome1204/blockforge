#include "blockforge/filesystem.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  blockforge::Limits limits;
  limits.max_image_bytes = 8 * 1024 * 1024;
  limits.max_file_bytes = 2 * 1024 * 1024;
  limits.max_walk_depth = 64;
  limits.max_directory_entries = 32768;
  if (size > limits.max_image_bytes)
    return 0;
  blockforge::Filesystem filesystem(limits);
  blockforge::MountOptions options;
  options.read_only = true;
  options.allow_dirty = true;
  options.replay_journal = false;
  blockforge::Error error;
  if (!filesystem.mount(data, size, options, error))
    return 0;
  auto entries = filesystem.walk("/", error);
  if (entries) {
    for (const auto &entry : *entries) {
      (void)filesystem.stat(entry.path, false, error);
      if (entry.stat.type == blockforge::InodeType::directory)
        (void)filesystem.list(entry.path, error);
    }
  }
  return 0;
}
