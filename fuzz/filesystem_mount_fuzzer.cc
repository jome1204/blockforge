#include "blockforge/filesystem.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  blockforge::Limits limits;
  limits.max_image_bytes = 8 * 1024 * 1024;
  limits.max_file_bytes = 2 * 1024 * 1024;
  limits.max_inodes = 8192;
  limits.max_blocks = 16384;
  if (size > limits.max_image_bytes)
    return 0;
  blockforge::Filesystem filesystem(limits);
  blockforge::MountOptions options;
  options.read_only = true;
  options.allow_dirty = true;
  options.replay_journal = false;
  blockforge::Error error;
  if (filesystem.mount(data, size, options, error)) {
    (void)filesystem.list("/", error);
    (void)filesystem.stat("/", true, error);
    (void)filesystem.invariant_hash();
  }
  return 0;
}
