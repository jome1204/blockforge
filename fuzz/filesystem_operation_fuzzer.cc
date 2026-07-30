#include "blockforge/filesystem.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  blockforge::Limits limits;
  limits.max_image_bytes = 4 * 1024 * 1024;
  limits.max_file_bytes = 512 * 1024;
  limits.max_inodes = 4096;
  limits.max_blocks = 4096;
  blockforge::Filesystem filesystem(limits);
  blockforge::FormatOptions format;
  format.block_size = 512;
  format.block_count = 256;
  format.inode_capacity = 4096;
  blockforge::Error error;
  if (!filesystem.format(format, error))
    return 0;
  const size_t count = std::min<size_t>(size, 1024);
  for (size_t index = 0; index < count; ++index) {
    uint8_t byte = data[index];
    unsigned slot = (byte >> 3) & 15u;
    std::string path = "/n" + std::to_string(slot);
    std::string other = "/n" + std::to_string((slot + 1) & 15u);
    switch (byte % 21) {
    case 0: (void)filesystem.create_directory(path); break;
    case 1: (void)filesystem.create_file(path); break;
    case 2: {
      uint8_t value[4]{byte, static_cast<uint8_t>(index),
                       static_cast<uint8_t>(byte ^ index), 0};
      (void)filesystem.write(path, byte & 31u, value, sizeof(value));
      break;
    }
    case 3: {
      uint8_t value = byte;
      (void)filesystem.write(path, byte, &value, 1);
      break;
    }
    case 4: (void)filesystem.read(path, byte, 128); break;
    case 5: (void)filesystem.remove(path); break;
    case 6: (void)filesystem.rename(path, other); break;
    case 7: (void)filesystem.create_hard_link(path, other); break;
    case 8: (void)filesystem.create_symlink(path, other); break;
    case 9: (void)filesystem.list("/", error); break;
    case 10: (void)filesystem.walk("/", error); break;
    case 11: (void)filesystem.begin(error); break;
    case 12: (void)filesystem.rollback(error); break;
    case 13: (void)filesystem.commit(error); break;
    case 14: (void)filesystem.checkpoint(error); break;
    case 15:
      (void)filesystem.set_attribute(path, "user.fuzz", {byte}, error);
      break;
    case 16: (void)filesystem.get_attribute(path, "user.fuzz", error); break;
    case 17: (void)filesystem.remove_attribute(path, "user.fuzz", error); break;
    case 18: {
      auto image = filesystem.serialize(error);
      if (!error && !image.empty()) {
        blockforge::Filesystem reopened(limits);
        blockforge::MountOptions options;
        options.allow_dirty = true;
        options.replay_journal = false;
        if (reopened.mount(image.data(), image.size(), options, error))
          filesystem = std::move(reopened);
      }
      break;
    }
    case 19: (void)filesystem.stat(path, true, error); break;
    case 20: (void)filesystem.remove(path, true); break;
    }
    (void)filesystem.invariant_hash();
  }
  return 0;
}
