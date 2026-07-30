#include "blockforge/filesystem.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  blockforge::Limits limits;
  limits.max_image_bytes = 8 * 1024 * 1024;
  limits.max_file_bytes = 2 * 1024 * 1024;
  limits.max_journal_records = 32768;
  if (size > limits.max_image_bytes)
    return 0;
  blockforge::ConsistencyChecker checker(limits);
  auto report = checker.analyze_image(data, size);
  (void)blockforge::ConsistencyChecker::text(report);
  (void)blockforge::ConsistencyChecker::json(report);
  blockforge::Filesystem filesystem(limits);
  blockforge::MountOptions options;
  options.read_only = true;
  options.allow_dirty = true;
  options.replay_journal = false;
  blockforge::Error error;
  if (filesystem.mount(data, size, options, error)) {
    auto actions = blockforge::RepairPlanner(limits).plan(filesystem, report);
    (void)blockforge::RepairPlanner::text(actions);
  }
  return 0;
}
