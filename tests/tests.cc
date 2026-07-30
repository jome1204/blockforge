#include "blockforge/filesystem.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
int failures = 0;

template <typename T> void check(const T &condition, const char *message) {
  if (!static_cast<bool>(condition)) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

blockforge::Filesystem make_filesystem() {
  blockforge::Filesystem filesystem;
  blockforge::FormatOptions options;
  options.block_size = 512;
  options.block_count = 256;
  blockforge::Error error;
  check(filesystem.format(options, error), "format filesystem");
  return filesystem;
}

void test_checked_arithmetic() {
  uint64_t output = 0;
  check(blockforge::checked_add(4, 5, output) && output == 9,
        "checked addition");
  check(!blockforge::checked_add(UINT64_MAX, 1, output),
        "addition overflow");
  check(blockforge::checked_multiply(7, 9, output) && output == 63,
        "checked multiplication");
  check(!blockforge::checked_multiply(UINT64_MAX, 2, output),
        "multiplication overflow");
}

void test_block_device() {
  blockforge::BlockDevice device;
  blockforge::Error error;
  check(device.create(512, 16, error), "block device create");
  std::vector<uint8_t> input{1, 2, 3, 4};
  check(device.write(3, 20, input.data(), input.size(), error),
        "block device write");
  std::vector<uint8_t> output(4);
  check(device.read(3, 20, output.data(), output.size(), error),
        "block device read");
  check(input == output, "block device content");
  check(!device.read(16, 0, output.data(), output.size(), error),
        "block bounds");
}

void test_allocator() {
  blockforge::BlockAllocator allocator;
  blockforge::Error error;
  check(allocator.initialize(17, {0, 1}, error), "allocator initialize");
  auto first = allocator.allocate(error);
  check(first && *first == 2, "allocator first free block");
  auto group = allocator.allocate_many(4, error);
  check(group && group->size() == 4, "allocator multiple blocks");
  check(allocator.release(*first, error), "allocator release");
  check(!allocator.is_allocated(*first), "released block is free");
  auto bitmap = allocator.bitmap();
  blockforge::BlockAllocator loaded;
  check(loaded.load(17, bitmap.data(), bitmap.size(), error),
        "allocator bitmap reload");
  check(loaded.allocated_count() == allocator.allocated_count(),
        "allocator reload state");
}

void test_operations() {
  auto filesystem = make_filesystem();
  check(filesystem.create_directory("/home"), "create directory");
  check(filesystem.create_directory("/home/user"), "nested directory");
  std::vector<uint8_t> content{'h', 'e', 'l', 'l', 'o'};
  check(filesystem.create_file("/home/user/note.txt", content),
        "create file");
  auto read = filesystem.read("/home/user/note.txt", 0, 100);
  check(read && *read.data == content, "read file content");
  std::vector<uint8_t> suffix{' ', 'w', 'o', 'r', 'l', 'd'};
  check(filesystem.write("/home/user/note.txt", 5, suffix.data(),
                         suffix.size()),
        "extend file");
  auto extended = filesystem.read("/home/user/note.txt", 0, 100);
  check(extended && std::string(extended.data->begin(), extended.data->end()) ==
                        "hello world",
        "extended file content");
  check(filesystem.create_symlink("note.txt", "/home/user/current"),
        "create relative symlink");
  auto through_link = filesystem.read("/home/user/current", 0, 100);
  check(through_link && *through_link.data == *extended.data,
        "read through symlink");
  check(filesystem.create_hard_link("/home/user/note.txt",
                                    "/home/user/alias.txt"),
        "create hard link");
  blockforge::Error error;
  auto stat = filesystem.stat("/home/user/note.txt", true, error);
  check(stat && stat->links == 2, "hard-link count");
  check(filesystem.rename("/home/user/alias.txt",
                          "/home/user/renamed.txt"),
        "rename hard link");
  auto listing = filesystem.list("/home/user", error);
  check(listing && listing->size() == 5, "directory listing with dots");
  auto walk = filesystem.walk("/", error);
  check(walk && walk->size() >= 6, "recursive walk");
  check(filesystem.remove("/home/user/renamed.txt"), "remove hard link");
  check(filesystem.remove("/home", true), "recursive remove");
}

void test_attributes() {
  auto filesystem = make_filesystem();
  check(filesystem.create_file("/document"), "attribute fixture");
  blockforge::Error error;
  check(filesystem.set_attribute(
            "/document", "user.mime",
            std::vector<uint8_t>{'t', 'e', 'x', 't'}, error),
        "set extended attribute");
  auto attribute =
      filesystem.get_attribute("/document", "user.mime", error);
  check(attribute && attribute->size() == 4, "get extended attribute");
  check(filesystem.remove_attribute("/document", "user.mime", error),
        "remove extended attribute");
  check(!filesystem.get_attribute("/document", "user.mime", error),
        "removed attribute is absent");
}

void test_transactions() {
  auto filesystem = make_filesystem();
  check(filesystem.create_file("/baseline", {1, 2, 3}),
        "transaction baseline");
  const uint64_t baseline = filesystem.invariant_hash();
  blockforge::Error error;
  check(filesystem.begin(error), "begin transaction");
  check(filesystem.create_directory("/temporary"), "transaction directory");
  check(filesystem.create_file("/temporary/file", {9, 8, 7}),
        "transaction file");
  check(filesystem.rollback(error), "rollback transaction");
  check(filesystem.invariant_hash() == baseline,
        "rollback restores invariant hash");
  check(filesystem.begin(error), "begin committed transaction");
  check(filesystem.create_file("/committed", {4, 5, 6}),
        "committed transaction file");
  check(filesystem.commit(error), "commit transaction");
  check(filesystem.invariant_hash() != baseline,
        "commit changes invariant hash");
  check(filesystem.checkpoint(error), "checkpoint filesystem");
  check(!filesystem.dirty(), "checkpoint clears dirty state");
}

void test_round_trip() {
  auto filesystem = make_filesystem();
  check(filesystem.create_directory("/tree"), "roundtrip directory");
  std::vector<uint8_t> data(3000);
  for (size_t index = 0; index < data.size(); ++index)
    data[index] = static_cast<uint8_t>((index * 29) & 0xff);
  check(filesystem.create_file("/tree/data.bin", data),
        "roundtrip large file");
  check(filesystem.create_symlink("/tree/data.bin", "/latest"),
        "roundtrip symlink");
  blockforge::Error error;
  auto image = filesystem.serialize(error);
  check(!error && !image.empty(), "serialize filesystem");
  blockforge::Filesystem reopened;
  blockforge::MountOptions options;
  options.allow_dirty = true;
  check(reopened.mount(image.data(), image.size(), options, error),
        "mount serialized filesystem");
  auto read = reopened.read("/tree/data.bin", 0, data.size() + 100);
  check(read && *read.data == data, "roundtrip data content");
  check(reopened.walk("/", error), "roundtrip tree walk");
  check(filesystem.invariant_hash() == reopened.invariant_hash(),
        "roundtrip invariant hash");
  image.back() ^= 1;
  blockforge::Filesystem corrupted;
  check(!corrupted.mount(image.data(), image.size(), options, error),
        "image checksum detects corruption");
}

void test_codecs() {
  blockforge::Limits limits;
  blockforge::Superblock superblock;
  superblock.block_size = 512;
  superblock.block_count = 32;
  blockforge::Inode inode;
  inode.identifier = 7;
  inode.type = blockforge::InodeType::regular;
  inode.mode = 0644;
  inode.link_count = 1;
  inode.size = 512;
  inode.allocated_bytes = 512;
  inode.extents.push_back({0, 3, 1, false});
  inode.attributes.push_back({"user.test", {1, 2, 3}});
  blockforge::Error error;
  blockforge::InodeCodec inode_codec(limits);
  auto encoded_inode = inode_codec.encode(inode, error);
  auto decoded_inode = inode_codec.decode(
      encoded_inode.data(), encoded_inode.size(), superblock, error);
  check(decoded_inode && decoded_inode->identifier == inode.identifier,
        "inode codec roundtrip");

  std::vector<blockforge::DirectoryEntry> entries{
      {7, blockforge::InodeType::regular, "file", 24, false},
      {8, blockforge::InodeType::symbolic_link, "link", 24, true}};
  blockforge::DirectoryCodec directory_codec(limits);
  auto encoded_directory = directory_codec.encode(entries, error);
  auto decoded_directory = directory_codec.decode(
      encoded_directory.data(), encoded_directory.size(), error);
  check(decoded_directory && decoded_directory->size() == entries.size(),
        "directory codec roundtrip");

  std::vector<blockforge::JournalRecord> records{
      {blockforge::JournalType::begin, 1, 1, 0, 0, {}, 0},
      {blockforge::JournalType::write_data, 2, 1, 7, 1, {1, 2}, 0},
      {blockforge::JournalType::commit, 3, 1, 0, 0, {}, 0}};
  blockforge::JournalCodec journal_codec(limits);
  auto encoded_journal = journal_codec.encode(records, error);
  auto decoded_journal = journal_codec.decode(
      encoded_journal.data(), encoded_journal.size(), error);
  check(decoded_journal && decoded_journal->size() == records.size(),
        "journal codec roundtrip");
}

void test_analysis() {
  auto filesystem = make_filesystem();
  check(filesystem.create_directory("/docs"), "analysis directory");
  check(filesystem.create_file("/docs/a", {1, 2, 3}), "analysis file");
  check(filesystem.create_symlink("a", "/docs/link"), "analysis symlink");
  blockforge::ConsistencyChecker checker;
  auto report = checker.check(filesystem);
  if (!report.clean())
    std::cerr << blockforge::ConsistencyChecker::text(report);
  check(report.clean(), "consistency checker accepts valid filesystem");
  blockforge::Error error;
  blockforge::StatisticsCollector statistics;
  auto values = statistics.collect(filesystem, error);
  check(!error && values.regular_files == 1 && values.directories == 2,
        "filesystem statistics");
  auto image = filesystem.serialize(error);
  auto analyzed = checker.analyze_image(image.data(), image.size());
  check(analyzed.clean(), "image consistency analysis");
  blockforge::RepairPlanner planner;
  check(planner.plan(filesystem, report).empty(),
        "clean filesystem has empty repair plan");
}
} // namespace

int main() {
  test_checked_arithmetic();
  test_block_device();
  test_allocator();
  test_operations();
  test_attributes();
  test_transactions();
  test_round_trip();
  test_codecs();
  test_analysis();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return EXIT_FAILURE;
  }
  std::cout << "All BlockForge tests passed\n";
  return EXIT_SUCCESS;
}
