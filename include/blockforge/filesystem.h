#ifndef BLOCKFORGE_FILESYSTEM_H
#define BLOCKFORGE_FILESYSTEM_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace blockforge {

enum class ErrorCode {
  none,
  truncated,
  invalid_signature,
  invalid_version,
  checksum_mismatch,
  invalid_offset,
  invalid_block,
  invalid_inode,
  invalid_directory,
  invalid_extent,
  invalid_path,
  invalid_name,
  loop_detected,
  not_found,
  already_exists,
  not_directory,
  is_directory,
  directory_not_empty,
  permission_denied,
  no_space,
  overflow,
  resource_limit,
  journal_error,
  transaction_error,
  unsupported,
  internal_error
};

struct Error {
  ErrorCode code = ErrorCode::none;
  uint64_t offset = 0;
  std::string message;
  explicit operator bool() const { return code != ErrorCode::none; }
  void clear() {
    code = ErrorCode::none;
    offset = 0;
    message.clear();
  }
};

struct Limits {
  uint64_t max_image_bytes = 256ull * 1024 * 1024;
  uint64_t max_file_bytes = 64ull * 1024 * 1024;
  uint64_t max_total_file_bytes = 192ull * 1024 * 1024;
  uint64_t max_inodes = 1'000'000;
  uint64_t max_blocks = 4'000'000;
  uint64_t max_directory_entries = 1'000'000;
  uint64_t max_journal_records = 1'000'000;
  uint64_t max_extended_attribute_bytes = 4ull * 1024 * 1024;
  uint32_t max_name_bytes = 255;
  uint32_t max_path_bytes = 4096;
  uint32_t max_path_components = 256;
  uint32_t max_symlink_depth = 40;
  uint32_t max_walk_depth = 256;
  uint32_t max_extents_per_inode = 65'536;
  uint32_t max_hard_links = 65'535;
  uint32_t min_block_size = 512;
  uint32_t max_block_size = 65'536;
  uint32_t default_block_size = 4096;
};

enum class InodeType : uint8_t {
  unused = 0,
  regular = 1,
  directory = 2,
  symbolic_link = 3
};

enum class JournalType : uint16_t {
  begin = 1,
  allocate_inode = 2,
  free_inode = 3,
  allocate_block = 4,
  free_block = 5,
  write_inode = 6,
  write_directory = 7,
  write_data = 8,
  rename_entry = 9,
  commit = 10,
  rollback = 11,
  checkpoint = 12
};

struct Superblock {
  uint32_t version = 1;
  uint32_t block_size = 4096;
  uint64_t block_count = 0;
  uint64_t inode_count = 0;
  uint64_t free_block_count = 0;
  uint64_t free_inode_count = 0;
  uint64_t root_inode = 1;
  uint64_t generation = 1;
  uint64_t journal_sequence = 0;
  uint32_t feature_flags = 0;
  uint32_t checksum = 0;

  bool validate(uint64_t image_size, const Limits &limits,
                Error &error) const;
};

struct Extent {
  uint64_t logical_block = 0;
  uint64_t physical_block = 0;
  uint32_t block_count = 0;
  bool sparse = false;

  uint64_t logical_end(Error &error) const;
  uint64_t physical_end(Error &error) const;
};

struct ExtendedAttribute {
  std::string name;
  std::vector<uint8_t> value;
};

struct Inode {
  uint64_t identifier = 0;
  InodeType type = InodeType::unused;
  uint16_t mode = 0;
  uint32_t owner = 0;
  uint32_t group = 0;
  uint32_t link_count = 0;
  uint64_t size = 0;
  uint64_t allocated_bytes = 0;
  uint64_t created_time = 0;
  uint64_t modified_time = 0;
  uint64_t changed_time = 0;
  uint64_t generation = 1;
  std::vector<Extent> extents;
  std::string symlink_target;
  std::vector<ExtendedAttribute> attributes;
  bool deleted = false;

  bool validate(const Superblock &superblock, const Limits &limits,
                Error &error) const;
};

struct DirectoryEntry {
  uint64_t inode = 0;
  InodeType type = InodeType::unused;
  std::string name;
  uint32_t record_length = 0;
  bool deleted = false;

  bool validate(const Limits &limits, Error &error) const;
};

struct JournalRecord {
  JournalType type = JournalType::begin;
  uint64_t sequence = 0;
  uint64_t transaction = 0;
  uint64_t target = 0;
  uint64_t generation = 0;
  std::vector<uint8_t> payload;
  uint32_t checksum = 0;
};

class CheckedReader {
public:
  CheckedReader(const uint8_t *data, size_t size);
  size_t position() const { return position_; }
  size_t remaining() const { return size_ - position_; }
  bool seek(size_t position, Error &error);
  bool skip(size_t count, Error &error);
  bool read_u8(uint8_t &value, Error &error);
  bool read_u16(uint16_t &value, Error &error);
  bool read_u32(uint32_t &value, Error &error);
  bool read_u64(uint64_t &value, Error &error);
  bool read_bytes(size_t count, std::vector<uint8_t> &value, Error &error);
  bool read_string(size_t maximum, std::string &value, Error &error);
  const uint8_t *current() const;

private:
  const uint8_t *data_;
  size_t size_;
  size_t position_ = 0;
};

class BlockDevice {
public:
  explicit BlockDevice(Limits limits = {});
  bool create(uint32_t block_size, uint64_t block_count, Error &error);
  bool open(const uint8_t *data, size_t size, uint32_t block_size,
            Error &error);
  bool read(uint64_t block, uint32_t offset, uint8_t *output, size_t length,
            Error &error) const;
  bool write(uint64_t block, uint32_t offset, const uint8_t *input,
             size_t length, Error &error);
  bool zero(uint64_t block, Error &error);
  const uint8_t *block_data(uint64_t block) const;
  uint8_t *block_data(uint64_t block);
  uint32_t block_size() const { return block_size_; }
  uint64_t block_count() const;
  uint64_t byte_size() const { return bytes_.size(); }
  const std::vector<uint8_t> &bytes() const { return bytes_; }

private:
  Limits limits_;
  uint32_t block_size_ = 0;
  std::vector<uint8_t> bytes_;
};

class BlockAllocator {
public:
  explicit BlockAllocator(Limits limits = {});
  bool initialize(uint64_t block_count, const std::set<uint64_t> &reserved,
                  Error &error);
  bool load(uint64_t block_count, const uint8_t *bitmap, size_t size,
            Error &error);
  std::optional<uint64_t> allocate(Error &error);
  std::optional<std::vector<uint64_t>> allocate_many(uint64_t count,
                                                     Error &error);
  bool reserve(uint64_t block, Error &error);
  bool release(uint64_t block, Error &error);
  bool is_allocated(uint64_t block) const;
  uint64_t allocated_count() const;
  uint64_t free_count() const;
  uint64_t block_count() const { return block_count_; }
  std::vector<uint8_t> bitmap() const;
  bool verify(Error &error) const;

private:
  Limits limits_;
  uint64_t block_count_ = 0;
  std::vector<uint8_t> bits_;
  uint64_t search_hint_ = 0;
};

class InodeTable {
public:
  explicit InodeTable(Limits limits = {});
  bool initialize(Error &error);
  std::optional<uint64_t> allocate(InodeType type, uint16_t mode,
                                   Error &error);
  bool insert(Inode inode, Error &error);
  bool erase(uint64_t identifier, Error &error);
  const Inode *get(uint64_t identifier) const;
  Inode *get(uint64_t identifier);
  bool contains(uint64_t identifier) const;
  const std::map<uint64_t, Inode> &all() const { return inodes_; }
  uint64_t next_identifier() const { return next_identifier_; }
  void set_next_identifier(uint64_t value);
  bool verify(const Superblock &superblock, Error &error) const;

private:
  Limits limits_;
  std::map<uint64_t, Inode> inodes_;
  uint64_t next_identifier_ = 1;
};

class DirectoryTable {
public:
  explicit DirectoryTable(Limits limits = {});
  bool initialize_root(uint64_t root_inode, Error &error);
  bool load(uint64_t inode, std::vector<DirectoryEntry> entries,
            Error &error);
  bool create(uint64_t inode, uint64_t parent, Error &error);
  bool erase_directory(uint64_t inode, Error &error);
  bool add(uint64_t directory, DirectoryEntry entry, Error &error);
  bool remove(uint64_t directory, std::string_view name,
              DirectoryEntry &removed, Error &error);
  bool rename(uint64_t source_directory, std::string_view source_name,
              uint64_t target_directory, std::string target_name,
              Error &error);
  const DirectoryEntry *find(uint64_t directory, std::string_view name) const;
  DirectoryEntry *find(uint64_t directory, std::string_view name);
  const std::vector<DirectoryEntry> *entries(uint64_t directory) const;
  std::vector<DirectoryEntry> *entries(uint64_t directory);
  const std::map<uint64_t, std::vector<DirectoryEntry>> &all() const {
    return directories_;
  }
  bool verify(const InodeTable &inodes, uint64_t root_inode,
              Error &error) const;

private:
  Limits limits_;
  std::map<uint64_t, std::vector<DirectoryEntry>> directories_;
};

struct ResolvedPath {
  uint64_t inode = 0;
  uint64_t parent = 0;
  std::string name;
  std::string canonical;
  uint32_t symlinks_followed = 0;
};

class PathResolver {
public:
  explicit PathResolver(Limits limits = {});
  std::optional<ResolvedPath>
  resolve(std::string_view path, uint64_t root, uint64_t working_directory,
          const InodeTable &inodes, const DirectoryTable &directories,
          bool follow_final_symlink, Error &error) const;
  std::optional<std::pair<uint64_t, std::string>>
  resolve_parent(std::string_view path, uint64_t root,
                 uint64_t working_directory, const InodeTable &inodes,
                 const DirectoryTable &directories, Error &error) const;
  std::optional<std::string> normalize(std::string_view path,
                                       Error &error) const;
  std::vector<std::string> split(std::string_view path, Error &error) const;

private:
  Limits limits_;
};

struct BlockMapping {
  uint64_t logical_block = 0;
  std::optional<uint64_t> physical_block;
  uint32_t contiguous_blocks = 0;
};

class ExtentResolver {
public:
  explicit ExtentResolver(Limits limits = {});
  std::optional<BlockMapping> map(const Inode &inode, uint64_t logical_block,
                                  const Superblock &superblock,
                                  Error &error) const;
  bool normalize(std::vector<Extent> &extents, const Superblock &superblock,
                 Error &error) const;
  bool verify(const Inode &inode, const Superblock &superblock,
              Error &error) const;
  std::set<uint64_t> physical_blocks(const Inode &inode,
                                     const Superblock &superblock,
                                     Error &error) const;

private:
  Limits limits_;
};

class InodeCodec {
public:
  explicit InodeCodec(Limits limits = {});
  std::vector<uint8_t> encode(const Inode &inode, Error &error) const;
  std::optional<Inode> decode(const uint8_t *data, size_t size,
                              const Superblock &superblock,
                              Error &error) const;

private:
  Limits limits_;
};

class DirectoryCodec {
public:
  explicit DirectoryCodec(Limits limits = {});
  std::vector<uint8_t> encode(const std::vector<DirectoryEntry> &entries,
                              Error &error) const;
  std::optional<std::vector<DirectoryEntry>>
  decode(const uint8_t *data, size_t size, Error &error) const;

private:
  Limits limits_;
};

class JournalCodec {
public:
  explicit JournalCodec(Limits limits = {});
  std::vector<uint8_t> encode(const std::vector<JournalRecord> &records,
                              Error &error) const;
  std::optional<std::vector<JournalRecord>>
  decode(const uint8_t *data, size_t size, Error &error) const;

private:
  Limits limits_;
};

class Journal {
public:
  explicit Journal(Limits limits = {});
  bool begin(Error &error);
  bool append(JournalType type, uint64_t target,
              std::vector<uint8_t> payload, Error &error);
  bool commit(Error &error);
  bool rollback(Error &error);
  bool checkpoint(Error &error);
  bool load(std::vector<JournalRecord> records, Error &error);
  const std::vector<JournalRecord> &records() const { return records_; }
  uint64_t active_transaction() const { return active_transaction_; }
  uint64_t next_sequence() const { return next_sequence_; }
  bool active() const { return active_transaction_ != 0; }
  void clear();

private:
  Limits limits_;
  uint64_t next_sequence_ = 1;
  uint64_t next_transaction_ = 1;
  uint64_t active_transaction_ = 0;
  std::vector<JournalRecord> records_;
};

struct MountOptions {
  bool read_only = false;
  bool replay_journal = true;
  bool allow_dirty = false;
  bool validate_checksums = true;
};

struct FormatOptions {
  uint32_t block_size = 4096;
  uint64_t block_count = 256;
  uint64_t inode_capacity = 1024;
  uint64_t journal_blocks = 8;
  std::string label = "BlockForge";
};

struct FileStat {
  uint64_t inode = 0;
  InodeType type = InodeType::unused;
  uint64_t size = 0;
  uint64_t allocated_bytes = 0;
  uint32_t links = 0;
  uint16_t mode = 0;
  uint64_t generation = 0;
};

struct WalkEntry {
  std::string path;
  FileStat stat;
  uint32_t depth = 0;
};

struct OperationResult {
  bool success = false;
  uint64_t affected_inode = 0;
  uint64_t bytes_processed = 0;
  Error error;
  explicit operator bool() const { return success; }
};

struct ReadResult {
  std::optional<std::vector<uint8_t>> data;
  Error error;
  explicit operator bool() const { return data.has_value(); }
};

class Filesystem {
public:
  explicit Filesystem(Limits limits = {});
  ~Filesystem();
  Filesystem(Filesystem &&) noexcept;
  Filesystem &operator=(Filesystem &&) noexcept;
  Filesystem(const Filesystem &) = delete;
  Filesystem &operator=(const Filesystem &) = delete;
  bool format(const FormatOptions &options, Error &error);
  bool mount(const uint8_t *data, size_t size, const MountOptions &options,
             Error &error);
  std::vector<uint8_t> serialize(Error &error) const;
  OperationResult create_directory(std::string_view path, uint16_t mode = 0755);
  OperationResult create_file(std::string_view path,
                              const std::vector<uint8_t> &content = {},
                              uint16_t mode = 0644);
  OperationResult create_symlink(std::string_view target,
                                 std::string_view path);
  OperationResult create_hard_link(std::string_view existing,
                                   std::string_view path);
  OperationResult remove(std::string_view path, bool recursive = false);
  OperationResult rename(std::string_view source, std::string_view target);
  OperationResult write(std::string_view path, uint64_t offset,
                        const uint8_t *data, size_t size);
  ReadResult read(std::string_view path, uint64_t offset, size_t size) const;
  std::optional<FileStat> stat(std::string_view path, bool follow_symlink,
                               Error &error) const;
  std::optional<std::vector<DirectoryEntry>>
  list(std::string_view path, Error &error) const;
  std::optional<std::vector<WalkEntry>>
  walk(std::string_view path, Error &error) const;
  bool set_attribute(std::string_view path, std::string name,
                     std::vector<uint8_t> value, Error &error);
  std::optional<std::vector<uint8_t>>
  get_attribute(std::string_view path, std::string_view name,
                Error &error) const;
  bool remove_attribute(std::string_view path, std::string_view name,
                        Error &error);
  bool begin(Error &error);
  bool commit(Error &error);
  bool rollback(Error &error);
  bool checkpoint(Error &error);
  const Superblock &superblock() const { return superblock_; }
  const InodeTable &inodes() const { return inodes_; }
  const DirectoryTable &directories() const { return directories_; }
  const BlockAllocator &allocator() const { return allocator_; }
  const Journal &journal() const { return journal_; }
  const BlockDevice &device() const { return device_; }
  uint64_t invariant_hash() const;
  bool read_only() const { return read_only_; }
  bool dirty() const { return dirty_; }

private:
  struct Snapshot;
  OperationResult create_node(std::string_view path, InodeType type,
                              uint16_t mode,
                              const std::vector<uint8_t> &content,
                              std::string symlink);
  bool resize_inode(Inode &inode, uint64_t size, Error &error);
  bool read_inode_data(const Inode &inode, uint64_t offset, size_t size,
                       std::vector<uint8_t> &output, Error &error) const;
  bool write_inode_data(Inode &inode, uint64_t offset, const uint8_t *data,
                        size_t size, Error &error);
  bool release_inode_blocks(Inode &inode, Error &error);
  bool ensure_writable(Error &error) const;
  void refresh_counts();
  Limits limits_;
  Superblock superblock_;
  BlockDevice device_;
  BlockAllocator allocator_;
  InodeTable inodes_;
  DirectoryTable directories_;
  Journal journal_;
  bool mounted_ = false;
  bool read_only_ = false;
  bool dirty_ = false;
  std::unique_ptr<Snapshot> snapshot_;
};

enum class IssueSeverity { information, warning, error, fatal };

enum class IssueCode {
  superblock_invalid,
  block_bitmap_mismatch,
  duplicate_block,
  unreferenced_block,
  missing_inode,
  orphan_inode,
  invalid_link_count,
  invalid_directory_entry,
  directory_cycle,
  extent_overlap,
  extent_out_of_range,
  size_mismatch,
  invalid_symlink,
  journal_sequence,
  journal_transaction,
  checksum_failure
};

struct ConsistencyIssue {
  IssueSeverity severity = IssueSeverity::information;
  IssueCode code = IssueCode::superblock_invalid;
  uint64_t inode = 0;
  uint64_t block = 0;
  std::string path;
  std::string message;
  bool repairable = false;
};

struct CheckReport {
  uint64_t inodes_scanned = 0;
  uint64_t directories_scanned = 0;
  uint64_t blocks_referenced = 0;
  uint64_t journal_records_scanned = 0;
  uint64_t files = 0;
  uint64_t directories = 0;
  uint64_t symlinks = 0;
  std::vector<ConsistencyIssue> issues;
  bool clean() const;
};

class ConsistencyChecker {
public:
  explicit ConsistencyChecker(Limits limits = {});
  CheckReport check(const Filesystem &filesystem) const;
  CheckReport analyze_image(const uint8_t *data, size_t size) const;
  static std::string text(const CheckReport &report);
  static std::string json(const CheckReport &report);

private:
  Limits limits_;
};

struct RepairAction {
  enum class Kind {
    release_block,
    reserve_block,
    remove_directory_entry,
    update_link_count,
    truncate_extent,
    reconnect_inode,
    clear_journal
  };
  Kind kind = Kind::release_block;
  uint64_t inode = 0;
  uint64_t block = 0;
  uint64_t value = 0;
  std::string path;
  std::string explanation;
};

class RepairPlanner {
public:
  explicit RepairPlanner(Limits limits = {});
  std::vector<RepairAction> plan(const Filesystem &filesystem,
                                 const CheckReport &report) const;
  static std::string text(const std::vector<RepairAction> &actions);

private:
  Limits limits_;
};

struct ImageStatistics {
  uint64_t image_bytes = 0;
  uint64_t allocated_blocks = 0;
  uint64_t free_blocks = 0;
  uint64_t allocated_inodes = 0;
  uint64_t logical_file_bytes = 0;
  uint64_t physical_file_bytes = 0;
  uint64_t regular_files = 0;
  uint64_t directories = 0;
  uint64_t symbolic_links = 0;
  uint64_t hard_links = 0;
  uint64_t sparse_files = 0;
  uint64_t fragmented_files = 0;
  uint64_t extended_attributes = 0;
  uint64_t journal_records = 0;
};

class StatisticsCollector {
public:
  explicit StatisticsCollector(Limits limits = {});
  ImageStatistics collect(const Filesystem &filesystem, Error &error) const;
  static std::string text(const ImageStatistics &statistics);
  static std::string json(const ImageStatistics &statistics);

private:
  Limits limits_;
};

class ImageDiff {
public:
  struct Change {
    enum class Kind { added, removed, metadata, content, type };
    Kind kind = Kind::added;
    std::string path;
    std::string detail;
  };
  explicit ImageDiff(Limits limits = {});
  std::vector<Change> compare(const Filesystem &left,
                              const Filesystem &right,
                              Error &error) const;
  static std::string text(const std::vector<Change> &changes);

private:
  Limits limits_;
};

uint32_t crc32(const uint8_t *data, size_t size);
uint64_t hash64(const uint8_t *data, size_t size);
std::string error_code_name(ErrorCode code);
std::string inode_type_name(InodeType type);
std::string issue_code_name(IssueCode code);
bool checked_add(uint64_t left, uint64_t right, uint64_t &output);
bool checked_multiply(uint64_t left, uint64_t right, uint64_t &output);

} // namespace blockforge

#endif
