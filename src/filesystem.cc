#include "internal.h"

#include <deque>

namespace blockforge {
namespace {
constexpr size_t kHeaderSize = 112;

OperationResult failed_result(Error error) {
  OperationResult result;
  result.error = std::move(error);
  return result;
}

OperationResult failed_result(ErrorCode code, uint64_t offset,
                              std::string message) {
  Error error;
  internal::fail(error, code, offset, std::move(message));
  return failed_result(std::move(error));
}

OperationResult successful_result(uint64_t inode, uint64_t bytes = 0) {
  OperationResult result;
  result.success = true;
  result.affected_inode = inode;
  result.bytes_processed = bytes;
  return result;
}

std::vector<uint8_t> encode_inodes(const InodeTable &table,
                                   const Limits &limits, Error &error) {
  std::vector<uint8_t> output;
  internal::append32(output, static_cast<uint32_t>(table.all().size()));
  InodeCodec codec(limits);
  for (const auto &entry : table.all()) {
    auto encoded = codec.encode(entry.second, error);
    if (error)
      return {};
    internal::append32(output, static_cast<uint32_t>(encoded.size()));
    output.insert(output.end(), encoded.begin(), encoded.end());
  }
  return output;
}

std::vector<uint8_t> encode_directories(const DirectoryTable &table,
                                        const Limits &limits, Error &error) {
  std::vector<uint8_t> output;
  internal::append32(output, static_cast<uint32_t>(table.all().size()));
  DirectoryCodec codec(limits);
  for (const auto &entry : table.all()) {
    auto encoded = codec.encode(entry.second, error);
    if (error)
      return {};
    internal::append64(output, entry.first);
    internal::append32(output, static_cast<uint32_t>(encoded.size()));
    output.insert(output.end(), encoded.begin(), encoded.end());
  }
  return output;
}

bool slice_section(const uint8_t *data, size_t size, size_t &position,
                   uint64_t length, const uint8_t *&section, Error &error) {
  if (length > size - position ||
      length > std::numeric_limits<size_t>::max())
    return internal::fail(error, ErrorCode::invalid_offset, position,
                          "filesystem section exceeds image");
  section = data + position;
  position += static_cast<size_t>(length);
  return true;
}
} // namespace

struct Filesystem::Snapshot {
  Superblock superblock;
  BlockDevice device;
  BlockAllocator allocator;
  InodeTable inodes;
  DirectoryTable directories;
  bool dirty = false;
};

Filesystem::Filesystem(Limits limits)
    : limits_(limits), device_(limits), allocator_(limits), inodes_(limits),
      directories_(limits), journal_(limits) {}

Filesystem::~Filesystem() = default;
Filesystem::Filesystem(Filesystem &&) noexcept = default;
Filesystem &Filesystem::operator=(Filesystem &&) noexcept = default;

bool Filesystem::format(const FormatOptions &options, Error &error) {
  error.clear();
  if (options.block_count < 8 ||
      options.block_count > limits_.max_blocks ||
      options.inode_capacity == 0 ||
      options.inode_capacity > limits_.max_inodes ||
      options.journal_blocks >= options.block_count)
    return internal::fail(error, ErrorCode::resource_limit, 0,
                          "format geometry exceeds resource limits");
  if (!device_.create(options.block_size, options.block_count, error))
    return false;
  std::set<uint64_t> reserved{0};
  if (!allocator_.initialize(options.block_count, reserved, error) ||
      !inodes_.initialize(error))
    return false;
  auto root = inodes_.allocate(InodeType::directory, 0755, error);
  if (!root || !directories_.initialize_root(*root, error))
    return false;
  superblock_ = {};
  superblock_.block_size = options.block_size;
  superblock_.block_count = options.block_count;
  superblock_.root_inode = *root;
  superblock_.inode_count = 1;
  superblock_.free_inode_count = options.inode_capacity - 1;
  superblock_.free_block_count = allocator_.free_count();
  superblock_.generation = 1;
  journal_.clear();
  mounted_ = true;
  read_only_ = false;
  dirty_ = false;
  snapshot_.reset();
  return true;
}

std::vector<uint8_t> Filesystem::serialize(Error &error) const {
  error.clear();
  if (!mounted_) {
    internal::fail(error, ErrorCode::internal_error, 0,
                   "filesystem is not mounted");
    return {};
  }
  auto bitmap = allocator_.bitmap();
  auto inode_section = encode_inodes(inodes_, limits_, error);
  if (error)
    return {};
  auto directory_section =
      encode_directories(directories_, limits_, error);
  if (error)
    return {};
  auto journal_section =
      JournalCodec(limits_).encode(journal_.records(), error);
  if (error)
    return {};
  uint64_t total = kHeaderSize;
  for (uint64_t length :
       {static_cast<uint64_t>(bitmap.size()),
        static_cast<uint64_t>(inode_section.size()),
        static_cast<uint64_t>(directory_section.size()),
        static_cast<uint64_t>(journal_section.size()),
        static_cast<uint64_t>(device_.bytes().size())})
    if (!checked_add(total, length, total) ||
        total > limits_.max_image_bytes) {
      internal::fail(error, ErrorCode::resource_limit, total,
                     "serialized filesystem exceeds image limit");
      return {};
    }
  std::vector<uint8_t> output(kHeaderSize, 0);
  std::memcpy(output.data(), "BFIMG1\0\0", 8);
  internal::patch32(output, 8, 1);
  internal::patch32(output, 12, superblock_.block_size);
  internal::patch64(output, 16, superblock_.block_count);
  internal::patch64(output, 24, inodes_.all().size());
  internal::patch64(output, 32, superblock_.root_inode);
  internal::patch64(output, 40, superblock_.generation);
  internal::patch64(output, 48, bitmap.size());
  internal::patch64(output, 56, inode_section.size());
  internal::patch64(output, 64, directory_section.size());
  internal::patch64(output, 72, journal_section.size());
  internal::patch64(output, 80, device_.bytes().size());
  internal::patch64(output, 88, inodes_.next_identifier());
  internal::patch32(output, 100, dirty_ ? 1u : 0u);
  output.insert(output.end(), bitmap.begin(), bitmap.end());
  output.insert(output.end(), inode_section.begin(), inode_section.end());
  output.insert(output.end(), directory_section.begin(),
                directory_section.end());
  output.insert(output.end(), journal_section.begin(), journal_section.end());
  output.insert(output.end(), device_.bytes().begin(), device_.bytes().end());
  internal::patch32(output, 96,
                    crc32(output.data() + kHeaderSize,
                          output.size() - kHeaderSize));
  return output;
}

bool Filesystem::mount(const uint8_t *data, size_t size,
                       const MountOptions &options, Error &error) {
  error.clear();
  if (size < kHeaderSize || size > limits_.max_image_bytes ||
      std::memcmp(data, "BFIMG1\0\0", 8) != 0)
    return internal::fail(
        error, size < kHeaderSize ? ErrorCode::truncated
                                 : ErrorCode::invalid_signature,
        0, "filesystem image header is invalid");
  if (internal::le32(data + 8) != 1)
    return internal::fail(error, ErrorCode::invalid_version, 8,
                          "filesystem image version is unsupported");
  uint32_t block_size = internal::le32(data + 12);
  uint64_t block_count = internal::le64(data + 16);
  uint64_t inode_count = internal::le64(data + 24);
  uint64_t root_inode = internal::le64(data + 32);
  uint64_t generation = internal::le64(data + 40);
  uint64_t bitmap_size = internal::le64(data + 48);
  uint64_t inode_size = internal::le64(data + 56);
  uint64_t directory_size = internal::le64(data + 64);
  uint64_t journal_size = internal::le64(data + 72);
  uint64_t device_size = internal::le64(data + 80);
  uint64_t next_inode = internal::le64(data + 88);
  uint32_t flags = internal::le32(data + 100);
  if ((flags & ~1u) != 0 || inode_count > limits_.max_inodes ||
      bitmap_size != internal::ceil_divide(block_count, 8))
    return internal::fail(error, ErrorCode::resource_limit, 16,
                          "filesystem header counts are invalid");
  uint64_t expected_device = 0;
  if (!checked_multiply(block_size, block_count, expected_device) ||
      expected_device != device_size)
    return internal::fail(error, ErrorCode::overflow, 16,
                          "filesystem device geometry is inconsistent");
  if (options.validate_checksums &&
      crc32(data + kHeaderSize, size - kHeaderSize) !=
          internal::le32(data + 96))
    return internal::fail(error, ErrorCode::checksum_mismatch, 96,
                          "filesystem image body checksum mismatch");
  if ((flags & 1u) != 0 && !options.allow_dirty &&
      !options.replay_journal)
    return internal::fail(error, ErrorCode::journal_error, 100,
                          "dirty image requires journal replay");

  size_t position = kHeaderSize;
  const uint8_t *bitmap = nullptr;
  const uint8_t *inode_data = nullptr;
  const uint8_t *directory_data = nullptr;
  const uint8_t *journal_data = nullptr;
  const uint8_t *device_data = nullptr;
  if (!slice_section(data, size, position, bitmap_size, bitmap, error) ||
      !slice_section(data, size, position, inode_size, inode_data, error) ||
      !slice_section(data, size, position, directory_size, directory_data,
                     error) ||
      !slice_section(data, size, position, journal_size, journal_data,
                     error) ||
      !slice_section(data, size, position, device_size, device_data, error))
    return false;
  if (position != size)
    return internal::fail(error, ErrorCode::invalid_offset, position,
                          "filesystem image has trailing bytes");

  BlockDevice loaded_device(limits_);
  BlockAllocator loaded_allocator(limits_);
  InodeTable loaded_inodes(limits_);
  DirectoryTable loaded_directories(limits_);
  Journal loaded_journal(limits_);
  if (!loaded_device.open(device_data, static_cast<size_t>(device_size),
                          block_size, error) ||
      !loaded_allocator.load(block_count, bitmap,
                             static_cast<size_t>(bitmap_size), error) ||
      !loaded_inodes.initialize(error))
    return false;

  Superblock loaded_superblock;
  loaded_superblock.block_size = block_size;
  loaded_superblock.block_count = block_count;
  loaded_superblock.inode_count = inode_count;
  loaded_superblock.root_inode = root_inode;
  loaded_superblock.generation = generation;
  loaded_superblock.free_block_count = loaded_allocator.free_count();
  loaded_superblock.free_inode_count =
      limits_.max_inodes > inode_count ? limits_.max_inodes - inode_count : 0;

  CheckedReader inode_reader(inode_data, static_cast<size_t>(inode_size));
  uint32_t encoded_inodes = 0;
  if (!inode_reader.read_u32(encoded_inodes, error) ||
      encoded_inodes != inode_count)
    return internal::fail(error, ErrorCode::invalid_inode,
                          inode_reader.position(),
                          "inode section count is inconsistent");
  InodeCodec inode_codec(limits_);
  for (uint32_t index = 0; index < encoded_inodes; ++index) {
    uint32_t length = 0;
    if (!inode_reader.read_u32(length, error) ||
        length > inode_reader.remaining())
      return internal::fail(error, ErrorCode::truncated,
                            inode_reader.position(),
                            "inode section record is truncated");
    auto inode = inode_codec.decode(inode_reader.current(), length,
                                    loaded_superblock, error);
    if (!inode || !inode_reader.skip(length, error) ||
        !loaded_inodes.insert(std::move(*inode), error))
      return false;
  }
  if (inode_reader.remaining() != 0)
    return internal::fail(error, ErrorCode::invalid_offset,
                          inode_reader.position(),
                          "inode section has trailing bytes");
  loaded_inodes.set_next_identifier(next_inode);

  CheckedReader directory_reader(
      directory_data, static_cast<size_t>(directory_size));
  uint32_t directory_count = 0;
  if (!directory_reader.read_u32(directory_count, error) ||
      directory_count > inode_count)
    return internal::fail(error, ErrorCode::invalid_directory,
                          directory_reader.position(),
                          "directory section count is invalid");
  DirectoryCodec directory_codec(limits_);
  for (uint32_t index = 0; index < directory_count; ++index) {
    uint64_t identifier = 0;
    uint32_t length = 0;
    if (!directory_reader.read_u64(identifier, error) ||
        !directory_reader.read_u32(length, error) ||
        length > directory_reader.remaining())
      return internal::fail(error, ErrorCode::truncated,
                            directory_reader.position(),
                            "directory section record is truncated");
    auto entries = directory_codec.decode(directory_reader.current(), length,
                                          error);
    if (!entries || !directory_reader.skip(length, error) ||
        !loaded_directories.load(identifier, std::move(*entries), error))
      return false;
  }
  if (directory_reader.remaining() != 0)
    return internal::fail(error, ErrorCode::invalid_offset,
                          directory_reader.position(),
                          "directory section has trailing bytes");
  auto records = JournalCodec(limits_).decode(
      journal_data, static_cast<size_t>(journal_size), error);
  if (!records || !loaded_journal.load(std::move(*records), error))
    return false;
  if (!loaded_inodes.verify(loaded_superblock, error) ||
      !loaded_directories.verify(loaded_inodes, root_inode, error) ||
      !loaded_allocator.verify(error))
    return false;

  device_ = std::move(loaded_device);
  allocator_ = std::move(loaded_allocator);
  inodes_ = std::move(loaded_inodes);
  directories_ = std::move(loaded_directories);
  journal_ = std::move(loaded_journal);
  superblock_ = loaded_superblock;
  mounted_ = true;
  read_only_ = options.read_only;
  dirty_ = (flags & 1u) != 0;
  snapshot_.reset();
  if (options.replay_journal && journal_.active()) {
    if (!options.allow_dirty)
      return internal::fail(error, ErrorCode::journal_error,
                            journal_.active_transaction(),
                            "image ends with an incomplete transaction");
  }
  refresh_counts();
  return true;
}

bool Filesystem::ensure_writable(Error &error) const {
  error.clear();
  if (!mounted_)
    return internal::fail(error, ErrorCode::internal_error, 0,
                          "filesystem is not mounted");
  if (read_only_)
    return internal::fail(error, ErrorCode::permission_denied, 0,
                          "filesystem is mounted read-only");
  return true;
}

void Filesystem::refresh_counts() {
  superblock_.inode_count = inodes_.all().size();
  superblock_.free_block_count = allocator_.free_count();
  superblock_.free_inode_count =
      limits_.max_inodes > inodes_.all().size()
          ? limits_.max_inodes - inodes_.all().size()
          : 0;
}

OperationResult Filesystem::create_node(std::string_view path, InodeType type,
                                        uint16_t mode,
                                        const std::vector<uint8_t> &content,
                                        std::string symlink) {
  Error error;
  if (!ensure_writable(error))
    return failed_result(std::move(error));
  auto parent = PathResolver(limits_).resolve_parent(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, error);
  if (!parent)
    return failed_result(std::move(error));
  if (directories_.find(parent->first, parent->second))
    return failed_result(ErrorCode::already_exists, parent->first,
                         "path already exists");
  auto identifier = inodes_.allocate(type, mode, error);
  if (!identifier)
    return failed_result(std::move(error));
  Inode *inode = inodes_.get(*identifier);
  if (type == InodeType::symbolic_link) {
    if (symlink.empty() || symlink.size() > limits_.max_path_bytes) {
      Error ignored;
      inodes_.erase(*identifier, ignored);
      return failed_result(ErrorCode::invalid_path, 0,
                           "symbolic-link target is invalid");
    }
    inode->symlink_target = std::move(symlink);
    inode->size = inode->symlink_target.size();
  }
  if (type == InodeType::directory &&
      !directories_.create(*identifier, parent->first, error)) {
    Error ignored;
    inodes_.erase(*identifier, ignored);
    return failed_result(std::move(error));
  }
  if (!directories_.add(
          parent->first,
          {*identifier, type, parent->second,
           internal::aligned_directory_length(parent->second.size()), false},
          error)) {
    Error ignored;
    if (type == InodeType::directory)
      directories_.erase_directory(*identifier, ignored);
    inodes_.erase(*identifier, ignored);
    return failed_result(std::move(error));
  }
  if (type == InodeType::regular && !content.empty() &&
      !write_inode_data(*inode, 0, content.data(), content.size(), error)) {
    DirectoryEntry ignored_entry;
    Error ignored;
    directories_.remove(parent->first, parent->second, ignored_entry, ignored);
    release_inode_blocks(*inode, ignored);
    inodes_.erase(*identifier, ignored);
    return failed_result(std::move(error));
  }
  if (journal_.active()) {
    std::vector<uint8_t> payload(parent->second.begin(),
                                 parent->second.end());
    if (!journal_.append(JournalType::allocate_inode, *identifier,
                         std::move(payload), error))
      return failed_result(std::move(error));
  }
  dirty_ = true;
  ++superblock_.generation;
  refresh_counts();
  return successful_result(*identifier, content.size());
}

OperationResult Filesystem::create_directory(std::string_view path,
                                              uint16_t mode) {
  return create_node(path, InodeType::directory, mode, {}, {});
}

OperationResult Filesystem::create_file(
    std::string_view path, const std::vector<uint8_t> &content,
    uint16_t mode) {
  return create_node(path, InodeType::regular, mode, content, {});
}

OperationResult Filesystem::create_symlink(std::string_view target,
                                            std::string_view path) {
  return create_node(path, InodeType::symbolic_link, 0777, {},
                     std::string(target));
}

OperationResult Filesystem::create_hard_link(std::string_view existing,
                                              std::string_view path) {
  Error error;
  if (!ensure_writable(error))
    return failed_result(std::move(error));
  auto source = PathResolver(limits_).resolve(
      existing, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, false, error);
  if (!source)
    return failed_result(std::move(error));
  Inode *inode = inodes_.get(source->inode);
  if (!inode || inode->type == InodeType::directory)
    return failed_result(ErrorCode::permission_denied, source->inode,
                         "hard links to directories are forbidden");
  if (inode->link_count >= limits_.max_hard_links)
    return failed_result(ErrorCode::resource_limit, source->inode,
                         "inode hard-link limit reached");
  auto parent = PathResolver(limits_).resolve_parent(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, error);
  if (!parent)
    return failed_result(std::move(error));
  if (!directories_.add(
          parent->first,
          {inode->identifier, inode->type, parent->second,
           internal::aligned_directory_length(parent->second.size()), false},
          error))
    return failed_result(std::move(error));
  ++inode->link_count;
  ++inode->generation;
  dirty_ = true;
  ++superblock_.generation;
  return successful_result(inode->identifier);
}

bool Filesystem::resize_inode(Inode &inode, uint64_t size, Error &error) {
  error.clear();
  if (size > limits_.max_file_bytes)
    return internal::fail(error, ErrorCode::resource_limit, size,
                          "file size exceeds limit");
  uint64_t old_blocks =
      internal::ceil_divide(inode.size, superblock_.block_size);
  uint64_t new_blocks =
      internal::ceil_divide(size, superblock_.block_size);
  if (new_blocks > old_blocks) {
    uint64_t needed = new_blocks - old_blocks;
    auto blocks = allocator_.allocate_many(needed, error);
    if (!blocks)
      return false;
    for (uint64_t block : *blocks) {
      if (!device_.zero(block, error))
        return false;
      Extent extent{old_blocks++, block, 1, false};
      inode.extents.push_back(extent);
    }
    if (!ExtentResolver(limits_).normalize(inode.extents, superblock_,
                                           error))
      return false;
  } else if (new_blocks < old_blocks) {
    std::vector<Extent> retained;
    for (Extent extent : inode.extents) {
      Error end_error;
      uint64_t end = extent.logical_end(end_error);
      if (end_error) {
        error = std::move(end_error);
        return false;
      }
      if (extent.logical_block >= new_blocks) {
        if (!extent.sparse)
          for (uint32_t index = 0; index < extent.block_count; ++index)
            if (!allocator_.release(extent.physical_block + index, error))
              return false;
        continue;
      }
      if (end > new_blocks) {
        uint32_t keep =
            static_cast<uint32_t>(new_blocks - extent.logical_block);
        if (!extent.sparse)
          for (uint32_t index = keep; index < extent.block_count; ++index)
            if (!allocator_.release(extent.physical_block + index, error))
              return false;
        extent.block_count = keep;
      }
      retained.push_back(extent);
    }
    inode.extents = std::move(retained);
  }
  inode.size = size;
  uint64_t physical_blocks = 0;
  for (const Extent &extent : inode.extents)
    if (!extent.sparse)
      physical_blocks += extent.block_count;
  if (!checked_multiply(physical_blocks, superblock_.block_size,
                        inode.allocated_bytes))
    return internal::fail(error, ErrorCode::overflow, inode.identifier,
                          "allocated byte count overflows");
  ++inode.generation;
  return true;
}

bool Filesystem::write_inode_data(Inode &inode, uint64_t offset,
                                  const uint8_t *data, size_t size,
                                  Error &error) {
  error.clear();
  uint64_t end = 0;
  if (!checked_add(offset, size, end) || end > limits_.max_file_bytes)
    return internal::fail(error, ErrorCode::overflow, offset,
                          "write range exceeds file limit");
  if (end > inode.size && !resize_inode(inode, end, error))
    return false;
  size_t consumed = 0;
  while (consumed < size) {
    uint64_t absolute = offset + consumed;
    uint64_t logical = absolute / superblock_.block_size;
    uint32_t within =
        static_cast<uint32_t>(absolute % superblock_.block_size);
    size_t chunk =
        std::min<size_t>(size - consumed, superblock_.block_size - within);
    auto mapping =
        ExtentResolver(limits_).map(inode, logical, superblock_, error);
    if (!mapping || !mapping->physical_block)
      return internal::fail(error, ErrorCode::invalid_extent, logical,
                            "write maps to a sparse or missing extent");
    if (!device_.write(*mapping->physical_block, within, data + consumed,
                       chunk, error))
      return false;
    consumed += chunk;
  }
  return true;
}

bool Filesystem::read_inode_data(const Inode &inode, uint64_t offset,
                                 size_t size, std::vector<uint8_t> &output,
                                 Error &error) const {
  error.clear();
  if (offset >= inode.size || size == 0) {
    output.clear();
    return true;
  }
  uint64_t available = inode.size - offset;
  size_t requested =
      static_cast<size_t>(std::min<uint64_t>(available, size));
  output.assign(requested, 0);
  size_t consumed = 0;
  while (consumed < requested) {
    uint64_t absolute = offset + consumed;
    uint64_t logical = absolute / superblock_.block_size;
    uint32_t within =
        static_cast<uint32_t>(absolute % superblock_.block_size);
    size_t chunk = std::min<size_t>(
        requested - consumed, superblock_.block_size - within);
    auto mapping =
        ExtentResolver(limits_).map(inode, logical, superblock_, error);
    if (!mapping)
      return false;
    if (mapping->physical_block &&
        !device_.read(*mapping->physical_block, within,
                      output.data() + consumed, chunk, error))
      return false;
    consumed += chunk;
  }
  return true;
}

OperationResult Filesystem::write(std::string_view path, uint64_t offset,
                                  const uint8_t *data, size_t size) {
  Error error;
  if (!ensure_writable(error))
    return failed_result(std::move(error));
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!resolved)
    return failed_result(std::move(error));
  Inode *inode = inodes_.get(resolved->inode);
  if (!inode || inode->type != InodeType::regular)
    return failed_result(inode && inode->type == InodeType::directory
                             ? ErrorCode::is_directory
                             : ErrorCode::invalid_inode,
                         resolved->inode,
                         "write target is not a regular file");
  if (!write_inode_data(*inode, offset, data, size, error))
    return failed_result(std::move(error));
  if (journal_.active()) {
    std::vector<uint8_t> payload;
    internal::append64(payload, offset);
    internal::append64(payload, size);
    if (!journal_.append(JournalType::write_data, inode->identifier,
                         std::move(payload), error))
      return failed_result(std::move(error));
  }
  dirty_ = true;
  ++superblock_.generation;
  refresh_counts();
  return successful_result(inode->identifier, size);
}

ReadResult Filesystem::read(std::string_view path, uint64_t offset,
                            size_t size) const {
  Error error;
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!resolved)
    return {std::nullopt, std::move(error)};
  const Inode *inode = inodes_.get(resolved->inode);
  if (!inode || inode->type != InodeType::regular) {
    internal::fail(error, inode && inode->type == InodeType::directory
                               ? ErrorCode::is_directory
                               : ErrorCode::invalid_inode,
                   resolved->inode,
                   "read target is not a regular file");
    return {std::nullopt, std::move(error)};
  }
  std::vector<uint8_t> output;
  if (!read_inode_data(*inode, offset, size, output, error))
    return {std::nullopt, std::move(error)};
  return {std::move(output), {}};
}

bool Filesystem::release_inode_blocks(Inode &inode, Error &error) {
  error.clear();
  for (const Extent &extent : inode.extents) {
    if (extent.sparse)
      continue;
    for (uint32_t index = 0; index < extent.block_count; ++index)
      if (!allocator_.release(extent.physical_block + index, error))
        return false;
  }
  inode.extents.clear();
  inode.allocated_bytes = 0;
  return true;
}

OperationResult Filesystem::remove(std::string_view path, bool recursive) {
  Error error;
  if (!ensure_writable(error))
    return failed_result(std::move(error));
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, false, error);
  if (!resolved)
    return failed_result(std::move(error));
  if (resolved->inode == superblock_.root_inode)
    return failed_result(ErrorCode::permission_denied, resolved->inode,
                         "cannot remove filesystem root");
  Inode *inode = inodes_.get(resolved->inode);
  if (!inode)
    return failed_result(ErrorCode::invalid_inode, resolved->inode,
                         "remove target inode is missing");
  if (inode->type == InodeType::directory) {
    const auto *entries = directories_.entries(inode->identifier);
    bool nonempty = entries && std::any_of(
        entries->begin(), entries->end(), [](const DirectoryEntry &entry) {
          return !entry.deleted && entry.name != "." && entry.name != "..";
        });
    if (nonempty && !recursive)
      return failed_result(ErrorCode::directory_not_empty, inode->identifier,
                           "directory is not empty");
    if (nonempty) {
      std::vector<std::string> children;
      for (const auto &entry : *entries)
        if (!entry.deleted && entry.name != "." && entry.name != "..")
          children.push_back(entry.name);
      for (const auto &name : children) {
        std::string child(path);
        if (child.back() != '/')
          child.push_back('/');
        child += name;
        auto result = remove(child, true);
        if (!result)
          return result;
      }
    }
  }
  DirectoryEntry removed;
  if (!directories_.remove(resolved->parent, resolved->name, removed, error))
    return failed_result(std::move(error));
  if (inode->link_count > 0)
    --inode->link_count;
  if (inode->link_count == 0 ||
      inode->type == InodeType::directory) {
    if (!release_inode_blocks(*inode, error))
      return failed_result(std::move(error));
    if (inode->type == InodeType::directory &&
        !directories_.erase_directory(inode->identifier, error))
      return failed_result(std::move(error));
    if (!inodes_.erase(inode->identifier, error))
      return failed_result(std::move(error));
  }
  dirty_ = true;
  ++superblock_.generation;
  refresh_counts();
  return successful_result(removed.inode);
}

OperationResult Filesystem::rename(std::string_view source,
                                   std::string_view target) {
  Error error;
  if (!ensure_writable(error))
    return failed_result(std::move(error));
  auto source_path = PathResolver(limits_).resolve(
      source, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, false, error);
  if (!source_path)
    return failed_result(std::move(error));
  if (source_path->inode == superblock_.root_inode)
    return failed_result(ErrorCode::permission_denied, source_path->inode,
                         "cannot rename filesystem root");
  auto target_parent = PathResolver(limits_).resolve_parent(
      target, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, error);
  if (!target_parent)
    return failed_result(std::move(error));
  if (!directories_.rename(source_path->parent, source_path->name,
                           target_parent->first, target_parent->second,
                           error))
    return failed_result(std::move(error));
  dirty_ = true;
  ++superblock_.generation;
  return successful_result(source_path->inode);
}

std::optional<FileStat> Filesystem::stat(std::string_view path,
                                         bool follow_symlink,
                                         Error &error) const {
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, follow_symlink, error);
  if (!resolved)
    return std::nullopt;
  const Inode *inode = inodes_.get(resolved->inode);
  if (!inode) {
    internal::fail(error, ErrorCode::invalid_inode, resolved->inode,
                   "stat inode is missing");
    return std::nullopt;
  }
  return FileStat{inode->identifier, inode->type, inode->size,
                  inode->allocated_bytes, inode->link_count, inode->mode,
                  inode->generation};
}

std::optional<std::vector<DirectoryEntry>>
Filesystem::list(std::string_view path, Error &error) const {
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!resolved)
    return std::nullopt;
  const Inode *inode = inodes_.get(resolved->inode);
  if (!inode || inode->type != InodeType::directory) {
    internal::fail(error, ErrorCode::not_directory, resolved->inode,
                   "list target is not a directory");
    return std::nullopt;
  }
  const auto *entries = directories_.entries(inode->identifier);
  if (!entries) {
    internal::fail(error, ErrorCode::invalid_directory, inode->identifier,
                   "directory table is missing");
    return std::nullopt;
  }
  std::vector<DirectoryEntry> output;
  for (const auto &entry : *entries)
    if (!entry.deleted)
      output.push_back(entry);
  return output;
}

std::optional<std::vector<WalkEntry>>
Filesystem::walk(std::string_view path, Error &error) const {
  auto root = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!root)
    return std::nullopt;
  std::vector<WalkEntry> output;
  struct Pending {
    uint64_t inode;
    std::string path;
    uint32_t depth;
  };
  std::deque<Pending> pending;
  pending.push_back({root->inode, root->canonical, 0});
  std::set<uint64_t> active_directories;
  while (!pending.empty()) {
    Pending current = std::move(pending.front());
    pending.pop_front();
    if (current.depth > limits_.max_walk_depth) {
      internal::fail(error, ErrorCode::resource_limit, current.depth,
                     "filesystem walk depth exceeds limit");
      return std::nullopt;
    }
    const Inode *inode = inodes_.get(current.inode);
    if (!inode) {
      internal::fail(error, ErrorCode::invalid_inode, current.inode,
                     "walk encountered missing inode");
      return std::nullopt;
    }
    output.push_back(
        {current.path,
         {inode->identifier, inode->type, inode->size,
          inode->allocated_bytes, inode->link_count, inode->mode,
          inode->generation},
         current.depth});
    if (output.size() > limits_.max_directory_entries) {
      internal::fail(error, ErrorCode::resource_limit, output.size(),
                     "filesystem walk entry count exceeds limit");
      return std::nullopt;
    }
    if (inode->type != InodeType::directory)
      continue;
    if (!active_directories.insert(inode->identifier).second) {
      internal::fail(error, ErrorCode::loop_detected, inode->identifier,
                     "filesystem walk detected directory cycle");
      return std::nullopt;
    }
    const auto *entries = directories_.entries(inode->identifier);
    if (!entries) {
      internal::fail(error, ErrorCode::invalid_directory, inode->identifier,
                     "walk directory table is missing");
      return std::nullopt;
    }
    for (const auto &entry : *entries) {
      if (entry.deleted || entry.name == "." || entry.name == "..")
        continue;
      std::string child = current.path;
      if (child.size() > 1 && child.back() != '/')
        child.push_back('/');
      child += entry.name;
      pending.push_back({entry.inode, std::move(child),
                         current.depth + 1});
    }
  }
  return output;
}

bool Filesystem::set_attribute(std::string_view path, std::string name,
                               std::vector<uint8_t> value, Error &error) {
  if (!ensure_writable(error))
    return false;
  if (name.empty() || name.size() > limits_.max_name_bytes ||
      value.size() > limits_.max_extended_attribute_bytes)
    return internal::fail(error, ErrorCode::resource_limit, value.size(),
                          "extended attribute exceeds limits");
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!resolved)
    return false;
  Inode *inode = inodes_.get(resolved->inode);
  auto iterator = std::find_if(
      inode->attributes.begin(), inode->attributes.end(),
      [&](const ExtendedAttribute &attribute) {
        return attribute.name == name;
      });
  if (iterator == inode->attributes.end())
    inode->attributes.push_back({std::move(name), std::move(value)});
  else
    iterator->value = std::move(value);
  ++inode->generation;
  dirty_ = true;
  return true;
}

std::optional<std::vector<uint8_t>>
Filesystem::get_attribute(std::string_view path, std::string_view name,
                          Error &error) const {
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!resolved)
    return std::nullopt;
  const Inode *inode = inodes_.get(resolved->inode);
  auto iterator = std::find_if(
      inode->attributes.begin(), inode->attributes.end(),
      [&](const ExtendedAttribute &attribute) {
        return attribute.name == name;
      });
  if (iterator == inode->attributes.end()) {
    internal::fail(error, ErrorCode::not_found, inode->identifier,
                   "extended attribute does not exist");
    return std::nullopt;
  }
  return iterator->value;
}

bool Filesystem::remove_attribute(std::string_view path,
                                  std::string_view name, Error &error) {
  if (!ensure_writable(error))
    return false;
  auto resolved = PathResolver(limits_).resolve(
      path, superblock_.root_inode, superblock_.root_inode, inodes_,
      directories_, true, error);
  if (!resolved)
    return false;
  Inode *inode = inodes_.get(resolved->inode);
  auto iterator = std::find_if(
      inode->attributes.begin(), inode->attributes.end(),
      [&](const ExtendedAttribute &attribute) {
        return attribute.name == name;
      });
  if (iterator == inode->attributes.end())
    return internal::fail(error, ErrorCode::not_found, inode->identifier,
                          "extended attribute does not exist");
  inode->attributes.erase(iterator);
  ++inode->generation;
  dirty_ = true;
  return true;
}

bool Filesystem::begin(Error &error) {
  if (!ensure_writable(error))
    return false;
  if (snapshot_)
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "filesystem transaction is already active");
  auto snapshot = std::make_unique<Snapshot>();
  snapshot->superblock = superblock_;
  snapshot->device = device_;
  snapshot->allocator = allocator_;
  snapshot->inodes = inodes_;
  snapshot->directories = directories_;
  snapshot->dirty = dirty_;
  if (!journal_.begin(error))
    return false;
  snapshot_ = std::move(snapshot);
  dirty_ = true;
  return true;
}

bool Filesystem::commit(Error &error) {
  if (!snapshot_)
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "no filesystem transaction is active");
  if (!journal_.commit(error))
    return false;
  snapshot_.reset();
  dirty_ = true;
  ++superblock_.generation;
  refresh_counts();
  return true;
}

bool Filesystem::rollback(Error &error) {
  if (!snapshot_)
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "no filesystem transaction is active");
  if (!journal_.rollback(error))
    return false;
  superblock_ = snapshot_->superblock;
  device_ = std::move(snapshot_->device);
  allocator_ = std::move(snapshot_->allocator);
  inodes_ = std::move(snapshot_->inodes);
  directories_ = std::move(snapshot_->directories);
  dirty_ = snapshot_->dirty;
  snapshot_.reset();
  return true;
}

bool Filesystem::checkpoint(Error &error) {
  if (!ensure_writable(error))
    return false;
  if (snapshot_)
    return internal::fail(error, ErrorCode::transaction_error, 0,
                          "cannot checkpoint active transaction");
  if (!journal_.checkpoint(error))
    return false;
  dirty_ = false;
  superblock_.journal_sequence = journal_.next_sequence() - 1;
  return true;
}

uint64_t Filesystem::invariant_hash() const {
  uint64_t hash = hash64(device_.bytes().data(), device_.bytes().size());
  auto absorb = [&](const uint8_t *data, size_t size) {
    for (size_t index = 0; index < size; ++index) {
      hash ^= data[index];
      hash *= 1099511628211ull;
    }
  };
  auto absorb64 = [&](uint64_t value) {
    uint8_t bytes[8];
    for (unsigned shift = 0; shift < 64; shift += 8)
      bytes[shift / 8] = static_cast<uint8_t>(value >> shift);
    absorb(bytes, sizeof(bytes));
  };
  for (const auto &item : inodes_.all()) {
    const Inode &inode = item.second;
    absorb64(inode.identifier);
    absorb64(static_cast<uint8_t>(inode.type));
    absorb64(inode.mode);
    absorb64(inode.link_count);
    absorb64(inode.size);
    absorb64(inode.allocated_bytes);
    for (const Extent &extent : inode.extents) {
      absorb64(extent.logical_block);
      absorb64(extent.physical_block);
      absorb64(extent.block_count);
      absorb64(extent.sparse ? 1 : 0);
    }
    absorb(reinterpret_cast<const uint8_t *>(inode.symlink_target.data()),
           inode.symlink_target.size());
    for (const auto &attribute : inode.attributes) {
      absorb(reinterpret_cast<const uint8_t *>(attribute.name.data()),
             attribute.name.size());
      absorb(attribute.value.data(), attribute.value.size());
    }
  }
  for (const auto &directory : directories_.all()) {
    absorb64(directory.first);
    for (const DirectoryEntry &entry : directory.second) {
      absorb64(entry.inode);
      absorb64(static_cast<uint8_t>(entry.type));
      absorb64(entry.deleted ? 1 : 0);
      absorb(reinterpret_cast<const uint8_t *>(entry.name.data()),
             entry.name.size());
    }
  }
  return hash;
}

} // namespace blockforge
