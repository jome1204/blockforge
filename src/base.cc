#include "internal.h"

#include <array>
#include <cmath>

namespace blockforge {

bool checked_add(uint64_t left, uint64_t right, uint64_t &output) {
  if (right > std::numeric_limits<uint64_t>::max() - left)
    return false;
  output = left + right;
  return true;
}

bool checked_multiply(uint64_t left, uint64_t right, uint64_t &output) {
  if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left)
    return false;
  output = left * right;
  return true;
}

uint32_t crc32(const uint8_t *data, size_t size) {
  uint32_t checksum = 0xffffffffu;
  for (size_t index = 0; index < size; ++index) {
    checksum ^= data[index];
    for (unsigned bit = 0; bit < 8; ++bit) {
      uint32_t mask = static_cast<uint32_t>(
          -static_cast<int32_t>(checksum & 1u));
      checksum = (checksum >> 1) ^ (0xedb88320u & mask);
    }
  }
  return ~checksum;
}

uint64_t hash64(const uint8_t *data, size_t size) {
  uint64_t hash = 1469598103934665603ull;
  for (size_t index = 0; index < size; ++index) {
    hash ^= data[index];
    hash *= 1099511628211ull;
  }
  return hash;
}

std::string error_code_name(ErrorCode code) {
  switch (code) {
  case ErrorCode::none: return "none";
  case ErrorCode::truncated: return "truncated";
  case ErrorCode::invalid_signature: return "invalid_signature";
  case ErrorCode::invalid_version: return "invalid_version";
  case ErrorCode::checksum_mismatch: return "checksum_mismatch";
  case ErrorCode::invalid_offset: return "invalid_offset";
  case ErrorCode::invalid_block: return "invalid_block";
  case ErrorCode::invalid_inode: return "invalid_inode";
  case ErrorCode::invalid_directory: return "invalid_directory";
  case ErrorCode::invalid_extent: return "invalid_extent";
  case ErrorCode::invalid_path: return "invalid_path";
  case ErrorCode::invalid_name: return "invalid_name";
  case ErrorCode::loop_detected: return "loop_detected";
  case ErrorCode::not_found: return "not_found";
  case ErrorCode::already_exists: return "already_exists";
  case ErrorCode::not_directory: return "not_directory";
  case ErrorCode::is_directory: return "is_directory";
  case ErrorCode::directory_not_empty: return "directory_not_empty";
  case ErrorCode::permission_denied: return "permission_denied";
  case ErrorCode::no_space: return "no_space";
  case ErrorCode::overflow: return "overflow";
  case ErrorCode::resource_limit: return "resource_limit";
  case ErrorCode::journal_error: return "journal_error";
  case ErrorCode::transaction_error: return "transaction_error";
  case ErrorCode::unsupported: return "unsupported";
  case ErrorCode::internal_error: return "internal_error";
  }
  return "unknown";
}

std::string inode_type_name(InodeType type) {
  switch (type) {
  case InodeType::unused: return "unused";
  case InodeType::regular: return "regular";
  case InodeType::directory: return "directory";
  case InodeType::symbolic_link: return "symbolic_link";
  }
  return "unknown";
}

std::string issue_code_name(IssueCode code) {
  switch (code) {
  case IssueCode::superblock_invalid: return "superblock_invalid";
  case IssueCode::block_bitmap_mismatch: return "block_bitmap_mismatch";
  case IssueCode::duplicate_block: return "duplicate_block";
  case IssueCode::unreferenced_block: return "unreferenced_block";
  case IssueCode::missing_inode: return "missing_inode";
  case IssueCode::orphan_inode: return "orphan_inode";
  case IssueCode::invalid_link_count: return "invalid_link_count";
  case IssueCode::invalid_directory_entry: return "invalid_directory_entry";
  case IssueCode::directory_cycle: return "directory_cycle";
  case IssueCode::extent_overlap: return "extent_overlap";
  case IssueCode::extent_out_of_range: return "extent_out_of_range";
  case IssueCode::size_mismatch: return "size_mismatch";
  case IssueCode::invalid_symlink: return "invalid_symlink";
  case IssueCode::journal_sequence: return "journal_sequence";
  case IssueCode::journal_transaction: return "journal_transaction";
  case IssueCode::checksum_failure: return "checksum_failure";
  }
  return "unknown";
}

bool Superblock::validate(uint64_t image_size, const Limits &limits,
                          Error &error) const {
  error.clear();
  if (version != 1)
    return internal::fail(error, ErrorCode::invalid_version, 8,
                          "unsupported filesystem version");
  if (block_size < limits.min_block_size ||
      block_size > limits.max_block_size ||
      (block_size & (block_size - 1)) != 0)
    return internal::fail(error, ErrorCode::invalid_block, 12,
                          "block size is not a supported power of two");
  if (block_count == 0 || block_count > limits.max_blocks)
    return internal::fail(error, ErrorCode::resource_limit, 16,
                          "block count exceeds resource limit");
  uint64_t expected = 0;
  if (!checked_multiply(block_count, block_size, expected) ||
      expected > limits.max_image_bytes || expected != image_size)
    return internal::fail(error, ErrorCode::overflow, 16,
                          "block count and image length are inconsistent");
  if (inode_count > limits.max_inodes || free_inode_count > inode_count)
    return internal::fail(error, ErrorCode::resource_limit, 24,
                          "inode counts are inconsistent");
  if (free_block_count > block_count)
    return internal::fail(error, ErrorCode::invalid_block, 40,
                          "free block count exceeds block count");
  if (root_inode == 0 || root_inode > limits.max_inodes)
    return internal::fail(error, ErrorCode::invalid_inode, 48,
                          "root inode is outside the supported range");
  return true;
}

uint64_t Extent::logical_end(Error &error) const {
  error.clear();
  uint64_t result = 0;
  if (block_count == 0 ||
      !checked_add(logical_block, block_count, result)) {
    internal::fail(error, ErrorCode::overflow, logical_block,
                   "logical extent end overflows");
    return 0;
  }
  return result;
}

uint64_t Extent::physical_end(Error &error) const {
  error.clear();
  if (sparse)
    return 0;
  uint64_t result = 0;
  if (block_count == 0 ||
      !checked_add(physical_block, block_count, result)) {
    internal::fail(error, ErrorCode::overflow, physical_block,
                   "physical extent end overflows");
    return 0;
  }
  return result;
}

bool Inode::validate(const Superblock &superblock, const Limits &limits,
                     Error &error) const {
  error.clear();
  if (identifier == 0 || identifier > limits.max_inodes)
    return internal::fail(error, ErrorCode::invalid_inode, identifier,
                          "inode identifier is invalid");
  if (type < InodeType::regular || type > InodeType::symbolic_link)
    return internal::fail(error, ErrorCode::invalid_inode, identifier,
                          "inode type is invalid");
  if (link_count == 0 || link_count > limits.max_hard_links)
    return internal::fail(error, ErrorCode::invalid_inode, identifier,
                          "inode link count is invalid");
  if (size > limits.max_file_bytes || allocated_bytes > limits.max_file_bytes)
    return internal::fail(error, ErrorCode::resource_limit, identifier,
                          "inode size exceeds resource limit");
  if (extents.size() > limits.max_extents_per_inode)
    return internal::fail(error, ErrorCode::resource_limit, identifier,
                          "inode extent count exceeds resource limit");
  if (type == InodeType::symbolic_link) {
    if (symlink_target.empty() ||
        symlink_target.size() > limits.max_path_bytes)
      return internal::fail(error, ErrorCode::invalid_path, identifier,
                            "symbolic-link target length is invalid");
  } else if (!symlink_target.empty()) {
    return internal::fail(error, ErrorCode::invalid_inode, identifier,
                          "non-symbolic inode has a link target");
  }
  uint64_t attribute_bytes = 0;
  std::set<std::string> names;
  for (const auto &attribute : attributes) {
    if (attribute.name.empty() ||
        attribute.name.size() > limits.max_name_bytes ||
        !names.insert(attribute.name).second)
      return internal::fail(error, ErrorCode::invalid_name, identifier,
                            "extended attribute name is invalid");
    uint64_t next = 0;
    if (!checked_add(attribute_bytes, attribute.name.size(), next) ||
        !checked_add(next, attribute.value.size(), attribute_bytes) ||
        attribute_bytes > limits.max_extended_attribute_bytes)
      return internal::fail(error, ErrorCode::resource_limit, identifier,
                            "extended attributes exceed resource limit");
  }
  ExtentResolver resolver(limits);
  return resolver.verify(*this, superblock, error);
}

bool DirectoryEntry::validate(const Limits &limits, Error &error) const {
  error.clear();
  if (inode == 0)
    return internal::fail(error, ErrorCode::invalid_inode, 0,
                          "directory entry inode is zero");
  if (name.empty() || name.size() > limits.max_name_bytes ||
      name.find('/') != std::string::npos || name.find('\0') != std::string::npos)
    return internal::fail(error, ErrorCode::invalid_name, 0,
                          "directory entry name is invalid");
  if (type < InodeType::regular || type > InodeType::symbolic_link)
    return internal::fail(error, ErrorCode::invalid_directory, 0,
                          "directory entry type is invalid");
  uint32_t minimum = internal::aligned_directory_length(name.size());
  if (record_length != 0 &&
      (record_length < minimum || (record_length & 7) != 0))
    return internal::fail(error, ErrorCode::invalid_directory, 0,
                          "directory record length is invalid");
  return true;
}

CheckedReader::CheckedReader(const uint8_t *data, size_t size)
    : data_(data), size_(size) {}

bool CheckedReader::seek(size_t position, Error &error) {
  error.clear();
  if (position > size_)
    return internal::fail(error, ErrorCode::invalid_offset, position,
                          "reader seek exceeds input");
  position_ = position;
  return true;
}

bool CheckedReader::skip(size_t count, Error &error) {
  error.clear();
  if (count > remaining())
    return internal::fail(error, ErrorCode::truncated, position_,
                          "reader skip exceeds input");
  position_ += count;
  return true;
}

bool CheckedReader::read_u8(uint8_t &value, Error &error) {
  if (remaining() < 1)
    return internal::fail(error, ErrorCode::truncated, position_,
                          "byte is truncated");
  value = data_[position_++];
  return true;
}

bool CheckedReader::read_u16(uint16_t &value, Error &error) {
  if (remaining() < 2)
    return internal::fail(error, ErrorCode::truncated, position_,
                          "16-bit value is truncated");
  value = internal::le16(data_ + position_);
  position_ += 2;
  return true;
}

bool CheckedReader::read_u32(uint32_t &value, Error &error) {
  if (remaining() < 4)
    return internal::fail(error, ErrorCode::truncated, position_,
                          "32-bit value is truncated");
  value = internal::le32(data_ + position_);
  position_ += 4;
  return true;
}

bool CheckedReader::read_u64(uint64_t &value, Error &error) {
  if (remaining() < 8)
    return internal::fail(error, ErrorCode::truncated, position_,
                          "64-bit value is truncated");
  value = internal::le64(data_ + position_);
  position_ += 8;
  return true;
}

bool CheckedReader::read_bytes(size_t count, std::vector<uint8_t> &value,
                               Error &error) {
  if (count > remaining())
    return internal::fail(error, ErrorCode::truncated, position_,
                          "byte sequence is truncated");
  value.assign(data_ + position_, data_ + position_ + count);
  position_ += count;
  return true;
}

bool CheckedReader::read_string(size_t maximum, std::string &value,
                                Error &error) {
  uint32_t length = 0;
  if (!read_u32(length, error))
    return false;
  if (length > maximum || length > remaining())
    return internal::fail(error, ErrorCode::resource_limit, position_ - 4,
                          "string length exceeds bounds");
  value.assign(reinterpret_cast<const char *>(data_ + position_), length);
  position_ += length;
  return true;
}

const uint8_t *CheckedReader::current() const {
  return position_ < size_ ? data_ + position_ : nullptr;
}

} // namespace blockforge
