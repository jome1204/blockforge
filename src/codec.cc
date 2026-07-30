#include "internal.h"

namespace blockforge {
namespace {

bool read_extent(CheckedReader &reader, Extent &extent, Error &error) {
  uint8_t sparse = 0;
  if (!reader.read_u64(extent.logical_block, error) ||
      !reader.read_u64(extent.physical_block, error) ||
      !reader.read_u32(extent.block_count, error) ||
      !reader.read_u8(sparse, error))
    return false;
  if (sparse > 1)
    return internal::fail(error, ErrorCode::invalid_extent,
                          reader.position() - 1,
                          "extent sparse flag is invalid");
  extent.sparse = sparse != 0;
  return true;
}

void append_extent(std::vector<uint8_t> &output, const Extent &extent) {
  internal::append64(output, extent.logical_block);
  internal::append64(output, extent.physical_block);
  internal::append32(output, extent.block_count);
  output.push_back(extent.sparse ? 1 : 0);
}

} // namespace

InodeCodec::InodeCodec(Limits limits) : limits_(limits) {}

std::vector<uint8_t> InodeCodec::encode(const Inode &inode,
                                        Error &error) const {
  error.clear();
  if (inode.identifier == 0 ||
      inode.extents.size() > limits_.max_extents_per_inode ||
      inode.symlink_target.size() > limits_.max_path_bytes ||
      inode.attributes.size() > limits_.max_directory_entries) {
    internal::fail(error, ErrorCode::resource_limit, inode.identifier,
                   "inode fields exceed encoding limits");
    return {};
  }
  std::vector<uint8_t> output;
  output.insert(output.end(), {'B', 'F', 'I', 'N'});
  internal::append64(output, inode.identifier);
  output.push_back(static_cast<uint8_t>(inode.type));
  internal::append16(output, inode.mode);
  internal::append32(output, inode.owner);
  internal::append32(output, inode.group);
  internal::append32(output, inode.link_count);
  internal::append64(output, inode.size);
  internal::append64(output, inode.allocated_bytes);
  internal::append64(output, inode.created_time);
  internal::append64(output, inode.modified_time);
  internal::append64(output, inode.changed_time);
  internal::append64(output, inode.generation);
  output.push_back(inode.deleted ? 1 : 0);
  internal::append32(output, static_cast<uint32_t>(inode.extents.size()));
  internal::append32(output, static_cast<uint32_t>(inode.attributes.size()));
  internal::append_string(output, inode.symlink_target);
  for (const Extent &extent : inode.extents)
    append_extent(output, extent);
  uint64_t attribute_bytes = 0;
  for (const ExtendedAttribute &attribute : inode.attributes) {
    uint64_t next = 0;
    if (attribute.name.size() > limits_.max_name_bytes ||
        !checked_add(attribute_bytes, attribute.name.size(), next) ||
        !checked_add(next, attribute.value.size(), attribute_bytes) ||
        attribute_bytes > limits_.max_extended_attribute_bytes) {
      internal::fail(error, ErrorCode::resource_limit, output.size(),
                     "inode attributes exceed encoding limits");
      return {};
    }
    internal::append_string(output, attribute.name);
    internal::append32(output,
                       static_cast<uint32_t>(attribute.value.size()));
    output.insert(output.end(), attribute.value.begin(),
                  attribute.value.end());
  }
  internal::append32(output, crc32(output.data(), output.size()));
  return output;
}

std::optional<Inode>
InodeCodec::decode(const uint8_t *data, size_t size,
                   const Superblock &superblock, Error &error) const {
  error.clear();
  if (size < 91 || size > limits_.max_file_bytes ||
      std::memcmp(data, "BFIN", 4) != 0) {
    internal::fail(error, size < 91 ? ErrorCode::truncated
                                   : ErrorCode::invalid_signature,
                   0, "inode record header is invalid");
    return std::nullopt;
  }
  if (crc32(data, size - 4) != internal::le32(data + size - 4)) {
    internal::fail(error, ErrorCode::checksum_mismatch, size - 4,
                   "inode record checksum mismatch");
    return std::nullopt;
  }
  CheckedReader reader(data + 4, size - 8);
  Inode inode;
  uint8_t type = 0;
  uint8_t deleted = 0;
  uint32_t extent_count = 0;
  uint32_t attribute_count = 0;
  if (!reader.read_u64(inode.identifier, error) ||
      !reader.read_u8(type, error) || !reader.read_u16(inode.mode, error) ||
      !reader.read_u32(inode.owner, error) ||
      !reader.read_u32(inode.group, error) ||
      !reader.read_u32(inode.link_count, error) ||
      !reader.read_u64(inode.size, error) ||
      !reader.read_u64(inode.allocated_bytes, error) ||
      !reader.read_u64(inode.created_time, error) ||
      !reader.read_u64(inode.modified_time, error) ||
      !reader.read_u64(inode.changed_time, error) ||
      !reader.read_u64(inode.generation, error) ||
      !reader.read_u8(deleted, error) ||
      !reader.read_u32(extent_count, error) ||
      !reader.read_u32(attribute_count, error) ||
      !reader.read_string(limits_.max_path_bytes, inode.symlink_target,
                          error))
    return std::nullopt;
  if (type < static_cast<uint8_t>(InodeType::regular) ||
      type > static_cast<uint8_t>(InodeType::symbolic_link) ||
      deleted > 1 ||
      extent_count > limits_.max_extents_per_inode ||
      attribute_count > limits_.max_directory_entries) {
    internal::fail(error, ErrorCode::resource_limit, reader.position(),
                   "inode counts or flags are invalid");
    return std::nullopt;
  }
  inode.type = static_cast<InodeType>(type);
  inode.deleted = deleted != 0;
  inode.extents.reserve(extent_count);
  for (uint32_t index = 0; index < extent_count; ++index) {
    Extent extent;
    if (!read_extent(reader, extent, error))
      return std::nullopt;
    inode.extents.push_back(extent);
  }
  uint64_t attribute_bytes = 0;
  for (uint32_t index = 0; index < attribute_count; ++index) {
    ExtendedAttribute attribute;
    uint32_t length = 0;
    if (!reader.read_string(limits_.max_name_bytes, attribute.name, error) ||
        !reader.read_u32(length, error) ||
        length > limits_.max_extended_attribute_bytes ||
        !reader.read_bytes(length, attribute.value, error))
      return std::nullopt;
    uint64_t next = 0;
    if (!checked_add(attribute_bytes, attribute.name.size(), next) ||
        !checked_add(next, attribute.value.size(), attribute_bytes) ||
        attribute_bytes > limits_.max_extended_attribute_bytes) {
      internal::fail(error, ErrorCode::resource_limit, reader.position(),
                     "inode attribute bytes exceed limit");
      return std::nullopt;
    }
    inode.attributes.push_back(std::move(attribute));
  }
  if (reader.remaining() != 0) {
    internal::fail(error, ErrorCode::invalid_offset, reader.position(),
                   "inode record has trailing bytes");
    return std::nullopt;
  }
  if (!inode.validate(superblock, limits_, error))
    return std::nullopt;
  return inode;
}

DirectoryCodec::DirectoryCodec(Limits limits) : limits_(limits) {}

std::vector<uint8_t>
DirectoryCodec::encode(const std::vector<DirectoryEntry> &entries,
                       Error &error) const {
  error.clear();
  if (entries.size() > limits_.max_directory_entries) {
    internal::fail(error, ErrorCode::resource_limit, entries.size(),
                   "directory entry count exceeds limit");
    return {};
  }
  std::vector<uint8_t> output;
  output.insert(output.end(), {'B', 'F', 'D', 'R'});
  internal::append32(output, static_cast<uint32_t>(entries.size()));
  for (const DirectoryEntry &entry : entries) {
    if (!entry.validate(limits_, error))
      return {};
    uint32_t record_length = entry.record_length
                                 ? entry.record_length
                                 : internal::aligned_directory_length(
                                       entry.name.size());
    size_t start = output.size();
    internal::append32(output, record_length);
    internal::append64(output, entry.inode);
    output.push_back(static_cast<uint8_t>(entry.type));
    output.push_back(entry.deleted ? 1 : 0);
    internal::append16(output, static_cast<uint16_t>(entry.name.size()));
    output.insert(output.end(), entry.name.begin(), entry.name.end());
    if (output.size() - start > record_length) {
      internal::fail(error, ErrorCode::invalid_directory, start,
                     "directory entry does not fit record length");
      return {};
    }
    output.resize(start + record_length, 0);
  }
  internal::append32(output, crc32(output.data(), output.size()));
  return output;
}

std::optional<std::vector<DirectoryEntry>>
DirectoryCodec::decode(const uint8_t *data, size_t size,
                       Error &error) const {
  error.clear();
  if (size < 12 || std::memcmp(data, "BFDR", 4) != 0) {
    internal::fail(error, size < 12 ? ErrorCode::truncated
                                   : ErrorCode::invalid_signature,
                   0, "directory record header is invalid");
    return std::nullopt;
  }
  if (crc32(data, size - 4) != internal::le32(data + size - 4)) {
    internal::fail(error, ErrorCode::checksum_mismatch, size - 4,
                   "directory record checksum mismatch");
    return std::nullopt;
  }
  CheckedReader reader(data + 4, size - 8);
  uint32_t count = 0;
  if (!reader.read_u32(count, error))
    return std::nullopt;
  if (count > limits_.max_directory_entries) {
    internal::fail(error, ErrorCode::resource_limit, 4,
                   "directory entry count exceeds limit");
    return std::nullopt;
  }
  std::vector<DirectoryEntry> entries;
  entries.reserve(count);
  for (uint32_t index = 0; index < count; ++index) {
    size_t start = reader.position();
    DirectoryEntry entry;
    uint8_t type = 0;
    uint8_t deleted = 0;
    uint16_t name_length = 0;
    if (!reader.read_u32(entry.record_length, error) ||
        !reader.read_u64(entry.inode, error) ||
        !reader.read_u8(type, error) ||
        !reader.read_u8(deleted, error) ||
        !reader.read_u16(name_length, error))
      return std::nullopt;
    if (entry.record_length < 16 || (entry.record_length & 7) != 0 ||
        entry.record_length > reader.remaining() + 16 ||
        name_length > entry.record_length - 16 ||
        name_length > limits_.max_name_bytes || deleted > 1) {
      internal::fail(error, ErrorCode::invalid_directory, start,
                     "directory record fields are invalid");
      return std::nullopt;
    }
    std::vector<uint8_t> name;
    if (!reader.read_bytes(name_length, name, error))
      return std::nullopt;
    entry.name.assign(name.begin(), name.end());
    entry.type = static_cast<InodeType>(type);
    entry.deleted = deleted != 0;
    size_t consumed = reader.position() - start;
    if (!reader.skip(entry.record_length - consumed, error))
      return std::nullopt;
    if (!entry.validate(limits_, error))
      return std::nullopt;
    entries.push_back(std::move(entry));
  }
  if (reader.remaining() != 0) {
    internal::fail(error, ErrorCode::invalid_offset, reader.position(),
                   "directory record has trailing bytes");
    return std::nullopt;
  }
  return entries;
}

JournalCodec::JournalCodec(Limits limits) : limits_(limits) {}

std::vector<uint8_t>
JournalCodec::encode(const std::vector<JournalRecord> &records,
                     Error &error) const {
  error.clear();
  if (records.size() > limits_.max_journal_records) {
    internal::fail(error, ErrorCode::resource_limit, records.size(),
                   "journal record count exceeds limit");
    return {};
  }
  std::vector<uint8_t> output;
  output.insert(output.end(), {'B', 'F', 'J', 'N', 'L', '1', 0, 0});
  internal::append32(output, 1);
  internal::append32(output, static_cast<uint32_t>(records.size()));
  uint64_t previous = 0;
  for (const JournalRecord &record : records) {
    if (record.sequence <= previous ||
        record.payload.size() > limits_.max_file_bytes) {
      internal::fail(error, ErrorCode::journal_error, record.sequence,
                     "journal sequence or payload is invalid");
      return {};
    }
    size_t start = output.size();
    internal::append32(
        output, static_cast<uint32_t>(48 + record.payload.size()));
    internal::append16(output, static_cast<uint16_t>(record.type));
    internal::append16(output, 0);
    internal::append64(output, record.sequence);
    internal::append64(output, record.transaction);
    internal::append64(output, record.target);
    internal::append64(output, record.generation);
    internal::append32(output,
                       static_cast<uint32_t>(record.payload.size()));
    output.insert(output.end(), record.payload.begin(), record.payload.end());
    internal::append32(output,
                       crc32(output.data() + start + 4,
                             output.size() - start - 4));
    previous = record.sequence;
  }
  return output;
}

std::optional<std::vector<JournalRecord>>
JournalCodec::decode(const uint8_t *data, size_t size, Error &error) const {
  error.clear();
  if (size < 16 || size > limits_.max_image_bytes ||
      std::memcmp(data, "BFJNL1\0\0", 8) != 0 ||
      internal::le32(data + 8) != 1) {
    internal::fail(error, size < 16 ? ErrorCode::truncated
                                   : ErrorCode::invalid_signature,
                   0, "journal header is invalid");
    return std::nullopt;
  }
  uint32_t count = internal::le32(data + 12);
  if (count > limits_.max_journal_records) {
    internal::fail(error, ErrorCode::resource_limit, count,
                   "journal record count exceeds limit");
    return std::nullopt;
  }
  size_t position = 16;
  uint64_t previous = 0;
  std::vector<JournalRecord> records;
  records.reserve(count);
  for (uint32_t index = 0; index < count; ++index) {
    if (size - position < 44) {
      internal::fail(error, ErrorCode::truncated, position,
                     "journal record header is truncated");
      return std::nullopt;
    }
    uint32_t length = internal::le32(data + position);
    if (length < 44 || length > size - position) {
      internal::fail(error, ErrorCode::invalid_offset, position,
                     "journal record length is invalid");
      return std::nullopt;
    }
    uint32_t payload_length = internal::le32(data + position + 40);
    if (payload_length != length - 48 ||
        payload_length > limits_.max_file_bytes) {
      internal::fail(error, ErrorCode::journal_error, position + 40,
                     "journal payload length is inconsistent");
      return std::nullopt;
    }
    uint32_t stored = internal::le32(data + position + length - 4);
    uint32_t actual =
        crc32(data + position + 4, length - 8);
    if (stored != actual) {
      internal::fail(error, ErrorCode::checksum_mismatch,
                     position + length - 4,
                     "journal record checksum mismatch");
      return std::nullopt;
    }
    JournalRecord record;
    record.type =
        static_cast<JournalType>(internal::le16(data + position + 4));
    uint16_t flags = internal::le16(data + position + 6);
    record.sequence = internal::le64(data + position + 8);
    record.transaction = internal::le64(data + position + 16);
    record.target = internal::le64(data + position + 24);
    record.generation = internal::le64(data + position + 32);
    if (flags != 0 || record.type < JournalType::begin ||
        record.type > JournalType::checkpoint ||
        record.sequence <= previous) {
      internal::fail(error, ErrorCode::journal_error, position,
                     "journal record fields are invalid");
      return std::nullopt;
    }
    record.payload.assign(data + position + 44,
                          data + position + 44 + payload_length);
    record.checksum = stored;
    records.push_back(std::move(record));
    previous = records.back().sequence;
    position += length;
  }
  if (position != size) {
    internal::fail(error, ErrorCode::invalid_offset, position,
                   "journal has trailing bytes");
    return std::nullopt;
  }
  return records;
}

} // namespace blockforge
