#include "internal.h"

#include <iomanip>

namespace blockforge {
StatisticsCollector::StatisticsCollector(Limits limits) : limits_(limits) {}

ImageStatistics
StatisticsCollector::collect(const Filesystem &filesystem,
                             Error &error) const {
  error.clear();
  ImageStatistics result;
  result.image_bytes = filesystem.device().byte_size();
  result.allocated_blocks = filesystem.allocator().allocated_count();
  result.free_blocks = filesystem.allocator().free_count();
  result.allocated_inodes = filesystem.inodes().all().size();
  result.journal_records = filesystem.journal().records().size();
  for (const auto &item : filesystem.inodes().all()) {
    const Inode &inode = item.second;
    if (inode.type == InodeType::regular) {
      ++result.regular_files;
      if (!checked_add(result.logical_file_bytes, inode.size,
                       result.logical_file_bytes) ||
          !checked_add(result.physical_file_bytes, inode.allocated_bytes,
                       result.physical_file_bytes)) {
        internal::fail(error, ErrorCode::overflow, inode.identifier,
                       "statistics byte total overflows");
        return {};
      }
      bool sparse = inode.allocated_bytes < inode.size;
      bool fragmented = inode.extents.size() > 1;
      result.sparse_files += sparse ? 1 : 0;
      result.fragmented_files += fragmented ? 1 : 0;
    } else if (inode.type == InodeType::directory) {
      ++result.directories;
    } else if (inode.type == InodeType::symbolic_link) {
      ++result.symbolic_links;
    }
    if (inode.link_count > 1 && inode.type != InodeType::directory)
      result.hard_links += inode.link_count - 1;
    if (!checked_add(result.extended_attributes, inode.attributes.size(),
                     result.extended_attributes)) {
      internal::fail(error, ErrorCode::overflow, inode.identifier,
                     "attribute statistic overflows");
      return {};
    }
  }
  return result;
}

std::string StatisticsCollector::text(
    const ImageStatistics &statistics) {
  std::ostringstream output;
  output << "Filesystem image statistics\n"
         << "  image bytes: " << statistics.image_bytes << '\n'
         << "  allocated blocks: " << statistics.allocated_blocks << '\n'
         << "  free blocks: " << statistics.free_blocks << '\n'
         << "  allocated inodes: " << statistics.allocated_inodes << '\n'
         << "  regular files: " << statistics.regular_files << '\n'
         << "  directories: " << statistics.directories << '\n'
         << "  symbolic links: " << statistics.symbolic_links << '\n'
         << "  additional hard links: " << statistics.hard_links << '\n'
         << "  sparse files: " << statistics.sparse_files << '\n'
         << "  fragmented files: " << statistics.fragmented_files << '\n'
         << "  logical file bytes: " << statistics.logical_file_bytes << '\n'
         << "  physical file bytes: " << statistics.physical_file_bytes
         << '\n'
         << "  extended attributes: "
         << statistics.extended_attributes << '\n'
         << "  journal records: " << statistics.journal_records << '\n';
  return output.str();
}

std::string StatisticsCollector::json(
    const ImageStatistics &statistics) {
  std::ostringstream output;
  output << "{\"image_bytes\":" << statistics.image_bytes
         << ",\"allocated_blocks\":" << statistics.allocated_blocks
         << ",\"free_blocks\":" << statistics.free_blocks
         << ",\"allocated_inodes\":" << statistics.allocated_inodes
         << ",\"regular_files\":" << statistics.regular_files
         << ",\"directories\":" << statistics.directories
         << ",\"symbolic_links\":" << statistics.symbolic_links
         << ",\"hard_links\":" << statistics.hard_links
         << ",\"sparse_files\":" << statistics.sparse_files
         << ",\"fragmented_files\":" << statistics.fragmented_files
         << ",\"logical_file_bytes\":" << statistics.logical_file_bytes
         << ",\"physical_file_bytes\":" << statistics.physical_file_bytes
         << ",\"extended_attributes\":"
         << statistics.extended_attributes
         << ",\"journal_records\":" << statistics.journal_records << '}';
  return output.str();
}

ImageDiff::ImageDiff(Limits limits) : limits_(limits) {}

std::vector<ImageDiff::Change>
ImageDiff::compare(const Filesystem &left, const Filesystem &right,
                   Error &error) const {
  error.clear();
  auto left_walk = left.walk("/", error);
  if (!left_walk)
    return {};
  auto right_walk = right.walk("/", error);
  if (!right_walk)
    return {};
  std::map<std::string, FileStat> left_paths;
  std::map<std::string, FileStat> right_paths;
  for (const auto &entry : *left_walk)
    left_paths[entry.path] = entry.stat;
  for (const auto &entry : *right_walk)
    right_paths[entry.path] = entry.stat;
  std::vector<Change> changes;
  for (const auto &entry : left_paths)
    if (right_paths.count(entry.first) == 0)
      changes.push_back(
          {Change::Kind::removed, entry.first, "path was removed"});
  for (const auto &entry : right_paths) {
    auto previous = left_paths.find(entry.first);
    if (previous == left_paths.end()) {
      changes.push_back(
          {Change::Kind::added, entry.first, "path was added"});
      continue;
    }
    if (previous->second.type != entry.second.type) {
      changes.push_back(
          {Change::Kind::type, entry.first,
           inode_type_name(previous->second.type) + " became " +
               inode_type_name(entry.second.type)});
      continue;
    }
    if (previous->second.size != entry.second.size ||
        previous->second.allocated_bytes != entry.second.allocated_bytes) {
      changes.push_back(
          {Change::Kind::content, entry.first,
           "size changed from " + std::to_string(previous->second.size) +
               " to " + std::to_string(entry.second.size)});
    }
    if (previous->second.mode != entry.second.mode ||
        previous->second.links != entry.second.links) {
      changes.push_back(
          {Change::Kind::metadata, entry.first,
           "mode or link count changed"});
    }
    if (changes.size() > limits_.max_directory_entries) {
      internal::fail(error, ErrorCode::resource_limit, changes.size(),
                     "image diff exceeds change limit");
      return {};
    }
  }
  return changes;
}

std::string ImageDiff::text(const std::vector<Change> &changes) {
  std::ostringstream output;
  output << "Filesystem changes: " << changes.size() << '\n';
  for (const auto &change : changes) {
    char marker = '?';
    switch (change.kind) {
    case Change::Kind::added: marker = '+'; break;
    case Change::Kind::removed: marker = '-'; break;
    case Change::Kind::metadata: marker = 'm'; break;
    case Change::Kind::content: marker = 'c'; break;
    case Change::Kind::type: marker = 't'; break;
    }
    output << marker << ' ' << change.path << ": " << change.detail << '\n';
  }
  return output.str();
}

} // namespace blockforge
