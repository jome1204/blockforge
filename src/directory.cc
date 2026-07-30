#include "internal.h"

namespace blockforge {

DirectoryTable::DirectoryTable(Limits limits) : limits_(limits) {}

bool DirectoryTable::initialize_root(uint64_t root_inode, Error &error) {
  error.clear();
  directories_.clear();
  std::vector<DirectoryEntry> entries;
  entries.push_back(
      {root_inode, InodeType::directory, ".",
       internal::aligned_directory_length(1), false});
  entries.push_back(
      {root_inode, InodeType::directory, "..",
       internal::aligned_directory_length(2), false});
  directories_.emplace(root_inode, std::move(entries));
  return true;
}

bool DirectoryTable::load(uint64_t inode,
                          std::vector<DirectoryEntry> entries,
                          Error &error) {
  error.clear();
  if (inode == 0 || directories_.count(inode) != 0)
    return internal::fail(error, ErrorCode::invalid_directory, inode,
                          "loaded directory identifier is invalid");
  if (entries.size() > limits_.max_directory_entries)
    return internal::fail(error, ErrorCode::resource_limit, entries.size(),
                          "loaded directory exceeds entry limit");
  for (const DirectoryEntry &entry : entries)
    if (!entry.validate(limits_, error))
      return false;
  directories_.emplace(inode, std::move(entries));
  return true;
}

bool DirectoryTable::create(uint64_t inode, uint64_t parent, Error &error) {
  error.clear();
  if (inode == 0 || parent == 0)
    return internal::fail(error, ErrorCode::invalid_inode, inode,
                          "directory inode or parent is zero");
  if (directories_.count(inode) != 0)
    return internal::fail(error, ErrorCode::already_exists, inode,
                          "directory already exists");
  std::vector<DirectoryEntry> entries;
  entries.push_back(
      {inode, InodeType::directory, ".",
       internal::aligned_directory_length(1), false});
  entries.push_back(
      {parent, InodeType::directory, "..",
       internal::aligned_directory_length(2), false});
  directories_.emplace(inode, std::move(entries));
  return true;
}

bool DirectoryTable::erase_directory(uint64_t inode, Error &error) {
  error.clear();
  auto iterator = directories_.find(inode);
  if (iterator == directories_.end())
    return internal::fail(error, ErrorCode::not_found, inode,
                          "directory does not exist");
  for (const auto &entry : iterator->second)
    if (!entry.deleted && entry.name != "." && entry.name != "..")
      return internal::fail(error, ErrorCode::directory_not_empty, inode,
                            "directory is not empty");
  directories_.erase(iterator);
  return true;
}

bool DirectoryTable::add(uint64_t directory, DirectoryEntry entry,
                         Error &error) {
  error.clear();
  auto iterator = directories_.find(directory);
  if (iterator == directories_.end())
    return internal::fail(error, ErrorCode::not_directory, directory,
                          "target inode is not a directory");
  if (entry.name == "." || entry.name == "..")
    return internal::fail(error, ErrorCode::invalid_name, directory,
                          "reserved directory entry name");
  if (!entry.validate(limits_, error))
    return false;
  if (find(directory, entry.name))
    return internal::fail(error, ErrorCode::already_exists, directory,
                          "directory entry already exists");
  uint64_t total = 0;
  for (const auto &table : directories_)
    if (!checked_add(total, table.second.size(), total) ||
        total >= limits_.max_directory_entries)
      return internal::fail(error, ErrorCode::resource_limit, total,
                            "directory entry count exceeds limit");
  if (entry.record_length == 0)
    entry.record_length = internal::aligned_directory_length(entry.name.size());
  iterator->second.push_back(std::move(entry));
  return true;
}

bool DirectoryTable::remove(uint64_t directory, std::string_view name,
                            DirectoryEntry &removed, Error &error) {
  error.clear();
  if (name == "." || name == "..")
    return internal::fail(error, ErrorCode::permission_denied, directory,
                          "cannot remove dot entries");
  auto iterator = directories_.find(directory);
  if (iterator == directories_.end())
    return internal::fail(error, ErrorCode::not_directory, directory,
                          "target inode is not a directory");
  std::string key = internal::normalize_name(name);
  auto entry = std::find_if(
      iterator->second.begin(), iterator->second.end(),
      [&](const DirectoryEntry &candidate) {
        return !candidate.deleted &&
               internal::normalize_name(candidate.name) == key;
      });
  if (entry == iterator->second.end())
    return internal::fail(error, ErrorCode::not_found, directory,
                          "directory entry does not exist");
  removed = *entry;
  entry->deleted = true;
  return true;
}

bool DirectoryTable::rename(uint64_t source_directory,
                            std::string_view source_name,
                            uint64_t target_directory,
                            std::string target_name, Error &error) {
  error.clear();
  if (target_name.empty() || target_name.size() > limits_.max_name_bytes ||
      target_name.find('/') != std::string::npos ||
      target_name == "." || target_name == "..")
    return internal::fail(error, ErrorCode::invalid_name, target_directory,
                          "rename target name is invalid");
  if (find(target_directory, target_name))
    return internal::fail(error, ErrorCode::already_exists, target_directory,
                          "rename target already exists");
  DirectoryEntry removed;
  if (!remove(source_directory, source_name, removed, error))
    return false;
  removed.name = std::move(target_name);
  removed.record_length =
      internal::aligned_directory_length(removed.name.size());
  removed.deleted = false;
  if (!add(target_directory, removed, error)) {
    Error ignored;
    auto *source = entries(source_directory);
    if (source)
      for (auto iterator = source->rbegin(); iterator != source->rend();
           ++iterator)
        if (iterator->deleted &&
            internal::normalize_name(iterator->name) ==
                internal::normalize_name(source_name)) {
          iterator->deleted = false;
          break;
        }
    return false;
  }
  if (removed.type == InodeType::directory &&
      source_directory != target_directory) {
    DirectoryEntry *parent = find(removed.inode, "..");
    if (!parent)
      return internal::fail(error, ErrorCode::invalid_directory,
                            removed.inode,
                            "moved directory lacks parent entry");
    parent->inode = target_directory;
  }
  return true;
}

const DirectoryEntry *
DirectoryTable::find(uint64_t directory, std::string_view name) const {
  auto iterator = directories_.find(directory);
  if (iterator == directories_.end())
    return nullptr;
  std::string key = internal::normalize_name(name);
  auto entry = std::find_if(
      iterator->second.begin(), iterator->second.end(),
      [&](const DirectoryEntry &candidate) {
        return !candidate.deleted &&
               internal::normalize_name(candidate.name) == key;
      });
  return entry == iterator->second.end() ? nullptr : &*entry;
}

DirectoryEntry *DirectoryTable::find(uint64_t directory,
                                     std::string_view name) {
  return const_cast<DirectoryEntry *>(
      static_cast<const DirectoryTable *>(this)->find(directory, name));
}

const std::vector<DirectoryEntry> *
DirectoryTable::entries(uint64_t directory) const {
  auto iterator = directories_.find(directory);
  return iterator == directories_.end() ? nullptr : &iterator->second;
}

std::vector<DirectoryEntry> *DirectoryTable::entries(uint64_t directory) {
  auto iterator = directories_.find(directory);
  return iterator == directories_.end() ? nullptr : &iterator->second;
}

bool DirectoryTable::verify(const InodeTable &inodes, uint64_t root_inode,
                            Error &error) const {
  error.clear();
  uint64_t total = 0;
  for (const auto &directory : directories_) {
    const Inode *inode = inodes.get(directory.first);
    if (!inode || inode->type != InodeType::directory)
      return internal::fail(error, ErrorCode::invalid_directory,
                            directory.first,
                            "directory table refers to non-directory inode");
    if (!checked_add(total, directory.second.size(), total) ||
        total > limits_.max_directory_entries)
      return internal::fail(error, ErrorCode::resource_limit, total,
                            "directory entry count exceeds limit");
    const DirectoryEntry *self = find(directory.first, ".");
    const DirectoryEntry *parent = find(directory.first, "..");
    if (!self || self->inode != directory.first || !parent ||
        !inodes.contains(parent->inode))
      return internal::fail(error, ErrorCode::invalid_directory,
                            directory.first,
                            "directory dot entries are invalid");
    std::set<std::string> names;
    for (const DirectoryEntry &entry : directory.second) {
      if (!entry.validate(limits_, error))
        return false;
      if (!entry.deleted) {
        if (!inodes.contains(entry.inode))
          return internal::fail(error, ErrorCode::invalid_inode, entry.inode,
                                "directory entry refers to missing inode");
        std::string key = internal::normalize_name(entry.name);
        if (!names.insert(key).second)
          return internal::fail(error, ErrorCode::invalid_directory,
                                directory.first,
                                "duplicate active directory entry");
        const Inode *target = inodes.get(entry.inode);
        if (target && target->type != entry.type)
          return internal::fail(error, ErrorCode::invalid_directory,
                                entry.inode,
                                "directory entry type differs from inode");
      }
    }
  }
  if (directories_.count(root_inode) == 0)
    return internal::fail(error, ErrorCode::invalid_directory, root_inode,
                          "root directory is missing");
  return true;
}

} // namespace blockforge
