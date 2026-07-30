#include "internal.h"

namespace blockforge {

PathResolver::PathResolver(Limits limits) : limits_(limits) {}

std::vector<std::string> PathResolver::split(std::string_view path,
                                            Error &error) const {
  error.clear();
  std::vector<std::string> components;
  if (path.empty() || path.size() > limits_.max_path_bytes ||
      path.find('\0') != std::string_view::npos) {
    internal::fail(error, ErrorCode::invalid_path, 0,
                   "path length or encoding is invalid");
    return {};
  }
  size_t position = 0;
  while (position < path.size()) {
    while (position < path.size() && path[position] == '/')
      ++position;
    if (position == path.size())
      break;
    size_t end = path.find('/', position);
    if (end == std::string_view::npos)
      end = path.size();
    std::string component(path.substr(position, end - position));
    if (component.size() > limits_.max_name_bytes) {
      internal::fail(error, ErrorCode::invalid_name, position,
                     "path component exceeds name limit");
      return {};
    }
    components.push_back(std::move(component));
    if (components.size() > limits_.max_path_components) {
      internal::fail(error, ErrorCode::resource_limit, components.size(),
                     "path has too many components");
      return {};
    }
    position = end;
  }
  return components;
}

std::optional<std::string>
PathResolver::normalize(std::string_view path, Error &error) const {
  auto components = split(path, error);
  if (error)
    return std::nullopt;
  std::vector<std::string> normalized;
  for (const std::string &component : components) {
    if (component.empty() || component == ".")
      continue;
    if (component == "..") {
      if (!normalized.empty())
        normalized.pop_back();
      continue;
    }
    normalized.push_back(component);
  }
  std::string output = "/";
  for (size_t index = 0; index < normalized.size(); ++index) {
    if (index)
      output.push_back('/');
    output += normalized[index];
  }
  return output;
}

std::optional<ResolvedPath>
PathResolver::resolve(std::string_view path, uint64_t root,
                      uint64_t working_directory, const InodeTable &inodes,
                      const DirectoryTable &directories,
                      bool follow_final_symlink, Error &error) const {
  error.clear();
  auto initial = split(path, error);
  if (error)
    return std::nullopt;
  uint64_t current = !path.empty() && path.front() == '/'
                         ? root
                         : working_directory;
  uint64_t parent = current;
  std::vector<std::string> pending = std::move(initial);
  std::vector<std::string> canonical;
  uint32_t followed = 0;
  uint32_t processed = 0;
  while (!pending.empty()) {
    if (++processed >
        limits_.max_path_components *
            (limits_.max_symlink_depth + 1u)) {
      internal::fail(error, ErrorCode::resource_limit, processed,
                     "path expansion exceeds component limit");
      return std::nullopt;
    }
    std::string component = std::move(pending.front());
    pending.erase(pending.begin());
    if (component.empty() || component == ".")
      continue;
    if (component == "..") {
      const DirectoryEntry *up = directories.find(current, "..");
      if (!up) {
        internal::fail(error, ErrorCode::invalid_directory, current,
                       "directory lacks a parent entry");
        return std::nullopt;
      }
      current = up->inode;
      parent = current;
      if (!canonical.empty())
        canonical.pop_back();
      continue;
    }
    const Inode *directory = inodes.get(current);
    if (!directory || directory->type != InodeType::directory) {
      internal::fail(error, ErrorCode::not_directory, current,
                     "path component parent is not a directory");
      return std::nullopt;
    }
    const DirectoryEntry *entry = directories.find(current, component);
    if (!entry) {
      internal::fail(error, ErrorCode::not_found, current,
                     "path component does not exist");
      return std::nullopt;
    }
    parent = current;
    current = entry->inode;
    const Inode *target = inodes.get(current);
    if (!target) {
      internal::fail(error, ErrorCode::invalid_inode, current,
                     "path refers to missing inode");
      return std::nullopt;
    }
    bool final = pending.empty();
    if (target->type == InodeType::symbolic_link &&
        (!final || follow_final_symlink)) {
      if (++followed > limits_.max_symlink_depth) {
        internal::fail(error, ErrorCode::loop_detected, current,
                       "symbolic-link resolution depth exceeded");
        return std::nullopt;
      }
      auto link_components = split(target->symlink_target, error);
      if (error)
        return std::nullopt;
      if (!target->symlink_target.empty() &&
          target->symlink_target.front() == '/') {
        current = root;
        parent = root;
        canonical.clear();
      } else {
        current = parent;
      }
      link_components.insert(link_components.end(),
                             std::make_move_iterator(pending.begin()),
                             std::make_move_iterator(pending.end()));
      pending = std::move(link_components);
      continue;
    }
    canonical.push_back(component);
  }
  ResolvedPath result;
  result.inode = current;
  result.parent = parent;
  result.name = canonical.empty() ? "/" : canonical.back();
  result.canonical = "/";
  for (size_t index = 0; index < canonical.size(); ++index) {
    if (index)
      result.canonical.push_back('/');
    result.canonical += canonical[index];
  }
  result.symlinks_followed = followed;
  return result;
}

std::optional<std::pair<uint64_t, std::string>>
PathResolver::resolve_parent(std::string_view path, uint64_t root,
                             uint64_t working_directory,
                             const InodeTable &inodes,
                             const DirectoryTable &directories,
                             Error &error) const {
  error.clear();
  auto components = split(path, error);
  if (error)
    return std::nullopt;
  while (!components.empty() &&
         (components.back().empty() || components.back() == "."))
    components.pop_back();
  if (components.empty() || components.back() == "..") {
    internal::fail(error, ErrorCode::invalid_path, 0,
                   "path has no creatable final component");
    return std::nullopt;
  }
  std::string name = std::move(components.back());
  components.pop_back();
  std::string parent_path =
      !path.empty() && path.front() == '/' ? "/" : ".";
  for (const auto &component : components) {
    if (parent_path.back() != '/')
      parent_path.push_back('/');
    parent_path += component;
  }
  auto parent = resolve(parent_path, root, working_directory, inodes,
                        directories, true, error);
  if (!parent)
    return std::nullopt;
  const Inode *parent_inode = inodes.get(parent->inode);
  if (!parent_inode || parent_inode->type != InodeType::directory) {
    internal::fail(error, ErrorCode::not_directory, parent->inode,
                   "new entry parent is not a directory");
    return std::nullopt;
  }
  return std::make_pair(parent->inode, std::move(name));
}

} // namespace blockforge
