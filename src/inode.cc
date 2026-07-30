#include "internal.h"

namespace blockforge {

InodeTable::InodeTable(Limits limits) : limits_(limits) {}

bool InodeTable::initialize(Error &error) {
  error.clear();
  inodes_.clear();
  next_identifier_ = 1;
  return true;
}

std::optional<uint64_t> InodeTable::allocate(InodeType type, uint16_t mode,
                                             Error &error) {
  error.clear();
  if (type < InodeType::regular || type > InodeType::symbolic_link) {
    internal::fail(error, ErrorCode::invalid_inode, 0,
                   "cannot allocate invalid inode type");
    return std::nullopt;
  }
  if (inodes_.size() >= limits_.max_inodes ||
      next_identifier_ > limits_.max_inodes) {
    internal::fail(error, ErrorCode::no_space, next_identifier_,
                   "inode table has reached its limit");
    return std::nullopt;
  }
  while (inodes_.count(next_identifier_) != 0) {
    if (++next_identifier_ > limits_.max_inodes) {
      internal::fail(error, ErrorCode::no_space, next_identifier_,
                     "no unused inode identifier remains");
      return std::nullopt;
    }
  }
  uint64_t identifier = next_identifier_++;
  Inode inode;
  inode.identifier = identifier;
  inode.type = type;
  inode.mode = mode;
  inode.link_count = type == InodeType::directory ? 2 : 1;
  inodes_.emplace(identifier, std::move(inode));
  return identifier;
}

bool InodeTable::insert(Inode inode, Error &error) {
  error.clear();
  if (inode.identifier == 0 || inode.identifier > limits_.max_inodes)
    return internal::fail(error, ErrorCode::invalid_inode, inode.identifier,
                          "inserted inode identifier is invalid");
  if (inodes_.count(inode.identifier) != 0)
    return internal::fail(error, ErrorCode::already_exists, inode.identifier,
                          "inode identifier already exists");
  if (inodes_.size() >= limits_.max_inodes)
    return internal::fail(error, ErrorCode::resource_limit, inodes_.size(),
                          "inode table exceeds limit");
  next_identifier_ = std::max(next_identifier_, inode.identifier + 1);
  inodes_.emplace(inode.identifier, std::move(inode));
  return true;
}

bool InodeTable::erase(uint64_t identifier, Error &error) {
  error.clear();
  auto iterator = inodes_.find(identifier);
  if (iterator == inodes_.end())
    return internal::fail(error, ErrorCode::not_found, identifier,
                          "inode does not exist");
  inodes_.erase(iterator);
  if (identifier < next_identifier_)
    next_identifier_ = identifier;
  return true;
}

const Inode *InodeTable::get(uint64_t identifier) const {
  auto iterator = inodes_.find(identifier);
  return iterator == inodes_.end() ? nullptr : &iterator->second;
}

Inode *InodeTable::get(uint64_t identifier) {
  auto iterator = inodes_.find(identifier);
  return iterator == inodes_.end() ? nullptr : &iterator->second;
}

bool InodeTable::contains(uint64_t identifier) const {
  return inodes_.count(identifier) != 0;
}

void InodeTable::set_next_identifier(uint64_t value) {
  next_identifier_ = std::max<uint64_t>(1, value);
}

bool InodeTable::verify(const Superblock &superblock, Error &error) const {
  error.clear();
  if (inodes_.size() > limits_.max_inodes)
    return internal::fail(error, ErrorCode::resource_limit, inodes_.size(),
                          "inode table exceeds resource limit");
  for (const auto &entry : inodes_) {
    if (entry.first != entry.second.identifier)
      return internal::fail(error, ErrorCode::invalid_inode, entry.first,
                            "inode map key and identifier differ");
    if (!entry.second.validate(superblock, limits_, error))
      return false;
  }
  return true;
}

ExtentResolver::ExtentResolver(Limits limits) : limits_(limits) {}

std::optional<BlockMapping>
ExtentResolver::map(const Inode &inode, uint64_t logical_block,
                    const Superblock &superblock, Error &error) const {
  error.clear();
  for (const Extent &extent : inode.extents) {
    uint64_t end = extent.logical_end(error);
    if (error)
      return std::nullopt;
    if (logical_block < extent.logical_block || logical_block >= end)
      continue;
    uint64_t relative = logical_block - extent.logical_block;
    BlockMapping mapping;
    mapping.logical_block = logical_block;
    mapping.contiguous_blocks =
        static_cast<uint32_t>(extent.block_count - relative);
    if (!extent.sparse) {
      uint64_t physical = 0;
      if (!checked_add(extent.physical_block, relative, physical) ||
          physical >= superblock.block_count) {
        internal::fail(error, ErrorCode::invalid_extent, logical_block,
                       "extent maps outside the device");
        return std::nullopt;
      }
      mapping.physical_block = physical;
    }
    return mapping;
  }
  BlockMapping hole;
  hole.logical_block = logical_block;
  hole.contiguous_blocks = 1;
  return hole;
}

bool ExtentResolver::normalize(std::vector<Extent> &extents,
                               const Superblock &superblock,
                               Error &error) const {
  error.clear();
  if (extents.size() > limits_.max_extents_per_inode)
    return internal::fail(error, ErrorCode::resource_limit, extents.size(),
                          "extent count exceeds limit");
  std::sort(extents.begin(), extents.end(),
            [](const Extent &left, const Extent &right) {
              return left.logical_block < right.logical_block;
            });
  std::vector<Extent> normalized;
  for (const Extent &extent : extents) {
    if (extent.block_count == 0)
      return internal::fail(error, ErrorCode::invalid_extent,
                            extent.logical_block, "zero-length extent");
    Error end_error;
    uint64_t logical_end = extent.logical_end(end_error);
    if (end_error) {
      error = std::move(end_error);
      return false;
    }
    if (!extent.sparse) {
      uint64_t physical_end = extent.physical_end(end_error);
      if (end_error || physical_end > superblock.block_count) {
        error = end_error;
        if (!error)
          internal::fail(error, ErrorCode::invalid_extent,
                         extent.physical_block,
                         "physical extent exceeds filesystem");
        return false;
      }
    }
    if (!normalized.empty()) {
      Extent &previous = normalized.back();
      uint64_t previous_end = previous.logical_end(end_error);
      if (extent.logical_block < previous_end)
        return internal::fail(error, ErrorCode::invalid_extent,
                              extent.logical_block,
                              "logical extents overlap");
      bool adjacent_logical = extent.logical_block == previous_end;
      bool adjacent_physical =
          previous.sparse ||
          extent.physical_block ==
              previous.physical_block + previous.block_count;
      if (adjacent_logical && previous.sparse == extent.sparse &&
          adjacent_physical) {
        uint64_t joined = static_cast<uint64_t>(previous.block_count) +
                          extent.block_count;
        if (joined <= std::numeric_limits<uint32_t>::max()) {
          previous.block_count = static_cast<uint32_t>(joined);
          continue;
        }
      }
    }
    normalized.push_back(extent);
    (void)logical_end;
  }
  extents = std::move(normalized);
  return true;
}

bool ExtentResolver::verify(const Inode &inode,
                            const Superblock &superblock,
                            Error &error) const {
  error.clear();
  std::vector<Extent> copy = inode.extents;
  if (!normalize(copy, superblock, error))
    return false;
  if (copy.size() != inode.extents.size())
    return internal::fail(error, ErrorCode::invalid_extent, inode.identifier,
                          "inode extents are not canonical");
  uint64_t physical_blocks = 0;
  for (const Extent &extent : inode.extents)
    if (!extent.sparse &&
        !checked_add(physical_blocks, extent.block_count, physical_blocks))
      return internal::fail(error, ErrorCode::overflow, inode.identifier,
                            "allocated block count overflows");
  uint64_t allocated_bytes = 0;
  if (!checked_multiply(physical_blocks, superblock.block_size,
                        allocated_bytes) ||
      allocated_bytes != inode.allocated_bytes)
    return internal::fail(error, ErrorCode::invalid_extent, inode.identifier,
                          "inode allocated byte count differs from extents");
  uint64_t logical_blocks =
      internal::ceil_divide(inode.size, superblock.block_size);
  for (const Extent &extent : inode.extents) {
    Error ignored;
    if (extent.logical_end(ignored) > logical_blocks && inode.size != 0)
      return internal::fail(error, ErrorCode::invalid_extent,
                            extent.logical_block,
                            "extent extends beyond logical file size");
  }
  return true;
}

std::set<uint64_t>
ExtentResolver::physical_blocks(const Inode &inode,
                                const Superblock &superblock,
                                Error &error) const {
  error.clear();
  std::set<uint64_t> result;
  if (!verify(inode, superblock, error))
    return {};
  for (const Extent &extent : inode.extents) {
    if (extent.sparse)
      continue;
    for (uint32_t offset = 0; offset < extent.block_count; ++offset)
      if (!result.insert(extent.physical_block + offset).second) {
        internal::fail(error, ErrorCode::invalid_extent,
                       extent.physical_block + offset,
                       "inode references a block more than once");
        return {};
      }
  }
  return result;
}

} // namespace blockforge
