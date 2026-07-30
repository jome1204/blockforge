#include "internal.h"

namespace blockforge {

BlockDevice::BlockDevice(Limits limits) : limits_(limits) {}

bool BlockDevice::create(uint32_t block_size, uint64_t block_count,
                         Error &error) {
  error.clear();
  if (block_size < limits_.min_block_size ||
      block_size > limits_.max_block_size ||
      (block_size & (block_size - 1)) != 0)
    return internal::fail(error, ErrorCode::invalid_block, block_size,
                          "block size is invalid");
  if (block_count == 0 || block_count > limits_.max_blocks)
    return internal::fail(error, ErrorCode::resource_limit, block_count,
                          "block count exceeds limit");
  uint64_t bytes = 0;
  if (!checked_multiply(block_size, block_count, bytes) ||
      bytes > limits_.max_image_bytes ||
      bytes > std::numeric_limits<size_t>::max())
    return internal::fail(error, ErrorCode::overflow, block_count,
                          "block device size overflows");
  try {
    bytes_.assign(static_cast<size_t>(bytes), 0);
  } catch (const std::bad_alloc &) {
    return internal::fail(error, ErrorCode::resource_limit, bytes,
                          "block device allocation failed");
  }
  block_size_ = block_size;
  return true;
}

bool BlockDevice::open(const uint8_t *data, size_t size, uint32_t block_size,
                       Error &error) {
  error.clear();
  if (block_size < limits_.min_block_size ||
      block_size > limits_.max_block_size ||
      (block_size & (block_size - 1)) != 0 || size == 0 ||
      size % block_size != 0 || size > limits_.max_image_bytes)
    return internal::fail(error, ErrorCode::invalid_block, size,
                          "block device geometry is invalid");
  if (size / block_size > limits_.max_blocks)
    return internal::fail(error, ErrorCode::resource_limit, size,
                          "block device count exceeds limit");
  bytes_.assign(data, data + size);
  block_size_ = block_size;
  return true;
}

bool BlockDevice::read(uint64_t block, uint32_t offset, uint8_t *output,
                       size_t length, Error &error) const {
  error.clear();
  if (block >= block_count() || offset > block_size_ ||
      length > block_size_ - offset)
    return internal::fail(error, ErrorCode::invalid_block, block,
                          "block read exceeds device or block boundary");
  uint64_t base = block * static_cast<uint64_t>(block_size_) + offset;
  std::memcpy(output, bytes_.data() + static_cast<size_t>(base), length);
  return true;
}

bool BlockDevice::write(uint64_t block, uint32_t offset, const uint8_t *input,
                        size_t length, Error &error) {
  error.clear();
  if (block >= block_count() || offset > block_size_ ||
      length > block_size_ - offset)
    return internal::fail(error, ErrorCode::invalid_block, block,
                          "block write exceeds device or block boundary");
  uint64_t base = block * static_cast<uint64_t>(block_size_) + offset;
  std::memcpy(bytes_.data() + static_cast<size_t>(base), input, length);
  return true;
}

bool BlockDevice::zero(uint64_t block, Error &error) {
  error.clear();
  if (block >= block_count())
    return internal::fail(error, ErrorCode::invalid_block, block,
                          "cannot zero an out-of-range block");
  std::memset(block_data(block), 0, block_size_);
  return true;
}

const uint8_t *BlockDevice::block_data(uint64_t block) const {
  return block < block_count()
             ? bytes_.data() + static_cast<size_t>(block * block_size_)
             : nullptr;
}

uint8_t *BlockDevice::block_data(uint64_t block) {
  return block < block_count()
             ? bytes_.data() + static_cast<size_t>(block * block_size_)
             : nullptr;
}

uint64_t BlockDevice::block_count() const {
  return block_size_ == 0 ? 0 : bytes_.size() / block_size_;
}

BlockAllocator::BlockAllocator(Limits limits) : limits_(limits) {}

bool BlockAllocator::initialize(uint64_t block_count,
                                const std::set<uint64_t> &reserved,
                                Error &error) {
  error.clear();
  if (block_count == 0 || block_count > limits_.max_blocks)
    return internal::fail(error, ErrorCode::resource_limit, block_count,
                          "allocator block count exceeds limit");
  uint64_t byte_count = internal::ceil_divide(block_count, 8);
  if (byte_count > std::numeric_limits<size_t>::max())
    return internal::fail(error, ErrorCode::overflow, block_count,
                          "allocation bitmap length overflows");
  bits_.assign(static_cast<size_t>(byte_count), 0);
  block_count_ = block_count;
  search_hint_ = 0;
  for (uint64_t block : reserved)
    if (!reserve(block, error))
      return false;
  return true;
}

bool BlockAllocator::load(uint64_t block_count, const uint8_t *bitmap,
                          size_t size, Error &error) {
  error.clear();
  uint64_t required = internal::ceil_divide(block_count, 8);
  if (block_count == 0 || block_count > limits_.max_blocks ||
      required != size)
    return internal::fail(error, ErrorCode::invalid_block, block_count,
                          "allocation bitmap geometry is invalid");
  bits_.assign(bitmap, bitmap + size);
  block_count_ = block_count;
  search_hint_ = 0;
  if (block_count % 8 != 0) {
    uint8_t allowed = static_cast<uint8_t>((1u << (block_count % 8)) - 1u);
    if ((bits_.back() & ~allowed) != 0)
      return internal::fail(error, ErrorCode::invalid_block, block_count,
                            "allocation bitmap has out-of-range bits");
  }
  return true;
}

std::optional<uint64_t> BlockAllocator::allocate(Error &error) {
  error.clear();
  if (block_count_ == 0) {
    internal::fail(error, ErrorCode::internal_error, 0,
                   "allocator is not initialized");
    return std::nullopt;
  }
  for (uint64_t step = 0; step < block_count_; ++step) {
    uint64_t block = (search_hint_ + step) % block_count_;
    if (!is_allocated(block)) {
      bits_[static_cast<size_t>(block / 8)] |=
          static_cast<uint8_t>(1u << (block % 8));
      search_hint_ = (block + 1) % block_count_;
      return block;
    }
  }
  internal::fail(error, ErrorCode::no_space, block_count_,
                 "filesystem has no free blocks");
  return std::nullopt;
}

std::optional<std::vector<uint64_t>>
BlockAllocator::allocate_many(uint64_t count, Error &error) {
  error.clear();
  if (count > free_count()) {
    internal::fail(error, ErrorCode::no_space, count,
                   "not enough free blocks");
    return std::nullopt;
  }
  std::vector<uint64_t> result;
  result.reserve(static_cast<size_t>(count));
  for (uint64_t index = 0; index < count; ++index) {
    auto block = allocate(error);
    if (!block) {
      Error ignored;
      for (uint64_t allocated : result)
        release(allocated, ignored);
      return std::nullopt;
    }
    result.push_back(*block);
  }
  return result;
}

bool BlockAllocator::reserve(uint64_t block, Error &error) {
  error.clear();
  if (block >= block_count_)
    return internal::fail(error, ErrorCode::invalid_block, block,
                          "reserved block is out of range");
  if (is_allocated(block))
    return internal::fail(error, ErrorCode::already_exists, block,
                          "block is already allocated");
  bits_[static_cast<size_t>(block / 8)] |=
      static_cast<uint8_t>(1u << (block % 8));
  return true;
}

bool BlockAllocator::release(uint64_t block, Error &error) {
  error.clear();
  if (block >= block_count_)
    return internal::fail(error, ErrorCode::invalid_block, block,
                          "released block is out of range");
  if (!is_allocated(block))
    return internal::fail(error, ErrorCode::invalid_block, block,
                          "block is already free");
  bits_[static_cast<size_t>(block / 8)] &=
      static_cast<uint8_t>(~(1u << (block % 8)));
  if (block < search_hint_)
    search_hint_ = block;
  return true;
}

bool BlockAllocator::is_allocated(uint64_t block) const {
  return block < block_count_ &&
         (bits_[static_cast<size_t>(block / 8)] &
          static_cast<uint8_t>(1u << (block % 8))) != 0;
}

uint64_t BlockAllocator::allocated_count() const {
  uint64_t count = 0;
  for (uint64_t block = 0; block < block_count_; ++block)
    count += is_allocated(block) ? 1 : 0;
  return count;
}

uint64_t BlockAllocator::free_count() const {
  return block_count_ - allocated_count();
}

std::vector<uint8_t> BlockAllocator::bitmap() const { return bits_; }

bool BlockAllocator::verify(Error &error) const {
  error.clear();
  if (block_count_ == 0 ||
      bits_.size() != internal::ceil_divide(block_count_, 8))
    return internal::fail(error, ErrorCode::invalid_block, block_count_,
                          "allocation bitmap has invalid size");
  if (block_count_ % 8 != 0) {
    uint8_t allowed = static_cast<uint8_t>((1u << (block_count_ % 8)) - 1u);
    if ((bits_.back() & ~allowed) != 0)
      return internal::fail(error, ErrorCode::invalid_block, block_count_,
                            "allocation bitmap has invalid tail bits");
  }
  return true;
}

} // namespace blockforge
