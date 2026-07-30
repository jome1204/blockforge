#define _CRT_SECURE_NO_WARNINGS

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BF_HEADER_SIZE 112u
#define BF_MAX_IMAGE (256u * 1024u * 1024u)

struct bf_header {
  uint32_t version;
  uint32_t block_size;
  uint64_t block_count;
  uint64_t inode_count;
  uint64_t root_inode;
  uint64_t generation;
  uint64_t bitmap_bytes;
  uint64_t inode_bytes;
  uint64_t directory_bytes;
  uint64_t journal_bytes;
  uint64_t device_bytes;
  uint64_t next_inode;
  uint32_t checksum;
  uint32_t flags;
};

static uint32_t read_u32(const unsigned char *data) {
  return (uint32_t)data[0] |
         ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) |
         ((uint32_t)data[3] << 24);
}

static uint64_t read_u64(const unsigned char *data) {
  return (uint64_t)read_u32(data) |
         ((uint64_t)read_u32(data + 4) << 32);
}

static int add_u64(uint64_t left, uint64_t right, uint64_t *output) {
  if (right > UINT64_MAX - left)
    return 0;
  *output = left + right;
  return 1;
}

static int multiply_u64(uint64_t left, uint64_t right, uint64_t *output) {
  if (left != 0 && right > UINT64_MAX / left)
    return 0;
  *output = left * right;
  return 1;
}

static uint32_t crc32_bytes(const unsigned char *data, size_t size) {
  uint32_t checksum = 0xffffffffu;
  size_t index;
  for (index = 0; index < size; ++index) {
    unsigned bit;
    checksum ^= data[index];
    for (bit = 0; bit < 8; ++bit) {
      uint32_t mask = (uint32_t)-(int32_t)(checksum & 1u);
      checksum = (checksum >> 1) ^ (0xedb88320u & mask);
    }
  }
  return ~checksum;
}

static int power_of_two(uint32_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

static int parse_header(
    const unsigned char *data,
    size_t size,
    struct bf_header *header,
    char *message,
    size_t message_size) {
  static const unsigned char signature[8] = {
      'B', 'F', 'I', 'M', 'G', '1', 0, 0};
  uint64_t expected_device;
  uint64_t expected_size = BF_HEADER_SIZE;
  const uint64_t *sections;
  unsigned section;
  if (size < BF_HEADER_SIZE) {
    snprintf(message, message_size, "image header is truncated");
    return 0;
  }
  if (memcmp(data, signature, sizeof(signature)) != 0) {
    snprintf(message, message_size, "image signature is invalid");
    return 0;
  }
  header->version = read_u32(data + 8);
  header->block_size = read_u32(data + 12);
  header->block_count = read_u64(data + 16);
  header->inode_count = read_u64(data + 24);
  header->root_inode = read_u64(data + 32);
  header->generation = read_u64(data + 40);
  header->bitmap_bytes = read_u64(data + 48);
  header->inode_bytes = read_u64(data + 56);
  header->directory_bytes = read_u64(data + 64);
  header->journal_bytes = read_u64(data + 72);
  header->device_bytes = read_u64(data + 80);
  header->next_inode = read_u64(data + 88);
  header->checksum = read_u32(data + 96);
  header->flags = read_u32(data + 100);
  if (header->version != 1u) {
    snprintf(message, message_size, "unsupported filesystem version");
    return 0;
  }
  if (header->block_size < 512u || header->block_size > 65536u ||
      !power_of_two(header->block_size)) {
    snprintf(message, message_size, "block size is invalid");
    return 0;
  }
  if (header->block_count == 0 || header->block_count > 4000000u ||
      header->inode_count > 1000000u || header->root_inode == 0) {
    snprintf(message, message_size, "filesystem counts exceed limits");
    return 0;
  }
  if (header->bitmap_bytes != (header->block_count + 7u) / 8u) {
    snprintf(message, message_size, "bitmap length is inconsistent");
    return 0;
  }
  if (!multiply_u64(
          header->block_count, header->block_size, &expected_device) ||
      expected_device != header->device_bytes) {
    snprintf(message, message_size, "device geometry is inconsistent");
    return 0;
  }
  if ((header->flags & ~1u) != 0u) {
    snprintf(message, message_size, "unknown filesystem flags");
    return 0;
  }
  sections = &header->bitmap_bytes;
  for (section = 0; section < 5; ++section) {
    if (!add_u64(expected_size, sections[section], &expected_size)) {
      snprintf(message, message_size, "section sizes overflow");
      return 0;
    }
  }
  if (expected_size != size) {
    snprintf(message, message_size, "section sizes differ from image");
    return 0;
  }
  if (crc32_bytes(data + BF_HEADER_SIZE, size - BF_HEADER_SIZE) !=
      header->checksum) {
    snprintf(message, message_size, "body checksum mismatch");
    return 0;
  }
  return 1;
}

static unsigned char *read_file(
    const char *path,
    size_t *size,
    char *message,
    size_t message_size) {
  FILE *input = fopen(path, "rb");
  long length;
  unsigned char *data;
  if (input == NULL) {
    snprintf(message, message_size, "cannot open: %s", strerror(errno));
    return NULL;
  }
  if (fseek(input, 0, SEEK_END) != 0 || (length = ftell(input)) < 0 ||
      fseek(input, 0, SEEK_SET) != 0) {
    snprintf(message, message_size, "cannot determine image length");
    fclose(input);
    return NULL;
  }
  if ((unsigned long)length > BF_MAX_IMAGE) {
    snprintf(message, message_size, "image exceeds resource limit");
    fclose(input);
    return NULL;
  }
  data = (unsigned char *)malloc(length == 0 ? 1u : (size_t)length);
  if (data == NULL) {
    snprintf(message, message_size, "memory allocation failed");
    fclose(input);
    return NULL;
  }
  if (fread(data, 1, (size_t)length, input) != (size_t)length) {
    snprintf(message, message_size, "image read failed");
    free(data);
    fclose(input);
    return NULL;
  }
  fclose(input);
  *size = (size_t)length;
  return data;
}

static void print_header(
    const char *path,
    size_t size,
    const struct bf_header *header) {
  printf("%s\n", path);
  printf("  bytes: %zu\n", size);
  printf("  block size: %" PRIu32 "\n", header->block_size);
  printf("  blocks: %" PRIu64 "\n", header->block_count);
  printf("  inodes: %" PRIu64 "\n", header->inode_count);
  printf("  root inode: %" PRIu64 "\n", header->root_inode);
  printf("  generation: %" PRIu64 "\n", header->generation);
  printf("  journal bytes: %" PRIu64 "\n", header->journal_bytes);
  printf("  status: %s\n", (header->flags & 1u) ? "dirty" : "clean");
  printf("  checksum: valid\n");
}

int main(int argc, char **argv) {
  int index;
  int failed = 0;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s IMAGE...\n", argv[0]);
    return 2;
  }
  for (index = 1; index < argc; ++index) {
    unsigned char *data;
    size_t size = 0;
    char message[256];
    struct bf_header header;
    data = read_file(argv[index], &size, message, sizeof(message));
    if (data == NULL) {
      fprintf(stderr, "%s: %s\n", argv[index], message);
      failed = 1;
      continue;
    }
    if (!parse_header(data, size, &header, message, sizeof(message))) {
      fprintf(stderr, "%s: %s\n", argv[index], message);
      failed = 1;
      free(data);
      continue;
    }
    print_header(argv[index], size, &header);
    free(data);
  }
  return failed;
}
