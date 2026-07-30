#include "blockforge/filesystem.h"

#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace {
struct Options {
  std::string output;
  uint32_t block_size = 4096;
  uint64_t blocks = 256;
  uint64_t inodes = 1024;
  uint64_t journal_blocks = 8;
  std::string label = "BlockForge";
  bool force = false;
};

void usage(std::ostream &output) {
  output
      << "Usage: blockforge_mkfs OUTPUT [OPTIONS]\n"
      << "  --block-size N       Power-of-two block size (512..65536)\n"
      << "  --blocks N           Number of blocks (minimum 8)\n"
      << "  --inodes N           Inode capacity\n"
      << "  --journal-blocks N   Journal reservation hint\n"
      << "  --label TEXT         Filesystem label\n"
      << "  --force              Replace an existing output file\n"
      << "  --help               Show this help\n";
}

std::optional<uint64_t> number(const std::string &text) {
  if (text.empty() || text.front() == '-')
    return std::nullopt;
  size_t consumed = 0;
  try {
    unsigned long long value = std::stoull(text, &consumed, 0);
    if (consumed != text.size())
      return std::nullopt;
    return static_cast<uint64_t>(value);
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

std::optional<uint64_t> byte_size(const std::string &text) {
  if (text.empty())
    return std::nullopt;
  std::string digits = text;
  uint64_t multiplier = 1;
  char suffix = static_cast<char>(
      std::tolower(static_cast<unsigned char>(digits.back())));
  if (suffix == 'k' || suffix == 'm' || suffix == 'g') {
    digits.pop_back();
    if (suffix == 'k')
      multiplier = 1024;
    else if (suffix == 'm')
      multiplier = 1024 * 1024;
    else
      multiplier = 1024ull * 1024 * 1024;
  }
  auto base = number(digits);
  if (!base || (*base != 0 &&
                multiplier > std::numeric_limits<uint64_t>::max() / *base))
    return std::nullopt;
  return *base * multiplier;
}

bool valid_geometry(const Options &options, std::string &reason) {
  if (options.block_size < 512 || options.block_size > 65536 ||
      (options.block_size & (options.block_size - 1)) != 0) {
    reason = "block size must be a power of two between 512 and 65536";
    return false;
  }
  if (options.blocks < 8 || options.blocks > 4'000'000) {
    reason = "block count must be between 8 and 4000000";
    return false;
  }
  if (options.inodes == 0 || options.inodes > 1'000'000) {
    reason = "inode capacity must be between 1 and 1000000";
    return false;
  }
  if (options.journal_blocks >= options.blocks) {
    reason = "journal block count must be smaller than the filesystem";
    return false;
  }
  uint64_t bytes = 0;
  if (!blockforge::checked_multiply(
          options.block_size, options.blocks, bytes) ||
      bytes > 256ull * 1024 * 1024) {
    reason = "filesystem device exceeds the 256 MiB image limit";
    return false;
  }
  if (options.label.empty() || options.label.size() > 255) {
    reason = "filesystem label must contain between 1 and 255 bytes";
    return false;
  }
  return true;
}

std::optional<Options> parse(int argc, char **argv) {
  if (argc < 2)
    return std::nullopt;
  Options options;
  options.output = argv[1];
  for (int index = 2; index < argc; ++index) {
    std::string argument = argv[index];
    auto next = [&](const char *name) -> std::optional<std::string> {
      if (++index >= argc) {
        std::cerr << name << " requires a value\n";
        return std::nullopt;
      }
      return std::string(argv[index]);
    };
    if (argument == "--force") {
      options.force = true;
    } else if (argument == "--help") {
      usage(std::cout);
      std::exit(0);
    } else if (argument == "--block-size") {
      auto text = next("--block-size");
      auto value = text ? byte_size(*text) : std::nullopt;
      if (!value || *value > std::numeric_limits<uint32_t>::max())
        return std::nullopt;
      options.block_size = static_cast<uint32_t>(*value);
    } else if (argument == "--blocks") {
      auto text = next("--blocks");
      auto value = text ? number(*text) : std::nullopt;
      if (!value)
        return std::nullopt;
      options.blocks = *value;
    } else if (argument == "--inodes") {
      auto text = next("--inodes");
      auto value = text ? number(*text) : std::nullopt;
      if (!value)
        return std::nullopt;
      options.inodes = *value;
    } else if (argument == "--journal-blocks") {
      auto text = next("--journal-blocks");
      auto value = text ? number(*text) : std::nullopt;
      if (!value)
        return std::nullopt;
      options.journal_blocks = *value;
    } else if (argument == "--label") {
      auto text = next("--label");
      if (!text)
        return std::nullopt;
      options.label = std::move(*text);
    } else {
      std::cerr << "unknown option: " << argument << '\n';
      return std::nullopt;
    }
  }
  return options;
}

bool exists(const std::string &path) {
  std::ifstream input(path, std::ios::binary);
  return static_cast<bool>(input);
}

bool write_image(const std::string &path,
                 const std::vector<uint8_t> &image) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output)
    return false;
  output.write(reinterpret_cast<const char *>(image.data()), image.size());
  output.flush();
  return static_cast<bool>(output);
}
} // namespace

int main(int argc, char **argv) {
  auto options = parse(argc, argv);
  if (!options) {
    usage(std::cerr);
    return 2;
  }
  std::string geometry_error;
  if (!valid_geometry(*options, geometry_error)) {
    std::cerr << "invalid geometry: " << geometry_error << '\n';
    return 2;
  }
  if (!options->force && exists(options->output)) {
    std::cerr << options->output
              << " already exists; use --force to replace it\n";
    return 1;
  }
  blockforge::FormatOptions format;
  format.block_size = options->block_size;
  format.block_count = options->blocks;
  format.inode_capacity = options->inodes;
  format.journal_blocks = options->journal_blocks;
  format.label = options->label;
  blockforge::Filesystem filesystem;
  blockforge::Error error;
  if (!filesystem.format(format, error)) {
    std::cerr << blockforge::error_code_name(error.code) << " at "
              << error.offset << ": " << error.message << '\n';
    return 1;
  }
  auto image = filesystem.serialize(error);
  if (error) {
    std::cerr << "serialization failed: " << error.message << '\n';
    return 1;
  }
  if (!write_image(options->output, image)) {
    std::cerr << "cannot write " << options->output << '\n';
    return 1;
  }
  std::cout << "Created BlockForge image " << options->output << '\n'
            << "  image bytes: " << image.size() << '\n'
            << "  block size: " << format.block_size << '\n'
            << "  blocks: " << format.block_count << '\n'
            << "  inode capacity: " << format.inode_capacity << '\n'
            << "  journal blocks: " << format.journal_blocks << '\n'
            << "  label: " << format.label << '\n';
  return 0;
}
