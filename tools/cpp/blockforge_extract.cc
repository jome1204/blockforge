#include "blockforge/filesystem.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {
std::optional<std::vector<uint8_t>> read_image(const fs::path &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return std::nullopt;
  input.seekg(0, std::ios::end);
  auto length = input.tellg();
  if (length < 0 || length > 256ll * 1024 * 1024)
    return std::nullopt;
  input.seekg(0, std::ios::beg);
  std::vector<uint8_t> output(static_cast<size_t>(length));
  if (!output.empty())
    input.read(reinterpret_cast<char *>(output.data()), length);
  return input ? std::optional<std::vector<uint8_t>>(std::move(output))
               : std::nullopt;
}

bool safe_relative(std::string_view path, fs::path &output) {
  output.clear();
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
    if (component.empty() || component == "." || component == ".." ||
        component.find('\\') != std::string::npos ||
        component.find(':') != std::string::npos)
      return false;
    output /= component;
    position = end;
  }
  return !output.empty();
}

bool write_regular(const fs::path &path,
                   const std::vector<uint8_t> &data) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output)
    return false;
  output.write(reinterpret_cast<const char *>(data.data()), data.size());
  return static_cast<bool>(output);
}

void usage() {
  std::cerr << "Usage: blockforge_extract IMAGE OUTPUT_DIRECTORY "
               "[PATH]\n";
}
} // namespace

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    usage();
    return 2;
  }
  fs::path image_path = argv[1];
  fs::path output_root = fs::absolute(argv[2]).lexically_normal();
  std::string source_root = argc == 4 ? argv[3] : "/";
  auto bytes = read_image(image_path);
  if (!bytes) {
    std::cerr << "cannot read image\n";
    return 1;
  }
  blockforge::Filesystem filesystem;
  blockforge::MountOptions options;
  options.read_only = true;
  options.allow_dirty = true;
  blockforge::Error error;
  if (!filesystem.mount(bytes->data(), bytes->size(), options, error)) {
    std::cerr << blockforge::error_code_name(error.code) << ": "
              << error.message << '\n';
    return 1;
  }
  auto entries = filesystem.walk(source_root, error);
  if (!entries) {
    std::cerr << blockforge::error_code_name(error.code) << ": "
              << error.message << '\n';
    return 1;
  }
  fs::create_directories(output_root);
  uint64_t extracted_bytes = 0;
  size_t extracted_files = 0;
  for (const auto &entry : *entries) {
    if (entry.path == source_root)
      continue;
    std::string relative_text = entry.path;
    if (source_root != "/" &&
        relative_text.rfind(source_root, 0) == 0)
      relative_text.erase(0, source_root.size());
    fs::path relative;
    if (!safe_relative(relative_text, relative)) {
      std::cerr << "refusing unsafe image path: " << entry.path << '\n';
      return 1;
    }
    fs::path destination =
        (output_root / relative).lexically_normal();
    auto destination_text = destination.native();
    auto root_text = output_root.native();
    if (destination_text.size() < root_text.size() ||
        destination_text.compare(0, root_text.size(), root_text) != 0) {
      std::cerr << "extraction path escapes destination\n";
      return 1;
    }
    if (entry.stat.type == blockforge::InodeType::directory) {
      fs::create_directories(destination);
      continue;
    }
    if (entry.stat.type == blockforge::InodeType::symbolic_link) {
      // Symlinks are represented as text manifests to avoid host traversal.
      fs::create_directories(destination.parent_path());
      std::ofstream link(destination.string() + ".symlink.txt");
      const auto *inode = filesystem.inodes().get(entry.stat.inode);
      if (!link || !inode) {
        std::cerr << "cannot write symbolic-link manifest\n";
        return 1;
      }
      link << inode->symlink_target << '\n';
      continue;
    }
    auto content = filesystem.read(entry.path, 0,
                                   static_cast<size_t>(entry.stat.size));
    if (!content) {
      std::cerr << "cannot read " << entry.path << ": "
                << content.error.message << '\n';
      return 1;
    }
    fs::create_directories(destination.parent_path());
    if (!write_regular(destination, *content.data)) {
      std::cerr << "cannot write " << destination << '\n';
      return 1;
    }
    extracted_bytes += content.data->size();
    ++extracted_files;
  }
  std::cout << "Extracted " << extracted_files << " files and "
            << extracted_bytes << " bytes to " << output_root << '\n';
  return 0;
}
