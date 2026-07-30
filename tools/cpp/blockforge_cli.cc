#include "blockforge/filesystem.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {
struct Options {
  std::string image;
  std::string output;
  std::string command;
  bool list = false;
  bool walk = false;
  bool check = false;
  bool statistics = false;
  bool interactive = false;
  bool read_only = false;
};

void usage(std::ostream &output) {
  output
      << "Usage: blockforge_cli IMAGE [OPTIONS]\n"
      << "  --format SIZE       Create an image with SIZE 4096-byte blocks\n"
      << "  --output FILE       Save changes to FILE\n"
      << "  --list              List the root directory\n"
      << "  --walk              Recursively walk the image\n"
      << "  --check             Run consistency analysis\n"
      << "  --statistics        Print allocation statistics\n"
      << "  --interactive       Run the operation shell\n"
      << "  --read-only         Refuse image mutations\n";
}

std::optional<std::vector<uint8_t>> read_file(const std::string &path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    std::cerr << "cannot open " << path << '\n';
    return std::nullopt;
  }
  input.seekg(0, std::ios::end);
  auto length = input.tellg();
  if (length < 0 || length > 256ll * 1024 * 1024) {
    std::cerr << "image length is invalid\n";
    return std::nullopt;
  }
  input.seekg(0, std::ios::beg);
  std::vector<uint8_t> bytes(static_cast<size_t>(length));
  if (!bytes.empty())
    input.read(reinterpret_cast<char *>(bytes.data()), length);
  if (!input) {
    std::cerr << "failed to read image\n";
    return std::nullopt;
  }
  return bytes;
}

bool write_file(const std::string &path,
                const std::vector<uint8_t> &bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) {
    std::cerr << "cannot create " << path << '\n';
    return false;
  }
  output.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  return static_cast<bool>(output);
}

std::vector<std::string> words(std::string_view line) {
  std::vector<std::string> output;
  size_t position = 0;
  while (position < line.size()) {
    while (position < line.size() &&
           std::isspace(static_cast<unsigned char>(line[position])))
      ++position;
    if (position == line.size())
      break;
    std::string word;
    char quote = 0;
    if (line[position] == '\'' || line[position] == '"')
      quote = line[position++];
    while (position < line.size()) {
      char character = line[position];
      if (quote) {
        if (character == quote) {
          ++position;
          break;
        }
      } else if (std::isspace(static_cast<unsigned char>(character))) {
        break;
      }
      if (character == '\\' && position + 1 < line.size())
        character = line[++position];
      word.push_back(character);
      ++position;
    }
    output.push_back(std::move(word));
  }
  return output;
}

void print_error(const blockforge::Error &error) {
  std::cerr << blockforge::error_code_name(error.code) << " at "
            << error.offset << ": " << error.message << '\n';
}

void print_entry(const blockforge::WalkEntry &entry) {
  char type = '?';
  if (entry.stat.type == blockforge::InodeType::regular)
    type = '-';
  else if (entry.stat.type == blockforge::InodeType::directory)
    type = 'd';
  else if (entry.stat.type == blockforge::InodeType::symbolic_link)
    type = 'l';
  std::cout << type << ' ' << std::oct << std::setw(4)
            << std::setfill('0') << entry.stat.mode << std::dec
            << std::setfill(' ') << ' ' << std::setw(8)
            << entry.stat.size << ' ' << entry.path << '\n';
}

bool execute(blockforge::Filesystem &filesystem,
             const std::vector<std::string> &arguments) {
  if (arguments.empty())
    return true;
  const std::string &command = arguments[0];
  if (command == "mkdir" && arguments.size() == 2) {
    auto result = filesystem.create_directory(arguments[1]);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "touch" && arguments.size() == 2) {
    auto result = filesystem.create_file(arguments[1]);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "write" && arguments.size() >= 3) {
    std::string text = arguments[2];
    for (size_t index = 3; index < arguments.size(); ++index)
      text += " " + arguments[index];
    auto result = filesystem.write(
        arguments[1], 0, reinterpret_cast<const uint8_t *>(text.data()),
        text.size());
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "cat" && arguments.size() == 2) {
    auto result = filesystem.read(arguments[1], 0, 64 * 1024 * 1024);
    if (!result) {
      print_error(result.error);
      return false;
    }
    std::cout.write(reinterpret_cast<const char *>(result.data->data()),
                    result.data->size());
    std::cout << '\n';
    return true;
  }
  if (command == "ls" && arguments.size() <= 2) {
    blockforge::Error error;
    auto entries = filesystem.list(
        arguments.size() == 2 ? arguments[1] : "/", error);
    if (!entries) {
      print_error(error);
      return false;
    }
    for (const auto &entry : *entries)
      if (entry.name != "." && entry.name != "..")
        std::cout << blockforge::inode_type_name(entry.type) << " "
                  << entry.inode << " " << entry.name << '\n';
    return true;
  }
  if (command == "rm" && arguments.size() == 2) {
    auto result = filesystem.remove(arguments[1], false);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "rmr" && arguments.size() == 2) {
    auto result = filesystem.remove(arguments[1], true);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "mv" && arguments.size() == 3) {
    auto result = filesystem.rename(arguments[1], arguments[2]);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "ln" && arguments.size() == 3) {
    auto result = filesystem.create_hard_link(arguments[1], arguments[2]);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "lns" && arguments.size() == 3) {
    auto result = filesystem.create_symlink(arguments[1], arguments[2]);
    if (!result)
      print_error(result.error);
    return static_cast<bool>(result);
  }
  if (command == "begin" && arguments.size() == 1) {
    blockforge::Error error;
    if (!filesystem.begin(error))
      print_error(error);
    return !error;
  }
  if (command == "commit" && arguments.size() == 1) {
    blockforge::Error error;
    if (!filesystem.commit(error))
      print_error(error);
    return !error;
  }
  if (command == "rollback" && arguments.size() == 1) {
    blockforge::Error error;
    if (!filesystem.rollback(error))
      print_error(error);
    return !error;
  }
  std::cerr << "unknown or malformed command\n";
  return false;
}

bool shell(blockforge::Filesystem &filesystem) {
  std::string line;
  while (true) {
    std::cout << "blockforge> " << std::flush;
    if (!std::getline(std::cin, line))
      return true;
    if (line == "quit" || line == "exit")
      return true;
    execute(filesystem, words(line));
  }
}
} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    usage(std::cerr);
    return 2;
  }
  std::string image_path = argv[1];
  Options options;
  options.image = image_path;
  uint64_t format_blocks = 0;
  for (int index = 2; index < argc; ++index) {
    std::string argument = argv[index];
    if (argument == "--output" && index + 1 < argc)
      options.output = argv[++index];
    else if (argument == "--format" && index + 1 < argc)
      format_blocks = std::stoull(argv[++index]);
    else if (argument == "--list")
      options.list = true;
    else if (argument == "--walk")
      options.walk = true;
    else if (argument == "--check")
      options.check = true;
    else if (argument == "--statistics")
      options.statistics = true;
    else if (argument == "--interactive")
      options.interactive = true;
    else if (argument == "--read-only")
      options.read_only = true;
    else {
      usage(std::cerr);
      return 2;
    }
  }
  blockforge::Filesystem filesystem;
  blockforge::Error error;
  if (format_blocks) {
    blockforge::FormatOptions format;
    format.block_count = format_blocks;
    if (!filesystem.format(format, error)) {
      print_error(error);
      return 1;
    }
  } else {
    auto bytes = read_file(image_path);
    if (!bytes)
      return 1;
    blockforge::MountOptions mount;
    mount.read_only = options.read_only;
    mount.allow_dirty = true;
    if (!filesystem.mount(bytes->data(), bytes->size(), mount, error)) {
      print_error(error);
      return 1;
    }
  }
  if (options.list)
    execute(filesystem, {"ls", "/"});
  if (options.walk) {
    auto entries = filesystem.walk("/", error);
    if (!entries)
      print_error(error);
    else
      for (const auto &entry : *entries)
        print_entry(entry);
  }
  if (options.check)
    std::cout << blockforge::ConsistencyChecker::text(
        blockforge::ConsistencyChecker().check(filesystem));
  if (options.statistics) {
    auto values =
        blockforge::StatisticsCollector().collect(filesystem, error);
    if (error)
      print_error(error);
    else
      std::cout << blockforge::StatisticsCollector::text(values);
  }
  if (options.interactive)
    shell(filesystem);
  if (!options.output.empty()) {
    auto bytes = filesystem.serialize(error);
    if (error || !write_file(options.output, bytes)) {
      if (error)
        print_error(error);
      return 1;
    }
  }
  return 0;
}
