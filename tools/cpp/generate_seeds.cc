#include "blockforge/filesystem.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {
bool save(const fs::path &path, const std::vector<uint8_t> &data) {
  fs::create_directories(path.parent_path());
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(reinterpret_cast<const char *>(data.data()), data.size());
  return static_cast<bool>(output);
}

blockforge::Filesystem formatted(uint64_t blocks = 96) {
  blockforge::Filesystem filesystem;
  blockforge::FormatOptions options;
  options.block_size = 512;
  options.block_count = blocks;
  blockforge::Error error;
  if (!filesystem.format(options, error))
    throw std::runtime_error(error.message);
  return filesystem;
}

void save_image(blockforge::Filesystem &filesystem, const fs::path &path) {
  blockforge::Error error;
  auto bytes = filesystem.serialize(error);
  if (error || !save(path, bytes))
    throw std::runtime_error(error ? error.message : "cannot save seed");
}

void generate_images(const fs::path &root) {
  {
    auto filesystem = formatted();
    save_image(filesystem, root / "empty.bfimg");
  }
  {
    auto filesystem = formatted();
    filesystem.create_directory("/home");
    filesystem.create_directory("/home/user");
    filesystem.create_directory("/home/user/docs");
    filesystem.create_file("/home/user/docs/readme.txt",
                           {'B', 'l', 'o', 'c', 'k', 'F', 'o', 'r', 'g', 'e'});
    save_image(filesystem, root / "nested.bfimg");
  }
  {
    auto filesystem = formatted(512);
    std::vector<uint8_t> data(64 * 1024);
    for (size_t index = 0; index < data.size(); ++index)
      data[index] = static_cast<uint8_t>((index * 31 + index / 7) & 0xff);
    filesystem.create_file("/large.bin", data);
    save_image(filesystem, root / "large_file.bfimg");
  }
  {
    auto filesystem = formatted();
    filesystem.create_file("/target", {'t', 'a', 'r', 'g', 'e', 't'});
    filesystem.create_symlink("target", "/relative-link");
    filesystem.create_symlink("/target", "/absolute-link");
    filesystem.create_hard_link("/target", "/hard-link");
    save_image(filesystem, root / "links.bfimg");
  }
  {
    auto filesystem = formatted();
    filesystem.create_directory("/deleted");
    filesystem.create_file("/deleted/old", {1, 2, 3});
    filesystem.remove("/deleted/old");
    filesystem.create_file("/deleted/new", {4, 5, 6});
    save_image(filesystem, root / "deleted_entries.bfimg");
  }
  {
    auto filesystem = formatted();
    blockforge::Error error;
    filesystem.begin(error);
    filesystem.create_directory("/transaction");
    filesystem.create_file("/transaction/data", {1, 3, 3, 7});
    filesystem.commit(error);
    filesystem.checkpoint(error);
    save_image(filesystem, root / "journal.bfimg");
  }
  {
    auto filesystem = formatted();
    filesystem.create_file("/metadata", {'x'});
    blockforge::Error error;
    filesystem.set_attribute("/metadata", "user.mime",
                             {'a', 'p', 'p', '/', 'b', 'i', 'n'}, error);
    filesystem.set_attribute("/metadata", "user.comment",
                             {'f', 'u', 'z', 'z', ' ', 'm', 'e'}, error);
    save_image(filesystem, root / "attributes.bfimg");
  }
  {
    auto filesystem = formatted();
    std::vector<uint8_t> filler(512, 0x41);
    filesystem.create_file("/a", filler);
    filesystem.create_file("/b", filler);
    filesystem.create_file("/c", filler);
    filesystem.remove("/b");
    std::vector<uint8_t> fragmented(1400, 0x5a);
    filesystem.create_file("/fragmented", fragmented);
    save_image(filesystem, root / "fragmented.bfimg");
  }
}

void copy_images(const fs::path &source, const fs::path &corpus) {
  for (const auto &entry : fs::directory_iterator(source)) {
    if (!entry.is_regular_file())
      continue;
    for (const std::string &harness :
         {"filesystem_mount_fuzzer", "filesystem_walk_fuzzer",
          "filesystem_repair_fuzzer"}) {
      fs::path target = corpus / harness / entry.path().filename();
      fs::create_directories(target.parent_path());
      fs::copy_file(entry.path(), target,
                    fs::copy_options::overwrite_existing);
    }
  }
}

void generate_read_seeds(const fs::path &image_root,
                         const fs::path &target) {
  fs::create_directories(target);
  struct Request {
    std::string image;
    std::string path;
    uint64_t offset;
    uint32_t length;
    std::string name;
  };
  std::vector<Request> requests{
      {"nested.bfimg", "/home/user/docs/readme.txt", 0, 128,
       "nested_read.seed"},
      {"large_file.bfimg", "/large.bin", 4093, 8192,
       "cross_block.seed"},
      {"links.bfimg", "/relative-link", 0, 64, "symlink_read.seed"}};
  for (const auto &request : requests) {
    std::ifstream input(image_root / request.image, std::ios::binary);
    std::vector<uint8_t> image(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    std::vector<uint8_t> seed;
    uint32_t image_size = static_cast<uint32_t>(image.size());
    for (unsigned shift = 0; shift < 32; shift += 8)
      seed.push_back(static_cast<uint8_t>(image_size >> shift));
    seed.insert(seed.end(), image.begin(), image.end());
    seed.push_back(static_cast<uint8_t>(request.path.size()));
    seed.insert(seed.end(), request.path.begin(), request.path.end());
    for (unsigned shift = 0; shift < 64; shift += 8)
      seed.push_back(static_cast<uint8_t>(request.offset >> shift));
    for (unsigned shift = 0; shift < 32; shift += 8)
      seed.push_back(static_cast<uint8_t>(request.length >> shift));
    if (!save(target / request.name, seed))
      throw std::runtime_error("cannot save read seed");
  }
}

void generate_operation_seeds(const fs::path &target) {
  fs::create_directories(target);
  save(target / "create_write_rename.seed",
       {0, 1, 2, 20, 3, 40, 4, 5, 6, 7, 8, 9, 10});
  save(target / "transaction_rollback.seed",
       {11, 1, 2, 99, 3, 17, 12, 11, 2, 55, 13, 14});
  save(target / "links_and_attributes.seed",
       {1, 2, 3, 4, 15, 16, 17, 18, 5, 19, 6, 20});
}
} // namespace

int main(int argc, char **argv) {
  try {
    fs::path repository = argc > 1 ? fs::path(argv[1]) : fs::current_path();
    fs::path generated = repository / "tools" / "generated-seeds";
    fs::path corpus = repository / "fuzz" / "corpus";
    generate_images(generated);
    copy_images(generated, corpus);
    generate_read_seeds(generated,
                        corpus / "filesystem_read_fuzzer");
    generate_operation_seeds(
        corpus / "filesystem_operation_fuzzer");
    std::cout << "BlockForge seed corpora generated\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "generate_seeds: " << error.what() << '\n';
    return 1;
  }
}
