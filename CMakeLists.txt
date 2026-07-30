cmake_minimum_required(VERSION 3.16)
project(BlockForge VERSION 1.0.0 LANGUAGES C CXX)

option(BLOCKFORGE_BUILD_TESTS "Build BlockForge tests" ON)
option(BLOCKFORGE_BUILD_TOOLS "Build BlockForge tools" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(blockforge
  src/analysis.cc
  src/base.cc
  src/block.cc
  src/checker.cc
  src/codec.cc
  src/directory.cc
  src/filesystem.cc
  src/inode.cc
  src/journal.cc
  src/path.cc
)
target_include_directories(blockforge PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
if(MSVC)
  target_compile_options(blockforge PRIVATE /W4 /permissive-)
else()
  target_compile_options(blockforge PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(BLOCKFORGE_BUILD_TESTS)
  enable_testing()
  add_executable(blockforge_tests tests/tests.cc)
  target_link_libraries(blockforge_tests PRIVATE blockforge)
  add_test(NAME blockforge_tests COMMAND blockforge_tests)
endif()

if(BLOCKFORGE_BUILD_TOOLS)
  add_executable(blockforge_cli tools/cpp/blockforge_cli.cc)
  target_link_libraries(blockforge_cli PRIVATE blockforge)
  add_executable(blockforge_generate_seeds tools/cpp/generate_seeds.cc)
  target_link_libraries(blockforge_generate_seeds PRIVATE blockforge)
  add_executable(bf_header_probe tools/c/bf_header_probe.c)
  add_executable(blockforge_extract tools/cpp/blockforge_extract.cc)
  target_link_libraries(blockforge_extract PRIVATE blockforge)
  add_executable(blockforge_mkfs tools/cpp/blockforge_mkfs.cc)
  target_link_libraries(blockforge_mkfs PRIVATE blockforge)
endif()
