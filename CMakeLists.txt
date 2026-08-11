cmake_minimum_required(VERSION 3.16)
project(ghost_recover CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-O1 -g -fno-omit-frame-pointer")

# Export compile_commands.json so language servers (e.g. clangd) and IDEs can
# index the project with correct include paths and compiler flags.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# A Debug build turns on the sanitizers. This tool parses hostile on-disk
# structures for a living, so being able to run the test suite under ASan/UBSan
# is worth keeping wired up. The flags have to reach the link line too, or the
# ASan runtime is not first in the library list and the binary refuses to run.
option(GHOST_SANITIZE "Build with AddressSanitizer and UBSan" OFF)
option(GHOST_BUILD_TESTS "Build lightweight unit tests" ON)
if(GHOST_SANITIZE OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)

find_package(Threads REQUIRED)

# zlib enables SquashFS/cramfs/JFFS2 content extraction. Optional: without it
# those drivers still list files but cannot decompress their contents.
find_package(ZLIB QUIET)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SOURCES
    src/main.cpp
    src/server.cpp

    src/core/io.cpp
    src/core/json.cpp
    src/core/util.cpp
    src/core/jobs.cpp

    src/fs/detect.cpp
    src/fs/ext.cpp
    src/fs/ntfs.cpp
    src/fs/fat.cpp
    src/fs/exfat.cpp
    src/fs/xfs.cpp
    src/fs/btrfs.cpp
    src/fs/f2fs.cpp
    src/fs/apple.cpp
    src/fs/optical.cpp
    src/fs/misc.cpp

    src/carve/matcher.cpp
    src/carve/signatures.cpp
    src/carve/engine.cpp

    src/disk/devices.cpp
    src/disk/partitions.cpp
    src/disk/raid.cpp

    src/recover/extract.cpp
    src/recover/repair.cpp
    src/recover/image.cpp
)

add_executable(ghost_recover ${SOURCES})
target_link_libraries(ghost_recover PRIVATE Threads::Threads)

if(ZLIB_FOUND)
    target_link_libraries(ghost_recover PRIVATE ZLIB::ZLIB)
    target_compile_definitions(ghost_recover PRIVATE GHOST_HAVE_ZLIB)
    message(STATUS "zlib found: compressed-filesystem extraction enabled")
else()
    message(WARNING "zlib not found: SquashFS/cramfs/JFFS2 contents cannot be decompressed")
endif()

install(TARGETS ghost_recover RUNTIME DESTINATION bin)
install(DIRECTORY web/ DESTINATION share/ghost-recover/web)
install(FILES ghost-recover.desktop DESTINATION share/applications OPTIONAL)

if(GHOST_BUILD_TESTS)
    enable_testing()

    add_executable(ghost_unit_tests
        tests/unit_util.cpp
        src/core/util.cpp
    )
    target_include_directories(ghost_unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    add_test(NAME ghost_unit_tests COMMAND ghost_unit_tests)
endif()
