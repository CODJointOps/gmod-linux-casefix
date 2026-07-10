cmake_minimum_required(VERSION 3.16)
project(gmod_patcher LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

find_package(Threads REQUIRED)

# The single helper library, loaded into the game client via a DT_NEEDED entry
# the patcher adds to filesystem_stdio_client.so. It carries both the
# case-insensitive filesystem shim and the native game-bug patches (join/reconnect
# crash + OpenSSL cert fix) plus the inline-hooking engine they need. Patches are
# kept in parity with the upstream src/patches/<game>/ layout so they port across
# with only their registration glue changed.
set(patch_sources
    src/hook/patch_shim.cpp
    src/hook/patch_elf.cpp
    src/resolve/patch_path.cpp
    src/common/patch_log.cpp
    src/patches/patch_api.cpp
    src/patches/gmod_reconnect_crash_guard.cpp
    src/patches/gmod_openssl_thread_safety.cpp
    src/vendor/safetyhook/safetyhook.cpp
    src/vendor/safetyhook/Zydis.c
)

add_library(gmod_patch SHARED
    ${patch_sources}
)
target_include_directories(gmod_patch PRIVATE src)
target_compile_definitions(gmod_patch PRIVATE
    TARGET_MODULE_NAME="filesystem_stdio_client.so"
    TARGET_HELPER_NAME="gmod-patch"
)
target_link_libraries(gmod_patch PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
# Hide all symbols: the helper patches via GOT/inline hooks, never via symbol
# interposition, and the vendored Zydis exports thousands of symbols that must
# not leak into the game's namespace.
set_target_properties(gmod_patch PROPERTIES
    OUTPUT_NAME "gmod_patch"
    CXX_VISIBILITY_PRESET hidden
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

add_executable(gmod_patcher
    src/patcher/main.cpp
    src/patcher/elf_patch.cpp
)
target_include_directories(gmod_patcher PRIVATE src)
set_target_properties(gmod_patcher PROPERTIES
    OUTPUT_NAME "gmod-patcher"
)
