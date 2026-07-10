cmake_minimum_required(VERSION 3.16)
project(css_patcher LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

find_package(Threads REQUIRED)

# The helper library, loaded into the game via a DT_NEEDED entry the patcher adds
# to filesystem_stdio.so. It carries the case-insensitive filesystem shim that
# fixes missing textures/models caused by Source requesting paths in the wrong
# letter case on Linux's case-sensitive filesystems.
set(helper_sources
    src/hook/patch_shim.cpp
    src/hook/patch_elf.cpp
    src/resolve/patch_path.cpp
    src/common/patch_log.cpp
)

add_library(css_patch SHARED
    ${helper_sources}
)
target_include_directories(css_patch PRIVATE src)
target_compile_definitions(css_patch PRIVATE
    TARGET_MODULE_NAME="filesystem_stdio.so"
    TARGET_HELPER_NAME="css-patch"
)
target_link_libraries(css_patch PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
set_target_properties(css_patch PROPERTIES
    OUTPUT_NAME "css_patch"
    CXX_VISIBILITY_PRESET hidden
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

add_executable(css_patcher
    src/patcher/main.cpp
    src/patcher/elf_patch.cpp
)
target_include_directories(css_patcher PRIVATE src)
set_target_properties(css_patcher PROPERTIES
    OUTPUT_NAME "css-patcher"
)
