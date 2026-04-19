cmake_minimum_required(VERSION 3.16)
project(gmod_linux_casefix LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

set(casefix_sources
    src/hook/casefix_shim.cpp
    src/hook/casefix_elf.cpp
    src/resolve/casefix_path.cpp
    src/common/casefix_log.cpp
)

add_library(gmod_casefix_client SHARED
    ${casefix_sources}
)
target_include_directories(gmod_casefix_client PRIVATE src)
target_compile_definitions(gmod_casefix_client PRIVATE
    TARGET_MODULE_NAME="filesystem_stdio_client.so"
    TARGET_HELPER_NAME="client"
)
set_target_properties(gmod_casefix_client PROPERTIES
    OUTPUT_NAME "gmod_casefix_client"
)

add_library(gmod_casefix_server SHARED
    ${casefix_sources}
)
target_include_directories(gmod_casefix_server PRIVATE src)
target_compile_definitions(gmod_casefix_server PRIVATE
    TARGET_MODULE_NAME="filesystem_stdio.so"
    TARGET_HELPER_NAME="server"
)
set_target_properties(gmod_casefix_server PROPERTIES
    OUTPUT_NAME "gmod_casefix_server"
)

add_executable(gmod_linux_casefix
    src/patcher/main.cpp
    src/patcher/elf_patch.cpp
)
target_include_directories(gmod_linux_casefix PRIVATE src)
set_target_properties(gmod_linux_casefix PROPERTIES
    OUTPUT_NAME "gmod-linux-casefix"
)
