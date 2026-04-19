#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace elf_patch {

std::vector<std::string> list_needed(const std::filesystem::path& path);
bool add_needed(const std::filesystem::path& path, std::string_view needed_name);

} // namespace elf_patch
