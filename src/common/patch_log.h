#pragma once

#include <string_view>

namespace patch_log {

const char* path();
void write(std::string_view helper_name, const char* fmt, ...);

} // namespace patch_log

