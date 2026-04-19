#pragma once

#include <string_view>

namespace casefix_log {

const char* path();
void write(std::string_view helper_name, const char* fmt, ...);

} // namespace casefix_log

