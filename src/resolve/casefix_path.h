#pragma once

#include <string>

bool should_retry_missing(int err);
bool fopen_has_write_intent(const char* mode);
std::string resolve_case_mismatched_path(const char* raw_path);
