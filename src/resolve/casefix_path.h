#pragma once

#include <string>

bool should_retry_missing(int err);
bool fopen_has_write_intent(const char* mode);
// True when raw_path is a known-missing probe within the current time bucket, so
// the caller can fail it with ENOENT and skip the real syscall.
bool negative_lookup_blocks(const char* raw_path);
std::string resolve_case_mismatched_path(const char* raw_path);
