#pragma once

#include "common/patch_log.h"
#include "common/patch_target.h"

template <typename... Args>
inline void debug_log(const char* fmt, Args... args) {
    if constexpr (sizeof...(args) == 0) {
        patch_log::write(k_helper_name, "%s", fmt);
    } else {
        patch_log::write(k_helper_name, fmt, args...);
    }
}
