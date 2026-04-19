#pragma once

#include "common/casefix_log.h"
#include "common/casefix_target.h"

template <typename... Args>
inline void debug_log(const char* fmt, Args... args) {
    if constexpr (sizeof...(args) == 0) {
        casefix_log::write(k_helper_name, "%s", fmt);
    } else {
        casefix_log::write(k_helper_name, fmt, args...);
    }
}
