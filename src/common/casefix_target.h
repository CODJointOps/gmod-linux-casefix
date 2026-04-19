#pragma once

#ifndef TARGET_MODULE_NAME
#error "TARGET_MODULE_NAME must be defined"
#endif

#ifndef TARGET_HELPER_NAME
#error "TARGET_HELPER_NAME must be defined"
#endif

inline constexpr const char* k_target_module = TARGET_MODULE_NAME;
inline constexpr const char* k_helper_name = TARGET_HELPER_NAME;
