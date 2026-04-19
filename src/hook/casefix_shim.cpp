#include "common/casefix_debug.h"
#include "common/casefix_target.h"
#include "hook/casefix_elf.h"
#include "resolve/casefix_path.h"

#include <cerrno>
#include <cstdio>
#include <dirent.h>
#include <dlfcn.h>
#include <mutex>
#include <sys/stat.h>

namespace {

using xstat_fn = int (*)(int, const char*, struct stat*);
using xstat64_fn = int (*)(int, const char*, struct stat64*);
using fopen64_fn = FILE* (*)(const char*, const char*);
using opendir_fn = DIR* (*)(const char*);
using scandir64_fn = int (*)(const char*, struct dirent64***,
    int (*)(const struct dirent64*),
    int (*)(const struct dirent64**, const struct dirent64**));

struct state_t {
    std::mutex mutex{};
    bool installed = false;
    xstat_fn orig_xstat = nullptr;
    xstat64_fn orig_xstat64 = nullptr;
    fopen64_fn orig_fopen64 = nullptr;
    opendir_fn orig_opendir = nullptr;
    scandir64_fn orig_scandir64 = nullptr;
};

state_t& state() {
    static state_t s{};
    return s;
}

template <typename T>
void resolve_next_symbol(T& slot, const char* name) {
    if (!slot) {
        slot = reinterpret_cast<T>(::dlsym(RTLD_NEXT, name));
    }
}

int hook_xstat(int ver, const char* path, struct stat* buf) {
    auto& s = state();
    if (!s.orig_xstat) {
        errno = ENOSYS;
        return -1;
    }
    const int ret = s.orig_xstat(ver, path, buf);
    if (ret == 0) {
        return ret;
    }
    const int err = errno;
    if (!should_retry_missing(err)) {
        return ret;
    }
    const std::string resolved = resolve_case_mismatched_path(path);
    if (resolved.empty()) {
        errno = err;
        return ret;
    }
    return s.orig_xstat(ver, resolved.c_str(), buf);
}

int hook_xstat64(int ver, const char* path, struct stat64* buf) {
    auto& s = state();
    if (!s.orig_xstat64) {
        errno = ENOSYS;
        return -1;
    }
    const int ret = s.orig_xstat64(ver, path, buf);
    if (ret == 0) {
        return ret;
    }
    const int err = errno;
    if (!should_retry_missing(err)) {
        return ret;
    }
    const std::string resolved = resolve_case_mismatched_path(path);
    if (resolved.empty()) {
        errno = err;
        return ret;
    }
    return s.orig_xstat64(ver, resolved.c_str(), buf);
}

FILE* hook_fopen64(const char* path, const char* mode) {
    auto& s = state();
    if (!s.orig_fopen64) {
        errno = ENOSYS;
        return nullptr;
    }
    FILE* file = s.orig_fopen64(path, mode);
    if (file != nullptr || fopen_has_write_intent(mode)) {
        return file;
    }
    const int err = errno;
    if (!should_retry_missing(err)) {
        return file;
    }
    const std::string resolved = resolve_case_mismatched_path(path);
    if (resolved.empty()) {
        errno = err;
        return file;
    }
    return s.orig_fopen64(resolved.c_str(), mode);
}

DIR* hook_opendir(const char* path) {
    auto& s = state();
    if (!s.orig_opendir) {
        errno = ENOSYS;
        return nullptr;
    }
    DIR* dir = s.orig_opendir(path);
    if (dir != nullptr) {
        return dir;
    }
    const int err = errno;
    if (!should_retry_missing(err)) {
        return dir;
    }
    const std::string resolved = resolve_case_mismatched_path(path);
    if (resolved.empty()) {
        errno = err;
        return dir;
    }
    return s.orig_opendir(resolved.c_str());
}

int hook_scandir64(const char* path, struct dirent64*** namelist,
                   int (*filter)(const struct dirent64*),
                   int (*compar)(const struct dirent64**, const struct dirent64**)) {
    auto& s = state();
    if (!s.orig_scandir64) {
        errno = ENOSYS;
        return -1;
    }
    const int ret = s.orig_scandir64(path, namelist, filter, compar);
    if (ret >= 0) {
        return ret;
    }
    const int err = errno;
    if (!should_retry_missing(err)) {
        return ret;
    }
    const std::string resolved = resolve_case_mismatched_path(path);
    if (resolved.empty()) {
        errno = err;
        return ret;
    }
    return s.orig_scandir64(resolved.c_str(), namelist, filter, compar);
}

void install_hooks() {
    auto& s = state();
    std::lock_guard lock(s.mutex);
    if (s.installed) {
        return;
    }

    resolve_next_symbol(s.orig_xstat, "__xstat");
    resolve_next_symbol(s.orig_xstat64, "__xstat64");
    resolve_next_symbol(s.orig_fopen64, "fopen64");
    resolve_next_symbol(s.orig_opendir, "opendir");
    resolve_next_symbol(s.orig_scandir64, "scandir64");

    int hooks_installed = 0;
    hooks_installed += install_got_hook("__xstat", reinterpret_cast<void*>(&hook_xstat),
        reinterpret_cast<void**>(&s.orig_xstat)) ? 1 : 0;
    hooks_installed += install_got_hook("__xstat64", reinterpret_cast<void*>(&hook_xstat64),
        reinterpret_cast<void**>(&s.orig_xstat64)) ? 1 : 0;
    hooks_installed += install_got_hook("fopen64", reinterpret_cast<void*>(&hook_fopen64),
        reinterpret_cast<void**>(&s.orig_fopen64)) ? 1 : 0;
    hooks_installed += install_got_hook("opendir", reinterpret_cast<void*>(&hook_opendir),
        reinterpret_cast<void**>(&s.orig_opendir)) ? 1 : 0;
    hooks_installed += install_got_hook("scandir64", reinterpret_cast<void*>(&hook_scandir64),
        reinterpret_cast<void**>(&s.orig_scandir64)) ? 1 : 0;

    s.installed = hooks_installed > 0;
    debug_log("install module=%s hooks=%d", k_target_module, hooks_installed);
}

} // namespace

__attribute__((constructor))
static void gmod_casefix_ctor() {
    debug_log("constructor loaded target=%s log=%s", k_target_module, casefix_log::path());
    install_hooks();
}
