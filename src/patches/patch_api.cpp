#include "patches/patch_api.h"

#include "common/patch_debug.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <limits.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

struct seg_t {
    std::uintptr_t base = 0;
    std::uintptr_t end = 0;
};

const char* path_basename(const char* path) {
    const char* slash = std::strrchr(path, '/');
    return slash ? slash + 1 : path;
}

std::vector<seg_t> module_exec_segments(const char* basename) {
    std::vector<seg_t> out;
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long b = 0;
        unsigned long e = 0;
        char perms[5] = {};
        char path[PATH_MAX] = {};
        if (std::sscanf(line.c_str(), "%lx-%lx %4s %*s %*s %*s %4095[^\n]", &b, &e, perms, path) < 4) {
            continue;
        }
        if (perms[2] != 'x' || std::strcmp(path_basename(path), basename) != 0) {
            continue;
        }
        out.push_back({static_cast<std::uintptr_t>(b), static_cast<std::uintptr_t>(e)});
    }
    return out;
}

} // namespace

namespace memory {

void* get_module_handle(const char* name) {
    return ::dlopen(name, RTLD_NOLOAD | RTLD_NOW);
}

bool is_executable_addr(std::uintptr_t addr) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long b = 0;
        unsigned long e = 0;
        char perms[5] = {};
        if (std::sscanf(line.c_str(), "%lx-%lx %4s", &b, &e, perms) < 3) {
            continue;
        }
        if (addr >= b && addr < e) {
            return perms[2] == 'x';
        }
    }
    return false;
}

std::uintptr_t find_signature_impl(const char* module, const char* pattern) {
    std::vector<std::uint8_t> bytes;
    std::vector<bool> mask;
    for (const char* p = pattern; *p;) {
        if (*p == ' ') {
            ++p;
            continue;
        }
        if (*p == '?') {
            bytes.push_back(0);
            mask.push_back(false);
            while (*p == '?') {
                ++p;
            }
            continue;
        }
        bytes.push_back(static_cast<std::uint8_t>(std::strtoul(p, nullptr, 16)));
        mask.push_back(true);
        p += 2;
    }
    if (bytes.empty()) {
        return 0;
    }

    for (const auto& s : module_exec_segments(module)) {
        const auto* hay = reinterpret_cast<const std::uint8_t*>(s.base);
        const std::size_t n = s.end - s.base;
        if (n < bytes.size()) {
            continue;
        }
        for (std::size_t i = 0; i + bytes.size() <= n; ++i) {
            std::size_t j = 0;
            for (; j < bytes.size(); ++j) {
                if (mask[j] && hay[i + j] != bytes[j]) {
                    break;
                }
            }
            if (j == bytes.size()) {
                return s.base + i;
            }
        }
    }
    return 0;
}

} // namespace memory

namespace patches {
namespace {

struct entry_t {
    const game_patch* patch = nullptr;
    bool installed = false;
};

std::vector<entry_t>& registry() {
    static std::vector<entry_t> r;
    return r;
}

bool disabled(const char* id) {
    const char* list = std::getenv("GMOD_PATCHER_DISABLE");
    return list && std::strstr(list, id) != nullptr;
}

// Install every not-yet-installed patch whose target modules are mapped. A patch
// returns false to be retried on a later pass (its module isn't loaded yet).
// Returns true once nothing remains to install.
bool reconcile() {
    bool all_done = true;
    for (auto& e : registry()) {
        if (e.installed || disabled(e.patch->id)) {
            continue;
        }
        if (e.patch->install()) {
            e.installed = true;
        } else {
            all_done = false;
        }
    }
    return all_done;
}

// GMod loads engine/lua/crypto well after this helper is injected via
// filesystem_stdio_client.so, so we poll for ~2 minutes giving each patch a
// chance to install once its modules appear, then stop.
void installer() {
    for (int i = 0; i < 600; ++i) {
        if (reconcile()) {
            return;
        }
        ::usleep(200000);  // 200ms
    }
    debug_log("patch installer gave up (some target modules never appeared)");
}

} // namespace

void register_patch(const game_patch* patch) {
    registry().push_back({patch, false});
}

} // namespace patches

__attribute__((constructor)) static void gmod_patches_ctor() {
    std::thread(patches::installer).detach();
}
