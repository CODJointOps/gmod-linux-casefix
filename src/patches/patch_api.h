#pragma once

#include "common/patch_log.h"
#include "common/patch_target.h"

#include <cstdint>

// Minimal in-process patch framework for native GMod game-bug fixes, kept in
// parity with the source project's src/patches/<game>/ layout so a patch can be
// ported across with only its include/registration glue changed. Each patch is
// one translation unit that self-registers a game_patch and is installed by a
// background reconcile loop once its target modules are mapped.
//
// Compiled ONLY into the client helper (these are client-side join/reconnect
// crash fixes); the server helper never sees them.

// Log a line at most once per call site (mirrors the source LOG_ONCE).
#define LOG_ONCE(...)                                            \
    do {                                                        \
        static bool _logged_once = false;                       \
        if (!_logged_once) {                                    \
            _logged_once = true;                                \
            patch_log::write(k_helper_name, __VA_ARGS__);     \
        }                                                       \
    } while (0)

namespace memory {

// dlopen(RTLD_NOLOAD) handle for an already-loaded module, or nullptr. The ref
// is intentionally leaked: the game keeps the module loaded for process life, so
// the returned handle (and any dlsym result) stays valid, and patches resolve
// their symbols once at install time.
void* get_module_handle(const char* name);

// True if addr lies in an executable mapping (guards against acting on a stale
// or bogus signature-scan result after a game update).
bool is_executable_addr(std::uintptr_t addr);

// IDA-style signature scan over a module's executable segments. Pattern is
// space-separated hex bytes with "??" wildcards, e.g. "55 48 89 E5 ?? ?? C3".
// Returns the address of the first match, or 0.
std::uintptr_t find_signature_impl(const char* module, const char* pattern);

template <typename T = std::uintptr_t>
T find_signature(const char* module, const char* pattern) {
    return static_cast<T>(find_signature_impl(module, pattern));
}

} // namespace memory

namespace patches {

struct game_patch {
    const char* id;          // stable key, e.g. "gmod_reconnect_crash_guard"
    bool (*install)();       // install hook/patch; true on success, false to retry later
    void (*remove)();        // revert to stock game behavior
};

// Called by each patch unit at static-init time. Pointer must be stable for
// process life (a file-static descriptor).
void register_patch(const game_patch* patch);

} // namespace patches
