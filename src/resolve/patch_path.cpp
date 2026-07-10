#include "resolve/patch_path.h"

#include "common/patch_debug.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <dirent.h>
#include <limits.h>
#include <mutex>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

namespace {

struct sv_hash {
    using is_transparent = void;
    std::size_t operator()(std::string_view sv) const noexcept {
        return std::hash<std::string_view>{}(sv);
    }
};

struct resolver_state_t {
    resolver_state_t() {
        resolved_cache.reserve(512);
        missing_cache.reserve(4096);
    }

    std::mutex mutex{};
    std::unordered_map<std::string, std::string, sv_hash, std::equal_to<>> resolved_cache{};
    std::unordered_set<std::string, sv_hash, std::equal_to<>> missing_cache{};
    std::uint64_t cache_generation = 1;
    std::uint64_t missing_epoch = 0;
};

resolver_state_t& resolver_state() {
    static resolver_state_t state{};
    return state;
}

// A genuinely-missing probe is re-issued by the engine every frame across ~25
// search roots, so a negative result is cached and the real syscall is skipped.
// The cache expires every k_negative_ttl_seconds so content downloaded
// mid-session re-resolves within that window instead of staying ERROR forever.
constexpr std::uint64_t k_negative_ttl_seconds = 2;

std::uint64_t current_epoch() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now).count();
    return static_cast<std::uint64_t>(secs) / k_negative_ttl_seconds;
}

// Clears the shared negative cache when the time bucket rolls. Must hold mutex.
void roll_missing_epoch_locked() {
    const std::uint64_t now = current_epoch();
    if (resolver_state().missing_epoch != now) {
        resolver_state().missing_epoch = now;
        resolver_state().missing_cache.clear();
    }
}

struct tls_missing_entry {
    std::uint64_t generation = 0;
    std::uint64_t epoch = 0;
    std::uint64_t hash = 0;
    std::string key{};
};

constexpr std::size_t k_tls_missing_cache_slots = 256;

std::uint64_t fast_path_hash(std::string_view text) {
    std::uint64_t hash = 1469598103934665603ull;
    for (const unsigned char ch : text) {
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash ? hash : 1ull;
}

std::array<tls_missing_entry, k_tls_missing_cache_slots>& tls_missing_cache() {
    thread_local std::array<tls_missing_entry, k_tls_missing_cache_slots> cache{};
    return cache;
}

bool tls_missing_cache_contains(std::string_view key) {
    const std::uint64_t hash = fast_path_hash(key);
    auto& entry = tls_missing_cache()[hash & (k_tls_missing_cache_slots - 1u)];
    return entry.generation == resolver_state().cache_generation &&
           entry.epoch == current_epoch() &&
           entry.hash == hash &&
           entry.key == key;
}

void tls_missing_cache_store(std::string_view key) {
    const std::uint64_t hash = fast_path_hash(key);
    auto& entry = tls_missing_cache()[hash & (k_tls_missing_cache_slots - 1u)];
    entry.generation = resolver_state().cache_generation;
    entry.epoch = current_epoch();
    entry.hash = hash;
    entry.key.assign(key);
}

void tls_missing_cache_erase(std::string_view key) {
    const std::uint64_t hash = fast_path_hash(key);
    auto& entry = tls_missing_cache()[hash & (k_tls_missing_cache_slots - 1u)];
    if (entry.generation == resolver_state().cache_generation &&
        entry.hash == hash &&
        entry.key == key) {
        entry = {};
    }
}

bool ascii_ieq(char lhs, char rhs) {
    return std::tolower(static_cast<unsigned char>(lhs)) == std::tolower(static_cast<unsigned char>(rhs));
}

bool equals_ci(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (!ascii_ieq(lhs[i], rhs[i])) {
            return false;
        }
    }
    return true;
}

std::string normalize_path(std::string_view raw) {
    std::string out(raw);
    std::replace(out.begin(), out.end(), '\\', '/');
    return out;
}

std::string append_component(std::string base, std::string_view component) {
    if (base.empty() || base == "/") {
        if (base != "/") {
            base.clear();
        }
        if (base.empty()) {
            base.push_back('/');
        }
        if (base.back() != '/') {
            base.push_back('/');
        }
        base.append(component);
        return base;
    }

    if (base.back() != '/') {
        base.push_back('/');
    }
    base.append(component);
    return base;
}

bool exact_path_exists(const std::string& path) {
    struct stat st{};
    return ::lstat(path.c_str(), &st) == 0;
}

void trim_to_parent(std::string& path) {
    if (path.empty() || path == "/") {
        path = "/";
        return;
    }

    while (path.size() > 1 && path.back() == '/') {
        path.pop_back();
    }

    const std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) {
        path.clear();
        return;
    }
    if (slash == 0) {
        path = "/";
        return;
    }
    path.resize(slash);
}

bool find_case_match_in_dir(const std::string& dir_path, std::string_view needle, std::string& match_out) {
    DIR* dir = ::opendir(dir_path.empty() ? "." : dir_path.c_str());
    if (!dir) {
        return false;
    }

    int matches = 0;
    while (dirent* ent = ::readdir(dir)) {
        const char* name = ent->d_name;
        if (!name || !name[0]) {
            continue;
        }
        if (equals_ci(name, needle)) {
            match_out.assign(name);
            ++matches;
            if (matches > 1) {
                break;
            }
        }
    }

    ::closedir(dir);
    return matches == 1;
}

const std::string& process_cwd() {
    static const std::string cwd = [] {
        char buf[PATH_MAX]{};
        return ::getcwd(buf, sizeof(buf)) ? std::string(buf) : std::string{};
    }();
    return cwd;
}

// Builds the cache key for raw_path into scratch and returns a view valid until
// this thread's next call. Empty view means the path cannot be keyed.
std::string_view make_key_view(const char* raw_path, std::string& scratch, bool& absolute) {
    absolute = raw_path[0] == '/' || raw_path[0] == '\\';
    if (absolute) {
        return std::string_view(raw_path);
    }
    const std::string& cwd = process_cwd();
    if (cwd.empty()) {
        return {};
    }
    scratch.assign(cwd);
    scratch.push_back('\n');
    scratch.append(raw_path);
    return scratch;
}

} // namespace

bool should_retry_missing(int err) {
    return err == ENOENT || err == ENOTDIR;
}

bool fopen_has_write_intent(const char* mode) {
    if (!mode) {
        return false;
    }

    for (const char* p = mode; *p; ++p) {
        switch (*p) {
        case 'w':
        case 'a':
        case '+':
            return true;
        default:
            break;
        }
    }
    return false;
}

bool negative_lookup_blocks(const char* raw_path) {
    if (!raw_path || !raw_path[0]) {
        return false;
    }
    thread_local std::string block_scratch{};
    bool absolute = false;
    const std::string_view key_view = make_key_view(raw_path, block_scratch, absolute);
    if (key_view.empty()) {
        return false;
    }
    if (tls_missing_cache_contains(key_view)) {
        return true;
    }
    std::lock_guard lock(resolver_state().mutex);
    roll_missing_epoch_locked();
    if (resolver_state().missing_cache.contains(key_view)) {
        tls_missing_cache_store(key_view);
        return true;
    }
    return false;
}

std::string resolve_case_mismatched_path(const char* raw_path) {
    if (!raw_path || !raw_path[0]) {
        return {};
    }

    thread_local std::string key_scratch{};
    bool absolute = false;
    const std::string_view cache_key = make_key_view(raw_path, key_scratch, absolute);
    if (cache_key.empty()) {
        return {};
    }

    if (tls_missing_cache_contains(cache_key)) {
        return {};
    }
    {
        std::lock_guard lock(resolver_state().mutex);
        roll_missing_epoch_locked();
        if (const auto it = resolver_state().resolved_cache.find(cache_key); it != resolver_state().resolved_cache.end()) {
            return it->second;
        }
        if (resolver_state().missing_cache.contains(cache_key)) {
            tls_missing_cache_store(cache_key);
            return {};
        }
    }

    const std::string normalized = normalize_path(raw_path);
    std::string current = absolute ? "/" : process_cwd();
    std::size_t pos = absolute ? 1 : 0;
    while (pos <= normalized.size()) {
        const std::size_t next = normalized.find('/', pos);
        const std::size_t len = (next == std::string::npos) ? (normalized.size() - pos) : (next - pos);
        const std::string_view part(normalized.data() + pos, len);
        pos = (next == std::string::npos) ? (normalized.size() + 1) : (next + 1);

        if (part.empty() || part == ".") {
            continue;
        }
        if (part == "..") {
            trim_to_parent(current);
            continue;
        }

        const std::string exact = append_component(current, part);
        if (exact_path_exists(exact)) {
            current = exact;
            continue;
        }

        std::string matched{};
        if (!find_case_match_in_dir(current, part, matched)) {
            std::lock_guard lock(resolver_state().mutex);
            roll_missing_epoch_locked();
            resolver_state().missing_cache.insert(std::string(cache_key));
            tls_missing_cache_store(cache_key);
            return {};
        }
        current = append_component(current, matched);
    }

    if (current.empty()) {
        current = absolute ? "/" : process_cwd();
    }

    {
        std::lock_guard lock(resolver_state().mutex);
        if (const auto it = resolver_state().missing_cache.find(cache_key); it != resolver_state().missing_cache.end()) {
            resolver_state().missing_cache.erase(it);
            tls_missing_cache_erase(cache_key);
        }
        resolver_state().resolved_cache.insert_or_assign(std::string(cache_key), current);
    }

    debug_log("fixed path='%s' resolved='%s'", raw_path, current.c_str());
    return current;
}
