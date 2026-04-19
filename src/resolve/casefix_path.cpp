#include "resolve/casefix_path.h"

#include "common/casefix_debug.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <dirent.h>
#include <limits.h>
#include <mutex>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

namespace {

struct resolver_state_t {
    std::mutex mutex{};
    std::unordered_map<std::string, std::string> resolved_cache{};
    std::unordered_set<std::string> missing_cache{};
};

resolver_state_t& resolver_state() {
    static resolver_state_t state{};
    return state;
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

std::string make_cache_key(const std::string& normalized_path, bool absolute, const std::string& cwd) {
    if (absolute) {
        return normalized_path;
    }

    std::string key = cwd;
    key.push_back('\n');
    key.append(normalized_path);
    return key;
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

std::string resolve_case_mismatched_path(const char* raw_path) {
    if (!raw_path || !raw_path[0]) {
        return {};
    }

    const std::string normalized = normalize_path(raw_path);
    const bool absolute = !normalized.empty() && normalized.front() == '/';

    char cwd_buf[PATH_MAX] = {};
    std::string cwd{};
    if (!absolute) {
        if (!::getcwd(cwd_buf, sizeof(cwd_buf))) {
            return {};
        }
        cwd.assign(cwd_buf);
    }

    const std::string cache_key = make_cache_key(normalized, absolute, cwd);
    {
        std::lock_guard lock(resolver_state().mutex);
        if (const auto it = resolver_state().resolved_cache.find(cache_key); it != resolver_state().resolved_cache.end()) {
            return it->second;
        }
        if (resolver_state().missing_cache.contains(cache_key)) {
            return {};
        }
    }

    std::string current = absolute ? "/" : cwd;
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
            resolver_state().missing_cache.insert(cache_key);
            return {};
        }
        current = append_component(current, matched);
    }

    if (current.empty()) {
        current = absolute ? "/" : cwd;
    }

    {
        std::lock_guard lock(resolver_state().mutex);
        resolver_state().missing_cache.erase(cache_key);
        resolver_state().resolved_cache[cache_key] = current;
    }

    debug_log("fixed path='%s' resolved='%s'", raw_path, current.c_str());
    return current;
}
