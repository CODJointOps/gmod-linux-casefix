#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "patcher/elf_patch.h"

namespace fs = std::filesystem;

namespace {

constexpr std::string_view k_client_target_rel = "bin/linux64/filesystem_stdio_client.so";
constexpr std::string_view k_server_target_rel = "bin/linux64/filesystem_stdio.so";
constexpr std::string_view k_backup_dir_rel = "bin/linux64/.gmod-fixes-backup";
constexpr std::string_view k_client_helper = "libgmod_casefix_client.so";
constexpr std::string_view k_server_helper = "libgmod_casefix_server.so";

struct target_patch_t {
    std::string helper_name{};
    fs::path relative_target{};
};

const std::array<target_patch_t, 2> k_targets = {{
    {std::string(k_client_helper), fs::path(k_client_target_rel)},
    {std::string(k_server_helper), fs::path(k_server_target_rel)},
}};

std::vector<std::string> print_needed(const fs::path& target) {
    return elf_patch::list_needed(target);
}

bool has_needed(const fs::path& target, std::string_view needed_name) {
    for (const auto& line : print_needed(target)) {
        if (line == needed_name) {
            return true;
        }
    }
    return false;
}

fs::path exe_dir() {
    std::array<char, PATH_MAX> buf{};
    const ssize_t len = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len <= 0) {
        throw std::runtime_error("failed to read /proc/self/exe");
    }
    buf[static_cast<std::size_t>(len)] = '\0';
    return fs::path(buf.data()).parent_path();
}

bool is_gmod_root(const fs::path& root) {
    return fs::exists(root / "hl2.sh") &&
           fs::exists(root / k_client_target_rel) &&
           fs::exists(root / k_server_target_rel);
}

std::vector<fs::path> parse_libraryfolders(const fs::path& vdf_path) {
    std::vector<fs::path> out;
    std::ifstream file(vdf_path);
    if (!file) {
        return out;
    }

    const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    const std::regex path_re(R"vdf("path"\s*"([^"]+)")vdf");
    for (std::sregex_iterator it(text.begin(), text.end(), path_re), end; it != end; ++it) {
        std::string path = (*it)[1].str();
        std::string unescaped;
        unescaped.reserve(path.size());
        for (std::size_t i = 0; i < path.size(); ++i) {
            if (path[i] == '\\' && i + 1 < path.size() && path[i + 1] == '\\') {
                unescaped.push_back('\\');
                ++i;
            } else {
                unescaped.push_back(path[i]);
            }
        }
        out.emplace_back(unescaped);
    }
    return out;
}

std::vector<fs::path> candidate_roots() {
    std::vector<fs::path> roots;
    if (const char* env = std::getenv("GMOD_DIR"); env && env[0]) {
        roots.emplace_back(env);
    }

    const char* home = std::getenv("HOME");
    if (!home || !home[0]) {
        return roots;
    }

    const fs::path home_path(home);
    const std::array<fs::path, 3> steamapps = {{
        home_path / ".local/share/Steam/steamapps",
        home_path / ".steam/steam/steamapps",
        home_path / ".steam/root/steamapps",
    }};

    for (const auto& steamapps_root : steamapps) {
        roots.push_back(steamapps_root / "common/GarrysMod");
        const auto libs = parse_libraryfolders(steamapps_root / "libraryfolders.vdf");
        for (const auto& lib : libs) {
            roots.push_back(lib / "steamapps/common/GarrysMod");
        }
    }
    return roots;
}

std::optional<fs::path> find_game_dir(const std::optional<fs::path>& override_path) {
    if (override_path) {
        if (is_gmod_root(*override_path)) {
            return fs::canonical(*override_path);
        }
        return std::nullopt;
    }

    for (const auto& candidate : candidate_roots()) {
        if (is_gmod_root(candidate)) {
            return fs::canonical(candidate);
        }
    }
    return std::nullopt;
}

void ensure_parent_dir(const fs::path& path) {
    const fs::path parent = path.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent);
    }
}

void copy_replace(const fs::path& from, const fs::path& to) {
    ensure_parent_dir(to);
    fs::copy_file(from, to, fs::copy_options::overwrite_existing);
    fs::permissions(to, fs::status(from).permissions(), fs::perm_options::replace);
}

void backup_if_missing(const fs::path& game_dir, const fs::path& target_rel) {
    const fs::path target = game_dir / target_rel;
    const fs::path backup = game_dir / k_backup_dir_rel / target_rel.filename();
    if (!fs::exists(backup)) {
        copy_replace(target, backup);
    }
}

bool restore_backup(const fs::path& game_dir, const fs::path& target_rel) {
    const fs::path target = game_dir / target_rel;
    const fs::path backup = game_dir / k_backup_dir_rel / target_rel.filename();
    if (!fs::exists(backup)) {
        return false;
    }
    copy_replace(backup, target);
    return true;
}

bool apply_one(const fs::path& game_dir, const target_patch_t& target) {
    const fs::path bin_dir = game_dir / "bin/linux64";
    const fs::path helper_src = exe_dir() / target.helper_name;
    const fs::path helper_dst = bin_dir / target.helper_name;
    const fs::path target_path = game_dir / target.relative_target;

    if (!fs::exists(helper_src)) {
        throw std::runtime_error("helper not found next to patcher: " + helper_src.string());
    }

    backup_if_missing(game_dir, target.relative_target);
    copy_replace(helper_src, helper_dst);

    if (has_needed(target_path, target.helper_name)) {
        std::cout << "already patched: " << target_path << '\n';
        return false;
    }

    elf_patch::add_needed(target_path, target.helper_name);

    std::cout << "patched: " << target_path << " -> " << target.helper_name << '\n';
    return true;
}

bool remove_one(const fs::path& game_dir, const target_patch_t& target) {
    const bool restored = restore_backup(game_dir, target.relative_target);
    const fs::path helper_dst = game_dir / "bin/linux64" / target.helper_name;
    if (fs::exists(helper_dst)) {
        fs::remove(helper_dst);
    }

    if (restored) {
        std::cout << "restored: " << (game_dir / target.relative_target) << '\n';
    } else {
        std::cout << "no backup: " << (game_dir / target.relative_target) << '\n';
    }
    return restored;
}

void status_one(const fs::path& game_dir, const target_patch_t& target) {
    const fs::path target_path = game_dir / target.relative_target;
    const fs::path helper_path = game_dir / "bin/linux64" / target.helper_name;
    const fs::path backup = game_dir / k_backup_dir_rel / target.relative_target.filename();

    bool needed = false;
    std::string needed_err;
    try {
        needed = has_needed(target_path, target.helper_name);
    } catch (const std::exception& e) {
        needed_err = e.what();
    }

    std::cout << target.relative_target.string() << '\n';
    std::cout << "  helper: " << (fs::exists(helper_path) ? "present" : "missing") << '\n';
    if (needed_err.empty()) {
        std::cout << "  needed: " << (needed ? "yes" : "no") << '\n';
    } else {
        std::cout << "  needed: error: " << needed_err << '\n';
    }
    std::cout << "  backup: " << (fs::exists(backup) ? "present" : "missing") << '\n';
}

void usage() {
    std::cout
        << "usage: gmod-linux-casefix [status|apply|remove] [--game-dir PATH]\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string command = "status";
        std::optional<fs::path> game_dir_override;

        for (int i = 1; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "status" || arg == "apply" || arg == "remove") {
                command = std::string(arg);
                continue;
            }
            if (arg == "--game-dir") {
                if (i + 1 >= argc) {
                    usage();
                    return 2;
                }
                game_dir_override = fs::path(argv[++i]);
                continue;
            }
            usage();
            return 2;
        }

        const auto game_dir = find_game_dir(game_dir_override);
        if (!game_dir) {
            std::cerr << "GarrysMod install not found\n";
            return 1;
        }

        std::cout << "game_dir: " << game_dir->string() << '\n';

        if (command == "status") {
            for (const auto& target : k_targets) {
                status_one(*game_dir, target);
            }
            return 0;
        }

        if (command == "apply") {
            bool changed = false;
            for (const auto& target : k_targets) {
                changed |= apply_one(*game_dir, target);
            }
            std::cout << (changed ? "apply: changed\n" : "apply: no-op\n");
            return 0;
        }

        if (command == "remove") {
            bool changed = false;
            for (const auto& target : k_targets) {
                changed |= remove_one(*game_dir, target);
            }
            std::cout << (changed ? "remove: changed\n" : "remove: no-op\n");
            return 0;
        }

        usage();
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
