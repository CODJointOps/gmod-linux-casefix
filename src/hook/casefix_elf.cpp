#include "hook/casefix_elf.h"

#include "common/casefix_debug.h"
#include "common/casefix_target.h"

#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <limits.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace {

#if INTPTR_MAX == INT64_MAX
using elf_ehdr_t = Elf64_Ehdr;
using elf_phdr_t = Elf64_Phdr;
using elf_dyn_t = Elf64_Dyn;
using elf_sym_t = Elf64_Sym;
using elf_rel_t = Elf64_Rela;
constexpr int k_dyn_rel_tag = DT_RELA;
constexpr int k_dyn_rel_sz_tag = DT_RELASZ;
constexpr int k_plt_rel_type_expected = DT_RELA;
inline uint32_t rel_sym(const elf_rel_t& rel) {
    return ELF64_R_SYM(rel.r_info);
}
inline uintptr_t rel_off(const elf_rel_t& rel) {
    return static_cast<uintptr_t>(rel.r_offset);
}
#else
using elf_ehdr_t = Elf32_Ehdr;
using elf_phdr_t = Elf32_Phdr;
using elf_dyn_t = Elf32_Dyn;
using elf_sym_t = Elf32_Sym;
using elf_rel_t = Elf32_Rel;
constexpr int k_dyn_rel_tag = DT_REL;
constexpr int k_dyn_rel_sz_tag = DT_RELSZ;
constexpr int k_plt_rel_type_expected = DT_REL;
inline uint32_t rel_sym(const elf_rel_t& rel) {
    return ELF32_R_SYM(rel.r_info);
}
inline uintptr_t rel_off(const elf_rel_t& rel) {
    return static_cast<uintptr_t>(rel.r_offset);
}
#endif

struct module_info_t {
    uintptr_t base = 0;
    uintptr_t end = 0;
    std::string path{};
};

std::vector<module_info_t> get_loaded_modules() {
    std::vector<module_info_t> modules;
    std::ifstream maps("/proc/self/maps");
    std::string line;

    module_info_t current{};
    std::string current_path{};
    while (std::getline(maps, line)) {
        unsigned long start_ul = 0;
        unsigned long end_ul = 0;
        char perms[5] = {};
        char path_buf[PATH_MAX] = {};

        const int n = std::sscanf(line.c_str(), "%lx-%lx %4s %*s %*s %*s %4095[^\n]",
            &start_ul,
            &end_ul,
            perms,
            path_buf);
        if (n < 3) {
            continue;
        }

        std::string path = (n >= 4) ? path_buf : "";
        while (!path.empty() && path.front() == ' ') {
            path.erase(path.begin());
        }
        if (path.empty()) {
            continue;
        }

        const uintptr_t start = static_cast<uintptr_t>(start_ul);
        const uintptr_t end = static_cast<uintptr_t>(end_ul);
        if (path == current_path) {
            current.end = end;
            continue;
        }

        if (!current_path.empty()) {
            modules.push_back(current);
        }
        current_path = path;
        current.base = start;
        current.end = end;
        current.path = path;
    }

    if (!current_path.empty()) {
        modules.push_back(current);
    }
    return modules;
}

const module_info_t* find_module_by_basename(const std::vector<module_info_t>& modules, const char* basename) {
    for (const auto& mod : modules) {
        const std::size_t slash = mod.path.find_last_of('/');
        const char* tail = (slash == std::string::npos) ? mod.path.c_str() : (mod.path.c_str() + slash + 1);
        if (std::strcmp(tail, basename) == 0) {
            return &mod;
        }
    }
    return nullptr;
}

bool make_writable(void* addr, size_t len) {
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        return false;
    }
    const uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(static_cast<uintptr_t>(page_size) - 1U);
    const size_t span = ((reinterpret_cast<uintptr_t>(addr) + len) - page + static_cast<size_t>(page_size) - 1U) /
        static_cast<size_t>(page_size);
    return ::mprotect(reinterpret_cast<void*>(page), span * static_cast<size_t>(page_size), PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

inline bool in_module_range(uintptr_t addr, uintptr_t base, uintptr_t end) {
    return addr >= base && addr < end;
}

inline bool range_in_module(uintptr_t addr, size_t size, uintptr_t base, uintptr_t end) {
    if (!in_module_range(addr, base, end)) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    if (addr > UINTPTR_MAX - size) {
        return false;
    }
    return (addr + size) <= end;
}

void** find_got_entry(uintptr_t base, uintptr_t end, const char* symbol_name) {
    if (end <= base) {
        return nullptr;
    }

    const auto* ehdr = reinterpret_cast<const elf_ehdr_t*>(base);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return nullptr;
    }

    const auto* phdr = reinterpret_cast<const elf_phdr_t*>(base + ehdr->e_phoff);
    const elf_dyn_t* dyn = nullptr;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const elf_dyn_t*>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) {
        return nullptr;
    }

    const elf_sym_t* symtab = nullptr;
    const char* strtab = nullptr;
    const elf_rel_t* plt_rels = nullptr;
    const elf_rel_t* dyn_rels = nullptr;
    size_t plt_rel_count = 0;
    size_t dyn_rel_count = 0;
    uintptr_t symtab_addr = 0;
    uintptr_t strtab_addr = 0;
    uintptr_t plt_rels_addr = 0;
    uintptr_t dyn_rels_addr = 0;
    uintptr_t plt_rel_type = 0;

    for (const elf_dyn_t* d = dyn; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
        case DT_SYMTAB:
            symtab_addr = d->d_un.d_ptr;
            break;
        case DT_STRTAB:
            strtab_addr = d->d_un.d_ptr;
            break;
        case DT_JMPREL:
            plt_rels_addr = d->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            plt_rel_count = d->d_un.d_val / sizeof(elf_rel_t);
            break;
        case DT_PLTREL:
            plt_rel_type = d->d_un.d_val;
            break;
        case k_dyn_rel_tag:
            dyn_rels_addr = d->d_un.d_ptr;
            break;
        case k_dyn_rel_sz_tag:
            dyn_rel_count = d->d_un.d_val / sizeof(elf_rel_t);
            break;
        default:
            break;
        }
    }

    auto resolve_mod_ptr = [base, end](uintptr_t raw) -> uintptr_t {
        if (in_module_range(raw, base, end)) {
            return raw;
        }
        if (raw <= UINTPTR_MAX - base) {
            const uintptr_t with_base = base + raw;
            if (in_module_range(with_base, base, end)) {
                return with_base;
            }
        }
        return 0;
    };

    if (symtab_addr) {
        if (const uintptr_t p = resolve_mod_ptr(symtab_addr)) {
            symtab = reinterpret_cast<const elf_sym_t*>(p);
        }
    }
    if (strtab_addr) {
        if (const uintptr_t p = resolve_mod_ptr(strtab_addr)) {
            strtab = reinterpret_cast<const char*>(p);
        }
    }
    if (plt_rels_addr) {
        if (const uintptr_t p = resolve_mod_ptr(plt_rels_addr)) {
            plt_rels = reinterpret_cast<const elf_rel_t*>(p);
        }
    }
    if (dyn_rels_addr) {
        if (const uintptr_t p = resolve_mod_ptr(dyn_rels_addr)) {
            dyn_rels = reinterpret_cast<const elf_rel_t*>(p);
        }
    }

    if (!symtab || !strtab) {
        return nullptr;
    }

    if (plt_rels) {
        const uintptr_t rp = reinterpret_cast<uintptr_t>(plt_rels);
        if (!in_module_range(rp, base, end)) {
            plt_rels = nullptr;
            plt_rel_count = 0;
        } else {
            const size_t max_count = (end - rp) / sizeof(elf_rel_t);
            if (plt_rel_count > max_count) {
                plt_rel_count = max_count;
            }
        }
    }
    if (dyn_rels) {
        const uintptr_t rp = reinterpret_cast<uintptr_t>(dyn_rels);
        if (!in_module_range(rp, base, end)) {
            dyn_rels = nullptr;
            dyn_rel_count = 0;
        } else {
            const size_t max_count = (end - rp) / sizeof(elf_rel_t);
            if (dyn_rel_count > max_count) {
                dyn_rel_count = max_count;
            }
        }
    }
    if (plt_rel_type && plt_rel_type != static_cast<uintptr_t>(k_plt_rel_type_expected)) {
        plt_rels = nullptr;
        plt_rel_count = 0;
    }

    auto match_symbol = [&](const elf_rel_t* rels, size_t count) -> void** {
        if (!rels) {
            return nullptr;
        }
        for (size_t i = 0; i < count; ++i) {
            const elf_rel_t& rel = rels[i];
            const uint32_t sym_idx = rel_sym(rel);
            if (sym_idx == 0) {
                continue;
            }

            const char* name = strtab + symtab[sym_idx].st_name;
            if (std::strcmp(name, symbol_name) != 0) {
                continue;
            }

            uintptr_t got_addr = 0;
            const uintptr_t off = rel_off(rel);
            if (in_module_range(off, base, end)) {
                got_addr = off;
            } else if (off <= UINTPTR_MAX - base && in_module_range(base + off, base, end)) {
                got_addr = base + off;
            }
            if (!got_addr || !range_in_module(got_addr, sizeof(void*), base, end)) {
                continue;
            }
            return reinterpret_cast<void**>(got_addr);
        }
        return nullptr;
    };

    if (void** entry = match_symbol(plt_rels, plt_rel_count)) {
        return entry;
    }
    return match_symbol(dyn_rels, dyn_rel_count);
}

} // namespace

bool install_got_hook(const char* symbol_name, void* hook_fn, void** original_out) {
    const auto modules = get_loaded_modules();
    const module_info_t* mod = find_module_by_basename(modules, k_target_module);
    if (!mod) {
        debug_log("target module not found: %s", k_target_module);
        return false;
    }

    void** got_entry = find_got_entry(mod->base, mod->end, symbol_name);
    if (!got_entry) {
        debug_log("symbol not imported by %s: %s", k_target_module, symbol_name);
        return false;
    }

    const void* original = *got_entry;
    if (original_out) {
        *original_out = *got_entry;
    }
    if (!make_writable(got_entry, sizeof(void*))) {
        debug_log("mprotect failed for %s", symbol_name);
        return false;
    }

    *got_entry = hook_fn;
    debug_log("hooked %s in %s original=%p hook=%p", symbol_name, k_target_module, original, hook_fn);
    return true;
}
