#include "patcher/elf_patch.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace elf_patch {
namespace {

template <typename T>
T read_struct(const std::vector<std::byte>& bytes, std::size_t offset) {
    if (offset + sizeof(T) > bytes.size()) {
        throw std::runtime_error("ELF read out of range");
    }

    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

template <typename T>
void write_struct(std::vector<std::byte>& bytes, std::size_t offset, const T& value) {
    if (offset + sizeof(T) > bytes.size()) {
        throw std::runtime_error("ELF write out of range");
    }
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

std::vector<std::byte> read_file(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open " + path.string());
    }

    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size < 0) {
        throw std::runtime_error("failed to stat " + path.string());
    }

    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    if (!file && !bytes.empty()) {
        throw std::runtime_error("failed to read " + path.string());
    }
    return bytes;
}

void write_file_atomic(const fs::path& path, const std::vector<std::byte>& bytes) {
    const fs::path temp = path.string() + ".tmp-casefix";
    {
        std::ofstream file(temp, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("failed to create " + temp.string());
        }
        if (!bytes.empty()) {
            file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        }
        if (!file) {
            throw std::runtime_error("failed to write " + temp.string());
        }
    }

    fs::permissions(temp, fs::status(path).permissions(), fs::perm_options::replace);
    fs::rename(temp, path);
}

std::size_t align_up(std::size_t value, std::size_t alignment) {
    const std::size_t mask = alignment - 1;
    return (value + mask) & ~mask;
}

struct elf_file_t {
    std::vector<std::byte> bytes{};
    Elf64_Ehdr ehdr{};
    std::vector<Elf64_Phdr> phdrs{};
    std::size_t dynamic_index = 0;
    std::size_t load_index = 0;
    std::vector<Elf64_Dyn> dynamic_entries{};
    std::size_t dynamic_entry_count = 0;
    std::size_t dynamic_offset = 0;
    std::size_t dynstr_offset = 0;
    std::size_t dynstr_size = 0;
};

std::string read_c_string(const std::vector<std::byte>& bytes, std::size_t offset) {
    if (offset >= bytes.size()) {
        throw std::runtime_error("ELF string offset out of range");
    }

    std::string out;
    for (std::size_t i = offset; i < bytes.size(); ++i) {
        const char ch = static_cast<char>(bytes[i]);
        if (ch == '\0') {
            return out;
        }
        out.push_back(ch);
    }
    throw std::runtime_error("unterminated ELF string");
}

std::size_t vaddr_to_offset(const std::vector<Elf64_Phdr>& phdrs, std::uint64_t vaddr) {
    for (const auto& phdr : phdrs) {
        if (phdr.p_type != PT_LOAD) {
            continue;
        }
        if (vaddr < phdr.p_vaddr || vaddr >= phdr.p_vaddr + phdr.p_filesz) {
            continue;
        }
        return static_cast<std::size_t>(phdr.p_offset + (vaddr - phdr.p_vaddr));
    }
    throw std::runtime_error("failed to map ELF virtual address");
}

elf_file_t parse_elf64(const fs::path& path) {
    elf_file_t elf{};
    elf.bytes = read_file(path);
    elf.ehdr = read_struct<Elf64_Ehdr>(elf.bytes, 0);

    if (std::memcmp(elf.ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        throw std::runtime_error("not an ELF file: " + path.string());
    }
    if (elf.ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        throw std::runtime_error("only ELF64 supported: " + path.string());
    }
    if (elf.ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        throw std::runtime_error("only little-endian ELF supported: " + path.string());
    }
    if (elf.ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
        throw std::runtime_error("unexpected program header size");
    }

    elf.phdrs.reserve(elf.ehdr.e_phnum);
    for (std::size_t i = 0; i < elf.ehdr.e_phnum; ++i) {
        const std::size_t off = elf.ehdr.e_phoff + (i * sizeof(Elf64_Phdr));
        elf.phdrs.push_back(read_struct<Elf64_Phdr>(elf.bytes, off));
    }

    bool found_dynamic = false;
    std::uint64_t max_load_end = 0;
    bool found_load = false;
    for (std::size_t i = 0; i < elf.phdrs.size(); ++i) {
        const auto& phdr = elf.phdrs[i];
        if (phdr.p_type == PT_DYNAMIC) {
            elf.dynamic_index = i;
            elf.dynamic_offset = static_cast<std::size_t>(phdr.p_offset);
            elf.dynamic_entry_count = static_cast<std::size_t>(phdr.p_filesz / sizeof(Elf64_Dyn));
            found_dynamic = true;
        }
        if (phdr.p_type == PT_LOAD) {
            const std::uint64_t end = phdr.p_offset + phdr.p_filesz;
            if (!found_load || end > max_load_end) {
                max_load_end = end;
                elf.load_index = i;
                found_load = true;
            }
        }
    }
    if (!found_dynamic) {
        throw std::runtime_error("PT_DYNAMIC not found");
    }
    if (!found_load) {
        throw std::runtime_error("PT_LOAD not found");
    }

    elf.dynamic_entries.reserve(elf.dynamic_entry_count);
    for (std::size_t i = 0; i < elf.dynamic_entry_count; ++i) {
        const std::size_t off = elf.dynamic_offset + (i * sizeof(Elf64_Dyn));
        elf.dynamic_entries.push_back(read_struct<Elf64_Dyn>(elf.bytes, off));
    }

    std::uint64_t dynstr_vaddr = 0;
    for (const auto& dyn : elf.dynamic_entries) {
        if (dyn.d_tag == DT_STRTAB) {
            dynstr_vaddr = dyn.d_un.d_ptr;
        } else if (dyn.d_tag == DT_STRSZ) {
            elf.dynstr_size = static_cast<std::size_t>(dyn.d_un.d_val);
        }
    }
    if (dynstr_vaddr == 0 || elf.dynstr_size == 0) {
        throw std::runtime_error("invalid dynamic string table");
    }

    elf.dynstr_offset = vaddr_to_offset(elf.phdrs, dynstr_vaddr);
    if (elf.dynstr_offset + elf.dynstr_size > elf.bytes.size()) {
        throw std::runtime_error("dynamic string table out of range");
    }
    return elf;
}

void update_section_headers(std::vector<std::byte>& bytes,
    const Elf64_Ehdr& ehdr,
    std::size_t dynstr_offset,
    std::uint64_t dynstr_vaddr,
    std::size_t dynstr_size,
    std::size_t dynamic_offset,
    std::uint64_t dynamic_vaddr,
    std::size_t dynamic_size) {
    if (ehdr.e_shoff == 0 || ehdr.e_shentsize != sizeof(Elf64_Shdr) || ehdr.e_shnum == 0) {
        return;
    }
    if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= ehdr.e_shnum) {
        return;
    }

    const std::size_t shstr_hdr_off = ehdr.e_shoff + (ehdr.e_shstrndx * sizeof(Elf64_Shdr));
    const auto shstr_hdr = read_struct<Elf64_Shdr>(bytes, shstr_hdr_off);
    if (shstr_hdr.sh_offset + shstr_hdr.sh_size > bytes.size()) {
        return;
    }

    for (std::size_t i = 0; i < ehdr.e_shnum; ++i) {
        const std::size_t sh_off = ehdr.e_shoff + (i * sizeof(Elf64_Shdr));
        auto shdr = read_struct<Elf64_Shdr>(bytes, sh_off);
        const std::size_t name_off = shstr_hdr.sh_offset + shdr.sh_name;
        if (name_off >= bytes.size()) {
            continue;
        }

        const std::string name = read_c_string(bytes, name_off);
        if (name == ".dynstr") {
            shdr.sh_offset = dynstr_offset;
            shdr.sh_addr = dynstr_vaddr;
            shdr.sh_size = dynstr_size;
            write_struct(bytes, sh_off, shdr);
        } else if (name == ".dynamic") {
            shdr.sh_offset = dynamic_offset;
            shdr.sh_addr = dynamic_vaddr;
            shdr.sh_size = dynamic_size;
            write_struct(bytes, sh_off, shdr);
        }
    }
}

} // namespace

std::vector<std::string> list_needed(const fs::path& path) {
    const auto elf = parse_elf64(path);

    std::vector<std::string> needed;
    for (const auto& dyn : elf.dynamic_entries) {
        if (dyn.d_tag == DT_NULL) {
            break;
        }
        if (dyn.d_tag != DT_NEEDED) {
            continue;
        }
        const std::size_t name_off = elf.dynstr_offset + static_cast<std::size_t>(dyn.d_un.d_val);
        needed.push_back(read_c_string(elf.bytes, name_off));
    }
    return needed;
}

bool add_needed(const fs::path& path, std::string_view needed_name) {
    auto elf = parse_elf64(path);

    for (const auto& name : list_needed(path)) {
        if (name == needed_name) {
            return false;
        }
    }

    const std::size_t needed_offset = elf.dynstr_size;
    const auto* old_dynstr = reinterpret_cast<const char*>(elf.bytes.data() + elf.dynstr_offset);
    std::vector<char> new_dynstr(old_dynstr, old_dynstr + elf.dynstr_size);
    new_dynstr.insert(new_dynstr.end(), needed_name.begin(), needed_name.end());
    new_dynstr.push_back('\0');

    std::vector<Elf64_Dyn> new_dynamic;
    new_dynamic.reserve(elf.dynamic_entries.size() + 1);
    for (const auto& dyn : elf.dynamic_entries) {
        if (dyn.d_tag == DT_NULL) {
            break;
        }
        new_dynamic.push_back(dyn);
    }

    Elf64_Dyn needed_dyn{};
    needed_dyn.d_tag = DT_NEEDED;
    needed_dyn.d_un.d_val = needed_offset;
    new_dynamic.push_back(needed_dyn);
    new_dynamic.push_back(Elf64_Dyn{});

    auto& load = elf.phdrs[elf.load_index];
    auto& dynamic = elf.phdrs[elf.dynamic_index];

    std::size_t append_off = align_up(elf.bytes.size(), 8);
    if (append_off > elf.bytes.size()) {
        elf.bytes.resize(append_off, std::byte{0});
    }

    const std::size_t dynstr_offset = append_off;
    elf.bytes.insert(elf.bytes.end(),
        reinterpret_cast<const std::byte*>(new_dynstr.data()),
        reinterpret_cast<const std::byte*>(new_dynstr.data() + new_dynstr.size()));

    const std::size_t dynamic_offset = align_up(elf.bytes.size(), 8);
    if (dynamic_offset > elf.bytes.size()) {
        elf.bytes.resize(dynamic_offset, std::byte{0});
    }

    const std::size_t dynamic_size = new_dynamic.size() * sizeof(Elf64_Dyn);
    const std::size_t dynamic_start = elf.bytes.size();
    elf.bytes.resize(dynamic_start + dynamic_size);
    std::memcpy(elf.bytes.data() + dynamic_start, new_dynamic.data(), dynamic_size);

    const auto dynstr_vaddr = static_cast<std::uint64_t>(load.p_vaddr + (dynstr_offset - load.p_offset));
    const auto dynamic_vaddr = static_cast<std::uint64_t>(load.p_vaddr + (dynamic_offset - load.p_offset));

    auto* dyn_entries = reinterpret_cast<Elf64_Dyn*>(elf.bytes.data() + dynamic_start);
    for (std::size_t i = 0; i < new_dynamic.size(); ++i) {
        if (dyn_entries[i].d_tag == DT_STRTAB) {
            dyn_entries[i].d_un.d_ptr = dynstr_vaddr;
        } else if (dyn_entries[i].d_tag == DT_STRSZ) {
            dyn_entries[i].d_un.d_val = new_dynstr.size();
        }
    }

    const std::size_t new_load_end = elf.bytes.size();
    const std::size_t load_start = static_cast<std::size_t>(load.p_offset);
    const std::size_t new_load_size = new_load_end - load_start;
    load.p_filesz = new_load_size;
    load.p_memsz = std::max<std::uint64_t>(load.p_memsz, new_load_size);

    dynamic.p_offset = dynamic_offset;
    dynamic.p_vaddr = dynamic_vaddr;
    dynamic.p_paddr = dynamic_vaddr;
    dynamic.p_filesz = dynamic_size;
    dynamic.p_memsz = dynamic_size;

    for (std::size_t i = 0; i < elf.phdrs.size(); ++i) {
        const std::size_t phoff = elf.ehdr.e_phoff + (i * sizeof(Elf64_Phdr));
        write_struct(elf.bytes, phoff, elf.phdrs[i]);
    }

    update_section_headers(elf.bytes,
        elf.ehdr,
        dynstr_offset,
        dynstr_vaddr,
        new_dynstr.size(),
        dynamic_offset,
        dynamic_vaddr,
        dynamic_size);

    write_file_atomic(path, elf.bytes);
    return true;
}

} // namespace elf_patch
