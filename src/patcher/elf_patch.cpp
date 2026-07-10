#include "patcher/elf_patch.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
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
    const fs::path temp = path.string() + ".tmp-css-patcher";
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

struct elf_file_t {
    std::vector<std::byte> bytes{};
    Elf64_Ehdr ehdr{};
    std::vector<Elf64_Phdr> phdrs{};
    std::size_t dynamic_index = 0;
    std::vector<Elf64_Dyn> dynamic_entries{};
    std::size_t dynamic_entry_count = 0;
    std::size_t dynamic_offset = 0;
    std::uint64_t dynamic_vaddr = 0;
    std::size_t dynamic_size = 0;
    std::size_t dynstr_offset = 0;
    std::uint64_t dynstr_vaddr = 0;
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
    for (std::size_t i = 0; i < elf.phdrs.size(); ++i) {
        const auto& phdr = elf.phdrs[i];
        if (phdr.p_type == PT_DYNAMIC) {
            elf.dynamic_index = i;
            elf.dynamic_offset = static_cast<std::size_t>(phdr.p_offset);
            elf.dynamic_vaddr = phdr.p_vaddr;
            elf.dynamic_size = static_cast<std::size_t>(phdr.p_filesz);
            elf.dynamic_entry_count = static_cast<std::size_t>(phdr.p_filesz / sizeof(Elf64_Dyn));
            found_dynamic = true;
        }
    }
    if (!found_dynamic) {
        throw std::runtime_error("PT_DYNAMIC not found");
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

    elf.dynstr_vaddr = dynstr_vaddr;
    elf.dynstr_offset = vaddr_to_offset(elf.phdrs, dynstr_vaddr);
    if (elf.dynstr_offset >= elf.bytes.size()) {
        throw std::runtime_error("dynamic string table out of range");
    }
    return elf;
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
        const std::uint64_t name_vaddr = elf.dynstr_vaddr + dyn.d_un.d_val;
        const std::size_t name_off = vaddr_to_offset(elf.phdrs, name_vaddr);
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

    std::size_t null_index = elf.dynamic_entries.size();
    std::optional<std::size_t> strsz_index;
    for (std::size_t i = 0; i < elf.dynamic_entries.size(); ++i) {
        const auto& dyn = elf.dynamic_entries[i];
        if (dyn.d_tag == DT_STRSZ) {
            strsz_index = i;
        }
        if (dyn.d_tag == DT_NULL) {
            null_index = i;
            break;
        }
    }
    if (null_index == elf.dynamic_entries.size()) {
        throw std::runtime_error("DT_NULL not found");
    }
    if (!strsz_index) {
        throw std::runtime_error("DT_STRSZ not found");
    }

    const std::size_t string_entry_index = null_index + 2;
    const std::size_t string_entry_offset = string_entry_index * sizeof(Elf64_Dyn);
    if (string_entry_offset > elf.dynamic_size) {
        throw std::runtime_error("not enough spare dynamic entries");
    }

    const std::size_t string_capacity = elf.dynamic_size - string_entry_offset;
    const std::size_t string_size = needed_name.size() + 1;
    if (string_capacity < string_size) {
        throw std::runtime_error("not enough spare dynamic storage for " + std::string(needed_name));
    }

    const std::uint64_t string_vaddr = elf.dynamic_vaddr + string_entry_offset;
    if (string_vaddr < elf.dynstr_vaddr) {
        throw std::runtime_error("invalid dynamic string placement");
    }

    const std::uint64_t needed_offset_u64 = string_vaddr - elf.dynstr_vaddr;
    if (needed_offset_u64 > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("dynamic string offset too large");
    }
    const std::size_t needed_offset = static_cast<std::size_t>(needed_offset_u64);

    const std::size_t string_file_offset = elf.dynamic_offset + string_entry_offset;
    if (string_file_offset + string_size > elf.bytes.size()) {
        throw std::runtime_error("dynamic string storage out of range");
    }

    std::fill(elf.bytes.begin() + static_cast<std::ptrdiff_t>(string_file_offset),
        elf.bytes.begin() + static_cast<std::ptrdiff_t>(string_file_offset + string_capacity),
        std::byte{0});
    std::memcpy(elf.bytes.data() + string_file_offset, needed_name.data(), needed_name.size());

    Elf64_Dyn needed_dyn{};
    needed_dyn.d_tag = DT_NEEDED;
    needed_dyn.d_un.d_val = needed_offset;
    write_struct(elf.bytes, elf.dynamic_offset + (null_index * sizeof(Elf64_Dyn)), needed_dyn);
    write_struct(elf.bytes, elf.dynamic_offset + ((null_index + 1) * sizeof(Elf64_Dyn)), Elf64_Dyn{});

    auto strsz_dyn = elf.dynamic_entries[*strsz_index];
    const std::uint64_t required_strsz = needed_offset_u64 + string_size;
    if (strsz_dyn.d_un.d_val < required_strsz) {
        strsz_dyn.d_un.d_val = required_strsz;
        write_struct(elf.bytes, elf.dynamic_offset + (*strsz_index * sizeof(Elf64_Dyn)), strsz_dyn);
    }

    write_file_atomic(path, elf.bytes);
    return true;
}

} // namespace elf_patch
