// Laboratory 2 - PE header parser (starter kit)
//
// Build:  clang++ -std=c++17 -O2 main.cpp -o pe_parser
//         g++     -std=c++17 -O2 main.cpp -o pe_parser
//         cl /std:c++17 /EHsc /O2 main.cpp /Fe:pe_parser.exe        (Developer Command Prompt)
// Run:    pe_parser <file.exe>
//
// Every place you have to write code is marked with TODO. Work top to bottom: the program walks
// the file step by step (see run() at the end) and prints each header as soon as it is parsed,
// so you can test after every function you finish. An unfinished function stops the program
// with "error: TODO: ...".
//
// All the offsets you need are in the tables on the lab page.

#include "pe_helpers.hpp"

#include <cstdio>
#include <optional>
#include <string>
#include <vector>

// =============================================================================================
// Data structures: what we keep from each header (already complete)
// =============================================================================================

struct DosHeader
{
    uint16_t e_magic;
    uint32_t e_lfanew;
};

struct FileHeader // a.k.a. COFF header
{
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct DataDirectory
{
    uint32_t rva;
    uint32_t size;
};

struct OptionalHeader
{
    uint16_t magic;
    bool is_pe32_plus; // true for 64-bit files (Magic == 0x20B)
    uint32_t address_of_entry_point;
    uint64_t image_base; // 4 bytes in PE32, 8 bytes in PE32+
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t number_of_rva_and_sizes;
    std::vector<DataDirectory> data_directories;
};

struct Section
{
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t characteristics;
};

struct PeFile
{
    DosHeader dos;
    FileHeader file;
    OptionalHeader optional;
    std::vector<Section> sections;
};

// =============================================================================================
// Lookup tables
// =============================================================================================

std::string machine_name(uint16_t machine)
{
    switch (machine)
    {
    case 0x014C:
        return "x86";
    // TODO: add x64 (0x8664) and ARM64 (0xAA64)
    case 0x8664:
        return "x64";
    case 0xAA64:
        return "ARM64";
    default:
        return "unknown";
    }
}

std::string subsystem_name(uint16_t subsystem)
{
    switch (subsystem)
    {
    case 1:
        return "Native";
    // TODO: add 2 (Windows GUI) and 3 (Windows console)
    case 2:
        return "Windows GUI";
    case 3:
        return "Windows console";
    default:
        return "unknown";
    }
}

std::string data_directory_name(size_t index)
{
    // TODO: complete the list of the 16 data directory names (see the lab page)
    static const char *names[16] = {"Export", "Import", "Resource", "Exception", "Security", "BaseReloc", "Debug", "Architecture",
                                    "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved"};
    return index < 16 ? names[index] : "?";
}

// TODO: complete both flag tables (see the lab page). decode_flags() shows unknown bits in hex.
const std::vector<FlagName> FILE_CHARACTERISTICS = {
    {0x0001, "RELOCS_STRIPPED"},
    {0x0002, "EXECUTABLE_IMAGE"},
    {0x0004, "LINE_NUMS_STRIPPED"},
    {0x0008, "LOCAL_SYMS_STRIPPED"},
    {0x0010, "AGGRESSIVE_WS_TRIM"},
    {0x0020, "LARGE_ADDRESS_AWARE"},
    {0x0080, "BYTES_REVERSED_LO"},
};

const std::vector<FlagName> DLL_CHARACTERISTICS = {
    {0x0020, "HIGH_ENTROPY_VA"},
    {0x0040, "DYNAMIC_BASE"},
    {0x0080, "FORCE_INTEGRITY"},
    {0x0100, "NX_COMPAT"},
    {0x0200, "NO_ISOLATION"},
    {0x0400, "NO_SEH"},
    {0x0800, "NO_BIND"},
    {0x1000, "APPCONTAINER"},
    {0x2000, "WDM_DRIVER"},
    {0x4000, "GUARD_CF"},
    {0x8000, "TERMINAL_SERVER_AWARE"},
};

// Returns "R-X", "RW-", ... from the IMAGE_SCN_MEM_READ (0x40000000), IMAGE_SCN_MEM_WRITE (0x80000000)
// and IMAGE_SCN_MEM_EXECUTE (0x20000000) bits of a section's Characteristics.
std::string section_permissions(uint32_t characteristics)
{
    std::string perm = "---";
    if (characteristics & 0x40000000)
        perm[0] = 'R';
    // TODO: W and X
    if (characteristics & 0x80000000)
        perm[1] = 'W';
    if (characteristics & 0x20000000)
        perm[2] = 'X';
    return perm;
}

// =============================================================================================
// Parsing
// =============================================================================================

// Worked example: read the fields you need with the read_uXX helpers and validate what you can.
DosHeader parse_dos_header(const Bytes &data)
{
    DosHeader dos;
    dos.e_magic = read_u16(data, 0x00);
    if (dos.e_magic != 0x5A4D) // "MZ"
        throw ParseError("not a PE file: missing \"MZ\" signature (found " + hex(dos.e_magic, 4) + ")");
    dos.e_lfanew = read_u32(data, 0x3C);
    return dos;
}

// Reads the 4-byte signature at `offset` and throws ParseError if it is not "PE\0\0" (0x00004550).
void check_pe_signature(const Bytes &data, uint64_t offset)
{
    // TODO
    uint32_t pe_signature = read_u32(data, offset);
    if (pe_signature != 0x00004550)
        throw ParseError("not a PE file: missing \"PE\\0\\0\" signature (found " + hex(pe_signature) + ")");
}

// `offset` is where the COFF file header starts (right after the signature).
FileHeader parse_file_header(const Bytes &data, uint64_t offset)
{
    FileHeader file;
    file.machine = read_u16(data, offset + 0x00);
    file.number_of_sections = read_u16(data, offset + 0x02);
    file.time_date_stamp = read_u32(data, offset + 0x04);
    file.size_of_optional_header = read_u16(data, offset + 0x10);
    file.characteristics = read_u16(data, offset + 0x12);
    return file;
}

// Reads `count` entries of 8 bytes each: { uint32 VirtualAddress (RVA); uint32 Size; }
std::vector<DataDirectory> parse_data_directories(const Bytes &data, uint64_t offset, uint32_t count)
{
    std::vector<DataDirectory> directories;
    for (uint32_t i = 0; i < count; i++)
    {
        uint64_t entry = offset + uint64_t(i) * 8;
        DataDirectory dir;
        dir.rva = read_u32(data, entry + 0);
        dir.size = read_u32(data, entry + 4);
        directories.push_back(dir);
    }
    return directories;
}

// `offset` is where the optional header starts. Remember: some offsets differ between PE32 and PE32+.
OptionalHeader parse_optional_header(const Bytes &data, uint64_t offset, uint16_t size_of_optional_header)
{
    OptionalHeader opt;

    opt.magic = read_u16(data, offset + 0x00);
    if (opt.magic == 0x10B)
        opt.is_pe32_plus = false;
    else if (opt.magic == 0x20B)
        opt.is_pe32_plus = true;
    else
        throw ParseError("invalid optional header magic " + hex(opt.magic, 4) + " (expected 0x010B or 0x020B)");

    const uint64_t dirs_offset = opt.is_pe32_plus ? 0x70 : 0x60;

    if (size_of_optional_header < dirs_offset)
        throw ParseError("SizeOfOptionalHeader " + hex(size_of_optional_header, 4) +
                         " is too small (need at least " + hex(dirs_offset, 4) + ")");

    opt.address_of_entry_point = read_u32(data, offset + 0x10);
    opt.image_base = opt.is_pe32_plus ? read_u64(data, offset + 0x18)
                                      : read_u32(data, offset + 0x1C);
    opt.section_alignment = read_u32(data, offset + 0x20);
    opt.file_alignment = read_u32(data, offset + 0x24);
    opt.size_of_image = read_u32(data, offset + 0x38);
    opt.size_of_headers = read_u32(data, offset + 0x3C);
    opt.subsystem = read_u16(data, offset + 0x44);
    opt.dll_characteristics = read_u16(data, offset + 0x46);
    opt.number_of_rva_and_sizes = read_u32(data, offset + (opt.is_pe32_plus ? 0x6C : 0x5C));

    uint32_t count = opt.number_of_rva_and_sizes < 16 ? opt.number_of_rva_and_sizes : 16;

    if (dirs_offset + uint64_t(count) * 8 > size_of_optional_header)
        throw ParseError("SizeOfOptionalHeader " + hex(size_of_optional_header, 4) + " is too small for " +
                         std::to_string(count) + " data directories");

    opt.data_directories = parse_data_directories(data, offset + dirs_offset, count);

    return opt;
}

// `offset` is where the section table starts; each section header is 40 bytes.
std::vector<Section> parse_sections(const Bytes &data, uint64_t offset, uint16_t count)
{
    std::vector<Section> sections;
    for (uint16_t i = 0; i < count; i++)
    {
        uint64_t entry = offset + uint64_t(i) * 40;
        Section s;
        s.name = read_fixed_string(data, entry + 0x00, 8);
        s.virtual_size = read_u32(data, entry + 0x08);
        s.virtual_address = read_u32(data, entry + 0x0C);
        s.size_of_raw_data = read_u32(data, entry + 0x10);
        s.pointer_to_raw_data = read_u32(data, entry + 0x14);
        s.characteristics = read_u32(data, entry + 0x24);
        sections.push_back(s);
    }
    return sections;
}

// =============================================================================================
// RVA -> file offset
// =============================================================================================

// Returns the section that contains `rva` once the image is loaded in memory, or nullptr:
// VirtualAddress <= rva < VirtualAddress + VirtualSize
// (some linkers write VirtualSize = 0; in that case use SizeOfRawData)
const Section *find_section(const PeFile &pe, uint32_t rva)
{
    for (const Section &s : pe.sections)
    {
        uint64_t size = s.virtual_size != 0 ? s.virtual_size : s.size_of_raw_data;
        uint64_t start = s.virtual_address;
        uint64_t end = start + size;
        if (rva >= start && rva < end)
            return &s;
    }
    return nullptr;
}

// Converts an RVA to a file offset. Returns std::nullopt if the RVA has no bytes in the file.
//   - rva < SizeOfHeaders              -> the headers are mapped 1:1, offset = rva
//   - find the section containing rva  -> none: return std::nullopt
//   - delta = rva - VirtualAddress     -> delta >= SizeOfRawData: zero-filled memory, return std::nullopt
//   - offset = PointerToRawData + delta
std::optional<uint64_t> rva_to_offset(const PeFile &pe, uint32_t rva)
{
    if (rva < pe.optional.size_of_headers)
        return rva;

    const Section *s = find_section(pe, rva);
    if (s == nullptr)
        return std::nullopt;

    uint32_t delta = rva - s->virtual_address;
    if (delta >= s->size_of_raw_data)
        return std::nullopt;

    return uint64_t(s->pointer_to_raw_data) + delta;
}

// =============================================================================================
// Printing (PROVIDED, you do not need to change anything below until run())
// =============================================================================================

void print_field(const std::string &name, const std::string &value)
{
    std::printf("  %-22s%s\n", name.c_str(), value.c_str());
}

void print_dos_header(const DosHeader &dos)
{
    std::printf("DOS header\n");
    print_field("e_magic", hex(dos.e_magic, 4) + " (\"MZ\")");
    print_field("e_lfanew", hex(dos.e_lfanew));
}

void print_pe_signature(uint64_t offset)
{
    std::printf("\nPE signature \"PE\\0\\0\" found at %s\n", hex(offset).c_str());
}

void print_file_header(const FileHeader &file)
{
    std::printf("\nCOFF file header\n");
    print_field("Machine", hex(file.machine, 4) + " (" + machine_name(file.machine) + ")");
    print_field("NumberOfSections", std::to_string(file.number_of_sections));
    print_field("TimeDateStamp", hex(file.time_date_stamp) + " (" + format_unix_timestamp(file.time_date_stamp) + ")");
    print_field("SizeOfOptionalHeader", hex(file.size_of_optional_header, 4));
    print_field("Characteristics",
                hex(file.characteristics, 4) + " (" + decode_flags(file.characteristics, FILE_CHARACTERISTICS) + ")");
}

void print_optional_header(const OptionalHeader &opt)
{
    std::printf("\nOptional header\n");
    print_field("Magic", hex(opt.magic, 4) + (opt.is_pe32_plus ? " (PE32+)" : " (PE32)"));
    print_field("AddressOfEntryPoint", hex(opt.address_of_entry_point));
    print_field("ImageBase", hex(opt.image_base, opt.is_pe32_plus ? 16 : 8));
    print_field("SectionAlignment", hex(opt.section_alignment));
    print_field("FileAlignment", hex(opt.file_alignment));
    print_field("SizeOfImage", hex(opt.size_of_image));
    print_field("SizeOfHeaders", hex(opt.size_of_headers));
    print_field("Subsystem", std::to_string(opt.subsystem) + " (" + subsystem_name(opt.subsystem) + ")");
    print_field("DllCharacteristics", hex(opt.dll_characteristics, 4) + " (" +
                                          decode_flags(opt.dll_characteristics, DLL_CHARACTERISTICS) + ")");
    print_field("NumberOfRvaAndSizes", std::to_string(opt.number_of_rva_and_sizes));

    std::printf("\nData directories\n");
    std::printf("  %-3s %-13s %-11s %s\n", "#", "Name", "RVA", "Size");
    for (size_t i = 0; i < opt.data_directories.size(); i++)
    {
        const DataDirectory &dir = opt.data_directories[i];
        std::printf("  %-3zu %-13s %-11s %s\n", i, data_directory_name(i).c_str(), hex(dir.rva).c_str(),
                    hex(dir.size).c_str());
    }
}

void print_sections(const std::vector<Section> &sections)
{
    std::printf("\nSections\n");
    std::printf("  %-3s %-9s %-11s %-11s %-11s %-11s %-11s %s\n", "#", "Name", "VirtAddr", "VirtSize", "RawPtr",
                "RawSize", "Flags", "Perm");
    for (size_t i = 0; i < sections.size(); i++)
    {
        const Section &s = sections[i];
        std::printf("  %-3zu %-9s %-11s %-11s %-11s %-11s %-11s %s\n", i, s.name.c_str(),
                    hex(s.virtual_address).c_str(), hex(s.virtual_size).c_str(), hex(s.pointer_to_raw_data).c_str(),
                    hex(s.size_of_raw_data).c_str(), hex(s.characteristics).c_str(),
                    section_permissions(s.characteristics).c_str());
    }
}

void print_entry_point(const PeFile &pe)
{
    const OptionalHeader &opt = pe.optional;
    uint32_t ep = opt.address_of_entry_point;
    std::printf("\nEntry point\n");
    if (ep == 0)
    {
        print_field("RVA", "0 (no entry point)");
        return;
    }
    std::string where = "outside every section";
    if (ep < opt.size_of_headers)
        where = "headers";
    else if (const Section *s = find_section(pe, ep))
        where = s->name;
    std::optional<uint64_t> offset = rva_to_offset(pe, ep);
    print_field("RVA", hex(ep));
    print_field("VA", hex(opt.image_base + ep, opt.is_pe32_plus ? 16 : 8));
    print_field("Section", where);
    print_field("File offset", offset ? hex(*offset) : "none (not backed by file data)");
}

// =============================================================================================
// Walking the file
// =============================================================================================

void run(const std::string &path)
{
    Bytes data = load_file(path);
    std::printf("File: %s (%zu bytes)\n\n", path.c_str(), data.size());
    PeFile pe;

    // Step 1: DOS header ("MZ" and e_lfanew) at file offset 0.
    pe.dos = parse_dos_header(data);
    print_dos_header(pe.dos);

    // Step 2: the "PE\0\0" signature is at e_lfanew.
    uint64_t pe_offset = pe.dos.e_lfanew;
    check_pe_signature(data, pe_offset);
    print_pe_signature(pe_offset);

    // Step 3: the COFF file header follows the 4-byte signature.
    uint64_t file_header_offset = pe_offset + 4;
    pe.file = parse_file_header(data, file_header_offset);
    print_file_header(pe.file);

    // Step 4: the optional header follows the 20-byte COFF file header.
    uint64_t optional_header_offset = file_header_offset + 20;
    pe.optional = parse_optional_header(data, optional_header_offset, pe.file.size_of_optional_header);
    print_optional_header(pe.optional);

    // Step 5: the section table follows the optional header (SizeOfOptionalHeader bytes).
    uint64_t section_table_offset = optional_header_offset + pe.file.size_of_optional_header;
    pe.sections = parse_sections(data, section_table_offset, pe.file.number_of_sections);
    print_sections(pe.sections);

    // Step 6: where does execution start? (uses find_section and rva_to_offset)
    print_entry_point(pe);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        std::fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    try
    {
        run(argv[1]);
    }
    catch (const ParseError &e)
    {
        std::fflush(stdout);
        std::fprintf(stderr, "\nerror: %s\n", e.what());
        return 1;
    }
    return 0;
}
