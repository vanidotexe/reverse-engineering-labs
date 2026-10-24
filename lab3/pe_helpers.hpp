// pe_helpers.hpp - helper functions for Laboratory 2 (PE header parser).
//
// You do NOT need to modify this file. It gives you:
//   - load_file()                      read a whole file into memory
//   - read_u8/u16/u32/u64()            read little-endian integers at a file offset
//   - read_bytes()                     read a range of raw bytes
//   - read_fixed_string()              read a fixed-size, maybe NUL-padded string (section names)
//   - read_cstring()                   read a NUL-terminated string (bonus: imports/exports)
//   - hex()                            format a number as "0x0000ABCD"
//   - format_unix_timestamp()          format a TimeDateStamp as "2020-09-13 12:26:40 UTC"
//   - decode_flags()                   turn a bit mask into "FLAG_A | FLAG_B"
//
// Every read is bounds-checked: reading outside the file throws ParseError
// instead of crashing. Malformed files (and malware) WILL try to make you read
// outside the file, so always use these functions instead of raw pointers.
//
// Requires C++17. Works with MSVC, g++ and clang++ on Windows, Linux and macOS.

#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

// Thrown by every helper when something is wrong. Throw it yourself too:
//     throw ParseError("invalid PE signature");
struct ParseError : std::runtime_error
{
    explicit ParseError(const std::string& message) : std::runtime_error(message) {}
};

// Formats a number in hexadecimal, padded to `width` digits: hex(0x4C, 4) == "0x004C".
inline std::string hex(uint64_t value, int width = 8)
{
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%0*llX", width, static_cast<unsigned long long>(value));
    return buffer;
}

// Reads the whole file into memory.
inline Bytes load_file(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw ParseError("cannot open file '" + path + "'");
    return Bytes(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Throws ParseError if the range [offset, offset + count) is not inside the file.
inline void check_range(const Bytes& data, uint64_t offset, uint64_t count)
{
    if (offset > data.size() || count > data.size() - offset)
        throw ParseError("read of " + std::to_string(count) + " byte(s) at offset " + hex(offset) +
                         " is outside the file (file size is " + hex(data.size()) + ")");
}

// Reads `count` bytes starting at `offset`.
inline Bytes read_bytes(const Bytes& data, uint64_t offset, uint64_t count)
{
    check_range(data, offset, count);
    return Bytes(data.begin() + static_cast<size_t>(offset), data.begin() + static_cast<size_t>(offset + count));
}

// Reads an unsigned little-endian integer of `size` bytes (used by the read_uXX functions below).
inline uint64_t read_le(const Bytes& data, uint64_t offset, int size)
{
    check_range(data, offset, size);
    uint64_t value = 0;
    for (int i = size - 1; i >= 0; i--)
        value = (value << 8) | data[static_cast<size_t>(offset) + i];
    return value;
}

inline uint8_t read_u8(const Bytes& data, uint64_t offset)   { return static_cast<uint8_t>(read_le(data, offset, 1)); }
inline uint16_t read_u16(const Bytes& data, uint64_t offset) { return static_cast<uint16_t>(read_le(data, offset, 2)); }
inline uint32_t read_u32(const Bytes& data, uint64_t offset) { return static_cast<uint32_t>(read_le(data, offset, 4)); }
inline uint64_t read_u64(const Bytes& data, uint64_t offset) { return read_le(data, offset, 8); }

// Reads a fixed-size text field (e.g. the 8-byte section Name). Stops at the first NUL byte,
// but the field does not have to contain one: ".textbss" uses all 8 bytes.
inline std::string read_fixed_string(const Bytes& data, uint64_t offset, uint64_t length)
{
    Bytes raw = read_bytes(data, offset, length);
    std::string result;
    for (uint8_t c : raw)
    {
        if (c == 0)
            break;
        result += static_cast<char>(c);
    }
    return result;
}

// Reads a NUL-terminated string (e.g. DLL or function names, for the bonus tasks).
inline std::string read_cstring(const Bytes& data, uint64_t offset, uint64_t max_length = 256)
{
    std::string result;
    for (uint64_t i = 0; i < max_length; i++)
    {
        uint8_t c = read_u8(data, offset + i);
        if (c == 0)
            return result;
        result += static_cast<char>(c);
    }
    throw ParseError("string at " + hex(offset) + " is longer than " + std::to_string(max_length) + " bytes");
}

// Converts a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) to "YYYY-MM-DD hh:mm:ss UTC".
inline std::string format_unix_timestamp(uint32_t timestamp)
{
    // Civil-from-days algorithm (Howard Hinnant); no time zone or OS-specific functions involved.
    int64_t days = timestamp / 86400;
    int64_t seconds = timestamp % 86400;
    days += 719468;
    int64_t era = days / 146097;
    int64_t day_of_era = days - era * 146097;
    int64_t year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    int64_t year = year_of_era + era * 400;
    int64_t day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    int64_t mp = (5 * day_of_year + 2) / 153;
    int64_t day = day_of_year - (153 * mp + 2) / 5 + 1;
    int64_t month = mp < 10 ? mp + 3 : mp - 9;
    if (month <= 2)
        year++;

    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%04lld-%02lld-%02lld %02lld:%02lld:%02lld UTC", (long long) year,
                  (long long) month, (long long) day, (long long) (seconds / 3600), (long long) (seconds / 60 % 60),
                  (long long) (seconds % 60));
    return buffer;
}

// One entry of a flag table: the bit value and its name.
struct FlagName
{
    uint64_t bit;
    const char* name;
};

// Splits `value` into the flags from `table`: decode_flags(0x22, table) == "EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE".
// Bits that are not in the table are shown in hex at the end, so nothing is silently lost.
inline std::string decode_flags(uint64_t value, const std::vector<FlagName>& table)
{
    std::string result;
    uint64_t remaining = value;
    for (const FlagName& flag : table)
    {
        if ((value & flag.bit) == flag.bit && flag.bit != 0)
        {
            result += result.empty() ? "" : " | ";
            result += flag.name;
            remaining &= ~flag.bit;
        }
    }
    if (remaining != 0)
    {
        result += result.empty() ? "" : " | ";
        result += hex(remaining, 1);
    }
    return result.empty() ? "none" : result;
}
