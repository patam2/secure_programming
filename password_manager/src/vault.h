#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <cryptopp/secblock.h>

constexpr std::size_t kMaxFieldLength = 255;
constexpr std::size_t kMaxEntries = 1000;

struct VaultEntry {
    std::string identifier;
    CryptoPP::SecByteBlock password;
    std::string notes;
};

// Each entry is stored as three fields, each a 1-byte length followed by that many bytes:
// [len][identifier][len][password][len][notes]
// Both throw std::runtime_error on a field over 255 bytes, too many entries, or malformed data.
CryptoPP::SecByteBlock serializeEntries(const std::vector<VaultEntry>& entries);
std::vector<VaultEntry> parseEntries(const CryptoPP::SecByteBlock& data);
