#include "vault.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace {
  void checkFieldLength(std::size_t length) {
      if (length > kMaxFieldLength) {
          throw std::runtime_error("field is longer than 255 characters");
      }
  }

  // Finds one length-prefixed field in data, starting at pos, and advances pos past it.
  // Returns a pointer to the field's bytes and its length.
  std::pair<const unsigned char*, std::size_t> readField(const CryptoPP::SecByteBlock& data,
                                                         std::size_t& pos) {
      if (pos >= data.size()) {
          throw std::runtime_error("vault data is truncated");
      }
      std::size_t length = data[pos++];
      if (length > data.size() - pos) {
          throw std::runtime_error("vault data is truncated");
      }
      const unsigned char* start = data.data() + pos;
      pos += length;
      return {start, length};
  }

  std::string readStringField(const CryptoPP::SecByteBlock& data, std::size_t& pos) {
      auto [bytes, length] = readField(data, pos);
      return std::string(reinterpret_cast<const char*>(bytes), length);
  }

  CryptoPP::SecByteBlock readSecretField(const CryptoPP::SecByteBlock& data, std::size_t& pos) {
      auto [bytes, length] = readField(data, pos);
      return CryptoPP::SecByteBlock(bytes, length);
  }

  void writeField(CryptoPP::SecByteBlock& out, std::size_t& pos,
                  const unsigned char* bytes, std::size_t length) {
      out[pos++] = static_cast<unsigned char>(length);
      std::copy(bytes, bytes + length, out.data() + pos);
      pos += length;
  }
  }

CryptoPP::SecByteBlock serializeEntries(const std::vector<VaultEntry>& entries) {
    if (entries.size() > kMaxEntries) {
        throw std::runtime_error("vault cannot hold more than 1000 entries");
    }

    std::size_t total = 0;
    for (const VaultEntry& entry : entries) {
        checkFieldLength(entry.identifier.size());
        checkFieldLength(entry.password.size());
        checkFieldLength(entry.notes.size());
        total += 3 + entry.identifier.size() + entry.password.size() + entry.notes.size();
    }

    CryptoPP::SecByteBlock out(total);
    std::size_t pos = 0;
    for (const VaultEntry& entry : entries) {
        writeField(out, pos, reinterpret_cast<const unsigned char*>(entry.identifier.data()),
                   entry.identifier.size());
        writeField(out, pos, entry.password.data(), entry.password.size());
        writeField(out, pos, reinterpret_cast<const unsigned char*>(entry.notes.data()),
                   entry.notes.size());
    }
    return out;
}

std::vector<VaultEntry> parseEntries(const CryptoPP::SecByteBlock& data) {
    std::vector<VaultEntry> entries;
    std::size_t pos = 0;
    while (pos < data.size()) {
        if (entries.size() == kMaxEntries) {
            throw std::runtime_error("vault contains more than 1000 entries");
        }
        VaultEntry entry;
        entry.identifier = readStringField(data, pos);
        entry.password = readSecretField(data, pos);
        entry.notes = readStringField(data, pos);
        entries.push_back(std::move(entry));
    }
    return entries;
}
