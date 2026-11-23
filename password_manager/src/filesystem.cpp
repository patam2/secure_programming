#include <algorithm>
#include <array>
#include <string>
#include <filesystem>
#include "filesystem.h"
#include <fstream>
#include <span>
#include <stdexcept>
#include "logger.h"


namespace {
  constexpr std::size_t kMinVaultSize = 4 + 16 + 12 + 16;  // version + salt + nonce + tag
  constexpr std::size_t kMaxVaultSize = 4 * 1024 * 1024;

  template <typename Bytes>
  void writeBytes(std::ofstream& file, const Bytes& bytes) {
      file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  }
  }


bool PasswordVault::checkForVault() const {
    return std::filesystem::exists(vault_name);
}

VaultFile PasswordVault::readVault() {
    std::ifstream file(vault_name, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("cant open vault");
    }
    const std::streamoff size = file.tellg();
    if (size < static_cast<std::streamoff>(kMinVaultSize)) {
          throw std::runtime_error("vault file is too short");
    }
    if (size > static_cast<std::streamoff>(kMaxVaultSize)) {
        throw std::runtime_error("vault file is too large");
    }

    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(bytes.data()), size)) {
        throw std::runtime_error("failed to read vault file");
    }

    std::span<const unsigned char> s(bytes);

    VaultFile vault;

    std::ranges::copy(s.first(vault.version.size()), vault.version.begin());
    s = s.subspan(vault.version.size());

    std::ranges::copy(s.first(vault.salt.size()), vault.salt.begin());
    s = s.subspan(vault.salt.size());

    std::ranges::copy(s.first(vault.nonce.size()), vault.nonce.begin());
    s = s.subspan(vault.nonce.size());

    std::ranges::copy(s.last(vault.tag.size()), vault.tag.begin());
    s = s.first(s.size() - vault.tag.size());

    vault.ciphertext.assign(s.begin(), s.end());

    if (vault.version != kVaultVersion) {
        throw std::runtime_error("not a vault file");
    }
    return vault;
}

void PasswordVault::writeVault(const VaultFile& vault) {
    const std::string temp_name = vault_name + ".tmp";
    {
        std::ofstream file(temp_name, std::ios::binary | std::ios::trunc);
        if (!file) {
            logEvent(LOG_ERR, "could not create vault");
            throw std::runtime_error("cant create vault file");
        }
        std::filesystem::permissions(temp_name,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace);
        writeBytes(file, vault.version);
        writeBytes(file, vault.salt);
        writeBytes(file, vault.nonce);
        writeBytes(file, vault.ciphertext);
        writeBytes(file, vault.tag);
        file.close();
        if (!file) {
            std::filesystem::remove(temp_name);
             logEvent(LOG_ERR, "failed to write vault file");

            throw std::runtime_error("failed to write vault file");
        }
    }
    std::filesystem::rename(temp_name, vault_name);
    logEvent(LOG_INFO, "successfully wrote vault file.");
    
}
