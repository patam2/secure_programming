#pragma once
#include <array>
#include <string>
#include <vector>

inline constexpr std::array<unsigned char, 4> kVaultVersion = {'P', 'M', 'V', '1'};

// On-disk layout: version | salt | nonce | ciphertext | tag
struct VaultFile {
    std::array<unsigned char, 4> version;
    std::array<unsigned char, 16> salt;
    std::array<unsigned char, 12> nonce;
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, 16> tag;
};

class PasswordVault {
  public:
      std::string vault_name = "passwords.vault";
      bool checkForVault() const;
      VaultFile readVault();
      // Writes to a temporary file and renames it over the vault, so a failed save
      // leaves the previous vault intact. The file is readable only by its owner.
      void writeVault(const VaultFile& vault);
  };
