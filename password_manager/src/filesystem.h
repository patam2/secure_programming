#pragma once
#include <array>
#include <string>
#include <vector>

inline constexpr std::array<unsigned char, 4> kVaultVersion = {'P', 'M', 'V', '1'};

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
      void writeVault(const VaultFile& vault);
  };
