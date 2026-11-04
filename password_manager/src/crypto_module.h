#pragma once

#include <cryptopp/secblock.h>

#include "filesystem.h"

class CryptoModule {
  public:
      // Returns the decrypted vault contents.
      // Throws std::runtime_error if the password is wrong or the file was modified.
      CryptoPP::SecByteBlock decrypt(const CryptoPP::SecByteBlock& password,
                                     const VaultFile& vault);

      // Encrypts plaintext with a fresh random salt and nonce on every call.
      VaultFile encrypt(const CryptoPP::SecByteBlock& password,
                        const CryptoPP::SecByteBlock& plaintext);
  };
