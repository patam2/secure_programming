#pragma once

#include <cryptopp/secblock.h>

#include "filesystem.h"

class CryptoModule {
  public:
      CryptoPP::SecByteBlock decrypt(const CryptoPP::SecByteBlock& password,
                                     const VaultFile& vault);

      VaultFile encrypt(const CryptoPP::SecByteBlock& password,
                        const CryptoPP::SecByteBlock& plaintext);
  };
