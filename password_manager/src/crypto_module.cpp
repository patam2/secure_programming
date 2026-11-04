#include "crypto_module.h"

#include <algorithm>
#include <array>
#include <stdexcept>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

namespace {
  constexpr unsigned int kPbkdf2Iterations = 600000;
  constexpr std::size_t kKeySize = 32;  // AES-256

  CryptoPP::SecByteBlock deriveKey(const CryptoPP::SecByteBlock& password,
                                   const std::array<unsigned char, 16>& salt) {
      CryptoPP::SecByteBlock key(kKeySize);
      CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
      pbkdf.DeriveKey(key, key.size(), 0, password, password.size(),
                      salt.data(), salt.size(), kPbkdf2Iterations, 0.0);
      return key;
  }

  // The header isn't encrypted, but passing it as associated data makes the tag cover it too.
  std::array<unsigned char, 4 + 16 + 12> makeHeader(const VaultFile& vault) {
      std::array<unsigned char, 4 + 16 + 12> header;
      auto out = std::copy(vault.version.begin(), vault.version.end(), header.begin());
      out = std::copy(vault.salt.begin(), vault.salt.end(), out);
      std::copy(vault.nonce.begin(), vault.nonce.end(), out);
      return header;
  }
  }

CryptoPP::SecByteBlock CryptoModule::decrypt(const CryptoPP::SecByteBlock& password,
                                             const VaultFile& vault) {
    CryptoPP::SecByteBlock key = deriveKey(password, vault.salt);
    std::array<unsigned char, 4 + 16 + 12> header = makeHeader(vault);

    CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), vault.nonce.data(), vault.nonce.size());

    CryptoPP::SecByteBlock plaintext(vault.ciphertext.size());
    bool ok = decryptor.DecryptAndVerify(plaintext, vault.tag.data(), vault.tag.size(),
                                         vault.nonce.data(), vault.nonce.size(),
                                         header.data(), header.size(),
                                         vault.ciphertext.data(), vault.ciphertext.size());
    if (!ok) {
        throw std::runtime_error("wrong password or vault is corrupted");
    }
    return plaintext;
}

VaultFile CryptoModule::encrypt(const CryptoPP::SecByteBlock& password,
                                const CryptoPP::SecByteBlock& plaintext) {
    VaultFile vault;
    vault.version = kVaultVersion;

    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(vault.salt.data(), vault.salt.size());
    rng.GenerateBlock(vault.nonce.data(), vault.nonce.size());

    CryptoPP::SecByteBlock key = deriveKey(password, vault.salt);
    std::array<unsigned char, 4 + 16 + 12> header = makeHeader(vault);

    CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), vault.nonce.data(), vault.nonce.size());

    vault.ciphertext.resize(plaintext.size());
    encryptor.EncryptAndAuthenticate(vault.ciphertext.data(), vault.tag.data(), vault.tag.size(),
                                     vault.nonce.data(), vault.nonce.size(),
                                     header.data(), header.size(),
                                     plaintext.data(), plaintext.size());
    return vault;
}
