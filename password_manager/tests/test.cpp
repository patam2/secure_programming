#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "vault.h"
#include "crypto_module.h"

TEST_CASE("truncated data throws") {
      const unsigned char raw[] = {3, 'a', 'b'};
      CryptoPP::SecByteBlock data(raw, sizeof raw);
      CHECK_THROWS_AS(parseEntries(data), std::runtime_error);
  }

TEST_CASE("wrong password is rejected") {
    CryptoModule crypto;
    CryptoPP::SecByteBlock passw(reinterpret_cast<const unsigned char*>("bytes"), 5);
    CryptoPP::SecByteBlock wrongpassw(reinterpret_cast<const unsigned char*>("wrong"), 5);

    CryptoPP::SecByteBlock encrypted(reinterpret_cast<const unsigned char*>("test"), 4);


    VaultFile vault = crypto.encrypt(passw, encrypted);
    CHECK_THROWS_AS(crypto.decrypt(wrongpassw, vault), std::runtime_error);
}

TEST_CASE("right password is accepted") {
    CryptoModule crypto;
    CryptoPP::SecByteBlock passw(reinterpret_cast<const unsigned char*>("password"), 8);
    CryptoPP::SecByteBlock rightpassword(reinterpret_cast<const unsigned char*>("password"), 8);

    CryptoPP::SecByteBlock encrypted(reinterpret_cast<const unsigned char*>("test"), 4);


    VaultFile vault = crypto.encrypt(passw, encrypted);
    CHECK_NOTHROW(crypto.decrypt(rightpassword, vault));
}

TEST_CASE("long password entry is rejected") {
    std::vector<VaultEntry> entries = {
      {"a", CryptoPP::SecByteBlock(reinterpret_cast<const unsigned char*>(std::string (256, 'a').data()), 256), "a"}
    };
    CHECK_THROWS_AS(serializeEntries(entries), std::runtime_error);
}