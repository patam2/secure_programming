#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <cryptopp/secblock.h>

#include "vault.h"

CryptoPP::SecByteBlock readPassword(const std::string& prompt);

std::string readLine(const std::string& prompt);
enum class Key { Up, Down, Enter, New, Quit, Other };


Key readKey();

void printEntries(const std::vector<VaultEntry>& entries, std::size_t selected);