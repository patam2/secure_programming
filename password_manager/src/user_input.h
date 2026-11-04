#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <cryptopp/secblock.h>

#include "vault.h"

CryptoPP::SecByteBlock readPassword(const std::string& prompt);

// Prompts on stdout and reads a visible line from stdin.
// Throws std::runtime_error if stdin closes before anything is entered.
std::string readLine(const std::string& prompt);
enum class Key { Up, Down, Enter, New, Quit, Other };

// Reads a single keypress without waiting for Enter (raw terminal mode).
// Throws std::runtime_error if stdin closes.
Key readKey();

// Prints each entry's identifier, marking the selected one with "> ".
void printEntries(const std::vector<VaultEntry>& entries, std::size_t selected);