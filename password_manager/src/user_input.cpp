#include "user_input.h"

#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <termios.h>
#include <unistd.h>

#include "vault.h"

namespace {

constexpr size_t kMaxPasswordLength = 256;

class EchoGuard {
public:
    EchoGuard() {
        if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original_) == 0) {
            termios silent = original_;
            silent.c_lflag &= ~ECHO;
            active_ = tcsetattr(STDIN_FILENO, TCSANOW, &silent) == 0;
        }
    }

    ~EchoGuard() {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSANOW, &original_);
            std::cout << '\n'; 
        }
    }

    EchoGuard(const EchoGuard&) = delete;
    EchoGuard& operator=(const EchoGuard&) = delete;

private:
    termios original_{};
    bool active_ = false;
};

class RawModeGuard {
public:
    RawModeGuard() {
        if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original_) == 0) {
            termios raw = original_;
            raw.c_lflag &= ~(ICANON | ECHO);
            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;
            active_ = tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0;
        }
    }

    ~RawModeGuard() {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSANOW, &original_);
        }
    }

    RawModeGuard(const RawModeGuard&) = delete;
    RawModeGuard& operator=(const RawModeGuard&) = delete;

private:
    termios original_{};
    bool active_ = false;
};

} 

CryptoPP::SecByteBlock readPassword(const std::string& prompt) {
    std::cout << prompt << std::flush;

    EchoGuard guard;
    CryptoPP::SecByteBlock buffer(kMaxPasswordLength);
    size_t length = 0;
    bool too_long = false;

    int c;
    while ((c = std::getchar()) != EOF && c != '\n') {
        if (length < kMaxPasswordLength) {
            buffer[length++] = static_cast<CryptoPP::byte>(c);
        } else {
            too_long = true;  
        }
    }

    if (c == EOF && length == 0) {
        throw std::runtime_error("no password entered");
    }
    if (too_long) {
        throw std::runtime_error("password is longer than 256 characters");
    }

    buffer.resize(length);
    return buffer;
}

std::string readLine(const std::string& prompt) {
    std::cout << prompt << std::flush;

    std::string line;
    int c;
    while ((c = std::getchar()) != EOF && c != '\n') {
        line.push_back(static_cast<char>(c));
    }
    if (c == EOF && line.empty()) {
        throw std::runtime_error("no input entered");
    }
    return line;
}

Key readKey() {
    RawModeGuard guard;
    int c = std::getchar();
    if (c == EOF) {
        throw std::runtime_error("input closed");
    }

    if (c == '\x1b') {
        if (std::getchar() != '[') {
            return Key::Other;
        }
        switch (std::getchar()) {
            case 'A': return Key::Up;
            case 'B': return Key::Down;
            default:  return Key::Other;
        }
    }
    if (c == '\n' || c == '\r') return Key::Enter;
    if (c == 'n') return Key::New;
    if (c == 'q') return Key::Quit;
    return Key::Other;
}

void printEntries(const std::vector<VaultEntry>& entries, std::size_t selected) {
    for (std::size_t i = 0; i < entries.size(); ++i) {
        std::cout << (i == selected ? "> " : "  ") << entries[i].identifier << '\n';
    }
}
