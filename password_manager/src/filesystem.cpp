#include <algorithm>
#include <array>
#include <string>
#include <filesystem>
#include "filesystem.h"
#include <fstream>
#include <span>
#include <stdexcept>
#include <system_error>
#include <vector>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "logger.h"


namespace {
  constexpr std::size_t kMinVaultSize = 4 + 16 + 12 + 16;  // version + salt + nonce + tag
  constexpr std::size_t kMaxVaultSize = 4 * 1024 * 1024;

  template <typename Bytes>
  void appendBytes(std::vector<unsigned char>& buf, const Bytes& bytes) {
      buf.insert(buf.end(), bytes.begin(), bytes.end());
  }

  struct Fd {
      int fd;
      explicit Fd(int f) : fd(f) {}
      ~Fd() { if (fd >= 0) ::close(fd); }
      Fd(const Fd&) = delete;
      Fd& operator=(const Fd&) = delete;
  };

  void throwErrno(const char* what) {
      throw std::system_error(errno, std::generic_category(), what);
  }

  void writeAll(int fd, std::span<const unsigned char> data) {
      while (!data.empty()) {
          ssize_t n = ::write(fd, data.data(), data.size());
          if (n < 0) {
              if (errno == EINTR) continue;
              throwErrno("failed to write vault file");
          }
          data = data.subspan(static_cast<std::size_t>(n));
      }
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
    const std::filesystem::path path(vault_name);
    const std::filesystem::path dir = path.has_parent_path() ? path.parent_path() : std::filesystem::path(".");
    const std::string name = path.filename().string();
    const std::string temp_name = name + ".tmp";

    Fd dirfd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (dirfd.fd < 0) {
        logEvent(LOG_ERR, "could not open vault directory");
        throwErrno("cant open vault directory");
    }
    struct stat st{};
    if (::fstat(dirfd.fd, &st) != 0) {
        throwErrno("cant stat vault directory");
    }
    if (st.st_uid != ::geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        logEvent(LOG_ERR, "insecure vault directory");
        throw std::runtime_error("vault directory must be owned by you and not group/world-writable");
    }

    if (::unlinkat(dirfd.fd, temp_name.c_str(), 0) != 0 && errno != ENOENT) {
        throwErrno("cant remove stale temp file");
    }

    {
        Fd file(::openat(dirfd.fd, temp_name.c_str(),
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (file.fd < 0) {
            logEvent(LOG_ERR, "could not create vault");
            throwErrno("cant create vault file");
        }

        std::vector<unsigned char> buf;
        buf.reserve(vault.version.size() + vault.salt.size() + vault.nonce.size()
                    + vault.ciphertext.size() + vault.tag.size());
        appendBytes(buf, vault.version);
        appendBytes(buf, vault.salt);
        appendBytes(buf, vault.nonce);
        appendBytes(buf, vault.ciphertext);
        appendBytes(buf, vault.tag);

        try {
            writeAll(file.fd, buf);
            if (::fsync(file.fd) != 0) {
                throwErrno("failed to write vault file");
            }
        } catch (...) {
            ::unlinkat(dirfd.fd, temp_name.c_str(), 0);
            logEvent(LOG_ERR, "failed to write vault file");
            throw;
        }
    }
    if (::renameat(dirfd.fd, temp_name.c_str(), dirfd.fd, name.c_str()) != 0) {
        ::unlinkat(dirfd.fd, temp_name.c_str(), 0);
        logEvent(LOG_ERR, "failed to replace vault file");
        throwErrno("failed to replace vault file");
    }
    ::fsync(dirfd.fd);
    logEvent(LOG_INFO, "successfully wrote vault file.");

}