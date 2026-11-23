#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "crypto_module.h"
#include "filesystem.h"
#include "logger.h"
#include "user_input.h"
#include "vault.h"
using namespace std;

int main() {
    SyslogSession syslog_session;
    logEvent(LOG_NOTICE, "password manager started");

    cout << "Welcome to the password manager!\n";
    PasswordVault passvault;
    CryptoModule crypto;

    try {
        CryptoPP::SecByteBlock password;
        vector<VaultEntry> entries;

        if (passvault.checkForVault()) {
            password = readPassword("Log in using your password: ");
            CryptoPP::SecByteBlock plaintext;
            try {
                plaintext = crypto.decrypt(password, passvault.readVault());
            } catch (const std::runtime_error& e) {
                logEvent(LOG_AUTH | LOG_WARNING,
                         string("login failed: ") + e.what());
                throw;
            }
            entries = parseEntries(plaintext);
            logEvent(LOG_AUTH | LOG_NOTICE,
                     "login successful, vault unlocked with " + to_string(entries.size()) + " entries");
        } else {
            cout << "No vault found, creating a new one.\n";
            logEvent(LOG_NOTICE, "no vault found, starting vault creation");
            password = readPassword("Choose a master password: ");
            if (password.empty()) {
                logEvent(LOG_WARNING, "vault creation aborted: empty master password");
                cerr << "Error: password cannot be empty\n";
                return 1;
            }
            CryptoPP::SecByteBlock confirm = readPassword("Repeat the master password: ");
            if (password != confirm) {
                logEvent(LOG_WARNING, "vault creation aborted: master passwords did not match");
                cerr << "Error: passwords do not match\n";
                return 1;
            }
            passvault.writeVault(crypto.encrypt(password, serializeEntries(entries)));
            logEvent(LOG_NOTICE, "new vault created");
        }

        std::size_t selected = 0;
        while (true) {
            cout << "\x1b[2J\x1b[H";  // clear screen, cursor to top-left
            cout << "Vault has " << entries.size() << " entries:\n";
            printEntries(entries, selected);
            cout << "\nUp/Down: select   Enter: show   n: new   q: quit\n" << flush;

            switch (readKey()) {
                case Key::Up:
                    if (selected > 0) --selected;
                    break;
                case Key::Down:
                    if (selected + 1 < entries.size()) ++selected;
                    break;
                case Key::Enter:
                    if (!entries.empty()) {
                        const VaultEntry& e = entries[selected];
                        logEvent(LOG_NOTICE, "password revealed for entry #" + to_string(selected));
                        cout << "\nIdentifier: " << e.identifier << "\nPassword:   ";
                        cout.write(reinterpret_cast<const char*>(e.password.data()),
                                   static_cast<std::streamsize>(e.password.size()));
                        cout << "\nNotes:      " << e.notes << "\n\nPress any key..." << flush;
                        readKey();
                        cout << "\x1b[2J\x1b[3J\x1b[H" << flush;  // also clear scrollback
                    }
                    break;
                case Key::New: {
                    VaultEntry entry;
                    entry.identifier = readLine("Identifier: ");
                    entry.password = readPassword("Password: ");
                    entry.notes = readLine("Notes: ");
                    entries.push_back(std::move(entry));
                    passvault.writeVault(crypto.encrypt(password, serializeEntries(entries)));
                    selected = entries.size() - 1;
                    logEvent(LOG_NOTICE, "entry #" + to_string(selected) +
                                         " added, vault saved with " + to_string(entries.size()) + " entries");
                    break;
                }
                case Key::Quit:
                    logEvent(LOG_NOTICE, "vault locked, user quit");
                    return 0;
                default:
                    break;
            }
        }

    } catch (const std::runtime_error& e) {
        logEvent(LOG_ERR, string("terminating on error: ") + e.what());
        cerr << "Error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
