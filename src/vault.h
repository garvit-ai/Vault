#ifndef VAULT_H
#define VAULT_H

#include <sqlite3.h>
#include <string>
#include <vector>
#include <sodium.h> // libsodium for crypto

// Simple struct for an entry (decrypted password for viewing)
struct Entry
{
    int id;
    std::string site;
    std::string username;
    std::string password; // Decrypted only when fetched for view
};

class Vault
{
public:
    // Constructor opens DB
    Vault();
    // Destructor closes DB
    ~Vault();

    // Initialize tables if needed
    bool init_db();

    // Setup vault on first run (generate salt)
    bool setup_vault(const std::string &master_pw);

    // Unlock with master_pw, derive key, verify with dummy token
    bool unlock(const std::string &master_pw, std::string &derived_key_hex);

    // Check if the vault has been initialized (salt exists)
    bool is_initialized();

    // CRUD Operations (use derived_key_hex for encrypt/decrypt)
    void add_entry(const std::string &derived_key_hex, const std::string &site, const std::string &username, const std::string &password);
    std::vector<Entry> view_all_entries(const std::string &derived_key_hex);
    Entry view_single_entry(const std::string &derived_key_hex, const std::string &site);
    void edit_entry(const std::string &derived_key_hex, const std::string &site, const std::string &new_username = "", const std::string &new_password = "");
    void delete_entry(const std::string &site);

private:
    sqlite3 *db_; // DB handle

    // Crypto helpers
    bool derive_key(const std::string &password, const std::string &salt_hex, std::string &key_out); // Argon2i KDF
    std::string encrypt(const std::string &key_hex, const std::string &plaintext);                   // SecretBox + nonce
    std::string decrypt(const std::string &key_hex, const std::string &encrypted);                   // Reverse

    // Hex utils (for storing binary as text in DB)
    std::string to_hex(const unsigned char *data, size_t len);
    std::vector<unsigned char> from_hex(const std::string &hex);
};

#endif
