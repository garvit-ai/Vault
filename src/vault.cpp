#include "vault.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

// Constructor: Init libsodium and open DB
Vault::Vault() : db_(nullptr)
{
    if (sodium_init() < 0)
    {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    // DB opens in init_db()
}

// Destructor: Close DB
Vault::~Vault()
{
    if (db_)
    {
        sqlite3_close(db_);
    }
}

// Init DB: Create tables if missing
bool Vault::init_db()
{
    if (sqlite3_open("vault.db", &db_) != SQLITE_OK)
    {
        std::cerr << "Failed to open database" << std::endl;
        return false;
    }

    // Unlock token table: Stores salt and encrypted dummy for verification
    const char *create_unlock = R"(
        CREATE TABLE IF NOT EXISTS unlock_token (
            id INTEGER PRIMARY KEY,
            salt TEXT,
            token BLOB
        );
        INSERT OR IGNORE INTO unlock_token (id) VALUES (1);
    )";

    // Entries table: Encrypted passwords as BLOB
    const char *create_entries = R"(
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        );
    )";

    char *error_msg = nullptr;
    if (sqlite3_exec(db_, create_unlock, nullptr, nullptr, &error_msg) != SQLITE_OK ||
        sqlite3_exec(db_, create_entries, nullptr, nullptr, &error_msg) != SQLITE_OK)
    {
        std::cerr << "SQL error: " << error_msg << std::endl;
        sqlite3_free(error_msg);
        return false;
    }
    return true;
}

// Setup: Generate salt on first run, encrypt dummy token
bool Vault::setup_vault(const std::string &master_pw)
{
    if (!db_)
        return false;

    // Check if salt exists
    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT salt FROM unlock_token WHERE id=1;";
    if (sqlite3_prepare_v2(db_, check_sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    bool has_salt = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_text(stmt, 0) != nullptr);
    sqlite3_finalize(stmt);

    if (!has_salt)
    {
        // Generate random salt
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof(salt));
        std::string salt_hex = to_hex(salt, sizeof(salt));

        // Derive key from master_pw + salt
        std::string key_hex;
        if (!derive_key(master_pw, salt_hex, key_hex))
        {
            return false;
        }

        // Encrypt dummy token for verification
        std::string dummy = "unlock_verified";
        std::string enc_token = encrypt(key_hex, dummy);

        // Store salt and token
        const char *update_sql = "UPDATE unlock_token SET salt=?, token=? WHERE id=1;";
        if (sqlite3_prepare_v2(db_, update_sql, -1, &stmt, nullptr) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, salt_hex.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 2, enc_token.data(), static_cast<int>(enc_token.size()), SQLITE_STATIC);
            bool success = (sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
            return success;
        }
    }
    return true; // Already set up
}

// Check if the vault has been initialized (salt exists)
bool Vault::is_initialized()
{
    if (!db_)
        return false;

    sqlite3_stmt *stmt = nullptr;
    const char *sql = "SELECT salt FROM unlock_token WHERE id=1;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    bool initialized = false;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const unsigned char *salt = sqlite3_column_text(stmt, 0);
        initialized = (salt != nullptr && sqlite3_column_bytes(stmt, 0) > 0);
    }
    sqlite3_finalize(stmt);
    return initialized;
}

// Unlock: Derive key, decrypt dummy to verify
bool Vault::unlock(const std::string &master_pw, std::string &derived_key_hex)
{
    if (!db_)
        return false;

    sqlite3_stmt *stmt;
    const char *select_sql = "SELECT salt, token FROM unlock_token WHERE id=1;";
    if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    if (sqlite3_step(stmt) != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        return false; // No setup
    }

    // Get salt (hex) and token (blob)
    const char *salt_text = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    int token_len = sqlite3_column_bytes(stmt, 1);
    // Copy out data BEFORE finalizing the statement (pointers become invalid after finalize)
    std::string salt_hex = salt_text ? std::string(salt_text) : std::string();
    std::string token_blob_str;
    if (token_len > 0)
    {
        const unsigned char *token_blob = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt, 1));
        if (token_blob)
        {
            token_blob_str.assign(reinterpret_cast<const char *>(token_blob), token_len);
        }
    }
    sqlite3_finalize(stmt);

    // Derive key
    if (!derive_key(master_pw, salt_hex, derived_key_hex))
    {
        return false;
    }

    // Verify by decrypting dummy
    try
    {
        std::string decrypted = decrypt(derived_key_hex, token_blob_str);
        return (decrypted == "unlock_verified");
    }
    catch (...)
    {
        return false; // Wrong password
    }
}

// Add: Encrypt password, insert row
void Vault::add_entry(const std::string &derived_key_hex, const std::string &site, const std::string &username, const std::string &password)
{
    if (!db_)
        return;

    std::string enc_pw = encrypt(derived_key_hex, password);

    sqlite3_stmt *stmt;
    const char *insert_sql = "INSERT INTO entries (site, username, password) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr) == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, enc_pw.data(), static_cast<int>(enc_pw.size()), SQLITE_STATIC);
        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            std::cerr << "Failed to add entry (site may exist)" << std::endl;
        }
        sqlite3_finalize(stmt);
    }
}

// View all: Fetch, decrypt passwords
std::vector<Entry> Vault::view_all_entries(const std::string &derived_key_hex)
{
    std::vector<Entry> entries;
    if (!db_)
        return entries;

    sqlite3_stmt *stmt;
    const char *select_sql = "SELECT id, site, username, password FROM entries;";
    if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) == SQLITE_OK)
    {
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            Entry e;
            e.id = sqlite3_column_int(stmt, 0);
            e.site = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            e.username = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
            const unsigned char *blob = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt, 3));
            int blob_len = sqlite3_column_bytes(stmt, 3);
            std::string enc_pw(reinterpret_cast<const char *>(blob), blob_len);
            try
            {
                e.password = decrypt(derived_key_hex, enc_pw);
            }
            catch (...)
            {
                e.password = "[Decrypt failed]";
            }
            entries.push_back(e);
        }
        sqlite3_finalize(stmt);
    }
    return entries;
}

// View single: Like view_all but by site
Entry Vault::view_single_entry(const std::string &derived_key_hex, const std::string &site)
{
    Entry e; // Empty if not found
    if (!db_)
        return e;

    sqlite3_stmt *stmt;
    const char *select_sql = "SELECT id, site, username, password FROM entries WHERE site = ?;";
    if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            e.id = sqlite3_column_int(stmt, 0);
            e.site = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
            e.username = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
            const unsigned char *blob = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt, 3));
            int blob_len = sqlite3_column_bytes(stmt, 3);
            std::string enc_pw(reinterpret_cast<const char *>(blob), blob_len);
            try
            {
                e.password = decrypt(derived_key_hex, enc_pw);
            }
            catch (...)
            {
                e.password = "[Decrypt failed]";
            }
        }
        sqlite3_finalize(stmt);
    }
    return e;
}

// Edit: Update username and/or password (re-encrypt)
void Vault::edit_entry(const std::string &derived_key_hex, const std::string &site, const std::string &new_username, const std::string &new_password)
{
    if (!db_)
        return;

    sqlite3_stmt *stmt;
    if (!new_password.empty())
    {
        std::string enc_pw = encrypt(derived_key_hex, new_password);
        const char *update_pw_sql = "UPDATE entries SET password = ? WHERE site = ?;";
        if (sqlite3_prepare_v2(db_, update_pw_sql, -1, &stmt, nullptr) == SQLITE_OK)
        {
            sqlite3_bind_blob(stmt, 1, enc_pw.data(), static_cast<int>(enc_pw.size()), SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, site.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    if (!new_username.empty())
    {
        const char *update_user_sql = "UPDATE entries SET username = ? WHERE site = ?;";
        if (sqlite3_prepare_v2(db_, update_user_sql, -1, &stmt, nullptr) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, new_username.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, site.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
}

// Delete: Remove by site
void Vault::delete_entry(const std::string &site)
{
    if (!db_)
        return;

    sqlite3_stmt *stmt;
    const char *delete_sql = "DELETE FROM entries WHERE site = ?;";
    if (sqlite3_prepare_v2(db_, delete_sql, -1, &stmt, nullptr) == SQLITE_OK)
    {
        sqlite3_bind_text(stmt, 1, site.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

// Derive key: Use Argon2id for secure KDF
bool Vault::derive_key(const std::string &password, const std::string &salt_hex, std::string &key_out)
{
    auto salt_bytes = from_hex(salt_hex);
    if (salt_bytes.size() != crypto_pwhash_SALTBYTES)
    {
        return false;
    }
    unsigned char key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(key, sizeof(key),
                      password.c_str(), password.size(),
                      salt_bytes.data(),
                      crypto_pwhash_OPSLIMIT_SENSITIVE,
                      crypto_pwhash_MEMLIMIT_SENSITIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        return false;
    }
    key_out = to_hex(key, sizeof(key));
    return true;
}

// Encrypt: SecretBox with random nonce (prepended to ciphertext)
std::string Vault::encrypt(const std::string &key_hex, const std::string &plaintext)
{
    auto key_bytes = from_hex(key_hex);
    if (key_bytes.size() != crypto_secretbox_KEYBYTES)
    {
        throw std::runtime_error("Invalid key");
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned char *ciphertext = new unsigned char[plaintext.size() + crypto_secretbox_MACBYTES];
    if (crypto_secretbox_easy(ciphertext,
                              reinterpret_cast<const unsigned char *>(plaintext.c_str()),
                              plaintext.size(),
                              nonce,
                              key_bytes.data()) != 0)
    {
        delete[] ciphertext;
        throw std::runtime_error("Encryption failed");
    }

    // Combine: nonce + ciphertext
    std::string result(reinterpret_cast<char *>(nonce), sizeof(nonce));
    result += std::string(reinterpret_cast<char *>(ciphertext), plaintext.size() + crypto_secretbox_MACBYTES);
    delete[] ciphertext;
    return result;
}

// Decrypt: Extract nonce, open box
std::string Vault::decrypt(const std::string &key_hex, const std::string &encrypted)
{
    if (encrypted.size() < static_cast<size_t>(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES))
    {
        throw std::runtime_error("Invalid encrypted data");
    }

    auto key_bytes = from_hex(key_hex);
    if (key_bytes.size() != crypto_secretbox_KEYBYTES)
    {
        throw std::runtime_error("Invalid key");
    }

    // Extract nonce and ciphertext
    std::string nonce_str = encrypted.substr(0, crypto_secretbox_NONCEBYTES);
    std::string ciphertext_str = encrypted.substr(crypto_secretbox_NONCEBYTES);

    unsigned char *plaintext = new unsigned char[ciphertext_str.size() - crypto_secretbox_MACBYTES];
    if (crypto_secretbox_open_easy(plaintext,
                                   reinterpret_cast<const unsigned char *>(ciphertext_str.c_str()),
                                   ciphertext_str.size(),
                                   reinterpret_cast<const unsigned char *>(nonce_str.c_str()),
                                   key_bytes.data()) != 0)
    {
        delete[] plaintext;
        throw std::runtime_error("Decryption failed");
    }

    std::string result(reinterpret_cast<char *>(plaintext), ciphertext_str.size() - crypto_secretbox_MACBYTES);
    delete[] plaintext;
    return result;
}

// to_hex: Convert binary to hex string for DB storage
std::string Vault::to_hex(const unsigned char *data, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
    {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return ss.str();
}

// from_hex: Reverse, hex string to binary
std::vector<unsigned char> Vault::from_hex(const std::string &hex)
{
    std::vector<unsigned char> bytes(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        std::stringstream ss;
        ss << hex.substr(i, 2);
        unsigned int byte_val;
        ss >> std::hex >> byte_val;
        bytes[i / 2] = static_cast<unsigned char>(byte_val);
    }
    return bytes;
}
