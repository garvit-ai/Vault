# Vault

Vault is a simple command-line password manager built in C++17.  
It stores all credentials locally in an encrypted SQLite database, protected by a master password.

### Features
- Local storage with SQLite3  
- AES-level encryption using libsodium  
- Lock/unlock system with master password  
- Add, view, edit, and delete entries via CLI  

### Tech Stack
C++17 · SQLite3 · libsodium · CMake

### Build
```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### Upcoming Changes

I am actively working on:

- **V2: CLI Improvements**
  - Add advanced search and sorting for your password entries
  - Tag and categorize passwords for easier management
  - Better input validation for tags
  - Perform stress tests with large vaults

- **V3: Chrome Extension**
  - Let the extension detect login forms on websites
  - Prompt to save new credentials while browsing
  - Communicate securely with your local vault

- **V4: Autofill and Security Features**
  - Check website domains before filling passwords (extra protection)
  - Warn about suspicious or mismatched domains (using fuzzy matching)
  - User-friendly warning popups—option to whitelist safe sites

- **V5: Desktop App**
  - Build a desktop app with a clean interface
  - Vault management via list and form views
  - Switch between dark and light theme
  - Add tray access for convenience
  - Use Qt for a minimalist design
