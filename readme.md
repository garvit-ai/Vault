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
