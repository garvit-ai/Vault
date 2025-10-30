cmake_minimum_required(VERSION 3.20)
project(PasswordVault)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# vcpkg toolchain
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain")

# Dependencies (support both official and vcpkg-unofficial targets)
# SQLite3
set(SQLITE_TARGET "")
find_package(SQLite3 CONFIG QUIET)
if(SQLite3_FOUND)
  set(SQLITE_TARGET SQLite::SQLite3)
else()
  find_package(unofficial-sqlite3 CONFIG REQUIRED)
  set(SQLITE_TARGET unofficial::sqlite3::sqlite3)
endif()

# Sodium
set(SODIUM_TARGET "")
find_package(Sodium CONFIG QUIET)
if(Sodium_FOUND)
  set(SODIUM_TARGET Sodium::sodium)
else()
  find_package(unofficial-sodium CONFIG REQUIRED)
  set(SODIUM_TARGET unofficial-sodium::sodium)
endif()

add_executable(vault_cli src/main.cpp src/vault.cpp)
target_include_directories(vault_cli PRIVATE src)
target_link_libraries(vault_cli PRIVATE ${SQLITE_TARGET} ${SODIUM_TARGET})
