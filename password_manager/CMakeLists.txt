cmake_minimum_required(VERSION 3.16)
project(password_manager CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_path(CRYPTOPP_INCLUDE_DIR cryptopp/sha.h
  HINTS /opt/homebrew/include /usr/local/include)
find_library(CRYPTOPP_LIBRARY NAMES cryptopp crypto++
  HINTS /opt/homebrew/lib /usr/local/lib)

if(NOT CRYPTOPP_INCLUDE_DIR OR NOT CRYPTOPP_LIBRARY)
  message(FATAL_ERROR "Crypto++ not found (brew install cryptopp)")
endif()

add_executable(password_manager
  src/main.cpp
  src/crypto_module.cpp
  src/vault.cpp
  src/filesystem.cpp
  src/user_input.cpp
)

target_include_directories(password_manager PRIVATE ${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(password_manager PRIVATE ${CRYPTOPP_LIBRARY})
