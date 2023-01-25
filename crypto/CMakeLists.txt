#set(TARGET Crypto)

set(SOURCE_FILES crypto.cpp)

list(APPEND CMAKE_MODULE_PATH "D:/GitHub/vcpkg/installed/x86-windows/include")

set(CryptoPP_INCLUDE_DIR D:/GitHub/vcpkg/installed/x86-windows/include)
set(CryptoPP_LIBRARY D:/GitHub/vcpkg/installed/x86-windows/lib)

include_directories(${CryptoPP_INCLUDE_DIR})

find_package(CryptoPP REQUIRED)