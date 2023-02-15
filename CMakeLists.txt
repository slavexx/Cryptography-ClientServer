# CMakeList.txt : CMake project for ClientServer, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project (ClientServer"ClientServer")

set(BOOST_ROOT ${VCPKG_INSTALLED_DIR}/x86-windows/include)
find_package(Boost REQUIRED)

add_subdirectory(Client)
add_subdirectory(Server)
add_subdirectory(Crypto)
