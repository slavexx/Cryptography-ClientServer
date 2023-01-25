# CMakeList.txt : CMake project for ClientServer, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project (ClientServer"ClientServer")

add_subdirectory(Client)
add_subdirectory(Server)
add_subdirectory(Crypto)