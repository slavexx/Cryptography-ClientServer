cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (Server "Server.cpp")

set(BOOST_ROOT D:/GitHub/vcpkg/installed/x86-windows/include)
include_directories(${BOOST_ROOT})