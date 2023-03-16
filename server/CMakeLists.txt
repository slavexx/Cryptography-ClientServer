add_executable (Server "Server.cpp" )

include_directories(${BOOST_ROOT})

target_link_libraries(Server PRIVATE cryptopp::cryptopp)