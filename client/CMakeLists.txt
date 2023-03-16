add_executable (Client "Client.cpp" )

include_directories(${BOOST_ROOT})

target_link_libraries(Client PRIVATE cryptopp::cryptopp)
