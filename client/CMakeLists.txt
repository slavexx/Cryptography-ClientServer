add_executable (Client "Client.cpp" )

include_directories(${BOOST_ROOT})

target_link_libraries(Client PUBLIC Crypto)

target_include_directories(Client PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/crypto"
                          )
