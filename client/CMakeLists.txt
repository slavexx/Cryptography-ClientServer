add_executable (Client "Client.cpp" )

include_directories(${BOOST_ROOT})

target_include_directories(Client PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          )
