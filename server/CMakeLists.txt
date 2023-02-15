add_executable (Server "Server.cpp" )

include_directories(${BOOST_ROOT})

target_link_libraries(Server PUBLIC Crypto)

target_include_directories(Server PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/crypto"
                          )
