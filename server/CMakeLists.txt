add_executable (Server "Server.cpp" )

include_directories(${BOOST_ROOT})

target_include_directories(Server PUBLIC
                          "${PROJECT_BINARY_DIR}"
                          )
