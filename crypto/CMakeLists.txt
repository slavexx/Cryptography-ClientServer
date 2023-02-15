set(TARGET Crypto)

set(SOURCE_FILES
	CryptoKey.h
	ICrypto.h
	Encryptor.h
	Encryptor.cpp
	Decryptor.h
	Decryptor.cpp
	)

find_package(cryptopp REQUIRED)
add_library(${TARGET} STATIC ${SOURCE_FILES})
target_link_libraries(${TARGET} PUBLIC cryptopp::cryptopp)
