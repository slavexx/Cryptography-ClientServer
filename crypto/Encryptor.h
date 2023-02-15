#pragma once
#include "ICrypto.h"
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>

class Encryptor : private ICrypto {
public:
	//TODO create key factory
	void generateKey();
	std::string encrypt(const std::string& message);
	//template
	std::string keyToString();
	//template
	std::string InitVecToString();
	~Encryptor() override = default;
};
