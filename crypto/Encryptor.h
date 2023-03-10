#pragma once
#include "ICrypto.h"
#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/files.h>

class Encryptor : private ICrypto {
public:
	//TODO create key factory
	void generateComplexKey();
	std::string Encryptor::encrypt(const std::string& message, const std::string& authData);
	//template
	std::string keyToString();
	//template
	std::string InitVecToString();
	~Encryptor() override = default;
};
