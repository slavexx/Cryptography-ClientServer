#pragma once
#include "ICrypto.h"
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>

class Decryptor : private ICrypto {
public:
	Decryptor(const std::string& key, const std::string& initVec);
	//template
	void showKeyAndInitVec();
	std::string decrypt(const std::string& message);
	~Decryptor() override = default;
};