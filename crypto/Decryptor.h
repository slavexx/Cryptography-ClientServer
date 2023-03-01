#pragma once
#include "ICrypto.h"
#include <cryptopp/hex.h>
#include <cryptopp/gcm.h>
#include <cryptopp/files.h>

#include <cassert>

class Decryptor : private ICrypto {
public:
	Decryptor(const std::string& key, const std::string& initVec);
	//template
	void showKeyAndInitVec();
	std::string decrypt(const std::string& encryptedMsgAndMAC, const std::string& authData);
	~Decryptor() override = default;
};