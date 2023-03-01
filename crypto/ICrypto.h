#pragma once
#include <memory>

#include "CryptoKey.h"
#include <cryptopp/rijndael.h>

class ICrypto {
protected:
	CryptoKey complexKey;

	CryptoKey& getComplexKey() {
		return complexKey;
	}
public:
	const int TAG_SIZE = 16;

	virtual ~ICrypto() = default;
};
