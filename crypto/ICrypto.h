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
	virtual ~ICrypto() = default;
};
