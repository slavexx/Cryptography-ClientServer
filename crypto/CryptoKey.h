#pragma once
#include <cryptopp/osrng.h>

using namespace CryptoPP;

class CryptoKey
{
	SecByteBlock key	= SecByteBlock(AES::DEFAULT_KEYLENGTH);
	SecByteBlock initVec	= SecByteBlock(12);

public:
	CryptoKey() = default;

	CryptoKey(const CryptoKey&)		= delete;
	CryptoKey& operator=(const CryptoKey&)	= delete;
	CryptoKey(CryptoKey&&)			= delete;
	CryptoKey&& operator=(CryptoKey&&)	= delete;

	void setComplexKey(const std::string& newKey, const std::string& newInitVec) {
		key	= SecByteBlock(reinterpret_cast<const byte*>(newKey.data()), newKey.size());
		initVec	= SecByteBlock(reinterpret_cast<const byte*>(newInitVec.data()), newInitVec.size());
	}
	//template
	std::string keyToString()	{ return std::string(reinterpret_cast<const char*>(key.data()), key.size()); };
	//template
	std::string InitVecToString()	{ return std::string(reinterpret_cast<const char*>(initVec.data()), initVec.size()); };

	byte* getKeyPtr()		{ return key.begin(); };

	byte* getInitVecPtr()		{ return initVec.begin(); };

	SecByteBlock& getKey()		{ return key; };

	SecByteBlock& getInitVec()	{ return initVec; };

	size_t getKeySize() const	{ return key.size(); };

	size_t getInitVecSize() const	{ return initVec.size(); };
};
