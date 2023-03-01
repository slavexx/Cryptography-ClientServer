#include "Decryptor.h"

Decryptor::Decryptor(const std::string& key, const std::string& initVec){
	complexKey.setComplexKey(key, initVec);
}

void Decryptor::showKeyAndInitVec(){
	HexEncoder encoder(new FileSink(std::cout));
	std::cout << "key: ";

	encoder.Put(getComplexKey().getKeyPtr(), getComplexKey().getKeySize());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::cout << "Initial vector: ";
	encoder.Put(getComplexKey().getInitVecPtr(), getComplexKey().getInitVecSize());
	encoder.MessageEnd();
	std::cout << std::endl;
}

std::string Decryptor::decrypt(const std::string& encryptedMsgAndMAC, const std::string& authData)
{
	HexEncoder encoder(new FileSink(std::cout));
	std::cout << "cipher text: ";

	encoder.Put(reinterpret_cast<const byte*>(encryptedMsgAndMAC.data()), encryptedMsgAndMAC.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	GCM<AES, GCM_2K_Tables>::Decryption decryption;
	decryption.SetKeyWithIV(complexKey.getKeyPtr(), complexKey.getKeySize(), complexKey.getInitVecPtr());

	AuthenticatedDecryptionFilter authDecrFilter(decryption, NULL,
		AuthenticatedDecryptionFilter::Flags::MAC_AT_BEGIN | HashVerificationFilter::Flags::THROW_EXCEPTION, TAG_SIZE);

	std::string encryptedMsg = encryptedMsgAndMAC.substr(0, encryptedMsgAndMAC.length() - TAG_SIZE);
	//Message Authentication Code
	std::string mac = encryptedMsgAndMAC.substr(encryptedMsgAndMAC.length() - TAG_SIZE);

	//Check correct dividing
	assert(encryptedMsgAndMAC.size() == encryptedMsg.size() + mac.size());
	//Tag is MAC in GCM mode
	assert(TAG_SIZE == mac.size());

	authDecrFilter.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(mac.data()), mac.size());
	authDecrFilter.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(authData.data()), authData.size());
	authDecrFilter.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(encryptedMsg.data()), encryptedMsg.size());

	//Here an exception can be thrown
	try {
		authDecrFilter.ChannelMessageEnd(AAD_CHANNEL);
		authDecrFilter.ChannelMessageEnd(DEFAULT_CHANNEL);
	}
	catch (CryptoPP::Exception& e) {
		std::cerr << e.what() << std::endl;
		//warning about a corrupted message
	}

	//cheking data integrity
	assert(true == authDecrFilter.GetLastResult());

	std::string recoveredMsg;
	if (auto msgLenth = static_cast<size_t>(authDecrFilter.MaxRetrievable()); msgLenth > 0) {
		recoveredMsg.resize(msgLenth);
		authDecrFilter.Get(const_cast<byte*>(reinterpret_cast<const byte*>(recoveredMsg.data())), msgLenth);
	}
	else {
		std::cout << "No data in channel\n";
	}

	return recoveredMsg;
}
