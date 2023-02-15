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

std::string Decryptor::decrypt(const std::string& encryptedMsg)
{
	HexEncoder encoder(new FileSink(std::cout));
	std::cout << "cipher text: ";

	encoder.Put(reinterpret_cast<const byte*>(encryptedMsg.data()), encryptedMsg.size());
	encoder.MessageEnd();
	std::cout << std::endl;

	std::string recoveredMsg;
	CBC_Mode<AES>::Decryption decryption;
	decryption.SetKeyWithIV(complexKey.getKeyPtr(), complexKey.getKeySize(), complexKey.getInitVecPtr());

	StringSource ss(encryptedMsg, true,
		new StreamTransformationFilter(decryption,
			new StringSink(recoveredMsg)
		)
	);
	return recoveredMsg;
}
