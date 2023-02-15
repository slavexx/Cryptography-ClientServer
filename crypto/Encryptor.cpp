#include "Encryptor.h"

void Encryptor::generateKey()
{
    AutoSeededRandomPool randomPool;
    
    randomPool.GenerateBlock(getComplexKey().getKeyPtr(), getComplexKey().getKeySize());
    randomPool.GenerateBlock(getComplexKey().getInitVecPtr(), getComplexKey().getInitVecSize());

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

std::string Encryptor::encrypt(const std::string& message)
{
    std::string cipheredMsg;

    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(getComplexKey().getKeyPtr(), getComplexKey().getKeySize(), getComplexKey().getInitVecPtr());

        StringSource strSrc(message, true,
            new StreamTransformationFilter(encryption,
                new StringSink(cipheredMsg)
            )
        );
    }
    catch (const Exception& e) {
        std::cerr << e.what() << std::endl;
    }

    HexEncoder encoder(new FileSink(std::cout));
    std::cout << "cipher text: ";
    
    encoder.Put(reinterpret_cast<const byte*>(cipheredMsg.data()), cipheredMsg.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    return cipheredMsg;
}

std::string Encryptor::keyToString()        { return complexKey.keyToString(); };

std::string Encryptor::InitVecToString()    { return complexKey.InitVecToString(); };