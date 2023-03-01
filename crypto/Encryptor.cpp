#include "Encryptor.h"

void Encryptor::generateKey()
{
    AutoSeededRandomPool randomPool;
    
    randomPool.GenerateBlock(getComplexKey().getKeyPtr(), getComplexKey().getKeySize());
    randomPool.GenerateBlock(getComplexKey().getInitVec(), getComplexKey().getInitVecSize());
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

std::string Encryptor::encrypt(const std::string& message, const std::string& authData)
{
    std::string cipheredMsg;

    try {
        GCM<AES, GCM_2K_Tables>::Encryption encryption;
        encryption.SetKeyWithIV(getComplexKey().getKeyPtr(), getComplexKey().getKeySize(), getComplexKey().getInitVecPtr());

        AuthenticatedEncryptionFilter authEncFilter(encryption,
            new StringSink(cipheredMsg), false, TAG_SIZE
        );

        authEncFilter.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(authData.data()), authData.size());
        authEncFilter.ChannelMessageEnd(AAD_CHANNEL);

        authEncFilter.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(message.data()), message.size());
        authEncFilter.ChannelMessageEnd(DEFAULT_CHANNEL);
    }
    catch (CryptoPP::Exception& e) {
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