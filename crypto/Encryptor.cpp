#include "Encryptor.h"

void Encryptor::generateComplexKey()
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

void Encryptor::regenerateKey()
{
    AutoSeededRandomPool randomPool;
    //getComplexKey().getKey().New(getComplexKey().getKeySize());
    getComplexKey().getKey().CleanNew(getComplexKey().getKeySize());
    randomPool.GenerateBlock(getComplexKey().getKeyPtr(), getComplexKey().getKeySize());

    HexEncoder encoder(new FileSink(std::cout));
    std::cout << "New key: ";
    encoder.Put(getComplexKey().getKeyPtr(), getComplexKey().getKeySize());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "Initial vector: ";
    encoder.Put(getComplexKey().getInitVecPtr(), getComplexKey().getInitVecSize());
    encoder.MessageEnd();
    std::cout << std::endl;
}

void Encryptor::regenerateInitVec()
{
    AutoSeededRandomPool randomPool;
    getComplexKey().getInitVec().CleanNew(getComplexKey().getInitVecSize());
    randomPool.GenerateBlock(getComplexKey().getInitVec(), getComplexKey().getInitVecSize());

    HexEncoder encoder(new FileSink(std::cout));

    std::cout << "key: ";
    encoder.Put(getComplexKey().getKeyPtr(), getComplexKey().getKeySize());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "New initial vector: ";
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