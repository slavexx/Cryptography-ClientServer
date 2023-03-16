#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/secblock.h>
#include <cryptopp/oids.h>
#include <cryptopp/integer.h>

using namespace boost::asio;
using namespace CryptoPP;

int main() {

    auto readString = [](ip::tcp::socket& socket_) -> std::string {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket_, buf, "\0");
        std::string data = boost::asio::buffer_cast<const char*>(buf.data());
        return data;
    };

    boost::asio::io_service io_service;
    //socket creation
    ip::tcp::socket socket(io_service);

    //connection
    socket.connect(ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));

    boost::system::error_code error;

    //key generation

    AutoSeededX917RNG<AES> rng;
    //ASN1::secp256r1() tihs is common part with other side
    ECDH<ECP>::Domain clientDomain(ASN1::secp256r1());

    SecByteBlock privateKey(clientDomain.PrivateKeyLength()), publicKey(clientDomain.PublicKeyLength());

    clientDomain.GenerateKeyPair(rng, privateKey, publicKey);
    std::string publicClientKeyStr(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());

    boost::asio::write(socket, boost::asio::buffer(publicClientKeyStr), error);
    if (!error) {
        std::cout << "Key was sended successfully" << std::endl;
    }
    else {
        std::cout << "Key send failed: " << error.message() << std::endl;
    }

    //key agreement
    std::string publicServerKeyStr = readString(socket);
    //Anyway it will be aborted in line 65 (due to incorrect reading from the socket)
    assert(publicServerKeyStr.size() == clientDomain.PublicKeyLength());
    SecByteBlock publicServerKey(reinterpret_cast<const byte*>(publicServerKeyStr.data()), publicServerKeyStr.size());

    SecByteBlock sharedKey(clientDomain.AgreedValueLength());

    bool correctness = clientDomain.Agree(sharedKey, privateKey, publicServerKey);

    Integer sharedKeyInt;
    sharedKeyInt.Decode(sharedKey.BytePtr(), sharedKey.SizeInBytes());

    if (correctness) {
        std::cout << "We have a right shared key:" << sharedKeyInt;
    }
    else {
        std::cout << "Error in shared key computation";
    }
    //hashing shared key and use it for encryprion
    return 0;
}
