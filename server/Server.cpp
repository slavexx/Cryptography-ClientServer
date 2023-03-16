#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/secblock.h>
#include <cryptopp/oids.h>
#include <cryptopp/asn.h>
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
    //listen for new connection  
    ip::tcp::acceptor acceptor(io_service, ip::tcp::endpoint(ip::tcp::v4(), 1234));

    //socket creation  
    ip::tcp::socket socket(io_service);

    //waiting for the connection  
    acceptor.accept(socket);

    //key generation

    AutoSeededX917RNG<AES> rng;
    //ASN1::secp256r1() tihs is common part with other side
    ECDH<ECP>::Domain serverDomain(ASN1::secp256r1());

    SecByteBlock privateKey(serverDomain.PrivateKeyLength()), publicKey(serverDomain.PublicKeyLength());

    serverDomain.GenerateKeyPair(rng, privateKey, publicKey);
    std::string publicServerKeyStr(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());

    boost::system::error_code error;

    boost::asio::write(socket, boost::asio::buffer(publicServerKeyStr), error);
    if (!error) {
        std::cout << "Key was sended successfully" << std::endl;
    }
    else {
        std::cout << "Key send failed: " << error.message() << std::endl;
    }

    //key agreement
    std::string publicClientKeyStr = readString(socket);
    //Anyway it will be aborted in line 65 (due to incorrect reading from the socket)
    assert(publicClientKeyStr.size() == serverDomain.PublicKeyLength());

    SecByteBlock publicClientKey(reinterpret_cast<const byte*>(publicClientKeyStr.data()), publicClientKeyStr.size());

    SecByteBlock sharedKey(serverDomain.AgreedValueLength());

    bool correctness = serverDomain.Agree(sharedKey, privateKey, publicClientKey);

    Integer sharedKeyInt;
    sharedKeyInt.Decode(sharedKey.BytePtr(), sharedKey.SizeInBytes());

    if (correctness) {
        std::cout << "We have a right shared key:" << sharedKeyInt;
    }
    else {
        std::cout << "Error in shared key computation";
    }

    return 0;
}
