#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

#include <Decryptor.h>

using namespace boost::asio;

std::string getPlainMessageFromSocket(ip::tcp::socket& socket_) {

    auto readString = [](ip::tcp::socket& socket_) -> std::string {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket_, buf, "\0");
        std::string data = boost::asio::buffer_cast<const char*>(buf.data());
        return data;
    };

    //read operation
    auto key        = readString(socket_);
    auto initVec    = readString(socket_);
    auto authData   = readString(socket_);
    auto message    = readString(socket_);

    Decryptor decryptor(key, initVec);
    decryptor.showKeyAndInitVec();

    return decryptor.decrypt(message, authData);
}


int main() {

    boost::asio::io_service io_service;

    //listen for new connection  
    ip::tcp::acceptor acceptor(io_service, ip::tcp::endpoint(ip::tcp::v4(), 1234));

    //socket creation  
    ip::tcp::socket socket(io_service);

    //waiting for the connection  
    acceptor.accept(socket);

    //Attack the first and last byte of the encrypted data and tag(MAC)
    //message[0] |= 0x0F;
    //message[message.size() - 1] |= 0x0F;

    std::cout << "Decrypted message with new key and new InitVector:\n" << getPlainMessageFromSocket(socket) << std::endl;

    std::cout << "\n\nDecrypted message with old key and new InitVector:\n" << getPlainMessageFromSocket(socket) << std::endl;

    std::cout << "\n\nDecrypted message with new key and old InitVector:\n" << getPlainMessageFromSocket(socket) << std::endl;

    return 0;
}
