#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

#include <Decryptor.h>

using namespace boost::asio;

int main() {

    auto readString = [](ip::tcp::socket& socket) -> std::string {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, "\0");
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

    //read operation
    auto key        = readString(socket);
    auto initVec    = readString(socket);
    auto authData    = readString(socket);
    auto message = readString(socket);

    //Attack the first and last byte of the encrypted data and tag(MAC)
    //message[0] |= 0x0F;
    //message[message.size() - 1] |= 0x0F;

    Decryptor decryptor(key, initVec);
    decryptor.showKeyAndInitVec();

    auto decryptedMsg = decryptor.decrypt(message, authData);
    std::cout << "Decrypted message: " << decryptedMsg << std::endl;

    return 0;
}
