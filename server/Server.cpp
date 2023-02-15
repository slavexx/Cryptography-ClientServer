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
    std::string message;

    //listen for new connection  
    ip::tcp::acceptor acceptor(io_service, ip::tcp::endpoint(ip::tcp::v4(), 1234));

    //socket creation  
    ip::tcp::socket socket(io_service);

    //waiting for the connection  
    acceptor.accept(socket);

    //read operation
    auto key        = readString(socket);
    auto initVec    = readString(socket);

    Decryptor decryptor(key, initVec);
    decryptor.showKeyAndInitVec();
    message = readString(socket);
    std::cout << "Decrypted message: " << decryptor.decrypt(message) << std::endl;

    return 0;
}
