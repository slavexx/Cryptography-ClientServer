#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

#include <Encryptor.h>

using namespace boost::asio;

int main() {
    boost::asio::io_service io_service;
    std::string message;

    //socket creation  
    ip::tcp::socket socket(io_service);

    //connection  
    socket.connect(ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));

    // request/message from client  
    std::cin >> message;

    const std::string authData("hashOfUsername");

    Encryptor encryptor;
    encryptor.generateKey();
    message = encryptor.encrypt(message, authData);

    boost::system::error_code error;

    //sending key
    boost::asio::write(socket, boost::asio::buffer(encryptor.keyToString()), error);
    if (!error) {
        std::cout << "Key was sended successfully" << std::endl;
    }
    else {
        std::cout << "Key send failed: " << error.message() << std::endl;
    }

    //sending initial vector
    boost::asio::write(socket, boost::asio::buffer(encryptor.InitVecToString()), error);
    if (!error) {
        std::cout << "IV was sended successfully" << std::endl;
    }
    else {
        std::cout << "IV send failed: " << error.message() << std::endl;
    };

    //sending authentification data
    boost::asio::write(socket, boost::asio::buffer(authData), error);
    if (!error) {
        std::cout << "Authentification data was sended successfully" << std::endl;
    }
    else {
        std::cout << "send failed: " << error.message() << std::endl;
    }

    //sending encrypted message
    boost::asio::write(socket, boost::asio::buffer(message), error);
    if (!error) {
        std::cout << "Message was sended successfully" << std::endl;
    }
    else {
        std::cout << "send failed: " << error.message() << std::endl;
    }

    return 0;
}
