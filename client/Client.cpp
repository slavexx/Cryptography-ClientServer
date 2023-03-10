#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

#include <Encryptor.h>

using namespace boost::asio;

void sendMessageAndMetainfo(
                ip::tcp::socket& socket_,
                Encryptor& encryptor_,
                const std::string& authData_,
                const std::string& message_)
{
    boost::system::error_code error;

    //sending key
    boost::asio::write(socket_, boost::asio::buffer(encryptor_.keyToString()), error);
    if (!error) {
        std::cout << "Key was sended successfully" << std::endl;
    }
    else {
        std::cout << "Key send failed: " << error.message() << std::endl;
    }
    Sleep(300);
    //sending initial vector
    boost::asio::write(socket_, boost::asio::buffer(encryptor_.InitVecToString()), error);
    if (!error) {
        std::cout << "IV was sended successfully" << std::endl;
    }
    else {
        std::cout << "IV send failed: " << error.message() << std::endl;
    };
    Sleep(300);
    //sending authentification data
    boost::asio::write(socket_, boost::asio::buffer(authData_), error);
    if (!error) {
        std::cout << "Authentification data was sended successfully" << std::endl;
    }
    else {
        std::cout << "send failed: " << error.message() << std::endl;
    }
    Sleep(300);
    //sending encrypted message
    boost::asio::write(socket_, boost::asio::buffer(message_), error);
    if (!error) {
        std::cout << "Message was sended successfully\n\n" << std::endl;
    }
    else {
        std::cout << "send failed: " << error.message() << std::endl;
    }
}

int main() {
    boost::asio::io_service io_service;
    std::string encryptedMsg, plainText;

    //socket creation
    ip::tcp::socket socket(io_service);

    //connection
    socket.connect(ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));

    // request/message from client
    std::cin >> plainText;

    const std::string authData("hashOfUsername");

    Encryptor encryptor;
    encryptor.generateComplexKey();

    //New key, new InitVector
    encryptedMsg = encryptor.encrypt(plainText, authData);
    sendMessageAndMetainfo(socket, encryptor, authData, encryptedMsg);

    //Old key, new InitVector
    encryptor.regenerateInitVec();
    encryptedMsg = encryptor.encrypt(plainText, authData);
    sendMessageAndMetainfo(socket, encryptor, authData, encryptedMsg);

    //New key, old InitVector
    encryptor.regenerateKey();
    encryptedMsg = encryptor.encrypt(plainText, authData);
    sendMessageAndMetainfo(socket, encryptor, authData, encryptedMsg);

    return 0;
}
