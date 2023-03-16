#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

using namespace boost::asio;

int main() {
    boost::asio::io_service io_service;
    std::string encryptedMsg, plainText;

    //socket creation
    ip::tcp::socket socket(io_service);

    //connection
    socket.connect(ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1234));

    boost::system::error_code error;
    std::string keyPart{ "testData" };

    boost::asio::write(socket, boost::asio::buffer(keyPart), error);
    if (!error) {
        std::cout << "Key was sended successfully" << std::endl;
    }
    else {
        std::cout << "Key send failed: " << error.message() << std::endl;
    }

    return 0;
}
