#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

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
     message += '\n';
     boost::system::error_code error;
     boost::asio::write(socket, boost::asio::buffer(message), error);
     if (!error) {
         std::cout << "Message was sended successfully" << std::endl;
     }
     else {
         std::cout << "send failed: " << error.message() << std::endl;
     }    
     return 0;
}