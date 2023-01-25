#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

using namespace boost::asio;

int main() {

    auto read_message = [](ip::tcp::socket& socket) -> std::string {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, "\n");
        std::string data = boost::asio::buffer_cast<const char*>(buf.data());
        return data;
    };

    boost::asio::io_service io_service;
    std::string message;

    //listen for new connection  
    ip::tcp::acceptor acceptor_(io_service, ip::tcp::endpoint(ip::tcp::v4(), 1234));

    //socket creation  
    ip::tcp::socket socket_(io_service);

    //waiting for the connection  
    acceptor_.accept(socket_);

    //read operation 
    message = read_message(socket_);
    std::cout << message << std::endl;

    return 0;
}