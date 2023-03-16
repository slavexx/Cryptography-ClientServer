#include <SDKDDKVer.h>
#include <iostream>  
#include <boost/asio.hpp>

using namespace boost::asio;

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

    std::cout << readString(socket) << '\n';

    return 0;
}
