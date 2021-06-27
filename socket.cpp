#include "socket.hpp"

//
// Socket
//

bool Socket::WSA_INITD = 0;

// Constructors...

Socket::Socket() { 
    if (!WSA_INITD && !socketInit()) {
        socketError("Socket Constructor", "Unable To Initialize WSA");
    }
}

Socket::Socket(SOCKET sock) : Socket() { 
    this->sock = sock;
}

Socket::Socket(SOCKET sock, sockaddr_in addr) : Socket(sock) {
    this->addr = addr;
}

Socket::Socket(int af, int type, int protocol) : Socket() {
    this->sock = ::socket(af, type, protocol);
    this->addr.sin_family = af;

    if (this->sock == INVALID_SOCKET) {
        socketError("Socket Constructor", "Failed To Initialize 'SOCKET' Value");
    }
}

Socket::~Socket() {
    //if (this->safeToClose)
    //    this->close();
}

// Socket Configuration

int Socket::setSockOpt(
    int level,
    int optname,
    const char* optval,
    int optlen
) {
    return ::setsockopt(this->sock, level, optname, optval, optlen);
}

int Socket::ioControl(
    long cmd,
    u_long* ptr
) {
    return ::ioctlsocket(this->sock, cmd, ptr);
}

// Data IO

int Socket::recvfrom(char* buffer, int bufferLen, sockaddr_in* addr, int flags) {
    int sizeofaddr = sizeof(sockaddr_in);
    return ::recvfrom(this->sock, buffer, bufferLen, flags, (sockaddr*)addr, &sizeofaddr);
}

int Socket::sendto(char* buffer, int bufferLen, sockaddr_in* addr, int flags) {
    return ::sendto(this->sock, buffer, bufferLen, flags, (sockaddr*)addr, sizeof(addr));
}

int Socket::recv(char* buffer, int bufferLen) {
    return this->recvfrom(buffer, bufferLen, NULL, 0);
}

int Socket::send(char* buffer, int bufferLen) {
    return this->sendto(buffer, bufferLen, NULL, 0);
}

std::string Socket::recvStr(sockaddr_in* addr, int flags) {
    std::string str(0xFFFF, ' ');
    int recvd = this->recvfrom((char*)str.c_str(), 0xFFFF, addr, flags);
    str.resize(recvd ? recvd : 0);
    return str;
}

int Socket::sendStr(std::string content, sockaddr_in* addr, int flags) {
    return this->sendto((char*)content.c_str(), content.size(), addr, flags);
}

std::vector<BYTE> Socket::recvBytes(sockaddr_in* addr, int flags) {
    std::vector<BYTE> bytes(0xFFFF);
    int recvd = this->recvfrom((char*)bytes.data(), 0xFFFF, addr, flags);
    bytes.resize(recvd ? recvd : 0);
    return bytes;
}

int Socket::sendBytes(std::vector<BYTE> bytes, sockaddr_in* addr, int flags) {
    return this->sendto((char*)bytes.data(), bytes.size(), addr, flags);
}

// Connection Flow

int Socket::listen(int backlog) {
    return ::listen(this->sock, backlog);
}

SOCKET Socket::accept(sockaddr_in* addr) {
    int sizeofaddr = sizeof(sockaddr_in);
    int ret = ::accept(this->sock, (sockaddr*)addr, &sizeofaddr);
    if (ret) {
        socketError("Socket::accept", "Unable To Accept Connection");
    }
    return ret;
}

int Socket::bind(sockaddr_in addr) {
    int ret = ::bind(this->sock, (sockaddr*)&addr, sizeof(sockaddr_in));
    if (ret) {
        socketError("Socket::bind", "Unable To Bind Socket");
    }
    return ret;
}

int Socket::connect(sockaddr_in addr) {
    int ret = ::connect(this->sock, (sockaddr*)&addr, sizeof(sockaddr_in));
    if (ret) {
        socketError("Socket::connect", "Unable To Establish Connection");
    }
    return ret;
}

bool Socket::valid() {
    return this->sock != INVALID_SOCKET;
}

void Socket::close() {
    ::closesocket(this->sock);
}

//
// TcpSocket
//

void TcpSocket::addrInit(std::string host, USHORT port) {
    this->addr.sin_port = htons(port);
    this->addr.sin_addr.S_un.S_addr = inet_addr(host.c_str());

    if (this->addr.sin_addr.S_un.S_addr == INADDR_NONE) {
        socketError("TcpSocket Host,Port Constructor", "Passed Host Value Invalid, Host Incorrectly Formatted");
    }
}

void TcpSocket::addrInit(std::string hostWithPort) {
    USHORT portbuf;
    char* end;
    size_t colonPos = 0;

    if ((colonPos = hostWithPort.find(':')) == std::string::npos) {
        socketError("TcpSocket Host:Port Constructor", "No Colon Found, Host Incorrectly Formatted");
        return;
    }

    portbuf = (USHORT)strtoul(&hostWithPort.c_str()[colonPos + 1], &end, 10);

    if (*end == '\0') {
        socketError("TcpSocket Host:Port Constructor", "Passed Port Value Invalid, Host Incorrectly Formatted");
        return;
    }

    // duplicate, could use cleanup
    this->addr.sin_port = htons(portbuf);
    this->addr.sin_addr.S_un.S_addr = inet_addr(hostWithPort.substr(0, colonPos).c_str());

    if (this->addr.sin_addr.S_un.S_addr == INADDR_NONE) {
        socketError("TcpSocket Host:Port Constructor", "Passed Host Value Invalid, Host Incorrectly Formatted");
    }
}

TcpSocket::TcpSocket() : Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) {
    this->addr.sin_addr.S_un.S_addr = INADDR_NONE;
}

TcpSocket::TcpSocket(std::string host, USHORT port) : TcpSocket() {
    this->addrInit(host, port);
}

TcpSocket::TcpSocket(std::string hostWithPort) : TcpSocket() {
    this->addrInit(hostWithPort);
}

TcpSocket::TcpSocket(SOCKET sock, sockaddr_in addr) : TcpSocket() {
    this->sock = sock;
    this->addr = addr;
}

int TcpSocket::connect() {
    if (this->isConnected)
        return 0;
    return this->connect(this->addr);
}

int TcpSocket::connect(std::string host, USHORT port) {
    this->addrInit(host, port);
    return this->connect();
}

int TcpSocket::connect(std::string hostWithPort) {
    this->addrInit(hostWithPort);
    return this->connect();
}

//
// TcpServer
//

TcpServer::TcpServer(USHORT port) : Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) {
    this->addr.sin_addr.S_un.S_addr = INADDR_ANY;
    this->addr.sin_port = htons(port);
}

int TcpServer::bind() {
    return this->bind(this->addr);
}

int TcpServer::bind(USHORT port) {
    this->addr.sin_port = htons(port);
    return this->bind();
}

TcpSocket TcpServer::accept() {
    SOCKET s;
    sockaddr_in a;
    s = this->accept(&a);
    return TcpSocket(s, a);
}

//
// UdpSocket
//

UdpSocket::UdpSocket() : Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) {
    this->addr.sin_addr.S_un.S_addr = INADDR_ANY;
}

UdpSocket::UdpSocket(SOCKET sock, sockaddr_in addr) : UdpSocket() {
    this->sock = sock;
    this->addr = addr;
}

UdpSocket::UdpSocket(std::string host, USHORT port) {
    // todo...
}

UdpSocket::UdpSocket(USHORT port) : UdpSocket() {
    this->addr.sin_port = htons(port);
}

UdpSocket::UdpSocket(sockaddr_in targetAddr) : UdpSocket() {
    this->addr = targetAddr;
}

int UdpSocket::connect() {
    this->addr.sin_addr.S_un.S_addr = INADDR_NONE;
    return this->connect(this->addr);
}

int UdpSocket::bind() {
    this->addr.sin_addr.S_un.S_addr = INADDR_ANY;
    return this->bind(this->addr);
}

int UdpSocket::bind(USHORT port) {
    this->addr.sin_port = htons(port);
    return this->bind();
}

int UdpSocket::recvfrom(char* buffer, int bufferLen, sockaddr_in* addr, int flags) {
    if (addr == NULL)
        addr = &this->lastAddrBuf;
    int sizeofaddr = sizeof(sockaddr_in);
    return ::recvfrom(this->sock, buffer, bufferLen, flags, (sockaddr*)addr, &sizeofaddr);
}

int UdpSocket::sendto(char* buffer, int bufferLen, sockaddr_in* addr, int flags) {
    if (addr == NULL)
        addr = &this->addr;
    return ::sendto(this->sock, buffer, bufferLen, flags, (sockaddr*)addr, sizeof(sockaddr));
}

sockaddr_in UdpSocket::getLastAddr() {
    return this->lastAddrBuf;
}

UdpSocket UdpSocket::getLastSocket() {
    return UdpSocket(this->lastAddrBuf);
}
