#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#include <iostream>

#include <WinSock2.h>
#include <Windows.h>

#include <vector>
#include <string>

// use ' -lws2_32 ' with mingw 
#pragma comment(lib, "ws2_32.lib")
#pragma once

static inline bool socketInit() {
    WSAData data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

// I really dislike the windows api sometimes...
static inline void socketError(const char* where, const char* msg) {
    int errc = WSAGetLastError();
    char msgBuffer[0xFF];

    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errc,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        msgBuffer,
        0xFF,
        NULL
    );

    std::cerr << '[' << where << "] ~ " << msg << std::endl;
    std::cerr << "[WSA Error " << errc << "] ~ " << msgBuffer << std::endl;
}


class Socket {
public:
    static bool WSA_INITD;

public:
    Socket();
    Socket(SOCKET sock);
    Socket(SOCKET sock, sockaddr_in addr);
    Socket(int af, int type, int protocol);

    int setSockOpt(int level, int optname, const char* optval, int optlen);
    int ioControl(long cmd, u_long* ptr);

    template<typename _ValType>
    int setSockOpt(int level, int optname, _ValType optval) {
        return this->setSockOpt(level, optname, (const char*)&optval, sizeof(_ValType));
    }

    int recvfrom(char* buffer, int bufferLen, sockaddr_in* addr = NULL, int flags = 0);
    int sendto(char* buffer, int bufferLen, sockaddr_in* addr = NULL, int flags = 0);

    int recv(char* buffer, int bufferLen);
    int send(char* buffer, int bufferLen);

    std::string recvStr(sockaddr_in* addr = NULL, int flags = 0);
    int sendStr(std::string content, sockaddr_in* addr = NULL, int flags = 0);

    std::vector<BYTE> recvBytes(sockaddr_in* addr = NULL, int flags = 0);
    int sendBytes(std::vector<BYTE> bytes, sockaddr_in* addr = NULL, int flags = 0);

    template<typename _Thing>
    int send(_Thing obj, sockaddr_in* addr = NULL, int flags = 0) {
        return this->sendto((char*)&obj, sizeof(_Thing), addr, flags);
    }
    template<typename _Thing>
    int recv(_Thing* objPtr, sockaddr_in* addr = NULL, int flags = 0) {
        return this->recvfrom((char*)objPtr, sizeof(_Thing), addr, flags);
    }

    bool valid();

    void close();

protected:
    SOCKET sock = INVALID_SOCKET;
    sockaddr_in addr = { 0 };
    bool safeToClose = 1; // for copying Socket class instances

    ~Socket();

    int listen(int backlog = SOMAXCONN);
    SOCKET accept(sockaddr_in* addr);
    int bind(sockaddr_in addr);
    int connect(sockaddr_in addr);
};


class TcpSocket : public Socket {
private:
    bool isConnected = 0;

    void addrInit(std::string host, USHORT port);
    void addrInit(std::string hostWithPort);

public:
    using Socket::connect;

    TcpSocket();
    TcpSocket(std::string host, USHORT port);
    TcpSocket(std::string hostWithPort);
    TcpSocket(SOCKET sock, sockaddr_in addr);

    int connect();
    int connect(std::string host, USHORT port);
    int connect(std::string hostWithPort);
};

class TcpServer : public Socket {
public:
    using Socket::listen;
    using Socket::bind;
    using Socket::accept;

    TcpServer(USHORT port);

    int bind();
    int bind(USHORT port);
    TcpSocket accept();
};

/*
 * This class operates on SINGLE!!! SOCKET instance
 * will override trivial 'sockaddr_in' values
 * for certain operations, such as bind
 * where 'sin_addr' is set to 'INADDR_ANY'
 */
class UdpSocket : public Socket {
private:
    sockaddr_in lastAddrBuf;

public:
    using Socket::bind;
    using Socket::connect;

    UdpSocket();
    UdpSocket(SOCKET sock, sockaddr_in addr);
    UdpSocket(std::string host, USHORT port);
    UdpSocket(USHORT port);
    UdpSocket(sockaddr_in targetAddr);

    int connect();
    int bind();
    int bind(USHORT port);

    int recvfrom(char* buffer, int bufferLen, sockaddr_in* addr = NULL, int flags = 0);
    int sendto(char* buffer, int bufferLen, sockaddr_in* addr = NULL, int flags = 0);

    sockaddr_in getLastAddr();
    UdpSocket getLastSocket();
};