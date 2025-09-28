#include "escaneo.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <chrono>
#include <algorithm>

using namespace std;

vector<ResultadoPuerto> escanearTCP(const string& ip, const vector<int>& puertos, int timeout_ms)
{
    vector<ResultadoPuerto> resultados;

    for (int puerto : puertos)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            resultados.push_back({puerto, "TCP", EstadoPuerto::Filtrado});
            continue;
        }

        fcntl(sock, F_SETFL, O_NONBLOCK);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        int res = connect(sock, (sockaddr*)&addr, sizeof(addr));
        if (res == 0)
        {
            resultados.push_back({puerto, "TCP", EstadoPuerto::Abierto});
            close(sock);
            continue;
        }

        if (errno != EINPROGRESS)
        {
            resultados.push_back({puerto, "TCP", EstadoPuerto::Cerrado});
            close(sock);
            continue;
        }

        pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLOUT;

        res = poll(&pfd, 1, timeout_ms);
        if (res > 0 && (pfd.revents & POLLOUT))
        {
            int err = -1;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);

            if (err == 0)
            {
                resultados.push_back({puerto, "TCP", EstadoPuerto::Abierto});
            }
            else if (err == ECONNREFUSED)
            {
                resultados.push_back({puerto, "TCP", EstadoPuerto::Cerrado});
            }
            else
            {
                resultados.push_back({puerto, "TCP", EstadoPuerto::Filtrado});
            }
        }
        else
        {
            int err = -1;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);

            if (err == ECONNREFUSED)
            {
                resultados.push_back({puerto, "TCP", EstadoPuerto::Cerrado});
            }
            else if (err == 0)
            {
                resultados.push_back({puerto, "TCP", EstadoPuerto::Filtrado});
            }
            else
            {
                resultados.push_back({puerto, "TCP", EstadoPuerto::Filtrado});
            }
        }

        close(sock);
    }

    return resultados;
}

vector<ResultadoPuerto> escanearUDP(const string& ip, const vector<int>& puertos, int timeout_ms)
{
    vector<ResultadoPuerto> resultados;

    for (int puerto : puertos)
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0)
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Filtrado, ""});
            continue;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        char payload[] = "ping";
        sendto(sock, payload, sizeof(payload), 0, (sockaddr*)&addr, sizeof(addr));

        pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLIN;

        int poll_res = poll(&pfd, 1, timeout_ms);
        if (poll_res > 0)
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Abierto, ""});
        }
        else
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Filtrado, ""});
        }

        close(sock);
    }

    return resultados;
}

int calcularTimeoutTCP(const string& ip, int puertoPrueba)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return 3000;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(puertoPrueba);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    auto inicio = chrono::steady_clock::now();
    int res = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (res == 0)
    {
        close(sock);
        return 1000;
    }

    if (errno != EINPROGRESS)
    {
        close(sock);
        return 2000;
    }

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    timeval tv{};
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    res = select(sock + 1, nullptr, &fdset, nullptr, &tv);
    auto fin = chrono::steady_clock::now();

    int err = -1;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
    close(sock);

    if (res > 0 && err == 0)
    {
        int latencia = chrono::duration_cast<chrono::milliseconds>(fin - inicio).count();
        return clamp(latencia * 2, 1500, 5000);
    }

    return 4000;
}

int calcularTimeoutUDP(const string& ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 3000;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(33434);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    char payload[] = "ping";
    auto inicio = chrono::steady_clock::now();
    sendto(sock, payload, sizeof(payload), 0, (sockaddr*)&addr, sizeof(addr));

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;

    int res = poll(&pfd, 1, 3000);
    auto fin = chrono::steady_clock::now();
    close(sock);

    if (res > 0)
    {
        int latencia = chrono::duration_cast<chrono::milliseconds>(fin - inicio).count();
        return clamp(latencia * 2, 1000, 5000);
    }

    return 5000;
}