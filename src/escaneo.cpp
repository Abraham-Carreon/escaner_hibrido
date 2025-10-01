// Abraham Alejandro Carreon Soriano
#include "../include/escaneo.h"
#include <sys/socket.h>      
#include <netinet/in.h>      
#include <fcntl.h>           
#include <unistd.h>          
#include <arpa/inet.h>       
#include <iostream>          
#include <poll.h>            
#include <chrono>            
#include <algorithm>        
#include <netinet/ip_icmp.h> 
#include <netinet/ip.h>     
#include <thread>            
#include <netinet/udp.h>    

using namespace std;

// Función principal para escanear puertos TCP
// Recibe una IP, lista de puertos y timeout, devuelve el estado de cada puerto
vector<ResultadoPuerto> escanearTCP(const string &ip, const vector<int> &puertos, int timeout_ms)
{
    vector<ResultadoPuerto> resultados;

    // Probamos cada puerto de la lista uno por uno
    for (int puerto : puertos)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            // Si no podemos crear el socket, marcamos como filtrado
            resultados.push_back({puerto, "TCP", EstadoPuerto::Filtrado});
            continue;
        }

        // Ponemos el socket en modo no-bloqueante para usar timeout
        fcntl(sock, F_SETFL, O_NONBLOCK);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Intentamos conectarnos
        int res = connect(sock, (sockaddr *)&addr, sizeof(addr));
        if (res == 0)
        {
            // ¡Conexión exitosa inmediata! Puerto abierto
            resultados.push_back({puerto, "TCP", EstadoPuerto::Abierto});
            close(sock);
            continue;
        }

        // Si falló por otra razón que no sea "en progreso", está cerrado
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

        // La conexión está "en progreso", esperamos con timeout
        pfd.fd = sock;
        pfd.events = POLLOUT; // Esperamos que esté listo para escribir

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


vector<ResultadoPuerto> escanearUDP(const string &ip, const vector<int> &puertos, int timeout_ms)
{
    vector<ResultadoPuerto> resultados;

    // Creamos un socket especial para recibir mensajes ICMP
    // Cuando un puerto UDP está cerrado, el sistema envía ICMP "port unreachable"
    int icmpSock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmpSock < 0)
    {
        perror("socket ICMP");
        return resultados;
    }

    // Probamos cada puerto UDP de la lista
    for (int puerto : puertos)
    {
        // Creamos un socket UDP para enviar el paquete de prueba
        int udpSock = socket(AF_INET, SOCK_DGRAM, 0);
        if (udpSock < 0)
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Desconocido});
            continue;
        }

        // Asociamos el socket a cualquier puerto local disponible
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port = htons(0);          
        if (bind(udpSock, (sockaddr *)&local, sizeof(local)) < 0)
        {
            perror("bind UDP");
            close(udpSock);
            resultados.push_back({puerto, "UDP", EstadoPuerto::Desconocido});
            continue;
        }

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
        char payload[] = "x";
        sendto(udpSock, payload, sizeof(payload), 0, (sockaddr *)&addr, sizeof(addr));

        auto inicio = chrono::steady_clock::now();
        bool icmpCerrado = false;
        bool respuestaUDP = false;

        while (chrono::steady_clock::now() - inicio < chrono::milliseconds(timeout_ms))
        {
            pollfd pfds[2] = {
                {icmpSock, POLLIN, 0},
                {udpSock, POLLIN, 0}};

            int res = poll(pfds, 2, 50);
            if (res > 0)
            {
                if (pfds[0].revents & POLLIN)
                {
                    char buffer[1024];
                    int n = recv(icmpSock, buffer, sizeof(buffer), 0);
                    if (n > 0)
                    {
                        struct ip *iphdr = (struct ip *)buffer;
                        int ip_header_len = iphdr->ip_hl * 4;
                        struct icmphdr *icmp = (struct icmphdr *)(buffer + ip_header_len);
                        if (icmp->type == 3 && icmp->code == 3)
                        {
                            struct ip *inner_ip = (struct ip *)(buffer + ip_header_len + sizeof(icmphdr));
                            int inner_ip_len = inner_ip->ip_hl * 4;
                            struct udphdr *inner_udp = (struct udphdr *)((char *)inner_ip + inner_ip_len);
                            if (ntohs(inner_udp->uh_dport) == puerto)
                            {
                                icmpCerrado = true;
                                break;
                            }
                        }
                    }
                }

                if (pfds[1].revents & POLLIN)
                {
                    char buffer[1024];
                    sockaddr_in src{};
                    socklen_t len = sizeof(src);
                    int n = recvfrom(udpSock, buffer, sizeof(buffer), 0, (sockaddr *)&src, &len);
                    if (n > 0)
                    {
                        respuestaUDP = true;
                        break;
                    }
                }
            }
            this_thread::sleep_for(chrono::milliseconds(10));
        }

        close(udpSock);

        if (respuestaUDP)
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Abierto});
        }
        else if (icmpCerrado)
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Cerrado});
        }
        else
        {
            resultados.push_back({puerto, "UDP", EstadoPuerto::Filtrado});
        }
    }

    close(icmpSock);
    return resultados;
}

// Función que calcula el timeout óptimo para TCP
// Hace una conexión de prueba para medir la latencia de la red
int calcularTimeoutTCP(const string &ip, int puertoPrueba)
{
    // Intentamos crear un socket para la prueba
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return 3000; // Si falla, usamos un timeout por defecto

    fcntl(sock, F_SETFL, O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(puertoPrueba);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Marcamos el tiempo de inicio para medir latencia
    auto inicio = chrono::steady_clock::now();
    int res = connect(sock, (sockaddr *)&addr, sizeof(addr));
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
        // Calculamos timeout basado en la latencia medida
        int latencia = chrono::duration_cast<chrono::milliseconds>(fin - inicio).count();
        // Usamos el doble de latencia, pero entre 1.5 y 5 segundos
        return std::max(1500, std::min(latencia * 2, 5000));
    }

    // Si no pudimos medir latencia, usamos un valor conservador
    return 4000;
}


int calcularTimeoutUDP(const string &ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 3000; // Valor por defecto si no podemos crear socket

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(33434); 
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Enviamos un paquete pequeño y medimos cuánto tarda la respuesta
    char payload[] = "ping";
    auto inicio = chrono::steady_clock::now();
    sendto(sock, payload, sizeof(payload), 0, (sockaddr *)&addr, sizeof(addr));

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;

    int res = poll(&pfd, 1, 3000);
    auto fin = chrono::steady_clock::now();
    close(sock);

    if (res > 0)
    {
        int latencia = chrono::duration_cast<chrono::milliseconds>(fin - inicio).count();
        return std::max(1000, std::min(latencia * 2, 5000));
    }

    return 5000;
}
