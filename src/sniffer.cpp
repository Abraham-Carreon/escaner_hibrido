#include "../include/sniffer.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <chrono>
#include <thread>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <net/ethernet.h>
#include <algorithm>
#include <ifaddrs.h>
#include <sys/socket.h>

// Función para obtener la IP local de la interfaz
std::string obtenerIPLocal(const char *interfaz)
{
    struct ifaddrs *ifaddrs_ptr, *ifa;
    std::string ip_local = "127.0.0.1"; // fallback

    if (getifaddrs(&ifaddrs_ptr) == -1)
    {
        std::cerr << "Error obteniendo direcciones de interfaces" << std::endl;
        return ip_local;
    }

    // Primero buscar la interfaz específica
    for (ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
        {
            if (strcmp(ifa->ifa_name, interfaz) == 0)
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                char *ip_str = inet_ntoa(sin->sin_addr);
                if (strcmp(ip_str, "127.0.0.1") != 0)
                { // Evitar loopback
                    ip_local = ip_str;
                    break;
                }
            }
        }
    }

    // Si no encontramos la interfaz específica, buscar cualquier IP no-loopback
    if (ip_local == "127.0.0.1")
    {
        for (ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                char *ip_str = inet_ntoa(sin->sin_addr);
                if (strcmp(ip_str, "127.0.0.1") != 0)
                { // Tomar la primera IP no-loopback
                    ip_local = ip_str;
                    break;
                }
            }
        }
    }

    freeifaddrs(ifaddrs_ptr);
    return ip_local;
}

std::string bytesHex(const u_char *data, int len)
{
    std::ostringstream oss;
    for (int i = 0; i < len; ++i)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i < len - 1)
            oss << " ";
    }
    return oss.str();
}

std::map<std::string, Captura> iniciarSniffer(const std::string &ip_objetivo, const std::vector<int> &puertos, int timeout_ms)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs)
    {
        std::cerr << "Error al obtener interfaces: " << errbuf << "\n";
        return {};
    }

    // Buscar la interfaz más apropiada (no loopback)
    const char *dev = nullptr;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next)
    {
        if (!(d->flags & PCAP_IF_LOOPBACK))
        {
            dev = d->name;
            break;
        }
    }

    if (!dev)
    {
        dev = alldevs->name; 
    }

    // Abrir en modo promiscuo con buffer más grande
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1, errbuf); // 1 = modo promiscuo
    pcap_freealldevs(alldevs);

    if (!handle)
    {
        std::cerr << "Error al abrir interfaz: " << errbuf << "\n";
        return {};
    }

    // Configurar buffer size para mejor rendimiento
    if (pcap_set_buffer_size(handle, 2 * 1024 * 1024) != 0)
    { 
    }

    // Configurar el descriptor de archivo como no bloqueante
    if (pcap_setnonblock(handle, 1, errbuf) == -1)
    {
        std::cerr << "Error al configurar modo no bloqueante: " << errbuf << "\n";
        pcap_close(handle);
        return {};
    }

    // Obtener nuestra IP local para el filtro
    std::string ip_local = obtenerIPLocal(dev);

    // Crear filtro BPF específico para capturar respuestas del objetivo hacia nosotros
    std::ostringstream filtro;
    filtro << "(src host " << ip_objetivo << " and dst host " << ip_local << ") and (";

    for (size_t i = 0; i < puertos.size(); ++i)
    {
        // Capturar respuestas TCP/UDP desde el puerto objetivo hacia cualquier puerto nuestro
        filtro << "(tcp src port " << puertos[i] << ") or (udp src port " << puertos[i] << ")";
        if (i < puertos.size() - 1)
            filtro << " or ";
    }
    filtro << ")";

    bpf_program fp;
    if (pcap_compile(handle, &fp, filtro.str().c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "Error al aplicar filtro BPF\n";
        pcap_close(handle);
        return {};
    }

    std::map<std::string, Captura> capturas;
    auto inicio = std::chrono::steady_clock::now();
    int paquetes_procesados = 0;

    while (true)
    {
        auto ahora = std::chrono::steady_clock::now();
        auto tiempo_transcurrido = std::chrono::duration_cast<std::chrono::milliseconds>(ahora - inicio).count();

        if (tiempo_transcurrido > timeout_ms)
        {
            break;
        }

        pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 1 && header->caplen >= 14)
        {
            paquetes_procesados++;

            const ether_header *eth = (ether_header *)packet;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP)
                continue;

            const ip *iphdr = (struct ip *)(packet + 14);
            int iphdr_len = iphdr->ip_hl * 4;
            if (header->caplen < 14 + iphdr_len)
                continue;

            int src_port = 0, dst_port = 0;
            std::string proto;
            int l4_offset = 14 + iphdr_len;
            int l4_len = 0;

            if (iphdr->ip_p == IPPROTO_TCP)
            {
                if (header->caplen < l4_offset + sizeof(tcphdr))
                    continue;
                const tcphdr *tcph = (tcphdr *)(packet + l4_offset);
                src_port = ntohs(tcph->th_sport);
                dst_port = ntohs(tcph->th_dport);
                proto = "TCP";
                l4_len = tcph->th_off * 4;
            }
            else if (iphdr->ip_p == IPPROTO_UDP)
            {
                if (header->caplen < l4_offset + sizeof(udphdr))
                    continue;
                const udphdr *udph = (udphdr *)(packet + l4_offset);
                src_port = ntohs(udph->uh_sport);
                dst_port = ntohs(udph->uh_dport);
                proto = "UDP";
                l4_len = 8;
            }
            else
            {
                continue;
            }

            // Capturar solo los primeros 16 bytes del header del protocolo L4 (TCP/UDP)
            int bytes_a_capturar = std::min(16, l4_len);
            std::string hex = bytesHex(packet + l4_offset, bytes_a_capturar);

            // Capturar tanto puerto origen como destino si están en nuestra lista
            for (int puerto : {src_port, dst_port})
            {
                if (std::find(puertos.begin(), puertos.end(), puerto) != puertos.end())
                {
                    std::string clave = std::to_string(puerto) + "_" + proto;
                    if (capturas.find(clave) == capturas.end())
                    {
                        capturas[clave] = {puerto, proto, hex};
                    }
                }
            }
        }
        else if (res == -1)
        {
            std::cerr << "Error de captura: " << pcap_geterr(handle) << "\n";
            break;
        }
        else if (res == 0)
        {
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    pcap_close(handle);
    return capturas;
}
