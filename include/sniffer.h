#pragma once
#include <string>
#include <map>
#include <vector>

struct Captura {
    int puerto;
    std::string protocolo; // "TCP" o "UDP"
    std::string header_bytes; // Hex string
};

std::map<std::string, Captura> iniciarSniffer(const std::string& ip_objetivo, const std::vector<int>& puertos, int timeout_ms);
std::string bytesHex(const u_char* data, int);

// Función auxiliar para obtener IP local
std::string obtenerIPLocal(const char* interfaz);