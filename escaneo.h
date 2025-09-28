#pragma once
#include <string>
#include <vector>
#include <map>

enum class EstadoPuerto { Abierto, Cerrado, Filtrado };

struct ResultadoPuerto {
    int puerto;
    std::string protocolo; // "TCP" o "UDP"
    EstadoPuerto estado;
    std::string servicio_estimado; // ssh, http, etc.
};

std::vector<ResultadoPuerto> escanearTCP(const std::string& ip, const std::vector<int>& puertos, int timeout_ms);
std::vector<ResultadoPuerto> escanearUDP(const std::string& ip, const std::vector<int>& puertos, int timeout_ms);
int calcularTimeoutTCP(const std::string& ip, int puertoPrueba=80);