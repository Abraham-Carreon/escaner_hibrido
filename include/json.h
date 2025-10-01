#pragma once
#include <string>
#include <vector>
#include <map>
#include "escaneo.h"
#include "sniffer.h"

// Función para identificar servicios basándose en puerto y protocolo
std::string identificarServicio(int puerto, const std::string& protocolo);

void generarJSON(const std::string& ip, 
                 const std::vector<ResultadoPuerto>& resultadosTCP,
                 const std::vector<ResultadoPuerto>& resultadosUDP,
                 const std::map<std::string, Captura>& capturas,
                 const std::string& nombreArchivo);