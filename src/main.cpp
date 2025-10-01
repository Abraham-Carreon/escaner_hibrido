#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <limits>
#include "../include/escaneo.h"
#include "../include/json.h"
#include "../include/sniffer.h"
#include "../include/validaciones.h"

// Esta función toma una cadena como "22,80,443" y la convierte en una lista de números
// Útil para cuando el usuario ingresa puertos separados por comas
std::vector<int> parsePuertos(const std::string &entrada)
{
    std::vector<int> puertos;
    std::stringstream ss(entrada);
    std::string token;
    // Separamos por comas y convertimos cada parte a número
    while (std::getline(ss, token, ','))
    {
        try
        {
            int p = std::stoi(token);
            // Solo aceptamos puertos válidos (1-65535)
            if (p >= 1 && p <= 65535)
                puertos.push_back(p);
        }
        catch (...)
        {
            // Si algo sale mal al convertir, simplemente lo ignoramos
        }
    }
    return puertos;
}

int main()
{
    // Primero pedimos al usuario qué quiere escanear (IP, puertos, etc.)
    objetivo *datos = obtener_datos();

    // Aquí guardaremos los resultados de TCP y UDP por separado
    std::vector<ResultadoPuerto> resultadosTCP;
    std::vector<ResultadoPuerto> resultadosUDP;
    std::map<std::string, Captura> capturas;

    std::mutex mtx;

    // Calculamos cuánto tiempo esperar para cada protocolo
    // Esto se basa en qué tan rápida responde la red
    int timeoutTCP = calcularTimeoutTCP(datos->ip);
    int timeoutUDP = calcularTimeoutUDP(datos->ip);
    int timeoutSniffer = timeoutTCP + timeoutUDP + 1000; // +1s de margen por las dudas

    std::thread hiloSniffer([&]()
                            {
        auto caps = iniciarSniffer(datos->ip, datos->puertos, timeoutSniffer);
        std::lock_guard<std::mutex> lock(mtx);
        capturas = std::move(caps); });

    // Le damos medio segundo al sniffer para que se prepare
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Creamos un hilo para escanear TCP
    // Esto permite que TCP y UDP trabajen al mismo tiempo
    std::thread hiloTCP([&]()
                        {
        auto res = escanearTCP(datos->ip, datos->puertos, timeoutTCP);
        // Protegemos los resultados para que no se mezclen con UDP
        std::lock_guard<std::mutex> lock(mtx);
        resultadosTCP = std::move(res); });

    // Y otro hilo para UDP en paralelo
    std::thread hiloUDP([&]()
                        {
       auto r = escanearUDP(datos->ip, datos->puertos, timeoutUDP);
       std::lock_guard<std::mutex> lock(mtx);
       resultadosUDP = std::move(r); });

    // Esperamos a que todos los hilos terminen su trabajo
    hiloTCP.join();
    hiloUDP.join();
    hiloSniffer.join();

    auto mostrar = [](const ResultadoPuerto &r)
    {
        std::string estado;
        // Convertimos el enum a texto legible
        switch (r.estado)
        {
        case EstadoPuerto::Abierto:
            estado = "Abierto";
            break;
        case EstadoPuerto::Cerrado:
            estado = "Cerrado";
            break;
        case EstadoPuerto::Filtrado:
            estado = "Filtrado";
            break;
        case EstadoPuerto::Desconocido:
            estado = "Desconocido";
            break;
        }
        std::cout << "[" << r.protocolo << "] Puerto " << r.puerto << ": " << estado << "\n";
    };
    
    std::cout << "\nResultados del escaneo:\n";
    for (const auto &r : resultadosTCP)
        mostrar(r);
    for (const auto &r : resultadosUDP)
        mostrar(r);

    // Guardamos todo en un archivo JSON para tener un reporte completo
    generarJSON(datos->ip, resultadosTCP, resultadosUDP, capturas, datos->filename);
    std::cout << "Informe guardado en: " << datos->filename << "\n";

    // Limpiamos la memoria que usamos
    delete datos;

    return 0;
}