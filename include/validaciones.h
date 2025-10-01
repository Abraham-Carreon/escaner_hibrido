#ifndef VALIDACIONES_H
#define VALIDACIONES_H

#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <limits>

//using namespace std; //puede contaminar los namespaces globales (no usar en .h)

struct objetivo {
    std::string ip; /// Aquí se añadiran los campos de los rangos o listas de puertos.
    int modo;
    int puerto_inicial = 0;
    int puerto_final = 0;
    std::vector<int> puertos = {};
    std::string filename;
};

struct puerto {
    int puerto;
    int modo;
};

// Funciones de validación mejoradas
bool validar_ip(std::string& ip);
void validar_rango_puertos(objetivo& Dir);
bool validar_lista(std::string& lista_puertos);

// Funciones existentes
objetivo* obtener_datos();
std::vector<int> ingresar_lista_puertos();

#endif
