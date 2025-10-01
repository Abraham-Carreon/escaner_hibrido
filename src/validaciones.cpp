#include <iostream>
#include "../include/validaciones.h"
#include <string>
#include <string.h>
#include <regex>
#include <limits>
#include <vector>
#include <exception>
#include <sstream>

// Esta función verifica que la IP esté bien escrita
// Usa expresiones regulares para validar el formato
bool validar_ip(std::string &ip)
{
    // Expresión regular que valida IPv4 (ej: 192.168.1.1)
    std::regex ipv4(R"(^((25[0-5]|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.){3}(25[0-5]|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))$)");
    if (!regex_match(ip, ipv4))
    {
        std::cout << "Error: Direccion IP invalida." << std::endl;
        return false;
    }
    else
    {
        return true;
    }
}

// Pide al usuario que ingrese un rango de puertos (ej: del 80 al 90)
void validar_rango_puertos(objetivo &Dir)
{
    std::cin.exceptions(std::ios::failbit | std::ios::badbit);
    int puerto_inicial;
    int puerto_final;
    while (true)
    {
        try
        {
            std::cout << "Ingresar puerto inicial (1 - 65535): ";
            std::cin >> puerto_inicial;
            if (puerto_inicial >= 1 and puerto_inicial <= 65535)
            {
                std::cout << "Ingresa puerto final (" << puerto_inicial << " - 65535): ";
                std::cin >> puerto_final;
                if (puerto_final >= puerto_inicial && puerto_final <= 65535)
                {
                    Dir.puerto_inicial = puerto_inicial;
                    Dir.puerto_final = puerto_final;
                    return;
                }
                else
                {
                    std::cout << "Puerto invalido, ingrese de nuevo." << std::endl;
                    continue;
                }
            }
            else
            {
                std::cout << "Puerto invalido, ingrese de nuevo" << std::endl;
                continue;
            }
        }
        catch (const std::ios_base::failure &e)
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Error al ingresar puertos, vuelva a ingresar." << std::endl;
        }
    }
}

bool validar_lista(std::string &lista_puertos)
{
    std::regex puertos(R"(^([1-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])(,([1-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))*$)");
    if (!regex_match(lista_puertos, puertos))
    {
        std::cout << "Error: Lista de puertos invalida." << std::endl;
        return false;
    }
    else
    {
        return true;
    }
}

std::vector<int> ingresar_lista_puertos()
{
    std::string lista_puertos;
    std::string token;
    std::vector<int> puertos;

    while (true)
    {
        try
        {
            std::cout << "Ingresar lista de puertos (ej: 80,443,53): ";
            std::cin >> lista_puertos;

            if (!validar_lista(lista_puertos))
            {
                std::cout << "Intente de nuevo." << std::endl;
                continue;
            }

            std::stringstream ss(lista_puertos);
            while (std::getline(ss, token, ','))
            {
                int puerto = std::stoi(token);
                if (puerto >= 1 && puerto <= 65535)
                {
                    puertos.push_back(puerto);
                }
            }
            return puertos;
        }
        catch (const std::ios_base::failure &e)
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Error inesperado, ingrese de nuevo: " << std::endl;
        }
    }
}

// Esta es la función principal que maneja todo el menú
// Le pregunta al usuario qué quiere escanear y cómo
objetivo *obtener_datos()
{
    // Creamos una estructura para guardar toda la información
    objetivo *Dir_escaneo = new objetivo;
    std::string ip;
    std::string filename;
    int opcion;
    std::cin.exceptions(std::ios::failbit | std::ios::badbit);

    // Primero pedimos la IP objetivo
    while (true)
    {
        try
        {
            std::cout << "Ingresar direccion IP objetivo a escanear: ";
            std::cin >> ip;
            // Verificamos que la IP esté bien escrita
            if (!validar_ip(ip))
            {
                continue; // Si está mal, preguntamos de nuevo
            }
            break; // Si está bien, salimos del bucle
        }
        catch (const std::ios_base::failure &e)
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Entrada invalida." << std::endl;
        }
    }

    // Ahora mostramos el menú de opciones
    while (true)
    {
        try
        {
            std::cout << R"( 
0) Rango de puertos      - Ej: del 80 al 90
1) Lista de puertos      - Ej: 22,80,443
2) Puertos comunes       - Los más típicos (web, ssh, etc.)
3) Todos los puertos     - Del 1 al 65535 (¡Tardará mucho!)
Elegir tipo de escaneo: )";
            std::cin >> opcion;
            // Verificamos que eligió una opción válida
            if (opcion >= 0 && opcion <= 3)
            {
                Dir_escaneo->modo = opcion;
                break; // Opción válida, continuamos
            }
            else
            {
                std::cout << "Opcion invalida, intente de nuevo." << std::endl;
            }
        }
        catch (const std::ios_base::failure &e)
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Entrada invalida, intente de nuevo." << std::endl;
        }
    }

    bool flag = true;
    while (flag)
    {
        try
        {
            switch (opcion)
            {
            case 0:
                validar_rango_puertos(*Dir_escaneo);
                // Convertir rango a vector de puertos
                for (int i = Dir_escaneo->puerto_inicial; i <= Dir_escaneo->puerto_final; i++)
                {
                    Dir_escaneo->puertos.push_back(i);
                }
                flag = false;
                break;
            case 1:
                Dir_escaneo->puertos = ingresar_lista_puertos();
                flag = false;
                break;
            case 2:
                // Puertos comunes
                Dir_escaneo->puertos = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900};
                std::cout << "Usando puertos comunes: 21,22,23,25,53,80,110,143,443,993,995,3389,5900" << std::endl;
                flag = false;
                break;
            case 3:
                // Todos los puertos (1-65535)
                std::cout << "Escaneando todos los puertos (1-65535). Esto puede tomar mucho tiempo." << std::endl;
                for (int i = 1; i <= 65535; i++)
                {
                    Dir_escaneo->puertos.push_back(i);
                }
                flag = false;
                break;
            default:
                flag = false;
                break;
            }
        }
        catch (const std::exception &e)
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Error, intente de nuevo" << std::endl;
        }
    }

    std::cout << "Ingresar nombre de archivo de resultados [default: registro.json]: ";
    std::getline(std::cin, filename);

    if (filename.empty())
        filename = "registro.json";

    if (filename.size() < 6 || filename.substr(filename.size() - 5) != ".json")
        filename += ".json";

    Dir_escaneo->filename = filename;
    Dir_escaneo->ip = ip;
    return Dir_escaneo;
}
