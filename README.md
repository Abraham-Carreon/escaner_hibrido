# Proyecto: Escáner híbrido de puertos y sniffing en C++ 
 
## Descripción general:
Herramienta en C++ para Linux que combina escaneo real de 
puertos TCP/UDP y captura de la primera trama de respuesta. Al 
finalizar, genera un informe JSON con servicios y primeros bytes 
de cabecera. 
 
## Integrantes del equipo:
 - Angel Adrian Alvarez Flores             [angelaf2005]     Modulo Sniffing  
- Abraham Alejandro Carreon Soriano        [Abraham-Carreon] Modulo Escaneo
- Jesus Kenneth Maurizio Martinez Vazquez  [RedKnight023]    Modulo JSONGEN
- Raul Alejandro Rios Turrubiates          [RSKR0]           Modulo Sniffing y Escaneo
## Requisitos - Sistema operativo: Ubuntu/Debian   - Compilador: g++ (C++17)   - Dependencias: libpcap, nlohmann/json   
 
## Compilación 
```bash 
g++ main.cpp Escaneo.cpp Sniffer.cpp JSONGen.cpp -o 
escaner_hibrido \ 
    -lpcap -pthread 
 Ejecución S
./escaner_hibrido 
# Ingresar: 
# IP objetivo: 192.168.1.100 
# Puerto inicial: 20 
# Puerto final: 1024 
# Timeout (ms): 500 
# Archivo JSON: resultado.json 
 Enfoque técnico 
