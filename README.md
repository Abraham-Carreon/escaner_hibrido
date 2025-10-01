# 🔍 Scanner TCP/UDP Avanzado en C++

## 📝 Descripción General
Scanner de puertos *TCP y UDP* desarrollado en C++ para *Linux*, con capacidades avanzadas de:
- ✅ Escaneo concurrente TCP/UDP 
- 📡 Captura de paquetes en tiempo real con *libpcap*
- 🎯 Timeouts adaptativos basados en latencia de red
- 📊 Reportes detallados en formato JSON
- 🔧 Interfaz de menú intuitiva con múltiples opciones de escaneo

---

## Integrantes del equipo:
 - Angel Adrian Alvarez Flores             [angelaf2005]     Modulo Sniffing  
- Abraham Alejandro Carreon Soriano        [Abraham-Carreon] Modulo Escaneo
- Jesus Kenneth Maurizio Martinez Vazquez  [RedKnight023]    Modulo JSONGEN
- Raul Alejandro Rios Turrubiates          [RSKR0]           Modulo Sniffing y Escaneo

---

## 🖥️ Instalación y Uso

### ✅ Requisitos del Sistema
- *SO*: Linux (Ubuntu/Debian recomendado)
- *Compilador*: g++ con soporte C++11
- *Dependencias*:
  - libpcap-dev - Para captura de paquetes
  - build-essential - Herramientas de compilación

### ⚙️ Instalación de Dependencias
bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential libpcap-dev

# CentOS/RHEL
sudo yum install gcc-c++ libpcap-devel


### 🔨 Compilación
bash
# Clonar el repositorio
git clone https://github.com/Abraham-Carreon/escaner_hibrido
cd escaner_hibrido

# Compilar el proyecto
g++ -std=c++11 -o scanner src/main.cpp src/escaneo.cpp src/json.cpp src/sniffer.cpp src/validaciones.cpp -lpcap


### 🚀 Ejecución
bash
# Ejecutar con privilegios de administrador (requerido para libpcap)
sudo ./scanner


---

## 🎛️ Características Principales

### 📋 Opciones de Escaneo
*0️⃣ Rango de Puertos*
- Escanea un rango continuo (ej: 80-90)
- Ideal para escaneos específicos

*1️⃣ Lista de Puertos*
- Puertos específicos separados por comas (ej: 22,80,443)
- Máxima flexibilidad

*2️⃣ Puertos Comunes*
- Lista predefinida: 21,22,23,25,53,80,110,143,443,993,995,3389,5900
- Escaneo rápido de servicios típicos

*3️⃣ Todos los Puertos*
- Escaneo completo (puertos 1-65535)
- ⚠️ Proceso extenso, usar con precaución

### 🔍 Detección de Estados
| Estado | TCP | UDP | Descripción |
|--------|-----|-----|-------------|
| *Abierto* | ✅ SYN-ACK | ✅ Respuesta | Puerto acepta conexiones |
| *Cerrado* | ❌ RST | ❌ ICMP Port Unreachable | Puerto cerrado explícitamente |
| *Filtrado* | ⏱️ Timeout | ⏱️ Sin respuesta | Firewall/filtro bloqueando |

### 📡 Captura de Tráfico
- *Monitoreo en tiempo real* con libpcap
- *Análisis de paquetes* TCP/UDP/ICMP
- *Correlación automática* entre escaneos y respuestas

### ⚡ Optimización Inteligente
- *Timeouts adaptativos*: Se ajustan automáticamente según latencia
- *Escaneo concurrente*: TCP y UDP en paralelo
- *Eficiencia*: Algoritmos optimizados para máximo rendimiento

---

## 📊 Formato de Salida

### 🖥️ Consola

Resultados del escaneo:
[TCP] Puerto 22: Filtrado  
[TCP] Puerto 80: Abierto
[UDP] Puerto 53: Filtrado


### 📄 Archivo JSON
json
[
    {
        "ip": "192.168.1.1",
        "port": 53,
        "protocol": "TCP",
        "service": "domain",
        "header_bytes": "00 35 d0 96 63 1c f6 34 04 53 3f c4 a0 12 71 20"
    },
    {
        "ip": "192.168.1.1",
        "port": 80,
        "protocol": "TCP",
        "service": "http",
        "header_bytes": "00 50 85 0e c3 bd 15 e9 38 46 94 e1 a0 12 71 20"
    }
]


---

## ⚠️ Consideraciones de Seguridad

### 🔒 Uso Ético
- *Solo usar en redes propias* o con autorización explícita
- *Respetar términos de servicio* de proveedores
- *Propósito educativo/administrativo* únicamente

### 🛡️ Detección
- Algunos firewalls pueden *detectar escaneos*
- *Rate limiting* puede aplicarse
- Considerar usar *delays* en escaneos extensos

---

## 🏗️ Arquitectura Técnica

### 📁 Estructura del Proyecto

scanner_tcp_ip/
├── include/
│   ├── escaneo.h      # Definiciones de escaneo TCP/UDP
│   ├── json.h         # Generación de reportes JSON
│   ├── sniffer.h      # Captura de paquetes libpcap
│   └── validaciones.h # Validación de entrada y menús
├── src/
│   ├── main.cpp       # Punto de entrada principal
│   ├── escaneo.cpp    # Lógica de escaneo y timeouts
│   ├── json.cpp       # Serialización JSON
│   ├── sniffer.cpp    # Implementación libpcap
│   └── validaciones.cpp # Sistema de menús y validación
└── README.md


## 📄 Licencia
Este proyecto está bajo la *MIT License* - consulta el archivo [LICENSE](LICENSE) para más detalles.

---
