#include "../include/json.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <unordered_map>

using json = nlohmann::ordered_json;

std::string identificarServicio(int puerto, const std::string &protocolo)
{
    static const std::unordered_map<int, std::pair<std::string, std::string>> servicios_tcp = {
        // Servicios web y HTTP
        {80, {"http", "HTTP"}},
        {443, {"https", "HTTPS"}},
        {8080, {"http-proxy", "HTTP Proxy"}},
        {8443, {"https-alt", "HTTPS alternate"}},
        {8000, {"http-alt", "HTTP alternate"}},
        {3000, {"http", "HTTP (development)"}},

        // SSH y acceso remoto
        {22, {"ssh", "SSH"}},
        {23, {"telnet", "Telnet"}},
        {3389, {"ms-wbt-server", "RDP"}},
        {5900, {"vnc", "VNC"}},
        {5901, {"vnc-1", "VNC"}},

        // Email
        {25, {"smtp", "SMTP"}},
        {110, {"pop3", "POP3"}},
        {143, {"imap", "IMAP"}},
        {993, {"imaps", "IMAPS"}},
        {995, {"pop3s", "POP3S"}},
        {587, {"submission", "SMTP Submission"}},

        // FTP
        {21, {"ftp", "FTP"}},
        {20, {"ftp-data", "FTP Data"}},
        {989, {"ftps-data", "FTPS Data"}},
        {990, {"ftps", "FTPS"}},

        // Base de datos
        {3306, {"mysql", "MySQL"}},
        {5432, {"postgresql", "PostgreSQL"}},
        {1433, {"ms-sql-s", "Microsoft SQL Server"}},
        {1521, {"oracle", "Oracle DB"}},
        {27017, {"mongod", "MongoDB"}},
        {6379, {"redis", "Redis"}},

        // Windows services
        {135, {"msrpc", "Microsoft RPC"}},
        {139, {"netbios-ssn", "NetBIOS Session"}},
        {445, {"microsoft-ds", "SMB"}},
        {137, {"netbios-ns", "NetBIOS Name Service"}},
        {138, {"netbios-dgm", "NetBIOS Datagram"}},

        // Otros servicios comunes
        {53, {"domain", "DNS"}},
        {123, {"ntp", "NTP"}},
        {161, {"snmp", "SNMP"}},
        {162, {"snmptrap", "SNMP Trap"}},
        {69, {"tftp", "TFTP"}},
        {79, {"finger", "Finger"}},
        {113, {"ident", "Ident"}},
        {119, {"nntp", "NNTP"}},
        {194, {"irc", "IRC"}},
        {389, {"ldap", "LDAP"}},
        {636, {"ldaps", "LDAPS"}},
        {993, {"imaps", "IMAPS"}},

        // Juegos y entretenimiento
        {25565, {"minecraft", "Minecraft"}},
        {27015, {"steam", "Steam"}},

        // Desarrollo
        {3000, {"nodejs", "Node.js"}},
        {4000, {"dev", "Development server"}},
        {5000, {"flask", "Flask development"}},
        {8000, {"django", "Django development"}},

        // Monitoreo
        {9090, {"prometheus", "Prometheus"}},
        {3000, {"grafana", "Grafana"}},
        {9200, {"elasticsearch", "Elasticsearch"}},
        {5601, {"kibana", "Kibana"}},
    };

    static const std::unordered_map<int, std::pair<std::string, std::string>> servicios_udp = {
        {53, {"domain", "DNS"}},
        {67, {"dhcps", "DHCP Server"}},
        {68, {"dhcpc", "DHCP Client"}},
        {69, {"tftp", "TFTP"}},
        {123, {"ntp", "NTP"}},
        {161, {"snmp", "SNMP"}},
        {162, {"snmptrap", "SNMP Trap"}},
        {500, {"isakmp", "IPSec IKE"}},
        {514, {"syslog", "Syslog"}},
        {1194, {"openvpn", "OpenVPN"}},
        {4500, {"ipsec-nat-t", "IPSec NAT-T"}},
        {5353, {"mdns", "Multicast DNS"}},
        {137, {"netbios-ns", "NetBIOS Name Service"}},
        {138, {"netbios-dgm", "NetBIOS Datagram"}},
        {1900, {"upnp", "UPnP"}},
        {5060, {"sip", "SIP"}},
        {5061, {"sips", "SIP over TLS"}},
    };

    const auto &mapa = (protocolo == "TCP") ? servicios_tcp : servicios_udp;
    auto it = mapa.find(puerto);

    if (it != mapa.end())
    {
        return it->second.first; // Retorna el nombre corto del servicio
    }

    return "unknown";
}

void generarJSON(const std::string &ip,
                 const std::vector<ResultadoPuerto> &resultadosTCP,
                 const std::vector<ResultadoPuerto> &resultadosUDP,
                 const std::map<std::string, Captura> &capturas,
                 const std::string &nombreArchivo)
{

    json salida = json::array();

    auto procesar = [&](const ResultadoPuerto &r)
    {
        if (r.estado != EstadoPuerto::Abierto && (r.estado != EstadoPuerto::Filtrado || r.protocolo != "UDP"))
            return;

        std::string header = "";
        std::string clave = std::to_string(r.puerto) + "_" + r.protocolo;
        auto it = capturas.find(clave);
        if (it != capturas.end())
        {
            header = it->second.header_bytes;
        }

        json obj;
        obj["ip"] = ip;
        obj["port"] = r.puerto;
        obj["protocol"] = r.protocolo;
        obj["service"] = identificarServicio(r.puerto, r.protocolo);
        obj["header_bytes"] = header;

        salida.push_back(obj);
    };

    for (const auto &r : resultadosTCP)
        procesar(r);
    for (const auto &r : resultadosUDP)
        procesar(r);

    // Agregar todas las capturas adicionales que no estén en los resultados de escaneo
    for (const auto &captura : capturas)
    {
        bool encontrado = false;
        // Buscar si esta captura ya está en los resultados de escaneo
        for (const auto &r : resultadosTCP)
        {
            std::string clave = std::to_string(r.puerto) + "_" + r.protocolo;
            if (clave == captura.first)
            {
                encontrado = true;
                break;
            }
        }
        if (!encontrado)
        {
            for (const auto &r : resultadosUDP)
            {
                std::string clave = std::to_string(r.puerto) + "_" + r.protocolo;
                if (clave == captura.first)
                {
                    encontrado = true;
                    break;
                }
            }
        }

        if (!encontrado)
        {
            json obj;
            obj["ip"] = ip;
            obj["port"] = captura.second.puerto;
            obj["protocol"] = captura.second.protocolo;
            obj["service"] = identificarServicio(captura.second.puerto, captura.second.protocolo);
            obj["header_bytes"] = captura.second.header_bytes;

            salida.push_back(obj);
        }
    }

    std::ofstream out(nombreArchivo);
    out << salida.dump(4);
    out.close();
}