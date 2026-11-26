# SOC Operations and Incident Response Lab

Laboratorio académico de un Centro de Operaciones de Seguridad (SOC) con Wazuh SIEM, Sysmon, reglas Sigma y pfSense. El proyecto documenta la arquitectura, la telemetría, las detecciones, la simulación controlada de amenazas y la contención de los eventos observados.

## Arquitectura e infraestructura

| Nodo | Sistema / rol | Dirección | Función |
| --- | --- | --- | --- |
| pfSense | FreeBSD / firewall perimetral | LAN `10.10.100.3/24`; WAN `192.168.38.129` | Enrutamiento, NAT SSH, bloqueo perimetral y reenvío Syslog UDP 514. |
| WAZUH-01 | Ubuntu Server 26.10 / SIEM | `10.10.100.20/24` | Wazuh Manager v4.14.10, Indexer (OpenSearch) y Dashboard. |
| LINUX-VICTIMA | Ubuntu Linux / servidor objetivo | `10.10.100.30/24`, agente 002 | Servidor SSH con agente Wazuh. |
| WIN11-VICTIMA | Windows 11 / endpoint | `10.10.100.40/24`, agente 001 | Agente Wazuh y telemetría Sysmon v15.22. |
| Parrot OS | Parrot Security / nodo de prueba externo | `192.168.38.128/24` | Reconocimiento con Netcat y simulación de intentos SSH con Hydra. |

## Ingeniería de detección

Las reglas Sigma describen los eventos base de interés. La regla Wazuh `100101` aplica el umbral de seis eventos en 60 segundos y se calibra sobre el SID `5760`, correspondiente a fallos de autenticación contra una cuenta existente.

| Regla Wazuh | Técnica MITRE ATT&CK | Detección |
| --- | --- | --- |
| `100101` (nivel 10) | `T1110.001` | Fuerza bruta SSH; 6 eventos en 60 segundos. |
| `100102` (nivel 12) | `T1059.001` | PowerShell con `-enc` o `-EncodedCommand`, vía Sysmon Event ID 1. |
| `100103` (nivel 8) | `T1033` | Ejecución de `whoami.exe` o `systeminfo.exe`, vía Sysmon. |

## Hallazgos e indicadores

Durante el ejercicio controlado, Wazuh registró 15 alertas: 9 en `LINUX-VICTIMA` y 6 en `WIN11-VICTIMA` (3 con la regla nativa `92057` y 3 con la regla personalizada `100103`). Los eventos se relacionaron con `T1110.001`, `T1059.001` y `T1033`.

- IP de origen: `192.168.38.128` (Parrot OS).
- Servicio expuesto: `192.168.38.129:22`, redirigido a `10.10.100.30:22`.
- Comando observado: `powershell.exe -EncodedCommand dwBoAG8AYQBtAGkAIAAvAGEAbABsAA==`.
- Payload decodificado: `whoami /all`.
- SHA-256 del binario PowerShell: `8BB6FA8C283B4D92120B1EF249A9B311B0F804D4CABBE9981159976C8BE76A5E`.

## Contención y endurecimiento

pfSense bloqueó en la interfaz WAN el tráfico proveniente de `192.168.38.128`; la verificación desde el nodo de prueba obtuvo un tiempo de espera agotado. Como medidas de endurecimiento se recomiendan:

- Deshabilitar `PasswordAuthentication` en SSH y exigir llaves Ed25519.
- Retirar el reenvío público del puerto TCP/22 y usar una VPN para administración remota.
- Habilitar PowerShell Constrained Language Mode y Script Block Logging (Event ID 4104).
- Vincular Wazuh Active Response (`firewall-drop`) a la detección de fuerza bruta.

## Estructura del repositorio

- `rules/sigma/`: reglas base Sigma en YAML.
- `rules/wazuh/local_rules.xml`: reglas Wazuh calibradas.
- `configs/`: fragmentos de configuración para Syslog y Sysmon.
- `docs/`: informe PDF con la cédula retirada de la portada.

## Informe del proyecto

[Descargar informe SOC en PDF](docs/Informe_SOC_Portafolio_Publico.pdf). 

## Alcance

Las direcciones, sistemas y comandos se describen como parte de un laboratorio académico aislado. Las reglas y configuraciones deben revisarse y probarse en el entorno de destino antes de su uso operativo.



