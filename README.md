# IP Port Network Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-Networking-blue?style=for-the-badge&logo=python&logoColor=white">
</p>
##

English Version
![](https://github.com/leonelpedroza/ip_monitor/blob/main/UKFlag.png)

## History

I've long wanted to make my own TCP/UDP/ICMP port scanning tool. Something that just worked and didn't require a lot of requirements. I bought a license for a commercial one about 15 years ago, but they discontinued support and it doesn't run on Windows 10/11.




A comprehensive network scanning tool with GUI that allows scanning TCP/UDP ports and ICMP with advanced features including proxy support, jump server capability, and multilingual interface.

## 🚀 Features

- **Port Scanning**
  - TCP port scanning with service detection
  - UDP port scanning
  - ICMP (ping) checking
  - Custom port ranges support
  - Pre-configured common TCP ports

- **Advanced Capabilities**
  - Multi-threaded scanning for faster results
  - Proxy support (HTTP/HTTPS/SOCKS4/SOCKS5)
  - Jump server support (SSH/Telnet)
  - Service version detection
  - Response time measurement

- **User Interface**
  - Clean and intuitive GUI built with Tkinter
  - Multilingual support (English/Spanish)
  - Real-time results display
  - Progress tracking
  - Results filtering (Open ports only, TCP/UDP only)

- **Export & Configuration**
  - Export results to CSV
  - Export results to HTML with styling
  - Save/Load configuration profiles
  - Customizable scan parameters

## 📋 Requirements

- Python 3.7 or higher
- No external dependencies (uses only Python standard library)

## 💻 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ip-port-network-scanner.git
cd ip-port-network-scanner
```

2. Run the application:
```bash
python IP_Scanner.pyw
```

## 🔧 Usage

### Basic Scanning

1. **Set Target**: Enter an IP address, IP range, or CIDR notation
   - Single IP: `192.168.1.1`
   - IP Range: `192.168.1.1-10`
   - CIDR: `192.168.1.0/24`

2. **Select Ports**: 
   - Choose from common TCP ports
   - Add custom TCP ports: `80,443,8080` or `1000-2000`
   - Add UDP ports: `53,67,68`

3. **Start Scan**: Click "Start Scan" to begin

### Advanced Options

- **Threads**: Number of concurrent threads (1-50)
- **Delay**: Delay between scans in milliseconds
- **Timeout**: Connection timeout in seconds
- **Proxy Settings**: Configure HTTP/HTTPS/SOCKS proxy
- **Jump Server**: Configure SSH/Telnet jump server

### Configuration Tab

Access additional settings:
- Language selection
- Save/Load scan configurations
- Advanced network options

## 🛠️ Configuration Options

### Proxy Configuration
- Type: HTTP, HTTPS, SOCKS4, SOCKS5
- Authentication support
- Host and port configuration

### Jump Server Configuration
- SSH or Telnet support
- Username/password authentication
- Custom port configuration

## 📊 Output Formats

### CSV Export
Exports scan results with columns:
- IP Address
- Port
- Protocol
- Status
- Service
- Version
- Response Time

### HTML Export
Generates a styled HTML report with:
- Scan summary information
- Color-coded results
- Responsive table design
- Timestamp and host information

## 🎨 Screenshots

<details>
<summary>Click to view screenshots</summary>

### Main Scan Interface
![Main Interface](https://github.com/leonelpedroza/IP_Port_Scanner/blob/main/interfaz-principal.png)

### Configuration Tab
![Configuration](https://github.com/leonelpedroza/IP_Port_Scanner/blob/main/configuracion.png)

### Results View
![Results](https://github.com/leonelpedroza/IP_Port_Scanner/blob/main/resultados.png)




</details>

## ⚠️ Disclaimer

This tool is intended for legitimate network administration, security testing, and educational purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any network or system they do not own.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Leonel Pedroza**
- Website: [leonelpedroza.com](https://www.leonelpedroza.com)
- GitHub: [@leonelpedroza](https://github.com/leonelpedroza)

## 🙏 Acknowledgments

- Built with Python's tkinter library
- Icon and UI design inspired by modern network tools
- Thanks to all contributors and testers

## 📞 Support

If you encounter any issues or have questions, please:
1. Check the [Issues](https://github.com/yourusername/ip-port-network-scanner/issues) page
2. Create a new issue if your problem isn't already listed
3. Provide detailed information about your environment and the problem

## 🔄 Version History

- **v1.0.0** (March 2024)
  - Initial release
  - Full TCP/UDP scanning capabilities
  - Proxy and jump server support
  - Multilingual interface

---
Made with 🧠 por [lgp](https://www.leonelpedroza.com)

__________________________________________________________
__________________________________________________________


# IP Port Network Scanner - Escáner de Red
Español
![](https://github.com/leonelpedroza/ip_monitor/blob/main/SpainFlag.png)

## Historia
Hace mucho quería hacer mi propia herramienta de escaneo de puertos TCP/UDP/ICMP. Algo que simplemente funcionara y sin muchos requerimientos.

Compre una licencia de uno comercial hace como 15 años, pero descontinuaron el soporte y no corre en Windows 10/11.




<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue.svg" alt="Versión de Python">
  <img src="https://img.shields.io/badge/Plataforma-Windows%20%7C%20Linux%20%7C%20macOS-green.svg" alt="Plataforma">
  <img src="https://img.shields.io/badge/Licencia-MIT-yellow.svg" alt="Licencia">
</p>

Una herramienta completa de escaneo de red con interfaz gráfica que permite escanear puertos TCP/UDP e ICMP con características avanzadas incluyendo soporte de proxy, capacidad de servidor de salto e interfaz multilingüe.

## 🚀 Características

- **Escaneo de Puertos**
  - Escaneo de puertos TCP con detección de servicios
  - Escaneo de puertos UDP
  - Verificación ICMP (ping)
  - Soporte para rangos de puertos personalizados
  - Puertos TCP comunes preconfigurados

- **Capacidades Avanzadas**
  - Escaneo multi-hilo para resultados más rápidos
  - Soporte de proxy (HTTP/HTTPS/SOCKS4/SOCKS5)
  - Soporte de servidor de salto (SSH/Telnet)
  - Detección de versión de servicios
  - Medición del tiempo de respuesta

- **Interfaz de Usuario**
  - GUI limpia e intuitiva construida con Tkinter
  - Soporte multilingüe (Inglés/Español)
  - Visualización de resultados en tiempo real
  - Seguimiento del progreso
  - Filtrado de resultados (Solo puertos abiertos, Solo TCP/UDP)

- **Exportación y Configuración**
  - Exportar resultados a CSV
  - Exportar resultados a HTML con estilo
  - Guardar/Cargar perfiles de configuración
  - Parámetros de escaneo personalizables

## 📋 Requisitos

- Python 3.7 o superior
- Sin dependencias externas (usa solo la biblioteca estándar de Python)

## 💻 Instalación

1. Clona el repositorio:
```bash
git clone https://github.com/tuusuario/ip-port-network-scanner.git
cd ip-port-network-scanner
```

2. Ejecuta la aplicación:
```bash
python IP_Scanner.pyw
```

## 🔧 Uso

### Escaneo Básico

1. **Establecer Objetivo**: Ingresa una dirección IP, rango de IP o notación CIDR
   - IP única: `192.168.1.1`
   - Rango de IP: `192.168.1.1-10`
   - CIDR: `192.168.1.0/24`

2. **Seleccionar Puertos**: 
   - Elige de los puertos TCP comunes
   - Agrega puertos TCP personalizados: `80,443,8080` o `1000-2000`
   - Agrega puertos UDP: `53,67,68`

3. **Iniciar Escaneo**: Haz clic en "Iniciar Escaneo" para comenzar

### Opciones Avanzadas

- **Hilos**: Número de hilos concurrentes (1-50)
- **Retraso**: Retraso entre escaneos en milisegundos
- **Tiempo de espera**: Tiempo de espera de conexión en segundos
- **Configuración de Proxy**: Configurar proxy HTTP/HTTPS/SOCKS
- **Servidor de Salto**: Configurar servidor de salto SSH/Telnet

### Pestaña de Configuración

Accede a configuraciones adicionales:
- Selección de idioma
- Guardar/Cargar configuraciones de escaneo
- Opciones avanzadas de red

## 🛠️ Opciones de Configuración

### Configuración de Proxy
- Tipo: HTTP, HTTPS, SOCKS4, SOCKS5
- Soporte de autenticación
- Configuración de host y puerto

### Configuración de Servidor de Salto
- Soporte SSH o Telnet
- Autenticación con usuario/contraseña
- Configuración de puerto personalizado

## 📊 Formatos de Salida

### Exportación CSV
Exporta resultados del escaneo con columnas:
- Dirección IP
- Puerto
- Protocolo
- Estado
- Servicio
- Versión
- Tiempo de Respuesta

### Exportación HTML
Genera un informe HTML con estilo que incluye:
- Información resumida del escaneo
- Resultados codificados por colores
- Diseño de tabla responsive
- Marca de tiempo e información del host

## 🎨 Capturas de Pantalla

<details>
<summary>Haz clic para ver capturas de pantalla</summary>

### Interfaz Principal de Escaneo
![Interfaz Principal](https://github.com/leonelpedroza/IP_Port_Scanner/blob/main/interfaz-principal.png)

### Pestaña de Configuración
![Configuración](https://github.com/leonelpedroza/IP_Port_Scanner/blob/main/configuracion.png)

### Vista de Resultados
![Resultados](https://github.com/leonelpedroza/IP_Port_Scanner/blob/main/resultados.png)

</details>

## ⚠️ Descargo de Responsabilidad

Esta herramienta está destinada únicamente para administración legítima de redes, pruebas de seguridad y propósitos educativos. Los usuarios son responsables de cumplir con las leyes aplicables y obtener la autorización adecuada antes de escanear cualquier red o sistema que no les pertenezca.

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Por favor, siéntete libre de enviar un Pull Request. Para cambios importantes, por favor abre primero un issue para discutir lo que te gustaría cambiar.

1. Haz Fork del Proyecto
2. Crea tu Rama de Característica (`git checkout -b feature/CaracteristicaIncreible`)
3. Confirma tus Cambios (`git commit -m 'Agregar alguna CaracteristicaIncreible'`)
4. Haz Push a la Rama (`git push origin feature/CaracteristicaIncreible`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está licenciado bajo la Licencia MIT - consulta el archivo [LICENSE](LICENSE) para más detalles.

## 👤 Autor

**Leonel Pedroza**
- Sitio web: [leonelpedroza.com](https://www.leonelpedroza.com)
- GitHub: [@leonelpedroza](https://github.com/leonelpedroza)

## 🙏 Agradecimientos

- Construido con la biblioteca tkinter de Python
- Diseño de iconos e interfaz inspirado en herramientas modernas de red
- Gracias a todos los colaboradores y testers

## 📞 Soporte

Si encuentras algún problema o tienes preguntas, por favor:
1. Revisa la página de [Issues](https://github.com/tuusuario/ip-port-network-scanner/issues)
2. Crea un nuevo issue si tu problema no está listado
3. Proporciona información detallada sobre tu entorno y el problema

## 🔄 Historial de Versiones

- **v1.0.0** (Marzo 2024)
  - Lanzamiento inicial
  - Capacidades completas de escaneo TCP/UDP
  - Soporte de proxy y servidor de salto
  - Interfaz multilingüe

---

Hecho con 🧠 por [lgp](https://www.leonelpedroza.com)
