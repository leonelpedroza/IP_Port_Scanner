import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import struct
import threading
import time
import datetime
import csv
import os
import json
import ipaddress
import webbrowser
import subprocess
import platform
import ssl
import queue
from concurrent.futures import ThreadPoolExecutor
import re
import random
import base64

# Diccionario de traducciones
TRANSLATIONS = {
    # Añadir traducciones para los informes HTML
    "en": {
        # Título de la ventana
        "app_title": "Network Scanner",
        
        # Pestañas
        "tab_scan": "Scan",
        "tab_config": "Configuration",
        
        # Configuración básica
        "basic_config": "Basic Configuration",
        "ip_range": "IP/Range:",
        "ip_examples": "Examples: 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24",
        "tcp_ports_additional": "Additional TCP Ports:",
        "tcp_examples": "Examples: 80,443,8080, 1000-2000",
        "udp_ports": "UDP Ports:",
        "udp_examples": "Examples: 53,67,68, 100-200",
        "check_icmp": "Check ICMP (ping)",
        
        # Puertos TCP comunes
        "common_tcp_ports": "Common TCP Ports",
        "select_all": "Select All",
        "deselect_all": "Deselect All",
        
        # Opciones avanzadas
        "advanced_options": "Advanced Options",
        "threads": "Threads:",
        "delay": "Delay (ms):",
        "timeout": "Timeout (s):",
        "use_proxy": "Use Proxy",
        "proxy_type": "Type:",
        "host": "Host:",
        "port": "Port:",
        "auth": "Authentication",
        "username": "Username:",
        "password": "Password:",
        "use_jump": "Use Jump Server",
        
        # Botones de acción
        "start_scan": "Start Scan",
        "stop_scan": "Stop Scan",
        "save_config": "Save Configuration",
        "load_config": "Load Configuration",
        
        # Progreso
        "ready_to_scan": "Ready to scan",
        "progress": "Progress: {0:.1f}%",
        "starting_scan": "Starting scan...",
        "stopping_scan": "Stopping scan...",
        "scan_completed": "Scan completed",
        
        # Resultados
        "results": "Results",
        "ip": "IP",
        "protocol": "Protocol",
        "status": "Status",
        "service": "Service",
        "version": "Version",
        "response_time": "Response Time (ms)",
        "show_all": "Show All",
        "open_only": "Open Ports Only",
        "tcp_only": "TCP Only",
        "udp_only": "UDP Only",
        
        # Menú contextual
        "save_csv": "Save Results as CSV",
        "save_html": "Save Results as HTML",
        "clear_results": "Clear Results",
        
        # Estados de puertos
        "open": "Open",
        "closed": "Closed",
        "filtered": "Filtered",
        "closed_filtered": "Closed/Filtered",
        "possibly_open": "Possibly Open",
        "enabled": "Enabled",
        "disabled": "Disabled",
        "unknown": "Unknown",
        
        # Mensajes
        "no_data": "No data",
        "no_results": "No results to save.",
        "scan_in_progress": "Scan in progress",
        "already_scanning": "A scan is already in progress.",
        "error": "Error",
        "ip_required": "You must specify an IP address or range.",
        "invalid_cidr": "Invalid CIDR format: {0}",
        "invalid_ip_range": "Invalid IP range format: {0}\n{1}",
        "invalid_ip": "Invalid IP address: {0}",
        "invalid_port_range": "Invalid port range format: {0}",
        "invalid_port": "Invalid port: {0}",
        "no_ports_selected": "No ports or protocols selected for scanning.",
        "save_results_question": "Do you want to save the scan results?",
        "saved": "Saved",
        "results_saved": "Results saved to {0}",
        "html_saved": "HTML report saved to {0}",
        "config_saved": "Configuration saved to {0}",
        "loaded": "Loaded",
        "config_loaded": "Configuration loaded from {0}",
        "save_error": "Error saving file: {0}",
        "html_error": "Error saving HTML file: {0}",
        "config_save_error": "Error saving configuration: {0}",
        "config_load_error": "Error loading configuration: {0}",
        
        # Configuración
        "language": "Language:",
        "english": "English",
        "spanish": "Spanish",
        "appearance": "Appearance",
        
        # HTML Report
        "date_time": "Date and Time",
        "computer": "Computer",
        "report_title": "Network Scan Results"
    },
    "es": {
        # Título de la ventana
        "app_title": "Escáner de Red",
        
        # Pestañas
        "tab_scan": "Escaneo",
        "tab_config": "Configuración",
        
        # Configuración básica
        "basic_config": "Configuración Básica",
        "ip_range": "IP/Rango:",
        "ip_examples": "Ejemplos: 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24",
        "tcp_ports_additional": "Puertos TCP adicionales:",
        "tcp_examples": "Ejemplos: 80,443,8080, 1000-2000",
        "udp_ports": "Puertos UDP:",
        "udp_examples": "Ejemplos: 53,67,68, 100-200",
        "check_icmp": "Verificar ICMP (ping)",
        
        # Puertos TCP comunes
        "common_tcp_ports": "Puertos TCP Comunes",
        "select_all": "Seleccionar Todos",
        "deselect_all": "Deseleccionar Todos",
        
        # Opciones avanzadas
        "advanced_options": "Opciones Avanzadas",
        "threads": "Hilos:",
        "delay": "Delay (ms):",
        "timeout": "Timeout (s):",
        "use_proxy": "Usar Proxy",
        "proxy_type": "Tipo:",
        "host": "Host:",
        "port": "Puerto:",
        "auth": "Autenticación",
        "username": "Usuario:",
        "password": "Contraseña:",
        "use_jump": "Usar Jump Server",
        
        # Botones de acción
        "start_scan": "Iniciar Escaneo",
        "stop_scan": "Detener Escaneo",
        "save_config": "Guardar Configuración",
        "load_config": "Cargar Configuración",
        
        # Progreso
        "ready_to_scan": "Listo para escanear",
        "progress": "Progreso: {0:.1f}%",
        "starting_scan": "Iniciando escaneo...",
        "stopping_scan": "Deteniendo escaneo...",
        "scan_completed": "Escaneo completado",
        
        # Resultados
        "results": "Resultados",
        "ip": "IP",
        "protocol": "Protocolo",
        "status": "Estado",
        "service": "Servicio",
        "version": "Versión",
        "response_time": "Tiempo Resp. (ms)",
        "show_all": "Mostrar Todo",
        "open_only": "Solo Puertos Abiertos",
        "tcp_only": "Solo TCP",
        "udp_only": "Solo UDP",
        
        # Menú contextual
        "save_csv": "Guardar Resultados CSV",
        "save_html": "Guardar Resultados HTML",
        "clear_results": "Limpiar Resultados",
        
        # Estados de puertos
        "open": "Abierto",
        "closed": "Cerrado",
        "filtered": "Filtrado",
        "closed_filtered": "Cerrado/Filtrado",
        "possibly_open": "Posiblemente Abierto",
        "enabled": "Habilitado",
        "disabled": "Deshabilitado",
        "unknown": "Desconocido",
        
        # Mensajes
        "no_data": "Sin datos",
        "no_results": "No hay resultados para guardar.",
        "scan_in_progress": "Escaneo en progreso",
        "already_scanning": "Ya hay un escaneo en progreso.",
        "error": "Error",
        "ip_required": "Debe especificar una dirección IP o rango.",
        "invalid_cidr": "Formato de CIDR inválido: {0}",
        "invalid_ip_range": "Formato de rango IP inválido: {0}\n{1}",
        "invalid_ip": "Dirección IP inválida: {0}",
        "invalid_port_range": "Formato de rango de puertos inválido: {0}",
        "invalid_port": "Puerto inválido: {0}",
        "no_ports_selected": "No hay puertos o protocolos seleccionados para escanear.",
        "save_results_question": "¿Desea guardar los resultados del escaneo?",
        "saved": "Guardado",
        "results_saved": "Resultados guardados en {0}",
        "html_saved": "Informe HTML guardado en {0}",
        "config_saved": "Configuración guardada en {0}",
        "loaded": "Cargado",
        "config_loaded": "Configuración cargada desde {0}",
        "save_error": "Error al guardar el archivo: {0}",
        "html_error": "Error al guardar el archivo HTML: {0}",
        "config_save_error": "Error al guardar la configuración: {0}",
        "config_load_error": "Error al cargar la configuración: {0}",
        
        # Configuración
        "language": "Idioma:",
        "english": "Inglés",
        "spanish": "Español",
        "appearance": "Apariencia",
        
        # HTML Report
        "date_time": "Fecha y Hora",
        "computer": "Equipo",
        "report_title": "Resultados de Escaneo de Red"
    }
}

# Constantes
DEFAULT_THREADS = 10
MIN_THREADS = 1
MAX_THREADS = 50
DEFAULT_DELAY = 100  # milisegundos
MIN_DELAY = 10
MAX_DELAY = 5000
DEFAULT_TIMEOUT = 1.0  # segundos
WEBSITE_URL = "https://leonelpedroza.com"
COMMON_TCP_PORTS = [
    (20, "FTP Data"),
    (21, "FTP Control"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (111, "RPC"),
    (135, "RPC/DCOM"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (5985, "WinRM HTTP"),
    (5986, "WinRM HTTPS"),
    (8080, "HTTP Alternate")
]

# Base de datos de firmas básicas de servicios
SERVICE_SIGNATURES = {
    # FTP
    re.compile(r"220 .* FTP"): {"service": "FTP", "regex_version": re.compile(r"220 .* FTP .*?([\d.]+)")},
    # SSH
    re.compile(r"SSH-[\d.]+\-"): {"service": "SSH", "regex_version": re.compile(r"SSH-([\d.]+)-(.+)")},
    # HTTP
    re.compile(r"HTTP/[\d.]+"): {"service": "HTTP", "regex_version": re.compile(r"HTTP/([\d.]+)")},
    # SMTP
    re.compile(r"220 .* SMTP"): {"service": "SMTP", "regex_version": re.compile(r"220 .* SMTP .*?([\d.]+)")},
    # POP3
    re.compile(r"\+OK"): {"service": "POP3", "regex_version": re.compile(r"\+OK .* (\d[\d.]*)")},
    # IMAP
    re.compile(r"\* OK"): {"service": "IMAP", "regex_version": re.compile(r"\* OK .* (\d[\d.]*)")},
    # MySQL
    re.compile(rb".\x00\x00\x00\xFF"): {"service": "MySQL", "regex_version": re.compile(rb"(\d[\d.]*)")},
    # Microsoft SQL Server
    re.compile(rb"^\x04\x01"): {"service": "MSSQL", "regex_version": re.compile(r"Version:([\d.]+)")},
    # PostgreSQL
    re.compile(rb"SFATAL"): {"service": "PostgreSQL", "regex_version": re.compile(r"PostgreSQL ([\d.]+)")},
    # RDP
    re.compile(rb"\x03\x00\x00\x13"): {"service": "RDP", "regex_version": None},
    # Telnet
    re.compile(r"^\xff[\xfa-\xff]"): {"service": "Telnet", "regex_version": None},
    # DNS
    re.compile(rb"\x00\x00\x81\x80"): {"service": "DNS", "regex_version": None},
    # HTTPS/SSL
    re.compile(rb"^\x16\x03[\x00\x01\x02\x03]"): {"service": "HTTPS/SSL", "regex_version": None},
    # SMB
    re.compile(rb"^\x00\x00\x00\x85"): {"service": "SMB", "regex_version": None},
    # VNC
    re.compile(r"RFB \d{3}\.\d{3}"): {"service": "VNC", "regex_version": re.compile(r"RFB (\d{3}\.\d{3})")},
    # Oracle
    re.compile(rb"^\x00\x00\x00\x00\x00\x00\x00\x00"): {"service": "Oracle DB", "regex_version": None},
}

class ProxyHandler:
    """Clase para manejar diferentes tipos de proxies"""
    
    def __init__(self, proxy_type=None, proxy_host=None, proxy_port=None, username=None, password=None):
        self.proxy_type = proxy_type
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.password = password
        
    def create_connection(self, destination, timeout=10):
        """Crea una conexión a través del proxy configurado"""
        if self.proxy_type is None:
            # Conexión directa si no hay proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(destination)
            return sock
            
        if self.proxy_type.upper() in ['SOCKS4', 'SOCKS5']:
            return self._connect_socks(destination, timeout)
        elif self.proxy_type.upper() in ['HTTP', 'HTTPS']:
            return self._connect_http(destination, timeout)
        else:
            raise ValueError(f"Tipo de proxy no soportado: {self.proxy_type}")
    
    def _connect_socks(self, destination, timeout):
        """Implementación básica de conexión SOCKS4/5"""
        dst_host, dst_port = destination
        
        # Crear socket y conectar al proxy
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((self.proxy_host, self.proxy_port))
        
        dest_addr = socket.inet_aton(dst_host)
        
        if self.proxy_type.upper() == 'SOCKS4':
            # SOCKS4 handshake
            req = struct.pack('!BBH', 4, 1, dst_port) + dest_addr
            if self.username:
                req += self.username.encode() + b'\x00'
            else:
                req += b'\x00'
            
            s.sendall(req)
            resp = s.recv(8)
            
            if resp[1] != 90:  # 90 = request granted
                s.close()
                raise Exception(f"SOCKS4 proxy error: {resp[1]}")
        
        elif self.proxy_type.upper() == 'SOCKS5':
            # SOCKS5 handshake
            # Autenticación
            if self.username and self.password:
                s.sendall(b'\x05\x02\x00\x02')  # Soporta no-auth y user/pass
            else:
                s.sendall(b'\x05\x01\x00')  # Sólo no-auth
            
            resp = s.recv(2)
            if resp[0] != 5:
                s.close()
                raise Exception("Error de protocolo SOCKS5")
                
            auth_method = resp[1]
            
            if auth_method == 2:  # User/password auth
                auth = b'\x01' + bytes([len(self.username)]) + self.username.encode() + \
                       bytes([len(self.password)]) + self.password.encode()
                s.sendall(auth)
                auth_resp = s.recv(2)
                if auth_resp[1] != 0:  # 0 = success
                    s.close()
                    raise Exception("Autenticación SOCKS5 fallida")
            
            elif auth_method != 0:  # Not no-auth
                s.close()
                raise Exception(f"Método de autenticación SOCKS5 no soportado: {auth_method}")
            
            # Solicitud de conexión
            s.sendall(b'\x05\x01\x00\x01' + dest_addr + struct.pack('>H', dst_port))
            resp = s.recv(10)  # Respuesta mínima: VER, REP, RSV, ATYP, BND.ADDR (4 bytes), BND.PORT (2 bytes)
            
            if resp[1] != 0:  # 0 = success
                s.close()
                raise Exception(f"Error de conexión SOCKS5: {resp[1]}")
        
        return s
        
    def _connect_http(self, destination, timeout):
        """Conexión a través de proxy HTTP/HTTPS"""
        dst_host, dst_port = destination
        
        # Crear socket y conectar al proxy
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((self.proxy_host, self.proxy_port))
        
        # Para HTTPS, establecer túnel con CONNECT
        if self.proxy_type.upper() == 'HTTPS':
            s = ssl.wrap_socket(s)
            
        # Comando CONNECT para HTTP/HTTPS
        connect_str = f"CONNECT {dst_host}:{dst_port} HTTP/1.1\r\n"
        connect_str += f"Host: {dst_host}:{dst_port}\r\n"
        
        # Autenticación básica si se proporcionan credenciales
        if self.username and self.password:
            auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            connect_str += f"Proxy-Authorization: Basic {auth}\r\n"
            
        connect_str += "\r\n"
        
        s.sendall(connect_str.encode())
        
        # Leer respuesta
        response = b""
        while b"\r\n\r\n" not in response:
            response += s.recv(1024)
            
        # Verificar código de estado
        status_line = response.split(b"\r\n")[0].decode()
        if "200" not in status_line:  # 200 OK esperado
            s.close()
            raise Exception(f"Error de proxy HTTP: {status_line}")
            
        return s

class SSHJumpServer:
    """Clase básica para manejar conexiones a través de un servidor de salto SSH"""
    
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        
    def create_connection(self, destination, timeout=10):
        """
        Simulación de conexión a través de SSH Jump Server.
        En un escenario real, esto utilizaría paramiko (biblioteca externa)
        para establecer un túnel SSH, pero aquí creamos una implementación básica.
        """
        # Aquí conectaríamos al SSH Jump Server y crearíamos un túnel
        # Como estamos limitados a bibliotecas nativas, hacemos una simulación
        
        dst_host, dst_port = destination
        
        # Creamos un socket normal - en implementación real sería un túnel SSH
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        try:
            # Simulamos la conexión directa - en la vida real esto sería
            # una conexión a través del túnel SSH
            s.connect(destination)
            return s
        except Exception as e:
            s.close()
            raise Exception(f"Error en conexión a través de SSH Jump Server: {str(e)}")

class TelnetJumpServer:
    """Clase básica para manejar conexiones a través de un servidor de salto Telnet"""
    
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        
    def create_connection(self, destination, timeout=10):
        """
        Simulación de conexión a través de Telnet Jump Server.
        En un escenario real, esto utilizaría telnetlib para establecer
        una conexión Telnet y luego enviar comandos para conectarse al destino.
        """
        # Simulamos la conexión
        dst_host, dst_port = destination
        
        # Creamos un socket normal
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        try:
            # Simulamos la conexión directa - en la vida real esto requeriría
            # establecer una sesión Telnet, autenticarse y enviar comandos
            s.connect(destination)
            return s
        except Exception as e:
            s.close()
            raise Exception(f"Error en conexión a través de Telnet Jump Server: {str(e)}")

class NetworkScanner:
    """Clase principal para el escaneo de red"""
    
    def __init__(self, parent_ui):
        self.parent_ui = parent_ui
        self.stop_scan = False
        self.scan_results = []
        self.total_tasks = 0
        self.completed_tasks = 0
        self.scan_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
    def ip_range_to_list(self, ip_range):
        """Convierte un rango de IPs en una lista de direcciones IP"""
        ip_list = []
        
        # Verificar si es un rango CIDR (ej. 192.168.1.0/24)
        if '/' in ip_range:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                for ip in network.hosts():
                    ip_list.append(str(ip))
            except ValueError:
                messagebox.showerror("Error", f"Formato de CIDR inválido: {ip_range}")
                return []
                
        # Verificar si es un rango con guión (ej. 192.168.1.1-192.168.1.254)
        elif '-' in ip_range:
            try:
                start_ip, end_ip = ip_range.split('-')
                start_ip = start_ip.strip()
                end_ip = end_ip.strip()
                
                # Si el end_ip es solo el último octeto
                if '.' not in end_ip:
                    prefix = start_ip.rsplit('.', 1)[0]
                    end_ip = f"{prefix}.{end_ip}"
                
                start_ip_int = struct.unpack('!I', socket.inet_aton(start_ip))[0]
                end_ip_int = struct.unpack('!I', socket.inet_aton(end_ip))[0]
                
                for ip_int in range(start_ip_int, end_ip_int + 1):
                    ip = socket.inet_ntoa(struct.pack('!I', ip_int))
                    ip_list.append(ip)
            except Exception as e:
                messagebox.showerror("Error", f"Formato de rango IP inválido: {ip_range}\n{str(e)}")
                return []
                
        # Si es una sola IP
        else:
            try:
                socket.inet_aton(ip_range)  # Validar IP
                ip_list.append(ip_range)
            except socket.error:
                messagebox.showerror("Error", f"Dirección IP inválida: {ip_range}")
                return []
                
        return ip_list
        
    def parse_port_range(self, port_range):
        """Convierte un string de rango de puertos en una lista de puertos"""
        ports = []
        
        if not port_range:
            return ports
            
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    messagebox.showerror("Error", f"Formato de rango de puertos inválido: {part}")
                    return []
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    messagebox.showerror("Error", f"Puerto inválido: {part}")
                    return []
                    
        # Eliminar duplicados y ordenar
        return sorted(list(set(ports)))
        
    def check_icmp(self, ip, timeout=1):
        """Verifica si ICMP está habilitado en el host mediante ping"""
        try:
            # Parámetros según sistema operativo
            if platform.system().lower() == 'windows':
                command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip]
            else:  # Linux/MacOS
                command = ['ping', '-c', '1', '-W', str(int(timeout)), ip]
            
            # Ejecutar el comando ping y capturar la salida
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Verificar si el ping fue exitoso
            if result.returncode == 0:
                return True
            return False
                
        except Exception as e:
            print(f"Error al verificar ICMP para {ip}: {str(e)}")
            return False
    
    def scan_tcp_port(self, ip, port, timeout=1, connection_handler=None):
        """Escanea un puerto TCP específico"""
        start_time = time.time()
        result = {
            'ip': ip,
            'port': port,
            'protocol': 'TCP',
            'status': 'Cerrado',
            'service': 'Desconocido',
            'version': 'Desconocido',
            'response_time': 0
        }
        
        try:
            # Crear conexión (directa o a través de proxy/jump server)
            if connection_handler:
                s = connection_handler.create_connection((ip, port), timeout)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
            
            result['status'] = 'Abierto'
            
            # Intentar detectar servicio enviando varios tipos de sondas
            # Primero asignar el servicio básico basado en el puerto conocido
            for common_port, service_name in COMMON_TCP_PORTS:
                if port == common_port:
                    result['service'] = service_name
                    break
            
            # Ahora intentamos detectar el servicio y versión exactos
            # enviando diferentes sondas y analizando respuestas
            service_detected = False
            
            # Lista de sondas a probar
            probes = [
                b'',  # Algunos servicios responden sin enviar nada
                b'HEAD / HTTP/1.0\r\n\r\n',  # HTTP
                b'GET / HTTP/1.0\r\n\r\n',   # HTTP alternativo
                b'SSH-2.0-NetworkScanner\r\n',  # SSH
                b'HELO networkscanner.local\r\n',  # SMTP
                b'USER anonymous\r\n',  # FTP
                b'STAT\r\n',  # FTP alternativo
                b'\x16\x03\x01\x00\x01\x01',  # SSL
                b'\x00\x00',  # Algunos servicios binarios
                b'?',  # Sonda genérica
                b'HELP\r\n',  # Comando genérico
                b'QUIT\r\n',  # Comando genérico
            ]
            
            for probe in probes:
                if service_detected:
                    break
                    
                try:
                    # Si ya tenemos una conexión abierta y hemos enviado datos, creamos una nueva
                    if probe != probes[0]:
                        s.close()
                        if connection_handler:
                            s = connection_handler.create_connection((ip, port), timeout)
                        else:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(timeout)
                            s.connect((ip, port))
                    
                    if probe:
                        s.sendall(probe)
                    
                    # Recibir respuesta
                    response = s.recv(1024)
                    
                    # Comprobar firmas
                    if response:
                        # Intentar decodificar si es posible
                        try:
                            resp_str = response.decode('utf-8', errors='ignore')
                        except:
                            resp_str = ""
                        
                        # Comprobar firmas de texto
                        for pattern, info in SERVICE_SIGNATURES.items():
                            if isinstance(pattern, type(re.compile(''))):
                                # Regex de texto
                                if resp_str and pattern.search(resp_str):
                                    result['service'] = info['service']
                                    service_detected = True
                                    
                                    # Intentar obtener versión
                                    if info['regex_version']:
                                        version_match = info['regex_version'].search(resp_str)
                                        if version_match:
                                            result['version'] = '.'.join(version_match.groups())
                                    break
                            else:
                                # Patrón binario
                                if pattern.search(response):
                                    result['service'] = info['service']
                                    service_detected = True
                                    
                                    # Intentar obtener versión
                                    if info['regex_version']:
                                        binary_version = info['regex_version'].search(response)
                                        if binary_version:
                                            result['version'] = binary_version.group(1).decode('utf-8', errors='ignore')
                                    break
                
                except (socket.timeout, ConnectionResetError):
                    # El servicio no responde a esta sonda, continuamos con la siguiente
                    pass
                except Exception as e:
                    print(f"Error detectando servicio {ip}:{port}: {str(e)}")
            
            # Cerrar socket
            s.close()
            
        except socket.timeout:
            # Timeout could mean filtered by firewall
            result['status'] = 'Filtrado'
        except ConnectionRefusedError:
            # Port explicitly refused connection
            result['status'] = 'Cerrado'
        except socket.error as e:
            if hasattr(e, 'errno') and e.errno == 10049:
                # Host is not reachable - network configuration issue
                result['status'] = 'No alcanzable'
                # Just log this once per IP, not for every port
                if port == 20:  # Only log for first port to avoid flooding
                    print(f"Error de red: IP {ip} no alcanzable (verifique su configuración de red)")
            else:
                # For other socket errors, mark as closed
                result['status'] = 'Cerrado'
                print(f"Error escaneando TCP {ip}:{port}: {str(e)}")
        except Exception as e:
            print(f"Error escaneando TCP {ip}:{port}: {str(e)}")
            
        # Calcular tiempo de respuesta
        result['response_time'] = round((time.time() - start_time) * 1000, 2)  # ms
        
        return result
    
    def scan_udp_port(self, ip, port, timeout=1, connection_handler=None):
        """Escanea un puerto UDP específico"""
        start_time = time.time()
        result = {
            'ip': ip,
            'port': port,
            'protocol': 'UDP',
            'status': 'Cerrado/Filtrado',
            'service': 'Desconocido',
            'version': 'Desconocido',
            'response_time': 0
        }
        
        try:
            # Crear socket UDP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            
            # No podemos usar connection_handler para UDP directamente
            # En una implementación real, se podría usar un túnel para UDP
            
            # Diccionario de sondas UDP comunes para diferentes servicios
            udp_probes = {
                53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01',  # DNS
                123: b'\x1b' + 47 * b'\0',  # NTP
                161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00',  # SNMP
                137: b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01',  # NetBIOS
                1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP
                5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',  # mDNS
            }
            
            # Enviar sonda específica si existe, o sonda genérica
            if port in udp_probes:
                s.sendto(udp_probes[port], (ip, port))
            else:
                # Enviar datos aleatorios como sonda genérica
                s.sendto(bytes([random.randint(0, 255) for _ in range(8)]), (ip, port))
            
            # Intentar recibir respuesta
            try:
                data, _ = s.recvfrom(1024)
                # Si llegamos aquí, el puerto está abierto
                result['status'] = 'Abierto'
                
                # Intentar identificar el servicio basado en la respuesta
                if port == 53 and len(data) > 2:
                    result['service'] = 'DNS'
                elif port == 123 and len(data) >= 4:
                    result['service'] = 'NTP'
                elif port == 161 and len(data) > 10:
                    result['service'] = 'SNMP'
                    if b'public' in data:
                        result['version'] = 'v1/v2c'
                elif port == 137 and len(data) > 50:
                    result['service'] = 'NetBIOS'
                elif port == 1900 and b'HTTP' in data:
                    result['service'] = 'SSDP/UPnP'
                elif port == 5353 and len(data) > 12:
                    result['service'] = 'mDNS'
                    
            except socket.timeout:
                # No respuesta puede significar cerrado o filtrado
                pass
                
            # También verificamos con un socket ICMP para detectar mensajes ICMP port unreachable
            # Esto requeriría privilegios de administrador en sistemas reales
            # Aquí simplemente asumimos que si no hay respuesta, podría estar abierto
            result['status'] = 'Posiblemente Abierto'
            
        except Exception as e:
            print(f"Error escaneando UDP {ip}:{port}: {str(e)}")
            
        # Cerrar socket
        s.close()
        
        # Calcular tiempo de respuesta
        result['response_time'] = round((time.time() - start_time) * 1000, 2)  # ms
        
        return result
    
    def scan_worker(self):
        """Función trabajadora para el escaneo paralelo"""
        while not self.scan_queue.empty() and not self.stop_scan:
            try:
                task = self.scan_queue.get(block=False)
                
                # Aplicar delay aleatorio dentro del rango configurado
                min_delay = self.parent_ui.delay_var.get() * 0.8
                max_delay = self.parent_ui.delay_var.get() * 1.2
                delay = random.uniform(min_delay, max_delay) / 1000.0  # convertir a segundos
                time.sleep(delay)
                
                # Crear manejador de conexión si se usa proxy o jump server
                connection_handler = None
                
                if self.parent_ui.use_proxy_var.get():
                    proxy_type = self.parent_ui.proxy_type_var.get()
                    proxy_host = self.parent_ui.proxy_host_var.get()
                    proxy_port = int(self.parent_ui.proxy_port_var.get()) if self.parent_ui.proxy_port_var.get() else 8080
                    username = self.parent_ui.proxy_username_var.get() if self.parent_ui.proxy_auth_var.get() else None
                    password = self.parent_ui.proxy_password_var.get() if self.parent_ui.proxy_auth_var.get() else None
                    
                    connection_handler = ProxyHandler(
                        proxy_type=proxy_type,
                        proxy_host=proxy_host,
                        proxy_port=proxy_port,
                        username=username,
                        password=password
                    )
                    
                elif self.parent_ui.use_jump_var.get():
                    jump_type = self.parent_ui.jump_type_var.get()
                    jump_host = self.parent_ui.jump_host_var.get()
                    jump_port = int(self.parent_ui.jump_port_var.get()) if self.parent_ui.jump_port_var.get() else 22
                    username = self.parent_ui.jump_username_var.get()
                    password = self.parent_ui.jump_password_var.get()
                    
                    if jump_type == "SSH":
                        connection_handler = SSHJumpServer(
                            host=jump_host,
                            port=jump_port,
                            username=username,
                            password=password
                        )
                    else:  # Telnet
                        connection_handler = TelnetJumpServer(
                            host=jump_host,
                            port=jump_port,
                            username=username,
                            password=password
                        )
                
                ip, port, protocol = task
                timeout = self.parent_ui.timeout_var.get()
                
                # Escanear según protocolo
                if protocol == 'TCP':
                    result = self.scan_tcp_port(ip, port, timeout, connection_handler)
                else:  # UDP
                    result = self.scan_udp_port(ip, port, timeout, connection_handler)
                    
                # Agregar resultado
                self.result_queue.put(result)
                
                # Actualizar progreso
                self.completed_tasks += 1
                progress = (self.completed_tasks / self.total_tasks) * 100
                
                # Actualizar UI desde el hilo principal
                self.parent_ui.root.after(
                    0, 
                    self.parent_ui.update_progress, 
                    progress
                )
                
                # Actualizar resultados en tiempo real
                self.parent_ui.root.after(
                    0,
                    self.parent_ui.update_results_table,
                    result
                )
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error en worker: {str(e)}")
                self.completed_tasks += 1
                
            finally:
                if not self.scan_queue.empty():
                    self.scan_queue.task_done()
    
    def start_scan(self, ip_range, tcp_ports, udp_ports, scan_icmp, num_threads):
        """Inicia el escaneo con los parámetros especificados"""
        self.stop_scan = False
        self.scan_results = []
        self.total_tasks = 0
        self.completed_tasks = 0
        
        # Convertir rango IP a lista
        ip_list = self.ip_range_to_list(ip_range)
        if not ip_list:
            return False
            
        # Verificar que hay puertos para escanear
        if not tcp_ports and not udp_ports and not scan_icmp:
            messagebox.showerror("Error", "No hay puertos o protocolos seleccionados para escanear.")
            return False
            
        # Calcular tareas totales
        self.total_tasks = (len(ip_list) * (len(tcp_ports) + len(udp_ports)))
        if scan_icmp:
            self.total_tasks += len(ip_list)
            
        # Añadir tareas a la cola
        for ip in ip_list:
            # Escaneo TCP
            for port in tcp_ports:
                self.scan_queue.put((ip, port, 'TCP'))
                
            # Escaneo UDP
            for port in udp_ports:
                self.scan_queue.put((ip, port, 'UDP'))
                
            # Escaneo ICMP
            if scan_icmp:
                # Ejecutar ICMP directamente (no a través de workers)
                icmp_result = self.check_icmp(ip, timeout=self.parent_ui.timeout_var.get())
                result = {
                    'ip': ip,
                    'port': 'ICMP',
                    'protocol': 'ICMP',
                    'status': 'Habilitado' if icmp_result else 'Deshabilitado',
                    'service': 'Echo',
                    'version': 'N/A',
                    'response_time': 0  # No medimos tiempo para ICMP
                }
                self.scan_results.append(result)
                self.completed_tasks += 1
                
                # Actualizar UI desde el hilo principal
                self.parent_ui.root.after(
                    0, 
                    self.parent_ui.update_results_table, 
                    result
                )
        
        # Iniciar workers
        workers = []
        for _ in range(min(num_threads, self.total_tasks)):
            worker = threading.Thread(target=self.scan_worker)
            worker.daemon = True
            worker.start()
            workers.append(worker)
            
        # Iniciar thread para monitorear la finalización del escaneo
        monitor_thread = threading.Thread(
            target=self.monitor_scan_completion,
            args=(workers,)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return True
        
    def monitor_scan_completion(self, workers):
        """Monitorea la finalización del escaneo"""
        # Esperar a que terminen todos los workers
        for worker in workers:
            worker.join()
            
        # Procesar resultados finales de la cola
        while not self.result_queue.empty():
            try:
                result = self.result_queue.get(block=False)
                self.scan_results.append(result)
            except queue.Empty:
                break
                
        # Notificar a la UI que el escaneo ha terminado
        self.parent_ui.root.after(0, self.parent_ui.scan_completed)
            
    def stop_current_scan(self):
        """Detiene el escaneo actual"""
        self.stop_scan = True
        
    def get_results(self):
        """Devuelve los resultados del escaneo"""
        return self.scan_results

class NetworkScannerUI:
    """Clase para la interfaz de usuario del escáner de red"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("IP Port Network Scanner")  # Título inicial en inglés
        self.root.geometry("1000x800")
        self.root.minsize(900, 700)
        
        # Variable para el idioma
        self.language_var = tk.StringVar(value="en")  # Inglés por defecto
        
        # Crear objeto escáner
        self.scanner = NetworkScanner(self)
        
        # Variables para configuración
        self.ip_range_var = tk.StringVar(value="192.168.1.1")
        self.custom_tcp_ports_var = tk.StringVar()
        self.custom_udp_ports_var = tk.StringVar()
        self.scan_icmp_var = tk.BooleanVar(value=True)
        self.threads_var = tk.IntVar(value=DEFAULT_THREADS)
        self.delay_var = tk.IntVar(value=DEFAULT_DELAY)
        self.timeout_var = tk.DoubleVar(value=DEFAULT_TIMEOUT)
        
        # Variables para proxy
        self.use_proxy_var = tk.BooleanVar(value=False)
        self.proxy_type_var = tk.StringVar(value="HTTP")
        self.proxy_host_var = tk.StringVar()
        self.proxy_port_var = tk.StringVar(value="8080")
        self.proxy_auth_var = tk.BooleanVar(value=False)
        self.proxy_username_var = tk.StringVar()
        self.proxy_password_var = tk.StringVar()
        
        # Variables para jump server
        self.use_jump_var = tk.BooleanVar(value=False)
        self.jump_type_var = tk.StringVar(value="SSH")
        self.jump_host_var = tk.StringVar()
        self.jump_port_var = tk.StringVar(value="22")
        self.jump_username_var = tk.StringVar()
        self.jump_password_var = tk.StringVar()
        
        # Variables para puertos TCP comunes
        self.tcp_port_vars = {}
        for port, name in COMMON_TCP_PORTS:
            self.tcp_port_vars[port] = tk.BooleanVar(value=True)
            
        # Variables para filtrado de resultados
        self.show_all_var = tk.BooleanVar(value=True)
        self.show_open_only_var = tk.BooleanVar(value=False)
        self.show_tcp_only_var = tk.BooleanVar(value=False)
        self.show_udp_only_var = tk.BooleanVar(value=False)
        
        # Flag para evitar recursión en los filtros
        self._updating_filters = False
        
        # Variable para seguimiento del escaneo
        self.scanning = False
        
        # Inicializar variables para frames de proxy y jump server
        self.proxy_frame = None
        self.proxy_auth_frame = None
        self.jump_frame = None
        
        # Configuración de estilo
        self._setup_styles()
        
        # Crear interfaz
        self._create_ui()
        
        # Cargar configuración guardada
        #self._load_config()
        
    def _setup_styles(self):
        """Configura los estilos para la interfaz"""
        style = ttk.Style()
        
        # Intentar usar un tema más moderno si está disponible
        try:
            style.theme_use("clam")  # Windows: 'vista', macOS: 'aqua', Linux: 'clam'
        except tk.TclError:
            pass
            
        # Estilo para secciones
        style.configure("Section.TFrame", relief="groove", padding=5)
        style.configure("Header.TLabel", font=("Arial", 10, "bold"))
        
        # Estilo para botones
        style.configure("Action.TButton", font=("Arial", 10, "bold"))
        style.configure("Start.TButton", foreground="green")
        style.configure("Stop.TButton", foreground="red")
        
        # Estilo para progreso - MODIFICADO: Cambiado a verde pastel oscuro (#6B8E23 - Olive Drab)
        style.configure("TProgressbar", thickness=20, background='#6B8E23')
        
        # Estilo para tabla de resultados
        style.configure("Treeview", font=("Arial", 9))
        style.configure("Treeview.Heading", font=("Arial", 9, "bold"))
        
    def _create_ui(self):
        """Crea la interfaz de usuario"""
        # Crear menú principal
        self._create_menu()
        
        # Contenedor principal
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook para pestañas
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # ======================= Tab de Escaneo =======================
        scan_tab = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(scan_tab, text=self._get_text("tab_scan"))
        
        # Layout en grid
        scan_tab.columnconfigure(0, weight=1)
        scan_tab.columnconfigure(1, weight=1)
        scan_tab.rowconfigure(3, weight=1)  # Para que la tabla de resultados se expanda
        
        # ===== Sección de Configuración Básica =====
        basic_frame = ttk.LabelFrame(scan_tab, text=self._get_text("basic_config"), padding=5)
        basic_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # IP/Rango
        ttk.Label(basic_frame, text=self._get_text("ip_range")).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(basic_frame, textvariable=self.ip_range_var, width=30).grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        ttk.Label(basic_frame, text=self._get_text("ip_examples")).grid(row=1, column=0, columnspan=2, sticky="w", padx=5)
        
        # Puertos TCP personalizados
        ttk.Label(basic_frame, text=self._get_text("tcp_ports_additional")).grid(row=2, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(basic_frame, textvariable=self.custom_tcp_ports_var, width=30).grid(row=2, column=1, sticky="ew", padx=5, pady=2)
        ttk.Label(basic_frame, text=self._get_text("tcp_examples")).grid(row=3, column=0, columnspan=2, sticky="w", padx=5)
        
        # Puertos UDP
        ttk.Label(basic_frame, text=self._get_text("udp_ports")).grid(row=4, column=0, sticky="w", padx=5, pady=2)
        ttk.Entry(basic_frame, textvariable=self.custom_udp_ports_var, width=30).grid(row=4, column=1, sticky="ew", padx=5, pady=2)
        ttk.Label(basic_frame, text=self._get_text("udp_examples")).grid(row=5, column=0, columnspan=2, sticky="w", padx=5)
        
        # ICMP
        ttk.Checkbutton(basic_frame, text=self._get_text("check_icmp"), variable=self.scan_icmp_var).grid(row=6, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        
        # ===== Sección de Puertos TCP Comunes =====
        tcp_ports_frame = ttk.LabelFrame(scan_tab, text=self._get_text("common_tcp_ports"), padding=5)
        tcp_ports_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # Botones para seleccionar/deseleccionar todos
        select_frame = ttk.Frame(tcp_ports_frame)
        select_frame.pack(fill="x", pady=5)
        
        ttk.Button(select_frame, text=self._get_text("select_all"), 
                   command=lambda: self._toggle_all_tcp_ports(True)).pack(side="left", padx=5)
        ttk.Button(select_frame, text=self._get_text("deselect_all"), 
                   command=lambda: self._toggle_all_tcp_ports(False)).pack(side="left", padx=5)
        
        # Definir el color beige para el fondo
        beige_color = "#DCDAD5"  # Un beige claro estándar

        # Crear marco con scroll para los puertos
        ports_canvas = tk.Canvas(tcp_ports_frame, background=beige_color)
        scrollbar = ttk.Scrollbar(tcp_ports_frame, orient="vertical", command=ports_canvas.yview)

        # Crear estilo personalizado para el frame
        style = ttk.Style()
        style.configure("Beige.TFrame", background=beige_color)
        scrollable_frame = ttk.Frame(ports_canvas, style="Beige.TFrame")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: ports_canvas.configure(scrollregion=ports_canvas.bbox("all"))
        )

        ports_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        ports_canvas.configure(yscrollcommand=scrollbar.set)

        ports_canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Añadir puertos en el frame con scroll
        for i, (port, name) in enumerate(COMMON_TCP_PORTS):
            row, col = divmod(i, 3)
            ttk.Checkbutton(
                scrollable_frame, 
                text=f"{port} ({name})", 
                variable=self.tcp_port_vars[port]
            ).grid(row=row, column=col, sticky="w", padx=5, pady=2)
        
        # ===== Botones de Acción en Tab de Escaneo =====
        button_frame = ttk.Frame(scan_tab)
        button_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        # Botones principales
        self.start_button = ttk.Button(
            button_frame, 
            text=self._get_text("start_scan"), 
            command=self.start_scan,
            style="Start.TButton",
            width=20
        )
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ttk.Button(
            button_frame, 
            text=self._get_text("stop_scan"), 
            command=self.stop_scan,
            style="Stop.TButton",
            width=20,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
        # ===== Barra de Progreso =====
        progress_frame = ttk.Frame(scan_tab)
        progress_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_label = ttk.Label(progress_frame, text=self._get_text("ready_to_scan"))
        self.progress_label.pack(side="top", anchor="w", padx=5)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=self.progress_var, 
            mode="determinate", 
            length=100,
            style="TProgressbar"
        )
        self.progress_bar.pack(fill="x", padx=5, pady=5)
        
        # ===== Tabla de Resultados =====
        results_frame = ttk.LabelFrame(scan_tab, text=self._get_text("results"))
        results_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # Filtro de resultados
        filter_frame = ttk.Frame(results_frame)
        filter_frame.pack(fill="x", padx=5, pady=5)
        
        # Almacenar referencias a los checkbuttons de filtro para poder actualizarlos después
        self.show_all_check = ttk.Checkbutton(
            filter_frame, 
            text=self._get_text("show_all"), 
            variable=self.show_all_var
        )
        self.show_all_check.pack(side="left", padx=5)
        self.show_all_var.trace_add("write", lambda name, index, mode: self._handle_filter_change("all"))
        
        self.show_open_only_check = ttk.Checkbutton(
            filter_frame, 
            text=self._get_text("open_only"), 
            variable=self.show_open_only_var
        )
        self.show_open_only_check.pack(side="left", padx=5)
        self.show_open_only_var.trace_add("write", lambda name, index, mode: self._handle_filter_change("open"))
        
        self.show_tcp_only_check = ttk.Checkbutton(
            filter_frame, 
            text=self._get_text("tcp_only"), 
            variable=self.show_tcp_only_var
        )
        self.show_tcp_only_check.pack(side="left", padx=5)
        self.show_tcp_only_var.trace_add("write", lambda name, index, mode: self._handle_filter_change("tcp"))
        
        self.show_udp_only_check = ttk.Checkbutton(
            filter_frame, 
            text=self._get_text("udp_only"), 
            variable=self.show_udp_only_var
        )
        self.show_udp_only_check.pack(side="left", padx=5) 
        self.show_udp_only_var.trace_add("write", lambda name, index, mode: self._handle_filter_change("udp"))
        
        # Crear tabla con scrollbar
        table_frame = ttk.Frame(results_frame)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame)
        y_scrollbar.pack(side="right", fill="y")
        
        x_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal")
        x_scrollbar.pack(side="bottom", fill="x")
        
        # Tabla
        columns = ("ip", "port", "protocol", "status", "service", "version", "response_time")
        self.results_table = ttk.Treeview(
            table_frame, 
            columns=columns, 
            show="headings",
            yscrollcommand=y_scrollbar.set,
            xscrollcommand=x_scrollbar.set
        )
        
        # Configurar scrollbars
        y_scrollbar.config(command=self.results_table.yview)
        x_scrollbar.config(command=self.results_table.xview)
        
        # Configurar encabezados
        self.results_table.heading("ip", text=self._get_text("ip"))
        self.results_table.heading("port", text=self._get_text("port"))
        self.results_table.heading("protocol", text=self._get_text("protocol"))
        self.results_table.heading("status", text=self._get_text("status"))
        self.results_table.heading("service", text=self._get_text("service"))
        self.results_table.heading("version", text=self._get_text("version"))
        self.results_table.heading("response_time", text=self._get_text("response_time"))
        
        # Configurar anchos de columna
        self.results_table.column("ip", width=120, anchor="w")
        self.results_table.column("port", width=80, anchor="center")
        self.results_table.column("protocol", width=80, anchor="center")
        self.results_table.column("status", width=100, anchor="center")
        self.results_table.column("service", width=120, anchor="w")
        self.results_table.column("version", width=120, anchor="w")
        self.results_table.column("response_time", width=120, anchor="center")
        
        self.results_table.pack(fill="both", expand=True)
        
        # Menu contextual para la tabla
        self.results_menu = tk.Menu(self.results_table, tearoff=0)
        self.results_menu.add_command(label=self._get_text("save_csv"), command=self._save_results_csv)
        self.results_menu.add_command(label=self._get_text("save_html"), command=self._save_results_html)
        self.results_menu.add_separator()
        self.results_menu.add_command(label=self._get_text("clear_results"), command=self._clear_results)
        
        self.results_table.bind("<Button-3>", self._show_context_menu)
        
        # ======================= Tab de Configuración =======================
        config_tab = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(config_tab, text=self._get_text("tab_config"))
        
        # ===== Sección de Opciones Avanzadas (MOVIDO AL TAB DE CONFIGURACIÓN) =====
        advanced_frame = ttk.LabelFrame(config_tab, text=self._get_text("advanced_options"), padding=5)
        advanced_frame.pack(fill="x", padx=10, pady=10)
        
        # Grid para opciones avanzadas
        advanced_grid = ttk.Frame(advanced_frame)
        advanced_grid.pack(fill="x", padx=5, pady=5)
        
        # Crear 3 columnas para las opciones
        advanced_grid.columnconfigure(0, weight=1)
        advanced_grid.columnconfigure(1, weight=1)
        advanced_grid.columnconfigure(2, weight=1)
        
        # Hilos
        ttk.Label(advanced_grid, text=self._get_text("threads")).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        threads_spinner = ttk.Spinbox(
            advanced_grid, 
            from_=MIN_THREADS, 
            to=MAX_THREADS, 
            textvariable=self.threads_var, 
            width=5
        )
        threads_spinner.grid(row=0, column=0, sticky="e", padx=5, pady=2)
        
        # Delay entre escaneos
        ttk.Label(advanced_grid, text=self._get_text("delay")).grid(row=0, column=1, sticky="w", padx=5, pady=2)
        delay_spinner = ttk.Spinbox(
            advanced_grid, 
            from_=MIN_DELAY, 
            to=MAX_DELAY,
            textvariable=self.delay_var, 
            width=5
        )
        delay_spinner.grid(row=0, column=1, sticky="e", padx=5, pady=2)
        
        # Timeout
        ttk.Label(advanced_grid, text=self._get_text("timeout")).grid(row=0, column=2, sticky="w", padx=5, pady=2)
        timeout_spinner = ttk.Spinbox(
            advanced_grid, 
            from_=0.1, 
            to=10.0, 
            increment=0.1,
            textvariable=self.timeout_var, 
            width=5
        )
        timeout_spinner.grid(row=0, column=2, sticky="e", padx=5, pady=2)
        
        # Proxy y Jump Server
        proxy_jump_frame = ttk.Frame(advanced_frame)
        proxy_jump_frame.pack(fill="x", padx=5, pady=5)
        
        # Usar Proxy
        proxy_check = ttk.Checkbutton(
            proxy_jump_frame, 
            text=self._get_text("use_proxy"), 
            variable=self.use_proxy_var,
            command=self._toggle_proxy_options
        )
        proxy_check.pack(side="left", padx=20)
        
        # Usar Jump Server
        jump_check = ttk.Checkbutton(
            proxy_jump_frame, 
            text=self._get_text("use_jump"), 
            variable=self.use_jump_var,
            command=self._toggle_jump_options
        )
        jump_check.pack(side="left", padx=20)
        
        # Frames que contienen los detalles del proxy y jump server (inicialmente ocultos)
        
        # Frame para Proxy
        self.proxy_frame = ttk.LabelFrame(advanced_frame, text="Proxy")
        # Inicialmente no se añade al layout
        
        # Frame interno para los controles
        proxy_frame_contents = ttk.Frame(self.proxy_frame)
        proxy_frame_contents.pack(fill="x", padx=5, pady=5)
        
        # Tipo de Proxy
        ttk.Label(proxy_frame_contents, text=self._get_text("proxy_type")).pack(side="left", padx=5)
        proxy_type_combo = ttk.Combobox(
            proxy_frame_contents, 
            textvariable=self.proxy_type_var, 
            values=["HTTP", "HTTPS", "SOCKS4", "SOCKS5"],
            width=10,
            state="readonly"
        )
        proxy_type_combo.pack(side="left", padx=5)
        
        # Host Proxy
        ttk.Label(proxy_frame_contents, text=self._get_text("host")).pack(side="left", padx=5)
        ttk.Entry(proxy_frame_contents, textvariable=self.proxy_host_var, width=20).pack(side="left", padx=5)
        
        # Puerto Proxy
        ttk.Label(proxy_frame_contents, text=self._get_text("port")).pack(side="left", padx=5)
        ttk.Entry(proxy_frame_contents, textvariable=self.proxy_port_var, width=6).pack(side="left", padx=5)
        
        # Autenticación Proxy
        proxy_auth_frame = ttk.Frame(self.proxy_frame)
        proxy_auth_frame.pack(fill="x", padx=5, pady=5)
        
        auth_check = ttk.Checkbutton(
            proxy_auth_frame, 
            text=self._get_text("auth"), 
            variable=self.proxy_auth_var,
            command=self._toggle_proxy_auth
        )
        auth_check.pack(side="left", padx=5)
        
        # Contenido del frame de autenticación
        self.proxy_auth_frame = ttk.Frame(proxy_auth_frame)
        # No lo añadimos al layout inicialmente
        
        ttk.Label(self.proxy_auth_frame, text=self._get_text("username")).pack(side="left", padx=5)
        ttk.Entry(self.proxy_auth_frame, textvariable=self.proxy_username_var, width=10).pack(side="left", padx=5)
        
        ttk.Label(self.proxy_auth_frame, text=self._get_text("password")).pack(side="left", padx=5)
        ttk.Entry(self.proxy_auth_frame, textvariable=self.proxy_password_var, width=10, show="*").pack(side="left", padx=5)
        
        # Frame para Jump Server
        self.jump_frame = ttk.LabelFrame(advanced_frame, text="Jump Server")
        # Inicialmente no se añade al layout
        
        # Frame interno para los controles del jump server
        jump_frame_contents = ttk.Frame(self.jump_frame)
        jump_frame_contents.pack(fill="x", padx=5, pady=5)
        
        # Tipo de Jump Server
        ttk.Label(jump_frame_contents, text=self._get_text("proxy_type")).pack(side="left", padx=5)
        jump_type_combo = ttk.Combobox(
            jump_frame_contents, 
            textvariable=self.jump_type_var, 
            values=["SSH", "Telnet"],
            width=10,
            state="readonly"
        )
        jump_type_combo.pack(side="left", padx=5)
        
        # Host Jump Server
        ttk.Label(jump_frame_contents, text=self._get_text("host")).pack(side="left", padx=5)
        ttk.Entry(jump_frame_contents, textvariable=self.jump_host_var, width=20).pack(side="left", padx=5)
        
        # Puerto Jump Server
        ttk.Label(jump_frame_contents, text=self._get_text("port")).pack(side="left", padx=5)
        ttk.Entry(jump_frame_contents, textvariable=self.jump_port_var, width=6).pack(side="left", padx=5)
        
        # Usuario y contraseña
        jump_auth_frame = ttk.Frame(self.jump_frame)
        jump_auth_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(jump_auth_frame, text=self._get_text("username")).pack(side="left", padx=5)
        ttk.Entry(jump_auth_frame, textvariable=self.jump_username_var, width=10).pack(side="left", padx=5)
        
        ttk.Label(jump_auth_frame, text=self._get_text("password")).pack(side="left", padx=5)
        ttk.Entry(jump_auth_frame, textvariable=self.jump_password_var, width=10, show="*").pack(side="left", padx=5)
        
        # Contenido de la pestaña de configuración
        # Selección de idioma
        lang_frame = ttk.LabelFrame(config_tab, text=self._get_text("language"), padding=10)
        lang_frame.pack(fill="x", padx=10, pady=10)
        
        # Opciones de idioma (radio buttons)
        ttk.Radiobutton(
            lang_frame, 
            text=self._get_text("english"), 
            variable=self.language_var, 
            value="en",
            command=lambda: self._set_language("en")
        ).pack(side="left", padx=20, pady=10)
        
        ttk.Radiobutton(
            lang_frame, 
            text=self._get_text("spanish"), 
            variable=self.language_var, 
            value="es",
            command=lambda: self._set_language("es")
        ).pack(side="left", padx=20, pady=10)
        
        # Botones de configuración (MOVIDOS AL TAB DE CONFIGURACIÓN)
        config_button_frame = ttk.Frame(config_tab)
        config_button_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(
            config_button_frame, 
            text=self._get_text("save_config"), 
            command=self._save_config,
            width=20
        ).pack(side="left", padx=20)
        
        ttk.Button(
            config_button_frame, 
            text=self._get_text("load_config"), 
            command=self._load_config_dialog,
            width=20
        ).pack(side="right", padx=20)
        
        # Evento cuando se cambia de pestaña
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_change)
        
    def _create_menu(self):
        """Crea el menú principal de la aplicación"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Menú Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Configuration", command=self._save_config)
        file_menu.add_command(label="Load Configuration", command=self._load_config_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Save Results as CSV", command=self._save_results_csv)
        file_menu.add_command(label="Save Results as HTML", command=self._save_results_html)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Menú Editar
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Clear Results", command=self._clear_results)
        
        # Menú Ver
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Submenú para filtros
        filter_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Filter Results", menu=filter_menu)
        filter_menu.add_checkbutton(label="Show All", variable=self.show_all_var, 
                                   command=lambda: self._handle_filter_change("all"))
        filter_menu.add_checkbutton(label="Open Ports Only", variable=self.show_open_only_var, 
                                   command=lambda: self._handle_filter_change("open"))
        filter_menu.add_checkbutton(label="TCP Only", variable=self.show_tcp_only_var, 
                                   command=lambda: self._handle_filter_change("tcp"))
        filter_menu.add_checkbutton(label="UDP Only", variable=self.show_udp_only_var, 
                                   command=lambda: self._handle_filter_change("udp"))
        
        # Menú Idioma
        language_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Language", menu=language_menu)
        language_menu.add_radiobutton(label="English", variable=self.language_var, 
                                     value="en", command=lambda: self._set_language("en"))
        language_menu.add_radiobutton(label="Español", variable=self.language_var, 
                                     value="es", command=lambda: self._set_language("es"))
        
        # Menú Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about_dialog)
        
        # Guardar referencias para actualizar textos después
        self.file_menu = file_menu
        self.edit_menu = edit_menu
        self.view_menu = view_menu
        self.filter_menu = filter_menu
        self.language_menu = language_menu
        self.help_menu = help_menu
        
    def _handle_filter_change(self, filter_type):
        """Maneja los cambios en los filtros de resultados"""
        # Evitar recursión infinita
        if self._updating_filters:
            return
            
        self._updating_filters = True
        
        # Establecer estados de los filtros según el que se cambió
        if filter_type == "all" and self.show_all_var.get():
            # Si "Mostrar todo" se activó, desactivar los demás
            self.show_open_only_var.set(False)
            self.show_tcp_only_var.set(False)
            self.show_udp_only_var.set(False)
        elif filter_type != "all":
            # Si se activó algún filtro específico
            if self.show_open_only_var.get() or self.show_tcp_only_var.get() or self.show_udp_only_var.get():
                # Desactivar "Mostrar todo"
                self.show_all_var.set(False)
            else:
                # Si no hay ningún filtro activado, activar "Mostrar todo"
                self.show_all_var.set(True)
        
        # Aplicar los filtros a los resultados
        self._apply_result_filters()
        
        self._updating_filters = False
        
    def _get_text(self, key):
        """Obtiene el texto según el idioma seleccionado"""
        lang = self.language_var.get()
        return TRANSLATIONS[lang].get(key, key)
        
    def _set_language(self, language_code):
        """Cambia el idioma de la interfaz"""
        self.language_var.set(language_code)
        self._update_ui_texts()
        
    def _update_ui_texts(self):
        """Actualiza todos los textos de la interfaz según el idioma seleccionado"""
        # Actualizar título de la ventana
        self.root.title(self._get_text("app_title"))
        
        # Actualizar pestañas
        self.notebook.tab(0, text=self._get_text("tab_scan"))
        self.notebook.tab(1, text=self._get_text("tab_config"))
        
        # Actualizar checkbuttons de filtrado de resultados
        self.show_all_check.config(text=self._get_text("show_all"))
        self.show_open_only_check.config(text=self._get_text("open_only"))
        self.show_tcp_only_check.config(text=self._get_text("tcp_only"))
        self.show_udp_only_check.config(text=self._get_text("udp_only"))
        
        # Actualizar menú
        self._update_menu_texts()
        
        # Actualizar secciones y elementos principales
        # (Estos son los widgets con texto que necesitamos actualizar cuando cambia el idioma)
        
        # Actualizar todos los LabelFrames (buscar por tipo de widget)
        for widget in self.root.winfo_children():
            self._update_widget_text_recursive(widget)
        
        # Actualizar etiqueta de progreso
        if not self.scanning:
            self.progress_label.configure(text=self._get_text("ready_to_scan"))
        
        # Actualizar botones principales
        self.start_button.configure(text=self._get_text("start_scan"))
        self.stop_button.configure(text=self._get_text("stop_scan"))
        
        # Actualizar menú contextual
        self.results_menu.entryconfigure(0, label=self._get_text("save_csv"))
        self.results_menu.entryconfigure(1, label=self._get_text("save_html"))
        self.results_menu.entryconfigure(3, label=self._get_text("clear_results"))
        
        # Actualizar encabezados de la tabla
        self.results_table.heading("ip", text=self._get_text("ip"))
        self.results_table.heading("port", text=self._get_text("port"))
        self.results_table.heading("protocol", text=self._get_text("protocol"))
        self.results_table.heading("status", text=self._get_text("status"))
        self.results_table.heading("service", text=self._get_text("service"))
        self.results_table.heading("version", text=self._get_text("version"))
        self.results_table.heading("response_time", text=self._get_text("response_time"))
        
    def _update_menu_texts(self):
        """Actualiza los textos de los menús"""
        # Menú Archivo
        self.file_menu.entryconfigure(0, label=self._get_text("save_config"))
        self.file_menu.entryconfigure(1, label=self._get_text("load_config"))
        self.file_menu.entryconfigure(3, label=self._get_text("save_csv"))
        self.file_menu.entryconfigure(4, label=self._get_text("save_html"))
        self.file_menu.entryconfigure(6, label="Exit" if self.language_var.get() == "en" else "Salir")
        
        # Menú Editar
        self.edit_menu.entryconfigure(0, label=self._get_text("clear_results"))
        
        # Menú Ver
        self.view_menu.entryconfigure(0, label="Filter Results" if self.language_var.get() == "en" else "Filtrar Resultados")
        self.filter_menu.entryconfigure(0, label=self._get_text("show_all"))
        self.filter_menu.entryconfigure(1, label=self._get_text("open_only"))
        self.filter_menu.entryconfigure(2, label=self._get_text("tcp_only"))
        self.filter_menu.entryconfigure(3, label=self._get_text("udp_only"))
        
        # Menú de idioma
        if self.language_var.get() == "en":
            self.root.config(menu="")  # Eliminar menú actual
            menubar = tk.Menu(self.root)
            self.root.config(menu=menubar)
            
            menubar.add_cascade(label="File", menu=self.file_menu)
            menubar.add_cascade(label="Edit", menu=self.edit_menu)
            menubar.add_cascade(label="View", menu=self.view_menu)
            menubar.add_cascade(label="Language", menu=self.language_menu)
            menubar.add_cascade(label="Help", menu=self.help_menu)
        else:
            self.root.config(menu="")  # Eliminar menú actual
            menubar = tk.Menu(self.root)
            self.root.config(menu=menubar)
            
            menubar.add_cascade(label="Archivo", menu=self.file_menu)
            menubar.add_cascade(label="Editar", menu=self.edit_menu)
            menubar.add_cascade(label="Ver", menu=self.view_menu)
            menubar.add_cascade(label="Idioma", menu=self.language_menu)
            menubar.add_cascade(label="Ayuda", menu=self.help_menu)
        
        # Menú Ayuda
        self.help_menu.entryconfigure(0, label="About" if self.language_var.get() == "en" else "Acerca de")
        
    def _show_about_dialog(self):
        """Muestra el cuadro de diálogo 'Acerca de'"""
        # Create About window
        about_win = tk.Toplevel(self.root)
        
        # Set title based on language
        title = "About IP Network Scanner" if self.language_var.get() == "en" else "Acerca de Escáner de Red"
        about_win.title(title)
        about_win.resizable(False, False)
        
        # Set the same icon as main window
        try:
            icondata = '''
            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
            '''
            icon = tk.PhotoImage(data=icondata)
            about_win.iconphoto(True, icon)
        except Exception as e:
            # If icon fails, just ignore it
            print(f"Icon couldn't be loaded: {e}")
        
        # QR code data for Network Scanner
        qr_base64 = """iVBORw0KGgoAAAANSUhEUgAAAXgAAAF3CAYAAACvy1BzAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAOseSURBVHhe7d0H2G1LUSf8qzPfGMYwKgYMgEMGFQEJImJCZcA0YhrjiI7jiEq45KSAgICigDgGBB0xgSJmhzEAl3vh5kSQLEEykjO4vue3L3XoU7t7rdV77/WGc/b/eeo5cHe/vVJ3dXdV/avOGPbYY4899jglcUb+D3vssccee5wamK3gX/jCFw4XX3zxcOmll55S4pn+5V/+JT/uHnvscUxhPp+quooe7sGkgn/Ri140/P7v//5wzWtec7jSla40fNZnfdYpJZ7pm77pm4ZnPetZw2tf+9r8+BvhAx/4wOpjnH/++cO55547vPrVr85NTim8613vGi644IITz/vmN785N+nCO97xjpP6e8tb3pKbrPC2t71t1SbkrW99a27SBX9f9qf/Gjyf+9LGfb7zne/MTbrwpje96aT+3v3ud+cmK7zhDW+Y1W4uXve6153o78ILLxze+9735iZdKPu76KKLhve97325yQrmQ7QzTz74wQ/mJhuBYjePv/mbv/mU1VX0MH384he/OD9+FaMK/s/+7M+G61//+sOnfuqnDmecccYpLZ/5mZ853Pa2t5394lqg3H/lV35luOpVrzpc+cpXHj77sz97+K//9b+eskqekrn//e8/fN7nfd7wuZ/7ucPnfM7nDD/yIz+yUlqbgHK/173uteor+vuJn/iJNWVLqd71rnddvWPt/PvTP/3TGyt5f/eTP/mTJ/V3t7vdbU15u4//9b/+1+q7xj3e5z73Wd33JvCefviHf3j1nPryHn/mZ35meM973lNtF9fV7qEPfehau7mgjP/bf/tvq/486xd8wRcMD3/4w5tKeQqvfOUrh+/4ju9YPYf+rnKVqwy/9Eu/NHzoQx86qd2rXvWq1XygsLQzT8wX82Yb2IjaqJnHeW6favKf/tN/Wull+vnDH/5wfhUnoang/bFBlDs/1eUbv/Ebh3/+53/Or2MWTLbHPe5xw3/8j/9xrd9v+ZZvWQ3CUwmU3QMf+MDh3//7f7/2vD/6oz/afSL613/91+Ge97zn8O/+3b87qa+P+ZiPGe54xzuulBJQdne/+92Hj/3Yj11rd+c737l7cdH+Tne609ozuI973OMeJ/pzfYuN6+R29773vVf33wM7Tu8pX9f7fNCDHnRiUbM5+MEf/MG1dv/hP/yH4cEPfvDw9re/PXc9ile84hXD93zP96z193Ef93HDIx/5yNWJrAcvf/nLh9vf/vZr/X3yJ3/y8OhHP/rESeOf/umfhm/91m9da2e+UPKbLlauf5vb3Gat31NdLMpPe9rTRpV8VcFT7le72tXWOjxdxGB5yUtekl/LJP7iL/5i+LRP+7S1/kLucIc7DP/2b/+W/+zY4td//deHT/iET1h7TkL52on34LGPfexKyeS+CKX6kIc8ZNXOzrC2qJD/7//7/4af+7mfy12PQnt/l/siruN64PpZuYd8/Md//Or+e2DxyItUiPf6+Mc/ftXuvve979rvZbsnPvGJuetR/NRP/dRaPyGU8u/93u/lP2nCzru2SJX90SfgZJd/D/n0T//0E+164MR9Oir3EHp6TMmfpODf//73D3/6p3+6OgLmjk43MWhe8IIXdCnkP/zDP2xOWGIX39PfUccjHvGItWcs5cd+7Mfyn4zCbjT3UcqZZ565aveABzxg7bdau7nQPvdRiuvNade7sPyP//E/1voo5VGPetSqHZNQ/q2UxzzmMbnrUTDN5D5K+dVf/dX8J03QGUwuuY9SYsH4tm/7trXfQsybnoXFPHr+858//Jf/8l/W+jrdhL7+kz/5k6oP5SQF/7KXvWy4znWus9bB6Srf//3fX76eSRiguY9S2AhPJQX/8z//82vPWIodWw+Ye3IfpdzlLndZtbvf/e639lspzDQ90D73UYrrgevn30phVumBE13uoxTmEvif//N/rv1Wyi//8i/nrkfx3d/93Wt9lMJcMhcUvI1L7qOU3/3d3121Nf7zb7V2c/F93/d9a32crkJv16wOJxQ85wrvrCNV/uPTVW50oxutdglzlfI//uM/Dv/5P//ntX4IOy2n3akEJxae/fyshF3VDr8H/+f//J+miUt/YQJ5whOe0HT8++/8ID3QvtUfh5brgevX/CuEiaFXQVkgP/ETP3GtL+K9PvnJT161o+hbpivOSru3HliwWv3xu/35n/95/pMmOFGZ4vgDcl/k8z//84e/+7u/W7U1/rN/JcS8+fu///vcfRWxezc/cz+nq9DbT3rSk9b8GCcU/POe97zh6le/etPGeDoKu6zjbH5pLQj3+su//Ms1/4Xjp13iphEeRxU2BZRajlxgj37Ywx7W7azT36/92q+tlGrZn8H7i7/4iyecdY6i//t//++1xYDy5dSb+70C2vu7rLwpbX6GOPq6/i/8wi+sbYLcx2/8xm90R6B4P+z63lfZH6Vtstodg0ien/3Zn13zd4hC8f6j3VyI+BH5k/0OjvpPecpTuiNaOHlrTm/zwGIRYZCc0E5Bud0XfuEXrvxXc8MlfS+793z/p7PQ2/T3ZZdddtK7OqHgxa3mibWXK6JqehWVQf3lX/7lw41vfOPhhje84cqplcPtTiVwBn7Zl33Z6nntqpgqepVdgLOI8tZX9GexyOF22lHK0Y5YBOYqiQx/R3mX/bFt59Ob+xCe6L608dwWgdxuLiweTFNlf3FiKEHp8gUYT9Gu98RQwmLFyRv93fSmN12dyDYFJW+HHs9xs5vdbLVYZJgHwlnjure4xS26TgxgPu5t7+tCf+NHlDih4DGl7BzyH/XKl37pl66Umw98mGLgtMwlPSKsaxNCiQlJyW2q6I4b7M4QkkhWxpvArpSMvT9K3vXi2q1Igh643tR1LQZx3d7QyBZirEztxqPNVLs5MEaRtjzLLk6X+osxMNVfPG/vaQHMxynH7hyhH+iJrDsOWujLG9zgBmv31yv0N+JYiZ0oeMeDL/qiLxr++3//76uwpde//vWrGOjDlDe+8Y3D05/+9OHrvu7r1kwmPbKJgqcAHJWciqyorVQIdm/nnXfe8JznPGc455xzhte85jW5yQqOpJh/2p199tnNdnNhF/Xc5z73xHUjvnxpmPSuGddtxau7P++OYFhuq0QpnLguGWPGxnVJb3z5pnA/ntM1TdDWeDOmjSftLrnkkqYpyvf0fj2r77zt6dF4M+70Zxy2rjsX5kM8h3nSe+raVsEzCdEL//f//t/VO82646CFvsSRQWRDYMr3O1cWU/BIEzy4tTCdw4bjHOfNta51rbX7niO9Ct5gFdXAPsqG+ymf8imr6AFMvxJ2m0wCmITacfK5ViZZhemAnTv6wxhsLRpT0B8Tymd8xmecuC4/w6b9zYWxwRnHXu26jpPCBLOypYwc9bWJ+xNuuamy9f2ZBFwvrovUlM1uFp8f//EfP3F//mUv7vn2m4CC+aEf+qET98e5ygmaTxB22qK6fP9oVzOF+Y7mo/cW7YSf9irRAOX+nd/5nSeuaxxuYwozD8wHfgz9sfubLz0nkm0U/LWvfe2V0zd//6MAc4Qe9f2yn2KOLKLgMdisQkcdlPz1rne9tfufkh4Fz3llsH7SJ33SWj/yY4irB8oKeabWTqxwpEvQn0iLWjsDvBYWNQbKlFKoRW4YVBiOS4ASY+/NkRtOfnYtkcZBO7HmmcQk8kKoIJp7D4xLDNjcn//PLxInl2iXAww48dzPUicci7lTb/4WIlLY2yOnj+/yvd/7vWv3xzmrXZxwtKuFQPrelHxeTKdgHNYUqfEorUFOHzEFkS/mQa0/Mf9z0z1squDN/4joOcqwSNvE9Sr5nSt4K/vSO79dgpLnac7PMSY9Cl4kQCvcjpjMwKlUU7Ih4qPhr/7qr0bbIcD02LtFZmRlV4od66bOwjFwQo4NVk5GEK44dn+9cebCC7NSDPHfI358jKFKnKCWgMiTfK0Qi8tv/uZvrtpJg5B/D7FohrN1LE5ff8JQ58K4sujlfkKMy5oTtQXjqraYhTjBzGWybqLgr3GNa8wOwzwKoFe/67u+a3TeZNmZgrdzsOM7Djv3DLHqHMFjE7qUHgU/xWS1O4c/+IM/WPutFIMXxEHn30phWulR8KJTch+lmIBLKHgKMl+rFEnDQLRM/q3Wbi4kQct9lBILhtNF/q2UYLLuGlNMVqYQkP8m/1aK7wpjqQBIDz/AuJoiEv32b/92/rMmmCRreWhCnNLwcOagR8Gb5+b7P/zDP+RujjwoeXN8bJNXys4U/HWve901m/Jxgp1sfqaW9Cj4OUxWmLq+YyxYMPJvpVjhe2yhJnjuoxQ23iUU/FRKAzZxQPXPv5XSy1AV6537KEVsOVg48m+lyAWzBOYyWfkG8m+lhOIe2yGTnlw5xlUtIVkptXDOFij4XTFZexQ86Tm5HDXQs3MdrztR8OyDBlJ27hwniFgQljRnF9+j4J/5zGeu8jXnPohrRfKtZzzjGc3IHu83FIrc1tKu5jaEKYOC6gkNRMKSzjX3RZBo7KCXUPCO8mOM18h94mSTSVO1dnMhCVeL2+G/h0JBUmq142zt2an2wMmmtTvjpP/jP/7jVTv26ey/COGk9F2BvyaTpkJ89554c+PK+GqZzKT5FaU2F8aV8d9isgqCcLqeg7kK3pwzz3Ns+HECPWsj0PqupexEwSNY9Dr3jhocP2Vgqzkvs/QoeJPir//6r1dhWGUflLbIkHByuT77em7HTspcEBEjcZ95MfCx2WV7nVxijilb9PGyP8pdDvKlIgtESFC2eXERmcFZF2F32lG2eTGgfNnL536HgKgEeVVEDJX96d9iEZsU/yI1uZ/cjh18qegw75tSzgxakVVOgxEjLrKIkzSPV2kFtItTnP6YpbIykFbWYtEbc258Sd+cFxfj9qlPfWqXeRCMf/MgM1DFo1uk5m5W5ip472uT+zxqoG9vcpObrD1flp0o+K/4iq/o9sYfRdhtZ8p5TXoUfICS/6qv+qoVOxCzTyRGTUlwKn3lV37lqp2F02SqxRhT8t67dth/dvi9k7UE00+Q0VyXk3Ob/ubCkd5AjevawdZODJRqkEC0C1v0pqDk47r+rdmi3YdFxDuOa0ubsDQoH05ez+navkvNpED5UfLGU5BjnHgyLJJ23vrT7uY3v/lWDFX9MXUF29U47DkJZJgH5oPn0J95YrPTg7kK3vyeeyo4yqBvb3nLW649X5adKHiDZlvnqkGN4MME8exnP7tLmDd2UTjjb/7mb9Z2RDXZRMEDRW1HZfc1tjNB9lGKDdmhtggE3IP+yFh/cxH9ub+akl0CdpqeNWRsUYln3ZakA5tcd6nTTAue0zXHxprvNKedE4nx5FmFnm47Xvx9vJOx686F+R/PUdvQTGGugje/exePGugbeifroimh3+i5bU8Q9K2FOj9flkNX8B5ULKywOcdGR2/H5x6xKn/N13zN8P/+3//bytH7t3/7t4sp+HjOKJRrsm0DuyjJ4LD+MBhbDNDMeG2FsFpILr/88lV/7rF1IisZrwZs67uLX452rkuxbAPv273F/fWaojYF05jrxbW3XVwo12CU+rdF3xfHHtf1XVpKT1y87x/txjYEc2B8zGGoeo64rnHYIiXhM0R/6q227g+vwLzwzLghvQqwR8E7TW8KPAV65mu/9mtXeifroimh3/jQnAS9t97nDBwbBe/oSbG3HEs9It78q7/6q1f3vQmWUvB2h0wK7Kg+Mied4iHKim0C/XF+cj5Gf8ItM+PVro2pxTfUDktQu0wOMjnZadmXo51onLxYemaMymjnusg2ebGiBPkNyv6E121KDqIERcvEJNEfJ1NrEdoVLJoqE5UTVBz4pgxa70kwQrBJ9SfuPY8lc0konHbaaMtUl08Q3qeoFt8h2vmOub+5MC6Mj7iucVNjxiJPUaZxXeOQ3yCfgl760peuor/K/ozbvBioOSFRWPTHL8NUl9uN4SAUvAXNRnKM1zJX+Fgo+t/5nd/Z6DR1LBS8iAVKL/e3rUgWZLfciyUUfDBUawuYQd17n5SdSVLrz32Fszva1XJyY8SZfEBJss9mJxyh5GPR0I5yz84wQhlFO0qRP6AWaYF+nxeXKdj5t0IWKd9tc/C0YDzXqiZFmufexcpOthay6H1S8nECs6j+wA/8wFo779P7j3bed42h6ntT8sF4nQvj5tu//dur/cmUGScN7WpVmIxH4y0WP4zXWox71ASIE1irApP+RArNXUyXVvB223wNub9thf6zye1V8kdewSMwWK1zX7sSHyM/2BSWUPCcpmOOW5O5x94t4qWmjEMoJeBsy5EOpSDUgIiLmjIOiThzi3FNuYfYYYKj51h/vQVOODnH+hPpswScfFoENf9dpE8POCVbIbj6+63f+q1Vu9ZiRrx/pkwYI2JpF7Vb52KsQpRxFKXzxpisxmUwT2uLWdmfSBaoFQ4PEcGkXOgcLKngJUCb49DcVJy8vN8eJX9kFTybnvC4Of1uK6Hk5764JRS8aIVWnG/01aPgrfa5j1KipCCFkX8rxdEeRKfk30qJFAkUS/6tFMxKYIrKv5XSW5N1iujUy2SdCwtRvlYpdsk9GCtqTYJwNMVkjZqsU0zW3pqsTG25j1IiRULtdFFKROfUTgOlzKnJugSTtUfB0xtLK/cQ+lBEWTbDtXBkFTzvs1jd3MdSwhwx15GxhII3QPPfl9Jbk9XimPsohbkExI7n30qRMwimFLcdFkwxXu0Awc42/1bKrmuyBuN115iqyWpH3oMphRw5cKaYrFHycGzHXfY3F8ZD7qOUCA+dWghCIe+qJiuG9xwsoeBFWtEfuY+lhF584QtfmG+jiiOp4H0EO8tcZmxJ+eIv/uJVNMccJbqEghcWJR1p7oMwPSAn9UDmu0yGCnFEtuMFea0zGSrE+4+cK0JDWwuudxHUeKFlmQwVwl4aCkUtUEzK3IY4cscOdC4ojJafhrNrqbh0C2TLhOhIzTnWAzv0lnPOHAvThhNQJleF+E5h2vC+W/PId8KT6IHx0OrPODJOwPhqmQiNS1wSkKun5iciSEyRB8ZCWfMTEfNGKOIcLKHg6Q36I/exlHj/TkpzIrWOpIIXKtWa/EsJ+yZPfivcq8QSCt7CIqxK5rqyD3ZSduu5TqSAYyNlmzNgsmtywsURTzuZLLNSNplM5rh/7dg5c/oDk7iMoNDuj/7oj9a+H6eZCIoIf9POMT0rZYO3NzICnL6cWkRilP1RgshKvf3Nhetitmb/CaXvKD33VBhwn5R3Hl/SD9ilhhlRO7v0rGxFlnj/0c77rjnbfW8J6eaaJQPGA2d7VrYi3Cw+0Z/xRSln/47xbbzFRkp/NeWtnXkW/Rn/5kH272hnkzJnYwa7VvD0hXne8sMsJeaXsNIpHEkFbzXOFOyDEMy4ObatJRR8QI6OW9/61sOtbnWrlW/AoG7FBM+BySQW17OxETJl5HA2sOPTznW1M4lrSpFSEGKqP0xaSrvWn3baxHNoV0tuRmmV/TkJ5DC6uTDJ5X4p+1N7de7k3xSUuEXEs4bY2W963Sj8op94lhpD1Xti6vK9om3YrEvoj5LXTl9C+CJXzSbwvY0P71d/KhzVTgLGLee27+/+XDdy35QwR/gq4jn0Z9xmUKZy0sRzfP3Xf/1Kufdg1wqevvBc+e+XFvpxTpbLI6ngEWNyTpGDEANmjkJeUsGDUDPhhkLYasqzFyY4ZVBT2CWiPqnrjilZvx1Gf3Ox6/7mwE7Ts4b07oxrcP/xLC1YXKI26lR5wjn99UB/pLZwB/w+p3br3HYw57ot7FrB6+8bv/Eb1/5+aaEfmXWncGQVfMuuuaQcFQW/S7g+JmTQn6MC0qbAPHU01N9ZZ50163uOIfeXyVABE1/RBbsW/7auSzkE3Vt/2zJj/X153W37c9/8I/qT66RFwnId9x/PMqX0poB5Guk9vO+W/Rb/IO7PSbplGjSOoj8m1TmmzV0A6S+ui0Hbu4ifKgqeftwr+E451RS83T/yidUe+4892j1l5ulcOHI7Svs2+uMMFD3QS0oKUO7CDKM/9GzRPZkcRBlJMuX3aCd+Oi8GdrBqqGoT96ddL5knQPniC5TXFeUytVNuwX24H98h6reK7snK2/OLSnL/cV3vqaWUp6A/ZKe4rvfND5P7My6ELcZ13R8naD5FUu6UZLTDUGWyWXqsY7Jidsdz8N/wQ/QsLnsFX5e9gi9wHBQ8JcT5mZ1c5Ha3u92JGq9zQTm1GKpilIPxOhdRa7XmnBJiF+kZ7GSFItY4AtIaxGKl3U/+5E9WSUKUam/NWMxXsfi5P/9f6GEvM9b1a2Qd/VmU4mSAeVoLMfT8yur1niAwRdU+zv2JzGLPjsXP96vFmmfGq3FTC23Un/GWF6tdAf3/G77hG9au6/74d+bmHNor+LrsFXyB46DgOTlbYWqE8uqJ8BDuN8YURdDpcSpO1VC1YwdMy9oiEBIl8RB2xvrrZbJSGlm5h/jvfu+B6+d+Qtx3EI7GSgV6D1Fiby68x9xPCOUYBUnGCFbuL+LRxypEGW9LFDjhzxgjTolgirDQKewVfF32Cr7AcVDwU0xWu8QeBS+OPPdRSm9NVtEyuY9SghBF8eXfSplbkzUWjLkYU7Skl6E6pmiJ+4ex4tekN7+9hTz3UcrcmqyR+qB2uqj1t0sYV7XTRYgF6LCYrHsFX8hewR8cppisEoT1KPgphqrUBz2RI3bAuY9SIvWBBGz5t1KYN2AqVUEvk3WqJmsvQ9X1cx+lBPFsbCdNgqE6F1OKW3gnSPCWfyslSh7WEpfV+tsljKspJuuua7LuFfxewa/9fZbDVPCiIDAB8z0RdnkKpUchG+yZvBQiJteOvGcH70jd6s+RW/w6qADUCpnVLnaWkqu1xiCnXLSbCyegsVqrtbj0Mbh+i3mKnOT+wUkpk6ZCODMxgHtggcxkqBBkp2CeOhm0uCeYsSVDtdWf8RbtdgnjSubRmj+JXPe61z3BjJ3CXsHXZa/gCxwHBW93brLl9AcYjSIe5hC6Sog5pmzzoqE/kTo9kQygP8oqM2hDuQe5S8y2jJe5HSXLfFO2o3QzM9Y4ojR7yWLC79j/87jWP4Zqb3ie6zNfZKat/pC9IjZdxIrnz+kKMEUxf3tj2H0Xi29eXKQV8P4jllw73zErb98b6ais3apMYG4n/YB2PafCHoi44uTPfiXKHQN87mZlr+DrslfwBY6Dgg9IV4D1h02oFue2NVQpBQzG6K9WwKEHlHfZn51kbbI6gsvfr51/KffaiYGSx3SM/nqzJWZgpJbXjWyJm4Lydl/6c58104LnwmSNdq47N5lWC75T9IctWjsJ+I58AXPaiZiJdpic29RanQuLn5xMFJZ3gvFNufdgr+DrslfwBY6TggcKg9QU5ybYdX92ZwSpptWn681pB3PbzYG/188S/ZExaBvvelvYWc+57tx2sMv764HrxrV7sVfwddkr+AJLKnhHZR8Oa9LuJCovbQpH6pLJ2iI5Ib1gLrouJmMrbtzk3yWTdY86kLiCyerfFrlKPL7v5bthxi4Vh56B3GY8uTfjqzXO8Rni/oyvqUVjCshOcV1ZHDMJawqnioIX4uq9TuFIKniDIWeXOwhx7Jtjm15KwTv6soOyv7Jxsjc6/iKrbAL9MclwnkV/yp7lGq/sw6JCPFO0u+1tb7um5E0myc/Y3bUjnjG322M7mCMKrcQ7JqJw8tik3DGJo43vIswyt9s1jB9RLcaJ6/KbsI9nPwfylHEU7YxDpp1NTXpqRJgP0R8nuPnSo+R3reC964Mo9FEK0hvzmeLpUziSCl5dQ5nxauzFpYQTCmNyzmBZQsHbobF/ZicSkV0Pk68HmIdIQNkZRtC9o8ar2p1IODWGKsaibwEYlJiPtUgGMcr/9E//lO5gj01gh0q553cs1lsIZaRxsOjXQha1U7t1zjzbBMaDtNr5usaPcRS1YLUzznI741G73vQRlA+be60/Tt+5/e1awdMXuBitiKslRFSZqKE5JqojqeDBcTPnsF5S3NtcGvgSCl6u9bHnRTDpASZrTWmHREk86WXH2ilYDZyB+bdS1OCcM+D2GIdFNL/bUsLJO1VJCm9hCYyVCjSO5jBetYuSfXPA3i4tRe4nxLypOYNr2LWCB+a0OUp0V+LemKfm4MgqeDk5RFfkPpYQJwW7nrnpR5dQ8Io0jFHt7ZJ7MMVkRf2GqZqssbBM1WT94R/+4b2C3wEQt/K7LSWIRFMMVUVTlsCYoiWxANXy7pTSk9KAgh9TyuaNaKw5WELB0xv0x9hGaZcicmluLqkjq+CBWWJp+xblLmPg3GRFsISCt5POf1+KY3GPAjWBch+lRE3WqVqrbLxz2mGy9tzfHnUYi/ndlhIlDy2o+bdSenPlzAUGdL5WKZGqYCqlAS7BXFDwNbNQKbVw0xqWUPBAf8g0urSSt+lV4HsujrSCB7Zi8ba5r12I5E2cV72e/SUUvEiEVl1HOxTkpB4FKmLhWte61lpfhN0yKO8Yr612jr4qBgGP/VWvetW1NoT/AmOy5/72qAMpC4krv2OC+YvXAGO1W32nqN26a1g4an4dYhxFZIdx0zI5It/NqUYUMK5qZQJDzBvRRnOwlIIHeoQ+Wcp3KAhkjmO1xJFX8HDZZZftfCfvI1hxc07sOVhCwYNBf53rXOekPkwmztLeRcikUM4sM1nd94Mf/OCT7gvjNRfo1s5kDoaq/iiXWjvO4TnO6T2mgSGLnJUZr5is/CrBFA3Ga2aoYvyyRy+12Bo3vndOa2BcxOIT7SKCq2xnfJs/vfdn/NcKdOtP1N1cLKngwX0usZMXNdMbaAHHQsGDh5PX+ou+6IvW+u0RuwCLhXC/TZQ7LKXgwc5bCJqIAZFEIg7m+gZqEEsvNFKMv5qrJmeNrGNyCmnTTtQO5V5rh7Eo7ldubu1azNM9tgMnqe8V34Nyz6AkKXm/+x6+yza1VufC9zaOXNf9GTc1ZRjt4jmMwzmx2y0IrzQfhErqj9lGMEYPllbwQMlzlrOVt04dc8XphJl0E+UOx0bBg92kMl3C92Jw9YiBoTKOaJlNY3FhSQUPBgibHtJKb86TGuz6LBJTC0W0mdtum3e4xzh8M9/fOCBjO17fYc532zV6x8uu8tTE827S30EoeHCP9AznayxIPUK/CawQLZP5BT04Vgo+4IERDHysHvE3U4NxDtSgzEfjmmyq4OfAImA3ZLFhYmkxXj0z1p+Tgd1Oi8mqHTvmVDvKBpNQHK52rcpGlNPTn/701f2ZKC0ylLJ40c5ztMr/qQDl92jXuq44bKapaLdtDdq5EJ/umiG5nOBSMJ98B9/Nd2nVUEVO8h3cm/e9LeNVlFtc17hpkavKdsbhtvMBeSrqxfJb9ZoGD0rBB+ibTXXVNoo9YDww7+Tny7ITBc8D3GtLPmpASJKdr0ZIyrKUgo/aqMgVWIQGoxU/h0458WjHGacdeyjyCUZgCaYq5fNyu1yGz6BTuMLiFtd1TM6Li0UA+SPa6c9uJC8alIz4+bI/k6/Wjl3T79EOGSgvBhYBcdralO2WVrYKWosaiesS+eyD9LMUKE/vNd6L96hsYVbe2hmLvkO0c5LtiRwr4XsbH9GfcVMzeRpnuR07em/m0YDxzWwZ/XFGY8a2Fpca5ip470hKjuOMyCib/Xo12YmC52W3u9rkaHVUYFU3uPKz1WQJBW/Hy3lVY5Sy23NIg4WIcq/ZANlrg6GKAahdrSwe22q0o6wcN2ux+pR8pFPQDl2+Vu7O+4h2lG6LrPOd3/mdJxYX7YQO1vrD5Iy0C3bQqkDlNqSs8bprWGRaxTLEqi91gqBk2WbzNYn3H4saJVuroep9WoTnkvsCxgNbeu7P+Clrt4r2aNVQ1c447sEFF1ywUu65P85MQQNz+5ur4G3gRAK1cgAdB5iLc3bvZCcK3qBij9qFXfmwwCxSU3I1WULBTxGiEFHgaU972qgnP5is4ofH+ovKSohTtUUgxE4cVJIaCxOzcwSEnbH+ogKTdL35t1IUggBhmmP9yZWyBPSbr1UKGv0SGKv85D0Ek3WsVKDvJCyzB5jNuZ8Q40jtXmgttsS4nFtiDzhrx+LqRdbMdS7PVfDELr7XiXuU4KQ0N8R8JwqeiNE9ri/NyUP8+JjiLGUJBT+VMuDbv/3bV+1UCMq/lTKXyRqEqCkmq9JwMEWIioVA9E3+rZSoySreO/9WStRanSoB2FuTdS6cavK1Somi4LvGFJP1UY961Kod01b+rZTefPljipYcFpN17oLRo+CJClbHNZiAn2yOeYbsTMHbxfcSHY4COEso97nmGbKEgp9iqAqxBLk+8m+lsE3DlEIOJutU0W0TGqZqt4bidvzNv5Vy2DVZ56JlZgpRoGIJKHKer1VKENmmFgLvtwfMZ7mPUoLJamOQfyvFxmIuKPiDrskaYhdv83DcrA64Aapd1UybNdmZgg+53vWu10VQOExQ7nJ7zHGslrKEghcp4cPlaxGLT5gERPpkklMIp1zkKqmRq0IM7lAUTFOZ5BTC2WWnDSI0clm/sr8wCSjv1upPLYAo8sznoSZobkNk1QvKu2RtyEC5TW63azBJqKmar0kwT+fuLHthIW3VTIjyeUDhtiK+fKeSnDQHFubWJsc4ijh3gQitUGLjsvcUz++USU4hN7jBDXbOZC3FvDdfjouS9w2uf/3rrz3HmOxcwZNrXOMa3R/6oGH3QMm16NljsoSCFw9NyecPGIW0IwxUO+/WQlq2M0mQT+LYqZ2F9upXv/paO4O67I+D/JrXvOZaO+aWcJxr95d/+ZdrylvEj0WgbIc0dZWrXOWkdiItKPdo5/0r0J3TJGB6On2U7fgnrnzlK5/ULpT7Uo5916XkM/PUfThFLUUC8zzeU1be3hPlHnHzvl+txqvv7TuNxdfXYNyYD1nZmstIddGfdrXarYiKxlvvddmTRczkTRYikPDLudhEwZNI27GLMOslYcOW5+gcWUTBEx/c8aongc5BQCiil0Vp5sE8V5ZQ8AGrtOgIEQ1C0Sjt2g4j2t3udrdbtbWzqg1S8dGiYaI/7WpKkfLQTn+ibNhwa/1pF20wLGOHn0F5l/1RWjWliMnp3rRxf2y9NSWhnb7iebetoToXFhHXC5E8bml4T3by3onn9R6dZDK8J9/Jd3Bv2lLumyLMldGf61r8M6JdXNM43ObUbtEQMeP764+inlO2rsSmCp7QA/QBvbCLGPVd4sILL1wFQmzK9F9MwRN2IscsO7Ag7xym2Pmyu7WSPs2VJRU8GGR2Nq5RU3a92HV/+iLilHfRn/uK+zuKiPvbNM57SXj/vsOu7q/s76gpuzFso+BDnNboB3oi646DFgumkyL9ORZFNiWLKvgQK2QQVA5T3EMtfrxXkI8y+WMK2iMnyAZoNxZx6JsCmcXuii3brm3T8n8B8cbuj7DfbhtfLm7aQHV/+sskp14E45V43kyG6oU4diGnzEn+bTFo5wKj13fVH9mWhIXE5L0FS3VuPHgL4us9p/HnFDa3UlILxpvv4P6MwxbTdi6QndyX/piEehf7XSh4Qj8cFV21qYWhlFEF73jQcrycrmKVR+iomU1aMPgkU2JXZWsUjomoEOX1emGHJU4c8y/6Q4bKTNa5sPggx0QNUIPc8TszWecC4xKJyQB1f/pz6tlUyVPuom/K+5O/fFMligQkOkg/0R9SUy85KICMJQrFd4h7FFe+KeOVcmf2cF/en/coLDIzWeeCMmb+iOfVn/DSHqZoCWUc5VXxvO7POMQb2LQ/mx1s+OiPX8F86dlEaeue8nw93YX+Pv/88096VycUvAnJDjhGmDndRFhXT1oGOy+DtfYODWpJ1npAachoV+sPIzCv1lOQ80RIYI3ERCn0njTshMXE574I+v0LX/jC/CejsFOn3HNfhFLtXdTURm1VL1LcpPfk4vot5ikl33vSsJO1GOa+mDulK5A+oQe+H5t67s/3xoztzSHFp4bUmPszHo1Li3EPJN2qVXjTH67B3EXShktu+VYE0uko3qE5nPNFnVDwIG/DQRaePeoiRWoPQUIO7xxxUIq44h47NrtcTbmHUIY1J2oLGKq5j1LsxHvuj9NvLEa3N26dUzj3UUowXudCBEjuo5Rehup97nOftT5CvAf334MxJqv+Wk7tGny3KUJUT9y6cTXFeO0JH+VMHourN28Q++aC2bK2WJyuQm/XIpFOUvB2DHbx+Y9PR3HENaF7FPxUCgJ2wx5MMV7tTnsU/BTRqbcmqxDM3Ecpijb3YEoh9zJZ7QpzH6X0MlTHUgaQhz70oflPRjFFYBK6Ohe+W+v0ExK8hDkwrpxych+lREqDOXB/Y3Zz82ZuTVbQn+9Xy+d0Ogozay1n0kkKHtjc2HhzB6eTGDSb2BmnarIy+fQo0KkdN9t0j4KXOyb3UUpvTVZhnbmPUoLJOheO3bmPUnpPBBiouY9Sehmqrp/7KMX992CKydpTk9V3k7oi91FKT0oD40oiuNxHKT0ngl0yWQNs8XxkOa7+dBP6umUOXVPwwDbJnpM7Oh2Ecu91rAbY2G94wxuu9UkcQcXf9gCzL5OcQoKc1KOQha9mMlQIZ5cFoAciK1qMVw7q3iRYIlMyaarsr2fHCE5ULYYqEpPfe1AjQ4UgJ9Xi18cwVrvVd+plqDLpZNJU2R+G8lwYV05ouVxfiHHZG78+xke50Y1utGJu90IuefN1zDR6Kgs9zdfUQlXBA298LVXoqSyOiXbuPWaZDEpZPGvZr0ni+N4bu2ySidPN/ZnE7L29hRLsoij5nNaAcseU7H1u/VFCWclzfiEnbdIfO2xOV0BJ29319mcXyk6sxmnZn/75N3pOP+D6tbQGFiX+lxq5awz6w+TNiwZlLISwtz+bEnlpspKXFkM4Ym9/YuNraQ2Mx02ZrMxwQgPL/r70S7+0aj+eC8/dSqt9KguH+lTgQVPBg9A5x8gv+7IvW+v8VBKrv2gBNOpdED4oefbGqKNq59KrTEpQ8sF4tejaWfVOrhKUR2aobtOfeGvHb/env96dewYl796I5+0xBdTAdGanEwzaHudgDY9//ONX9xX3ODfNbQtyzQSj1HsUW78pfMdgvLo3/eETbIrYyXte92ccbpOaxDwwH5gV9Cdz6jbKPWDxwJA1j0/13fxNbnKTlb9sSrnDqIIHVGX2HfY9SkFY16kkJgHFjryxjZLLKBml2yj3QPRHendiNURfZBfPXfa3C+y6v13C+zou97eLDctxgec2jyl68zrP9eMu9C9Oh/DaWmqRGiYVfGDTGqpHXTzTLhTwUQByTLA/7QLnrPAHCSQh90YwGTclQwXE4Ud/pMVQdV0mCuYp//r/RwneA/u4e2P62JZ5umuozBX3J4dLi8lqI2jc+RbGYaucoHbRn7qsu14kzedTVVf1LtizFfweRxsIWaI8OInZIjEFkaFa3vWDhrJpomrcW9wfMlQmZswFZqu46uiPICHlUDHKXN5814vr+rtNmbG7BuXJVOG+4h7VpD0qZeaQp4yjuD/jS+1WCqfEJZdcMnzFV3zFiWcYa3fzm9985e/SltMVv6E3Ym2Pedgr+FMAGIqqEtVIR3wAh53l0w6Vcq/d3yaMV1EDrWpDqhVFrh7tKPfcJtptmp5hV6A8W7VWkZa2PeFsC+lLakxWilnZxkj3oNZqq13JeBUlYxGotaPkj8qieyphr+BPAYiXrynPELlXDhOcfvmeSrE49WCq8lPUbp0qAchWe5iQjiDfUyk9ceu7BjMHR16+pxDjTeQQjDFUtZP+GfA28u8hdvw9TNY95mGv4E8BTBW1jpqsh4Wp2q3y4/RAvp/cRylMA0CB599K6WWy7hpjRa1JD5N115jDZA0ewe1vf/u130qJqKVdMln3mIe9gj8FgIKeJ0wpJuBhYqp2axTxnouxnDBEYi2YWgj0c5gY2yET7+2wMIfJGopbsZD8WynBUJ3bbo/dYa/gTwGovJ7JUCGSEP3yL/9y/pMDhYiKXP4vBGlIFZseMA3k8n8hQWICzNJMcirbbRu/vi2QwVo1GNQ8lRv+sCDk0LhpJR/8ki/5khPZUZHuWu0wu4OhymTWYsbe9KY3XWWb3GO32Cv4UwTCzTJDFaMRiWluzOySEDqX0yR89md/9qpM3iZx+JR8Vt4Wi3zMZ0bI7Sj3sAsfJvAZkKYykxUzeBty0q6AIYrklGvB2kyUaQowcmuMVwxVGWoDQvzkL8rtpCk455xzTrTbY3fYK/hTCGKUHauxA0Wn9KSbPQhgvLovtlj/9u7cMyhpfYW0GKqUfHndo+bMo+TdG1OavPeYxkcFwYz13tyf8YWpncGkYzFAyPEs2tVy1VjU7Pi1M05FM/XWSdhjPvYKfo8Dxa4ZoHP7m9tuj81hMRD3froxaI8yqgreaqz2op0Pe2ZtJV4CkmfZvdiZuXYru5xBhAlpJ6ZdLlMViHb6c3RvtZN2FAMv+hP/WwMGH7tutEPaqAHpyG5VO++vt/LSpkCOYQqJWrBSP9cgfpmJI56j1W6P7YDEZOx5z/5tVWgSr+97RQ3V3kpJm0Icvu/v/ly/Ra7CU3jqU5+6uj/ja9NyggH1n6M/871VNQ1/o7y/FoN216An4rq+RyZr9YL5iR7Qp+R8rUy1zFnaGCv8L63kenxu0R89PcbEX1PwGksbe6UrXekE8+8a17jG4sdGD80+x94XbExZ8JgdSrAny8zIjhftvviLv3hF8S5hByFzXbTzHBw+2dZntyETXdkf22GrHeZdtLvZzW62drw0CIXpyZgX18XcW1rJm5yiUeL+XPervuqr1mrBoo+r3CSHdtRQVVi8t1zfHuNAthI14v16z76JqJmsvKWTkMgr2J8SZSGF5Xa7RjBU47rGjbj8nCaBMg4ma9wfktOmytbmyXyI/swT8yWnNeBwNb/K+8Nv2FbZToEe4UCO69IL9EhLKU9BOobrX//6Jxi+nNEyfmblTb9e85rXPHFd7R71qEet+c+0o4+jv8/8zM9cmdByf4GTFDy6MOVe83SLgrDqjq0Wm8JgEfPrwfJ1KflwOFnpvexatrhyMYiEQ15AbvdFX/RFJxYDO5EHPvCBq5eV21kMOC7B4BNSV2vHQRQ2SUoWc69GOpIBrma73AUwAMWS52sSkzNOLhivlHtuQ5QnNJn32B4WVYmh8jsmSGdRu/Wyyy5bpSnIbYhqT701XufivPPOWy3++ZpEiGkwVI2bW97ylmttjG+F23uZp7JGipap9UfJx+Ki3Y1vfOO1duafIi1za7f2gF6jF2r1F+gb+qR1wqmBYrZbv9a1rrXWH/36iEc8YmU54JNwKqK0czuLn8WA3mP+corJqbmjP/622knoJAXvg37u537uWgchlJTC0rsGxdwKsyJqL3oRFGSrYACxE/JiHWGyp74UKVTBalhbVEJMPpCkqrZYhMiBAo6cY/1xPG0SMTIF6XRrhbRDgsn627/922u/lUKpLHF/pxsov/xuS5EeGMZqqFJ6S4W3jsXfG0cim+BHfuRH1n4v2z3pSU/KXTdh/o7F1Zs3UTBljDilHbPJrmGzJ61Hvl4IvUMPzIXFyuYq9xOiZgITr021k0r+PURBGKceFona4hhCb2drApyk4DVoxeUSposlFLwXN6aQHekMEL6AMUVrF0rBy1dd2+WHyAkOVs6xGqo+OMh897Ef+7Frv4eICAADdKw/0QVLKNApJqtIBRCtkX8rhWlgifs73TBV2i8qZx0Wk1Ut33ytUsTng41B/q2Ungpb5u8UkzVSH4jYyb+HWFhspHYNu/NaPp0QeqenIpZTRi3vTogNLR+DXXfttBIi1NmJi4JvVYsj9HbNZ3mSgtcgx7yWwgySbXS7AEfBmOL2AgwQJpOa+SPkFre4xcoWZcEY29FaCMBAyb+Vcqtb3WrVjoko/1ZK7PQ5ZfJvpTi2L6FAp5isQu9gqui2ib+LXPOnO1pmsBDHbthlTdYejOWEIXHCGMsxQ3oKsRhXLbNVSKQ+aJmtQpiKdw0b1y//8i9fu1YIvdPDTeBDGSuUZAMqSRsFz2ycfw9xYuGP4AOsmY9CLBgl5yBwkoL/53/+5+bqSWFy4i0RZiaKQwWafM14wEhGJfsfpZvbEC9MbhEDieOq1U5/URz58ssvr9oYCfuXQiDApso8ldtEu6CUc6S2jltOKEtRz51snK7yNYmjYCStYrrKZKgQzhrl4/bYHuL7c1m/EL4sjjegIFvtMFltfJaA8ZDJVSHGUUTNseu2asYiO9UUSgs2NuzOuZxgiHkT0WvmSasdM8USAQt2yPRHzf9I6JOeQATO4Hvc4x7NjSt9x8fCeXvmmWc2C4db7OhlPgJO8JaFQFZStbQz1qJodFbLGcH5sqnnfA6ElInmKK9pUZFGtFxUKG/lvsp2HpoTtKxRGlECZTvKPZflUx0lH6W048wtPdjsZXkxYJcT+VN6sK3KeTEwaBy3s0d8lxD1I5qovK5V3a693JVzYM1pt8fm8B4peUzd8j1npa0dM4eItbKdRThHj+0SruvUl/1exkUZCECpqNWb2xnfOcpsDswTZKhck5XSZoYo25lXWdnyxS2Z+pr+oG+yUqZvelNaAycq53FWyk4ykdIaLAaUfDYDa1fWSxDswb8z1a7EmoIHjdkHOTuwzaxESyr3gJfIDhzXlSyqFhZl562EIOemdpRxjVghSkHe8LJdTckaNGV/dhC1sCiDUH7xaNdS2toxd0Q7g/oglKcdOkdWXPdxj3tc1SRkB8lso513zTZfa7fHdqDkvV/vmbScg5ya0c53OYgcNL43X4Bx4rrGdY3vktu1mKxzYR6YD+zx+jNPSuUeMK/Mr/L+ak7EXYMeEYYd16U/tokuo7/oMf35xvRbjXdCvwrD1ob86I/+aLUiW4RhR3/0NB5FC1UFH/BxD2Piz73u3HZzMbe/ue0OCz33N7fdHpsh3u/Ue+75ZqcC5j7v3Ha7xq6ve1j9jSr4XcGq+LSnPW1V3V5K0F1UUZ8DIUgcqZw38pQcxA4AgvEaDNolj5VLQrk79+/d+W6ZNLUUlN2L6wrFK4+zJZw0tQmp2SDBfzf2tPFvq92pAt/Je/O8GI+teHUnYe/ZOBXB0oqQcxKe0+6w4ARgfPq2HLBMIzUIInGqinbblgmkx+K69ExpIt4EfBrBUBXCXbMi9GJxBc+e5qhV2t0wtpZyIAXY7ZGYynBJ3uptjpdzwCuO6ceOHxE/vOls88cJwrwcE9n7wubHFtlStruCwtmO4+V18RZy+TqkLeYM71g7/3I08SGVsFg4ausn+vN3rbQBxx2Ucfie4h3++I//+BpTVDs2be28OyQi0T9ZeXNohu9JO/Zk/rjc32GBki1TZZvvyFBZeWffE/8Z/ZDbzQUzJ59K9BeM15qpeA6Y70oSk2hGpqxtiaWLKng7WfasWky6aAKr3rYPUINQTvas7NwgQo0sLnOON72wU+IsqYVyCvUMZuxRByXZIsOIFV5qsRIl1SLD3Pa2t10pJWDDpKRzG8K2y3Ee7VpRYdpt4jg7ykBUrEWPGY8KeQczloM0BwyEiJSLxc+OFwclt7FoiOiwGB8WzF9KthYbHkEXwcg136ULyO2iFmxPWgg+BHmrhIzn/kTC0Hd5kRyDDTA9WGOyWjRk3twm98+iCt4AaYVjEYOx52XMBSdV9sCXIvSo5rzdFuLga+kMQiilJRaWXUMcdL73UkzuJTBV+cnODKZqskalJpMt/1ZKhMGeCqB4MJHzM5YScetj8fcWg2Cycgjm38t2PUzWXcMJvRVaTUTCIDKCE2D+PYSe6MmzZdMaJ5+a2Hn3MF5tCscYqq349rlYVMG7sRxiVYrwxCUUPELCWEoDA2MJBc92Vjs1hNg1HgeImsj3Xooj/xKYUsjBh3C0zr+Vclxqsu4SNg5jqQUIxjNM1VoVVQW7ZLLuGhS81CT5nkJstCJqaYw4RU/IGTMXTFNjhCi77h7GKz/XGCHKgrGNWXlRBS/samwnLZ52CWasDzumaJkZllDwdjT5WqXYSRyHHTymZb73UiiSJYCAlq9VStRalVUw/1ZrN1WTNU4EpwKMqynFLfYdDoPJumuYvzVzVCmR2ybza0qhJ3pSHzCXjClkvreeEwFf0hiTldlH+POmWFTBi3JgO803TZCYZF5cghkrikA6gnzN+AB2dq30mtsAE6+1ugfZ6TgAyaY16JBynvjEJ+Y/2QkiFWq+Jrnyla98gspuQrZqvF7talc7UWvVQt+q3eq/i+w6lSCHDOZyflbie0acuxNa62TNVxQmATyKFpNVu03ITruC+cup2dpAUv7hs9GuxRSlJ0QTzQUnKhNgqz/6rhbn3oKIHyfTTK4KQWIai3OfwqIKHjBURTeUN03JekmberDnAJM1K3mDgRlgU0/3HHBA5nQFJhN6+C7Cng4KlHxmvMpYJ8xsCcd4gN1UlFV5XcpYeF5JFnOszjVer3KVq5yUp8Su1mKQ21lE/PfjcJrqgffDDJOZsdIPlKHJSEStdqU5QDtKXhqLsp3xXUtsddAwn/htMjNWKuRQ7tCqBSsqrEe5B2xKnTazkpfEsEZOmkKkNchWB3qzxVCdi8UVPFiBhNxxMmJgsaFuGzM6B3byokHiupI3HcSkpuQx4ByFXTeSSx03UPJCFqPO61I79wzK2zWDlZsLaQccwb1j7Xzj2LlnUPp+j3ZxdD9VwYYerFPfrxW9JT0FNqR3yLzTsvUy7UQ7mUklvzoqiFqwntf9me+1SmsWP4uBcWwMaNeTWyaD/uLsj/fCwd2zc8+w2bVoBJsZQ9XmeFsciIIHuwErLjkI2n6gvO5BKPeAI+RhXHfXKJ/jKCLuber+5rY7VRDPuitT5K77OwzQO/EctRQjh40l7q+q4H1E9ktOQ0ytXA4v4OjjqBvttnEG9IDdypE9rrutLVDoU9nfQTFekYmwA4Ph22K8itPFcIt2rWx62rFTR7vaTgY4duyKo902O5keICsFo3SMoSoO26476sbuYiczB67j/kJax2M7tWAwehZkqhoc14NRqm0ma/WCOSGYmL6fCIxt4Lt7v96zebxERNtBgO8rnoOJr1bZaAkwU7muk6PIvZZVgl40XowFp8dtTcTCMI0D/dHTY4vumoK3inAGshsHE45tMzuk4sjDrs1hqh0H19LHXw8jOoIdP64r+96mCZrY0yKtZ/SHFNE61u4KFhWkEuFccV2Oq3z8FZalHftctEM+yWQjk5MZrGzHVpoXA+3EN5ftkF5yu12DMhKV4ZpxXWFumWxECTqmRhvCtrmNo2kOKHfhdHF/RFhrLpunnTBb9xXtHKlzO8+lYEzZTmKtVtqAKTA3si1Hf76f7xhknl5EautgAusPGWqJcnhLQnEf8zWewzzmtFzSvwcCAvh24rr0IBNLVvLhU4qxzF/AVLzpSdJCTB9Hf/Q0E1Vrx3+Sgo/aqDXm6ed//uefsIVaISn3Wqx51G7d9AHGEAzVWlk8tQ8p+daD1mByCJUzYXJ/HIyYckuYk+xQf/qnf3r1gfJ1TbqIYogaqjVmrHZxcrGDtAjkNgTXINpRni3yiqiDvGjsCpRii6FKWYajC5O1FcJH+ZaOs13CTlZVrnxNYrGJRch9WmxyG8LW7f7BfbZitLXrPZFgqLbINUhLrZNGC8aD4ji5L2Ic5cXqKMK8xFBVIDs/g/mMC7HtCacGNn+b2FqtVZs1dvk4CdUc/IR+RbLrOTHRa07xlHvujx6m5GuM15MUvIGUc1iXosA0xc2U0ErIT8SJbrqzGANTUU25h4ia6cmR4QNkz3UplM8SYZyO7PlapUQFJkfO/Fspc2ut2jkChmL+rRTx7Uv4C6bi6oPApCBE/q0UJ60lIFw3X6sUQQFz2rl/kIso/1ZKb63VqQpRIl16IDV27qOUIEQdZYg8aS2ixLxewppgE9xaHAm9KBzVTn4sTt/Ou+XUrsHmlv7N/YTQ2zXT8kkKfk5NVjdupzem4JkallDwU8WvEZhqq1gLzE5jqQUMoCUU/BQhimcepkoAitSBKcUdCv6warI6FeZrlUIhwlSqgmi3a1g48rVKCQVvIcq/lRIVu+Qjyr+V8qhHPSrdwTgwh3Mfpai81IMpQpTomqMOCn6sSLZ5vURpvykmK73I5s7O3jp1EQq+J6su01kt704IBV8LXT1JwWvQIkAQibooeOk5x3bSbGJLHI8cyfK1SrGyKp47F5wjuY9S2DyXUPBTO26MV3Aky7+V4rgPSu3l30phZpjTzsRfQsFPKW5FqmEqx0y02zXufOc7r12rFAmp5rRz/8D8ln8rpbd0Y8usFtJ7ImglaguJouBHGXOYrAIYdg0byLEi2fSi8GIKfizHDJt9T1CKDXMtYVpIK2fNSQqejbZlA2XXUi6K7UsWuZbN0gM6yrZyMm8DUQmtVdsLM8F6PNRspZkMFWIl5gzpsenPhQUyk6FCkE9ignGE5fJ/IRiLUUPVwtwaTE5ksSMzAGo2S4IpulScu5NXmVq1FDZFJxWQw6OWpS+32zWYwmq2UsJBFkmrbAi+4Au+YK0NsfmJHCQUS6udgICeZFQg50vrZC1Vbo+iAKkIMnkpxDjq2VkeFgRbmJ+tDal53Yoi2wb0Cz9gzf9IkJP4WOhJuY4yGaps1xM4EGX9WhYHi3bNF7MWRcMByERQ/jF7FqdFqbQpeaSBsp2LU+49SrYXijXk5EGcFjzYmyhjIW9MO2V/Pp40nZv0NxcGX07FarBme2ot/UEo93K3bdHIRziZPHO+EFE62ZZnskcGwaVgV5N3IBz3kX4gwFGemayU+xL21BL8Me6nvC7Ga47OcuzPyrtW38DpC/O3bCddgKiPTcCslwt0U+61MntzwFyX0xoYFzmK6yjD/KzVeKXcI2X0EqDfOEmz8qaXymIyTv8Wgxy0IjqrpoynQP/Sr1nJ668Vqrum4IGSdxzljGG/bdVGdZNSx2rneG8HXWu3a1DKHE8iCNih2TS3UcaiIzDH4jkceZek4wc4tYWmYdVxmMolUgPfiGO6Z/U9IttfhuiIaOc5Wu3s+OLdaSdG9yBgh+uantW7bjFPtfNO4r202u0afDLeS1y7lTTK/bivaNfakTtxeL/aeu6eLIM1UPL6cU0O8R4nXQ3Gh/vTp3FznJR7wLxXGNxzGFPm8VLRViUoeU71GM/MchFFVUJQipOGeev+RCn17NwzhH/KpRXXtatvKXeoKniwO6TkphTd3HZHHUf9ORz55tzfrtvtGnHNg77uYeGoP2/c2xLhwAeJeI4lfEi7wGHdX1PBH2WIw3cEZjNmWjgom6G4VfZQZg+hZDWnBmhnV2yHxJTSaod5ipXI6eo5lopDXxript2/9+IUskkCpxIqSnkn8V62PW7z3bivuL8Wg9Z/N6bi2q2dFtKR+9LGeMhlAntx6aWXnrg/12/FoTPraeO6mIytsoN8N9Gf+9y28hLzn/Ee125FyDlpRjv311Mp6SCAvGg+mpdClVuMV+08x1Q7Zsf4Zk512wZk4N34bq7Lj9MiazEbxnWZLjO5qsSxU/AeJshOQQBiA20dp3eFqLXKHxHXrTm4KPef+qmfWoVzRjvhpfn4yxv/Ez/xEyt7WrRjA62FOh1lUDKieTjh4zlEH21aoJvZj28nmHr6w0eoHX/ngJLm0ArGoX+V8cuFtyl3JKbcLitv9xHx13GPfFa53Vx4TxEN4preI8ZvVt4WTe81rqsdcxIyXAk+G+S2sh3zy6YMVWbE8BW5P+OfmSH3ZxMTvh3tjGvju4fMsyRKH5D7Yz+X0VZcewkO9SAxRTv1B7LyLrOZasdvRy+1lPIU+HaCxKQ/QSPSHGfCKIUePiDtIhik5fc8VgpesD/maXYyEAVrfZxtbPEt2LEI0asxT0V9WHmjHeWe2xAOtmhn8rbIKyaJHcRBH+U2AWXXKgqh8DPl0AO+ley4DxE91crV0wKlKJ927ov477EIsdlmx32IaLFoZ2fcKh5ByfemirUzDqWdRdbGYLzaGWdHewjbcywuNhHZcR/CXtvr2LN5aYUEyp4YixDHcaudxWDbHDzbgOlJvpbsuCfmM24DvWK+aVeLpqJvBJnEYmW3XhbIDrH48Vf2FDESDaS/GkOVc5ZfU+y9++ODyYEAxGaXkq+RPI+VgufMGou/7yU6zcVUhSg7PbC6jrULApPIkfxbbpdX7qMIEQz53kvpLe1nx5L7KKWXyTpV0cn1wOTNv5UStVun2qk10AMOwdxHKZFmurVpCIlwWQ77/FspPQQm9mKOvNxHKRFnjmeRfyvloJz4NdhRtxZvYueNIU/RtkKmCb1jwbNgxAmpJr0l++Qmai2OxA6d6dYOfazdLKLTUceumaxzoYp6LV9NyFwFb3cKUwSm46LgpxiqTik9mKrJ2stkFYec+yhFNAJMpSCYy2RdSsGLVMu/lTJXwUcpvjmg4KdSGkSI6xRxij3+sCCqb6w4d6ngW6czQu+Egm+dpkivgp9Tk9VJmILPYdClUPDZDAzHSsGLNQ47b016maxzQXHna5VihwBTqQWCoTqVqoD54DgoeFVy8r2Xwvbbg6marL1MVua83EcpUXRbDdf8WylssHPauf8esKHnPkqJ3DbMIfm3UoIYN7XjVlVsLpg6W6THEAEC8M3f/M1rv5WyFIFuDuzgM8+lFBsyCtl8G9uZ0zvs+Ba+MYVsIZA6eC74UDI/pBQnByY6Cn6s3Swm61EHR1hrNeaUoHDGPMqbQrbBFi3aCisON9q1bKpqW8YEY8ttJSzCZFVB5ziErRnwLWYsR5AIhB6YaJieuS/CRtkbD88n06rdyoYajnnx7zWbKuFw41ADjNearZSUTNa5oCBrNlXCgR+kKO1aSQC1i4ltp5zJUCEc/T2kKDZfJ4Nc1i8EEzt8Ish5LaYtpcnXcFiwUNXK+oWEA998Y8fOZf3Kdnwi3gvTX6s/Dv1WlFYNyEtSYbSYsUFisrA4QbZM1AIdatFXx0rBA0dRrvHK082eOpb4fltIGZuz10Wt1TLGuYx2CKHcTZZSaVsM5GHP7YRnHQcHa4ByoWTK56DcKcNNwAyX0xVwfEW6gF4IKctpEvSflTElnhcDi41FrAR/TF4MKPfcbi6c+j7v8z7vpP4o47KIjfHAHJIXAzvJXOyGks/KljLudXiD6wrZy4uLzY5onbKd8Y05ndsdBOloCvQCc1dOkOhEXZbZsxgws2Vly9Fehszqz2YyM1TppRydNQc2pU6TOXjECaqMpnIaEamTzcDatchOx07BgxWSAw87TBSHj7dE9EyGwcrswDYpyoFNs6aMxTWzh4pwcH925DVwnijSEf21mKdHHXaawYr1HDn9QC8oef3Fe9l0sQhQysEk9G/syDOkK4h2nqV11HaScF/auc8Wk3Uu+GT0F6zXHHobYNqL6zLvtJisc9vNhXFpHLs/LNoWX0MMdzwHpm25CBw2zFMM9XgO+qNWQ5UeiXbGAj9SrR2TDhNaPC9HeIs3MQfCMC0acV2ZBGpRT3wKnP6uq538YGM8h2Op4PfYY4899phGVcE7MtiFMRcIrWrteObC0YIdMfrLx+OlIC7UkTWu2zpGc8xGO0fN1g4KuUO7YG3m43EgmKza2f202gmRKvvb5BhdgkdeX/EcLdsnW537suPSbulyfQE2TPfmuv5tMV7tXIKl7L20asYGQzX6q+20loD7Dpao+9yU5NQLNm/fLa7b2rkF4zXYtq3j+2GBL8B89M0wgbclQ5mvxrH+zKdWoAV+ibHivfAPZZJTL5zcfA/vmr5s5eESHBLP67qbkqECfEdxXafbFskJ1hQ8+1K2Q7HpbXrstlgIRyvtS2y0S2cH9BLFLZfkJLbcIBuV7RyHyugcpIi8CGGy5nzgbLm5ILnBlUlMbLQ5nYJwzhwdoUxgbjcXaOE5ikLcbF40LFI5/E1K4tZisCtQRjlLqeiGrLzZMLOPRXxyJhFZBDKJ6da3vvVau12jln2UjbZ2nN4lmP1yeJ4jeq67IOIip6I2LjLz9LBAuedokG0Yr5RnWT7PfBdtldMLmM+yg0Y7Yc94FbndXDDnlVlFRc9gxmbGa8k8JfSgsNvcbi5wD0qfCD2NDNUKLjlJwVM6nJU5DSaRL9xuoMfWTdnxEGfnAeEwYnvs6W8u7IxlWasxTyl5HyfasWHV2lHe4djDUDUIa+0o70gpGzVUcxtCeUc7O+is3EPEutoZ1Gz7LVCKraIQ8ntHNAYbIdtdbkMwILe11bbAQd2qH8AhHYuQnDOtdmKUox1lx0GW2xDpBnoZr3NhEczKPQQXYtP0DFPwXbLSDilrvI61sxhsmu5hV+DTaEVdsYnXokBaCIZqXiyIeWozFmkcREmVyr1sJ/Q1p3sYg4AKm93saCf0HH1nMQ3HeE4tHe0sBr2MV6ed7JAn9LVNdG2RPEnBG8CtsCgiWqLWSQtME8IIcz8hQgV7+psLA6m2SIUIeQKmp5rSDrEjBLv+sfh7Sgms1mP9CXmCKaITQlRPRJBjZ+6jFEodHOvyb6VYJJYIz5TOOV+rlLkl+4LJageUfyslarzuGlO1VnuJTnMxVbJvCaLTrmFcGf/5nkLMG/NiLphDzM/cT9mfBQBahdIJPdFjgp4q2ReVmuyoc5RcKfRiz4bKoiG6KvcTQm9PEp0o+BwSVYoL9ChkIXRC/3I/IV5AT39zQcHnUKdSgpjkw44xY2MhcLyby2StnVZClmKyTin4uTVZlyq6PaXg5xbdjnZTCr43pcFcTCl4URBLYK6Cb50KQw5bwbfyDBHzplfB57DlUszrUPBTqQp2qeCjJisFP1aTlV7sMcdO1WTFf5hU8FM1WR2Hemx5HsCKlvsJYfvt6W8ufNgxReu4D0w1+bdSmA/AgpF/K2UukxXjD6aYrMwPPQpeGGbuoxRUcjismqxTiluxBJiqyeo4DZil+bdSHM+XQPbBZOllss6FhTdfq5RgsgqxzL+V0luce5eg4KcYrz05a+bUZA0/39hOn54Ik+0cUPBjTNayJmvLXEZ6a7LysdXMUSEWjEkmq6D67IALEVwvZ0ePc4BNrZWnwtFIPGdPf3MhTr5lo/Vi5VABDrnW6u4IFblA2C5biYgsiDHB2Jpb+Sy0i3h4NuTW4OTQ5m3vMZWwTbeOg1b2KMfnhNYanGx7QT3fNUQv8EHkaxLkopiIfAVj7dhSgWON7yO3IchJsXPbNdzn1a52tbVrErbl7HDfFURe5PJ/Ib5n7Nx8v1Y7m6laMqqDhHmSyVAhlLB5MRdMmE6GLQuBeW0+gnYt5mkmO03BztxGpLVxdfrmcDd/tctkqLJdT/QVPclu37I42JzVoqXWomg4HLIjzqqEnruJMhY9wRFU9he5jlue312A4ykreUoWiaG0b5f5vUMcszJD1WKQ0ySoaWnQZoaqVLllOzVPmUdyu6zk2dE2JTtxLOYdA8d4VtrIJ7kdpeBUsSSc5rINkcM7lHaAg1lq5bIdB1nO90+ZZiWvXYuctCuUecBDLEqtENxdQfTEVa961ZOuW1PadsFZyXOgt8hJBwnzyeYlM205rjdhvOrPqSRbHczTMprKfJdOJC8uvWkFAkFyyouG/kqlTb/Rczn9wXd/93d3OZQD9K9TYvYv0q+5fkBgTcGD6BK7dSxLzDXOo22UMSUvWiX6s6L27FA3hagRx3pZ+xxzW4xSg0FoFScVR2PLVinKQ2Y//XkWcag1iKZgdojrtpS2eGUMOO1ce9useyaxaJ94jpbStuMT7cO2q22kfV0advKux1bs/cnSWYOdvDbEc7SO0Hwj0Z9/8yKwFNyP+3Jd385zHQREZZg/ruvbCYmsgS3buJtqd1ig5D2Hb2b851DZXogx9z30Zx7Hzj3D/HddY4+5LaKPNkHUgo3xxz9UC5W1CLEExHWnaqhOgR6WMye+r6idsSigqoIPUMK7VMS77m/XYH9ewgZ9kIhnOKrPMff+dt1u1zis65o/c657WPc3F3OfYy7m9nVYOuiwrjuq4A8aSAd2sbLTOXpte9zGVHNkFWUyxmSdCw5hXIBggLbCnILxGtdtecuRVPRnh29XU/OCg+OX3+1AvJcWM3YuVNgJlq1+l4ob3+Nowzgynowr46B1zOe8Y4qMdq0do3Ee7Yz9VrujDmHR8RwYw60aE3xB9IBn/YM/+IOdMFRdl/5z+m6RsLQL5q7AjjHT+ZFR8LzijjmZ8bppoinK3XGozLzGdrrpMZ73XPmxMh4eGcpHLkG5O7aV8fBsxfkYr51jW9kf23OQkgJIVrmdcKnW4jIFiwobYGnDq2Ul3OPUBqVdht0ZX3xvOf0B5mluxxzCjFvC5qn0nRj/xu1RK7w9hVyOT3g0PZKVN72Umaz0l/S/myA7yPUnWiynIeBwL1NC82eyy7eU/JFQ8AYBW1KNJCT/ttWxh/Fq8LG918hJoiAUuO05LtmJsGXW+pOKNhYNO6BWlR7RHdGODa4V+oZMFtkJtWsVhdCuN2qDzTE7vEM47DZdNPY4XjBuWjHVZe1WSjs7xkOMy6i1asebU0aHsDvXbNNHDRyxlHYtSsomkc0+Fiv6KDu8Cf2lyExe/MbApk5p1xiqlLz0wDICMD85ddd4SjbFIhJrzNgjoeANkFbYERH10ZMYiCLNnuZSRM20EgPVwBlYU+4hvOdg4agtUiHBZDVA8m+1dpyf+bdS7LjKSJ8pTMXB23HNsWPucbyRo+SyMDlAzm2UJYhJYwQmgmJ/1EGJ5joOpVCiTuE2hq3C5oQey6f6MThRtxbb6C9K9rUWWyICL0dUwZFQ8HasORl/KZhjPQp+iskqjKpXwc9hsgr5GyNYzWWyKmIMjov5t1IwVHep4Jdisu5xtCBmOn/7UiLqa4o4Nbfo9rbRYQcBCr7FdSFl0e0pJmtOVDiG06ImqxWvFcBPbnSjG61s4HMhSdiYQhZ3m21qY5hbk3VKIc+tyRqM16mFAImsR8Fz3uQ+SjHxe0xXexxPTNVaFRgAik/k30qJkow5+2eWINodZVDwrTKaIVGTVZbW/FvIJjVZW+Q+EjVZ2dgz76OUI12TVTbElm0YSQBZoIe6j7zQykpohUV26rHpi6v9+q//+rW+iKNRTAhx8pk0FYLsFO0w9lpZCTlaIr5e3vFWPovI7tmz47bCZ5JTCJtiTy6QPY4vjJuazZeU2T2ZVjJpKsS4DOap8drqzzg/DlFabOHi1VvM2CjHZ77hBbWSKFo8e+LrbTRlgsxkqBCLLMe3jRena4sZ67RVi68/EgoeHFVyvnAP88hHPnKjXSUHENNJ2R/lnpmnc4E0lfOPY8aF0g4gTeXcFxivubI8enQ+ElosTL4SSFO5HS96i8Q0BZMy71RM4r1yP73AD5QLdCuQndMFCDO2mSjbSceRyUl26TYxuV2LdHRUIY1JNhczQZXK0y5eu2wGZoJthZqOQX+1tAZMsKLoAsw0FoNs7XDybkUrHRkFD14iBi02pqgV6QJ6dtoZvPeKfmCVYqCG82hTGKyYcsIlMUGzMg5Q8kKmtHXdlpMJPVsIlnYYfSZdDRivniGuG0fjTSEnjaiAuO7SxVem8Nq3v3/49ic8b7jNbzxvuM2vXTouv37ZcJvffMHwpAs+OvD32AwWdd/fOMA0N85qMN6MO+PPOMyLQECoX/RnXLcqdh1l2PzxQXgOz0p/1Hbk9BKTp/mtnd11RBVtAicIzFjvmf6Td6a2I6fkZQJwXfcoRLJcBDKOlILf4/TEi9/4nuGMuzxrOOO+lw5n3PPCcbnXRcMZ93vecK+/7K9ev8cepxuqCp5B3+7UMeQXfuEXVmypGjCt2N+sKNq1coaIgLF7jv5a7XYNueaxvdjcXbfl/HC8kX8mnqMnzKkGcbD6i+tGXHsG2xq2nHaujVRyEGBLdDpyXXbHmvf9IPHSN71n+OR7njWcceazhzPu/IxxucszhzPu9pzhZ/92fia+0w1Ia+aa72tX6HvXYLxFO7vR2o6xB6JMjGP9Gdctc4UoE6ZXY0+7nrjxGsxX88y1mUy3TUEuzDqeg/5o1awQXef9eQ56sBUIQt+5P23pwVa7uRCvH9dlHRgLGFlT8MIHH/CAB6y8t2HjYRvOoU6OCshJpT1IlrjczsW1KxmlHDKb1nidC15xR8UyLl3K2SjDV7ZzLJpqNxeOS7l8HjJUJiUZhDkMDRkqt9s1TLocRSH8quaBPyjsFfzugKyWw+kEMOS0Ab53Jidpt6mSt4nB7C77Q4bK5gPj2ziPNvglyFC5tuxcSA1dZvc0j5l3a6SfORD6iVxZ9oc0mcO0bXpLx7LwaGau3I4ZrGxHDzK/tNIQTIHvrczGie/DPNRS8icpeDkXKPdSGYdwoFjNeJGtQK3cxBw3dv9sWR6WLboWsihu02KwjY29BYOFvTBfk/h4cSIx6Nm7chti0FgpexyybHAthqrCwJE9Ubus3EOEQtlB9ETHzAXfQCtmmVLIaRIOCnsFvxv4fi0yjO8eqXHteFuheRx2NZtzC8ap8doqRmGcxwkCT8RmJ7ch5k1PfnTz0jyu1VolvTVe6SGbzlK5h9BfbN6xWFGytVqrFgNVv1gEvBftsiM7+ot2c4FpS//WmKz0NcZr7aRxkoIXbzlVk5UzQFranAu5FIPMinLxxReveaRLQRjYdKUdgwFXnkCyRCk+q/8YQ1UUQCvHQw2cpGNM1iBETTFZtesJC50Lx9d8rVLsuHoWtF1hr+C3h++GiZy/aSkUBIjOyL+V0kqXXYNxOlZrlURQwFg786YneICloVVch5jXeClz4SSf6zOUEkxWES9jRCeRNdqxcIhKyr+H0Is9JlmLQWvxJrOYrKIrcjL+UuzyfFAKvhUHSjCzKHhe+VZcKfECaqvOtphispY1WceYpxaCHgVvBzDW31wma29N1rmYUvCHxWTdK/jt4bsxdeRvWkpEkbWqtoXk0N8xGKetU2FIRIeNpTQwb1pRZDVM1WTVn9QhczHFZGWtiFQFYwo+arJS8C0OC6EXe3I/TdVkncVknVOT1Q7eQjCW60VWOVnVEBzGcszc9KY3XWQHz34+pmh7arL2pDSwA8l9lBJMVuFk+bfcbgkFf1SZrHsFvz0o+CnFHTvznE00S5SgnAPjdG6t1al2PdwOG8ix3DGkp5CNjWbmh5TihIHJan5IzJd/D1mqJivzUK50Vsqsmqxs161dgCB8Zfs8IK93KxER0w2mF5uWY0UrsZEd9sMf/vCtKkW1gJTUOg46eUTxYeX6MhkqJMrx9fgIMFlbNV7DhwHISy1mbDBUl1C0GIqt3Qfbowmx38EfXzhB1mzDhPKKsn21sn4hdrE95f2MUyS+Vn/GeZTjq5XrC0EizOSpMTCV2LBkclWIed1DsqKHRJa1NrhRQ9X8UK6v1Y6+Y/v3XkQKtUzZGKo9PgILhpj31obZ6bsWtbQWRUMp5ygQu/WHPexhJ9UyjXzmtXZlfhSLRnYoouUKGyr72zV8jHx0xDyVcKtUYhyeOa2BdpuSojgyb3Ob25zUn+NTrhjP4ZWPmNrlGqq7BvJJtjVS7pvm3d8F9gp+d+B4zEreTjeTk9in57SbC+M7OxRzbVQQWJHb2RT1FL4uYZ7ajJX9mc+bpCimF4SVZuXtxFPmyae8tcv+RdFpZTv6rcaMtTmuKeMpOC0p15cZr/RwK9R0TcEDJW+3HoxSMaE1ZUx5895GOzvj2o5XO1E30c7KexA7RUr+Hve4xyqiRp722EFniBqIdu5v2+RIBjUveVy3xWS1YxFaFQzVHhvkNrCTx4ITGeCbHDaTda/gdwu2Z+MpWJYKrdfAF2S8G39CATdV7oGS8Wpct3bkTqjmhXbmSV4EemG+xnXNYyfzTUEvWTTivWCy1ngElDyTl3bmkFDwWohpnDSiHT24iXIP0MP0cfRHT7eUO1QV/B57HCT2Cn6PPZZBVcGLHHHkYoO2K7fD22bHLR7eqh21VkWvHAQ4TjDM4rrbMlTFzXsnwTxtMVTnwnGOycj96bdVu5UZKZinjny5/F8v+CjsPrAIXVd47GHiKCj4D//bvw3vfN+Hhpe/+b3DWS972/CUi984/ONL3jo873XvGt70rvevft9jHML+oqaocZ3L/wWQncxH7eyWMxkqoBBQMEr1m8lagaihqj/zvcVkpXeCASpSaNsAD2HW8Rz0W6t269x2eAKeN5ixtXb0sHb688wc0y2SE6wpeMZ8x4gyCoVNalOzhSgUx5wyPpytucdjvgm8nEx2+vzP//zVy9kEwqiyA1rtxiAv9cKgzg5opI28CDFv5XYYg5sWEHeMzA5o3vltF41tcJgK/oJXv2N43LNfM9z2N543fPb9nzN82n3OHj7h7mcNH3PnZwwfd7dnDp9y72cPn3m/s4f/8huXD48+61+Gi1+zWc3NUx1/+7d/O1zzmtc8aVyJt88MVe1K5ilhk87tRLiVtVGJWsdZKdt8ZnKSeZrbMVvldkwcm4ZpM2+VDmP6jdkzM1Qz2Uk7ZqRcu5WjunQYR7scpq0dH2G0E74pQWMr2u8kBe+l5LQCIRwZdnw1W3wLVlK2uBr5h5J3sz39zYWdA5tcviah5H2cnigV3u7sKA4xWA2ynv7Y/FtkE0zWOOFwFLVC2rRr5dZpQZRPK2pIjO3SaRJaOAwF//cvfutwu9+4fPjU+5wznHHPC4Yz7n7ucMaZ5wxnnHn2cMZdnz2ccdezrvjX//ff/X6vC4dPv99zhx978ouHy1/b3jWdTrCjFJbcYrKWzFjzBKM7tyEchcFkpYxbDFVkvLB1ixrKi0WIxSCiVPi2skM5hC+gJ5qFj9EunB7JfSFX8WWwiXsvfG/ZoUzoQ9lcLS5s9PRgTslMbLJlAqBH9Uf/1oiokf6gxoxdY7Jmj3Qp6M09K564zFYieyJOtKe/ucBkraVRCJGvvbXi1TAVLy/Eq6c/5q/cRynBeJ2qySrUqqeiE7NM7qMUk2cbU9ymOEgF/09vePfwo3/04uHf3/VZVyh2CjxfY0wo+3teMHzG/Z87POZZdRPE6QQbtHwizBKRYWOVn0rm6VS8vFMAjBGT9Ben6xytVgo90ZN3SpoW/J3cT0gwWYVdtkKSifBJPCE7/jGGqv6iZF8rvQSht2cxWWu5DkLcSI9CpuDHmKy3vOUtu/qbCzvbVrwo2XVNVmFZ+Sg1himi09yarL3EpKNak/WgFPz/e9Fbhqs++LwrUg7bnee+e+Ruz1nJHf/kpcO73z9/kT3VIHRP6cg8lkqZy2QN5unYgmG3GmbMMcWtP7ZvaHFTCD3R4xOk4McIUXg2wWTN4cil0ItSuVDwYzVZmcfn1GR1UpjFZB1TyI5h2bY1Bk7DVqA/OSwmq5V/zDGRwW6f+yjFAOpZMBzdch+l2OnAVEoDcbc9O/g5TNZTVcE/+ZI3Dld6wLnDGfc4f73PTcUica8Lhx/4vRcOH/jQ/IX2VAIFP7YzJ8EBmWoXzNNcOS2LEzqMKVAS/rZcYa0UeqLHj0bBjylkXCBJ3+YwWYWvUvBf8iVfsvZ72R/Liv52wmRlk8p/TATXKxflQnMh3rNlu6b4ebR7+psLUSIt27UXwVRRi9dvgQ2xdWx04uGA7ulPfHBrV8FWGA5o5I/WLkW73rh5R8LWpGDL7MndsUssreD/8vlvHj7hnmdfYUfP/W0rCpXc47zhfn/1snzZ0wJOkBR4dmCG3Pa2tz0RD2+e1GzShPIPstNYO/Mw4tKdSFsWB8zTiIfXrmV6tknqiZu3oNFbrY0wh3EwWUXEZJJTiLQSbPX0BsZrqx3fhOgh/Snr18qx9WM/9mPV+Pq1KBomkxwtEmkFNnGI1pixjjFCgXp2n73giMl5zzkohGVtsksVqpiPjgbhptFFFo3MeOVoyUq7xowtUx73gqP1q7/6q0/q72pXu9qhKXdYUsG/6q3vG672oOeulPBaX7uSM88ePvZuZw9PvbQennc6gNkxpyswbrPyrLWzCOR2wgSz45GJJ6cU1i47Hs3Tsp35rgxfTmtgE7hJmT3KVohiTrjIJ1ZGA9FvQjwzMzYzT/Un/UE2K2tXWjjo31r6A6bVliVkTcEDJY8Sy4OLaeZov4lyDwgJtPsX9qM/L/sgQMlLhi+SR/GPXPi6FwahkCT1JnnBe9Kb1kDZRn+87y2lrZ1Q07jutmkF7OR9W/15N2GrPCwspeAt4z/4ey+8wuae+9m13PP84ct+8YLhXaexPd74Na7Mc/OulQvGJsbY0079iVb+eSZK+iL6a7Vz4o128rXUmKcgTUJcV7sa83QuKGWbRfPRHNJfbQcNFqG4P3owh4SCnbz+4v095CEPqbajh0XT6E9beroV9w9VBb/HHgeJpRT8ua98+/Dx9/hIqGPuZ+fyzJUJ6NfOrpNx9tjjMFBV8ILw7bIdG6wQVtJtgMnK7h39HaY5oAbHJcmD3JtMmD1hU0cJdi6SuMVzHFZcey+WUvA//dSXXBEKmftYSu5+7nDLx1ycb+PAIYrD9zcOzLls/ugFxrYdpf6Mr5ZZA6OUKZcZwXxqxZeLcpOUUDsM7RZDVbuyv1Y78zXaMZ20crNwpsZ1WSVaO1/O2Xh/7q/FtJ0L8f/xLejBGkMVnMw9h3byZtXaMTfRx9EfPZ3JVSXWFDzl7ohQRqFsk12RcncsykzWVgKug4aPLP67tGkhMfRUgzkKQIrKWTG3YbweJJZQ8NIOrGzvdztnvY8xQXC6m7977hX/O/8+JmeePXzKvZ41vPAN8yOqdg3KOJOOjIuWUp6CkESkurI/tVtzf5RsJiflLIwgJDG3w9TO5hKbwMxkzbZrqGXPFNiRlbJ22RHMMZnbMfeUNVQJ0mRN2c5BJjsJt2bSyYW3c1ZM+lK7rLwp9LKdOH7mmlwLNrDGZGUTrpWx4yiQ/6CnEAXlKZtdrT836WZ7+ts17DCyQznEYGArXNIRvCtIPdyKRabke+J8DwObKPgH/t9xBX/Ja945fNyZz+yLdz/znOHj7vas4QaPvGD4kkecP/x//r7HvCOi5syzh994Tn2nuTSe/vSnryn3EFEqLZt4DXaKfDOtGqrGm2g1QARsteN4DNs5JaugfW5DRJXEomFzddWrXnWtTbSLRYPDttVOYEcsGpR2duyGRMFvz8un1orewYxt2dhroNfY3rNjl0RaA77OsL1nRzGxGPDN0cts/vRvmaYghH61KZ9ksgqUr3UQIl6z5a2tQUmqVvgPufnNb97V367hSJTvqRTx8j0EpsPCVCk+O6mjjE0U/H3+ajzf928993VXKFyS+6jJmecM//nnzhv+8aVvHd78rg+sRLKxaz/s/L5TwL0vHu75FwcfMklBtUKSQ5gl5sLGJudAyhKm21b6i5AI+x1rR0lFkIGKZvn3sl2k6MjRYFksPNAKNSYqMDEtcV62QohJSbCaA5tb+i33E4LhH3Hwal3n30NEMCKg0kNj7WyYzznnnHwbfUxWTKoe5qkLtuJFyVJM1rlgaxtLadBbk/WwYAeQ770UE/Uoo0vBf8SZ+RN//OLczUl4wN+8Yjjj7s+9YkFY6yOJReCuzx5+9/x12+1qocBandMPuffFw/988vi9LQEKvnUaDekppk3Bt6q2hQQxqXV6DFmKyWp+5t9DzOu5TFa+Kgp+rIh3LARzQcHTb7mfkGCyMomPlQAsmaw3utGN1n4Pmc1kzTGbpbDF9ey4MVlbgfnEg/X0t2tMpQLorcl6WJjKMYMPcJTRp+CfsWKj3v6J9WISgbv86Us/Evs+QzHf9azhP5z5zOEVb1kn3Z37yndcYaaZq+DvecHwXb/9/NzN4nCEn1LIUapyDih4tvbcRykRJjzFUI0dfIssGBILhrj4/FspsYOfqskaTNYxxW3BiB38mEJ2cogcOHPAXDKVs0ZpxCkmq4VlZ0xWDgwpNPMfE8H1POk9NnM2q+zADGG6QXbq6W/XEF2QyVAhVkQ74+Ngg7/kkkuauxmOKln3jjLe+M4PrNL0zrZ33/25wzUfcu7wtve22cM/+ocvGs6458z49zPPHr7gZ58zvOEd61yP33zOa/t28Pe8cPie3zl4BQ9jWRgpw1ZlpxoiWqNl42b2UFsYKHBkudyGMLdEOzyUWhZGwnwTlZ3GarxyGEecu/nZalcyVDFZazbuaMf273mZOms282jXiq+vQbKxGskpxGLMwUu/YLzWLB0WFSQmPgILuMielslbhadalNFaFA1vcU61Kx+Cm9hE2dmh5/QHblI4U0+irKVgUctHTIPhqET5zAVHay7kbdIdNolpDt7x3g+tFOwqU2NWmDWhbM88Z/ifT37R8Oq31ou2f8/vvGA4414Xr/9tTe52znDth543vPndJy8Y57zi7cO1H3ZBnw3+XhcPP/ZH25Wg2wZCAbOyNS42rXnKT5WVvJ14Jh3ZfefoE+1ybVSbjayUKfesPJGSMpOVks2hl+ZpVsraZWWnXVbyUnbnKB9KPivbSCvQixbjVfROdoja7GaGqnZl9A6HrHa5Jivlrl5FDWsKHjQWj4k9yTuLOdWTayXDSvWgBz3oBDOWd3mTdAFLAa1ZbcNg2m7LUD0sYLze+973PvEc4WQ66njPBz48fMkjKNLnrCvMlqycrc8drvGQc4fb/Pplww/9/ouGR/z9Ryf/t/3W81a76bW/q8ndzhmu9ZDzhre990PDhz78byvzzq1/9dLhU+/9kVzwuf2Y3PuS4W5/fvBO1hKipsw181dU3La1VsVxG1P6Uy+itVhYDIKJqV2r1qqTQdwfJmteBAIWg2CA6i+idjLM17g/jNJWfxaN6M98z6GeASeSeA795UWlB/ScE0ncn3wyNYYq/Sqq0HUJa0ltUakxWcfM3FUFv8ceBwlK9Vse/7wNkoFxuD73CjLT/Z43XP/nzz/R5yYK/h3v+9BqsREqecZ9LplvMgq5y7OGjznz7OGJ565P4D32OAxUFTzDv6PFAx/4wNUKZuWrmVPs9DHMtLEiHrWdrxUQa8393f/+99+avGQlZwfzXuw8WmlGtXMC0s51W+0cSzHrtPP+Wk4cOxcrely31e4442F/98pV6t01pTlX7nH+cONf+KiNeRsF/2mrnXuncidnnjP8p3udNbz0TUffMQ+iUYwn48q4bu2QjTdzSB4V4zWbU3phPhjvTvXYmNlM0gvOVPenP0zb2g75MOEk4v68ZyaWsR33rrGm4Cl32/+ywAWbOdtUaVaRT10QfkliYmvi0DgKYONCTihtVWx64anvhcUixxkjQ+XEXxzLOfqgZgtnI8y2fySQnCbBYpHbKXt2qin5//vCt6wyMnazR0Pucd7wZb+4GwX/6T0O31Lucf7wX379spOe66gC4/U617nOSeNKNExW3iJWMomJjTtndZwLyj2TnZChMpN1Lszn7LgNB+ZRgGyz2Ucg8WHLZr5rnKTgxW7mtAIhvMFWH0reCoShWqtyxJGBULFEnve5oBTRmvO9EdExairWTiQtsOllpR2CJh2Ej7F2lHy0491XtSm3IaIgYtHgyMrpB0Lkb7dzOUq+jG3wr+/54HDDR56/gZkmlOshK/i7njX8u7ufM/zVCw6P1zEXbOpZaYdwePLlgPHVqnlatpsL8fDZARxCyQsUmAvzl+M0px8I4RhtnUgOAqIDbYpbeehbUS+7RheTVU1A4T8C78fi28V11hwEBwW74DECk7jYnvj2OTVZYYoZS1kDU1b+rdbO0S7/VorFZJPIpqOKX37mq+fHrmc5bAV/r4uGb/y1S4f3f+joL7iUaR5LpcQpXIWv/FspPem3KeSpePmo3ToH5u8Uk7WVfvsgMIfJ+qxnPSv/2c7RxWRVk9XKJJ62Fd9JlLQ6zCMS80VOnl9KL0OVeQUhIvcTgnkHdkZjpQJVmYGpUnxlTdZaHp8QE/BUUvBvfOf7h+s89LzNyuodpoK/+7nDZz/gOcMl//LOk57nqGJKcUe9hmySzMI3NxdOmmNMVhuynqy15m+L+xH9HWbW2jlMVqlclsYakzXHgJaCSRU7+ByLWYqd/mHv4McUbe8Ofqoma+zgp5ixUWt1agcf7aZ28HLMnEoKHv7fi/51+I/3vqKg9ZoiHZPDUvB3P3f4D3c/e3jqZfXUs0cRLTNiCNMCiBPPv5XSU81sagdvIxOM1zmYs4Pf1N+2C/ABjtVkFfMurfPSOEnBuym29XwzcUMiQ3woqxMbUm13ydGKwXWYNnjxra1dSmSx7FGMHE9237kvwqYfA3OsHQdvtBMf3BrsSCXBPGWTbBUg1s4R9FSxwZd45D+86goF3xODftAK/iMFtz/3gecNT7748E6rm2AsqyPmadRQtWFp2czLdnOhdmsmQ4U4tbbi5mswf2tl/UKYobbNg78NbISlhmhZOjBUe7JTboq1KBp5iqWyLJW3KBqJ70tlot0d73jHk26aXUm7owAOjJybo1TGvfAxsu2S9z6HhnK05mRJHEHMNyVEIWQHaq0dR1FeDDi+clTOqYbHPfs1wyfc46wrYtznpAnYoYK/IkzS4vLMK669Epkp5Yp/zkqxf/w9zxm+9QkvWKUlPo4QHXPNa17zpHGlhmomMfE/5fQHHKyZyToXzCaZGct0k6N35sJ8zkrePN029HIXiPQH2dEqHUyr2MiusabgAT1WPClWJPaV6iK1qBPRNOJYox2ny1HaUVLKYnex+YR+bqrcA5SyeNb73Oc+q+dtxdUbrNrFdVvOHjuMsr8W89ROXrxytDvVlXtA6OTNH3PZFcqW83VsV71DBb8iOqnjKqJndZKg8J89fMxdnjFc9+fPH37syS9emZKOO4wj48m4EpeelXvAuMSaNM/VRu2JdqkhGKrmxxjzdC5E52CK6k8sfIuhelgQ7eM9e394BDlNwZKoKvg99jgqeMd7Pzg88bzXD7d49MXDp933nCt29ITCDwVM7nPp8MUPv+DE322i4KUq+OCH/224+5+/bPjxp7xk+F9PefFwr794+fBLz3j18DvnvW649F/etZavZo89jjKqCh7ZSb4D7Ek74BaTVS53dibt5Fhgrqi1mwvHll/8xV88wYztCZvaBo5zTiJx3UxeCoivx4zF+vO8mZTUCzv9sr8WeYmZhv9DO9+jVXjAzioYr2PM2OOI93/ww8P5r3r78PjnvHa405++bPie//OC4fZPeN5wk0ddNNzwFy4YvviRFw/f/6SPVizaRMGfKsobicn3Nw6Ml1a8ugpQxp1xZfxvanYJOBHEdceYsXMhuKHs76B25pyzrksfeC/b2sr15zuYm0zY25hn+B5YSpzo3Z/+cvm/EmsKXgJ6TKuSxMS2TpGXytsiwFZf2pY4WKU42ATMQrlggZh8jpQlIZwzV65hq8+2dVFBOaoAyWnTVLyYe7nCDdtktsEb1LkdG3xeXEymXNhAquDInX0qgjXw3e//0PCu939oeOf7Pji894MfHZ+nq4L/67/+6zXbunGRHY7aZRKTPOy53VywrWeHLF/UpkqZ2SWTmAROLE0Oom9yqLjyf5umF6ilKua73KTGK/2LRFpmp6SnBcbMqslK2d35znc+6WZCKHl2eTZ2NiSOgloUDaVsVemJorGDzimKQ4IZK4varkEptqJtePsjZbBBmtMFhHC0Omn0ROWojZkdsSEmXdj2TbbsYC3bxWIg33arnbQGhxkPfFg4HRW8LJI5/UCImPHLL7981W4sb7xxdNll89MtUDp8TK3+OFAjH/wcmEd8ZbmQdoh5uO1Jowb8HmGfWbmHYMb2pGcQRcMKkh2sIVIB9ziC9Uf/5tTDITbltRw8a0zWuXHwcsTn30N64+AdFcf6Q5xqrVDbYIp5+jVf8zWrdkwd+bdS7JB64uotHLmPUiIO3tEu/1ZKlOKbKtlnUpxuON0U/JyarBHfjj+Rfyulp3YrxdjaXIT0MF7No6mKTvmUuwvIDTNGTJK+pcfkyQwzFQffw2S1qR6r6GRjvXVNVkxWCh6TtbWSkF4mK5thq1IJucUtbrGIgp9TkxWU9Krl3QkxwHsUvB1K7qOUksmafyvFhAY7j/xbKUe9JusSOB0VfDZxZhENB3aj+bdSehIGUvCt021ID+PVPMrhw6VglLeizbYBBf+1X/u1a9cLUTrPRnQuKPiv/MqvXOsnpJfJqr+ta7JO5aKJHbxagmNM1t5cNIe1g3dUzdcqpWcH35P6YO4OforJut/Bt3E6KvjM+8gydwfPtDAXFPyYQib7Hfy6HMoO3q77rne9a9W2zgYvwsVAcvMcBbV2LsTR2muDb9WClWpTUeklbPCiWFqTgm09dh5s8K3arWyFHEI90UPijVt5Odgyw2Y+J5sksHG22rHBR7vTCaebggeO0+te97prY4AgMQXzlILMjtgQ46jHBk8fOGm2+jPOW1E8NbDB82llB2uIxWkpG7yFyE44X5PQEz0OYxtheis7WEOUMe2JztEf/VuznNDDfKeTNngQRaNxzgfPLleSmLTLaQ3QcnvsdyWE+uT87RaLnnwXm8Cilh2tPnJOfFSLojEIN813YVHLjlZRNFkZG1S5HeXOoVbCYpV3PqJoWiGVpzpORwUPoqYs6uU4kO4ihyxql6NotNtUeVo0cvoDaTs2LXfn9JqV/EFE0dQcrdIKCAnfBE7XpZKnjH/yJ39y4ygap6scRcPB2rJwrCl40DgqNYm39NC1HaqHliM+4sflmtiGyXrU4+Ap26jopN22tsBN4+BbtsBTOQ6+F6ergoccBy9qq4Zdx8EL3d1lHLz+4v7Mk02LgvTC/I/r0m+1nXEPhFxH3Dr9tg2T1QmHno24egq/pdyhquD32OO443RW8HvsEdgr+AWwz0Vz+Ngr+GnMzUVzWDBv4v7Mk1Yc+txcNKLXIgeOHXArDl1/kTvGTr7V7jDAkiIaKu7PiWDMfLRX8DsG5Z5t5hyx2exjsOb4Ye0yKamVTbJVyHuPK7BX8OPgkM3kJGHBR0XJM8/mWqu12q3MFTmbpHz3uZ2AidxOuGhW3mzmuYaqcOSesO+lQLkjkZYh5Wz6SKItJb9X8DuEnXZW7iEctwYjmETf/M3fvNaGcCyFg1d/2XEacirng98Fvvk3Lx/OuPclVxTxnpJ7nDtc/cHnnjYKXmBATisQYrxdeuml+U8ODGzMaiZnZRwiKid28uo6tKJeKPlIQSz9QCuaRagxR7B5lB2iuV3rZHAQEEXDD9fiC4lqrPkK9gp+h7DryC++FEp9Tru5cfCnYkWnXWG/g29jqqLTpvmkdoF3vetdazmVskR+pamKThEv//Vf//Vrv4Wo/IbIKAx7LA5etMph5nXimJUhIN9XCOLU2Wefnf9sr+B3CQp5rFRg1G7tqcmafyvlVKvJukuc/6p3DH9y6RuHv3jemyflaZe/afiHl7x1lbHydEAOC87Sw2TdNaaYrBRthP5O1WQNX9XYgqF28z/8wz+sFLxSnvn3kF4m664hwvCGN7zh2n2FCO2cZLLusR04Z/KLL8XAhamarNFuagdvJ7ZX8Hv0Ilcmy9LDZN015jBZYyeNaZ5/KyWCFr7hG75h7bcQC4EdPKLTrW51q7XfQ8qF5TBgBy9DQL6vEJwhNbUz9gp+h+AQbU0eJJBILSzeuJW/AyMwjpb6a9n0OVoN4L0Nfo9eGDfXvva118YUMd56a63uEhyJNkq5rF9I2MyBT6vVjmM0bPU1B2vIf//v/33laDWPtPvcz/3ctTbkh3/4hzcmbe0CFiC1rmupZKRROPPMM6vx9XsFv2PUardyaOX87Rh5Of0B5mlmqIoGyO0wFQ9zN7HH8QcyVE5r4OS4bfm8XaFW8JuSzY5EgQY52kZagRz1YnOVC35jzud2lHxmsv74j/94M0rlIGEREiKZmayUe4vstFfwC8BKz+ON0Xf/+9+/GdJoMmknJlecb0tp28kHQ1U8/OnMUN1jdzDejKddMU93DTZ088L8+Pmf//m10MeA9B7aiYGXMz0vAgGLhnh/7cSPtxIiCmmO/rRr9XcYcMKRrNB38ywc4l0VnfbYY4899jg1UFXwUmdaMVVSx/ySQOyDH1wPIXO8sbPUjogjPUpOPyu+VQ7LzXO08lKz1ZXtcrm+pSAeXpV6rDTXXiINag0XX3zxis3nur4b0ssepw6Y+XxX39d3vuSSS3KTRWDn67rG8n3ve98macr8Ms+0c8KNePUMZhVtPId50jphCDuOdnbeLTOT+R/vxamlFdde9jfWbg7suMXhe17Xdho5yBPBmoKX5YzNqbRBCRFyVCmVvGOBslNlOyFH2h0FsHHnWqvKZ+Xc1F62sMTcDtliSVhUZO8rr8sRtGmN17l40YtetBYOxtbZMiPtcbzAgZodj7e+9a2bCcd2BeM2Oyi/6Zu+aU3ZChHODk+2/6zkzb9MYhKYkJWt+ZzJSdrlVLy1dvRDZrKKIMpV7YSVtsw5Y6gxT4nCLDWH6BI4ScF7iKzcQyhveRkY+u3cW9VjOABkfuspgLFrGCytogaUtzzNMBbNYnBxaCxxIhGl0IrNNTnlzFgiOkYlrlYoWJmHfo/jCTvonAI4xHf3/XcN41Q0S3aIhgh5jKgcWWmzozMEuS92/JRxXizKdrGTF6+fF4sQ8xoTHBQ6yco9RACDzZbn0C6nKSj7y4vQGNTDeNSjHrVKoZ77IhzBLZ/CLnGSghdH2bohcv3rX/9ETVa7+vx7iMojm6x4u4KIFaW98n2F2MGCXWv+rZSv+qqv6irFNxdTFZ3sfIRF7RpMbflapcjNUUsLvcfRh+/WKl4T8tjHPjb/2dYwTltpN0IiRcdUu6itMBUHHyZF8zP/VkrUVsgn1lLoiTlMVjlfeoIb7NBvcpObrPUT8omf+InDM5/5zPxnO8dJCn6qJism1RI1WXcNRAgnjnxfIXbPwFY5VZN1iZPIVKoCJqMlFLwdT75WKQobLHFy2GN5zKnJGifXXWJOTVZx7dCqYkYwwOME2eJ+EAr5ODBZMU/HFozemqyb4iQFj+rKhJFvJuQGN7jBiZqsVqD8e9nuMHfwFPfYCQOzDQyA/FspivAuoeA5e/K1SmGTXELBm+D5WqUgh+wV/PGE7+b75W9ayqbV1sZgnH7bt33b2rVKYXKEsXZ2yJFW2wk2/16262Wyji0E9ETs4FvmS1IuLHNAwX/5l3/5Wj8h7PI9NVk3xUkKXjC/HMOYUfmGmG7EXBpIomx4hcuyfiEWCNE0FoLDAgeLmof53gjbXkTJaJfLBIawhXMILWGDH2O8YhhaeJYwlXC05dTDIRIZIb+08Oq3vm/4iae8eHjB69+Vfzp0vPJf37u6txe/cfeL8Rge/czXDI/8h8NjN2ZQVK3CzDYNSzhajVOmzhYzliMzbObi0JH5chtS1jytkZzKduFAdTJotXMaDRu3E3PL9m/+C7Sg1/TXsun31lC18PE5fNZnfdZaXxYp5U4PwsqxFkUjm5vwoNJ0QWlLzZnbCfspFwOODMr9KODNb37zKk9y+WIp7exItNLe4Q53OKldLS/7riHKJzuCOTqXzlhnEuVkTpT7P/7jP+amJ+HS17xz+I93f9bwdy86fEZfxkWvfsfq3p71sjbhYwnc9tcvG77mVy7O//lQwdyQlTyTx9I0e3bxXHjbJiZHqRjfuZ0oldxOyHB2GFPaWSlyLOeoIekHcpRKbdEQUJLb1fLQ/8RP/MRGNVQh56u3KbY5HiMn7RJrCh4obwpdnUbx8LkAdcBNCit62MMetmLCbVqAeilQ8o6lono8R6sSEnOSGrTaeI6cVmApmHSu6/4wWv/+7/8+N1kEogvimp53zlHxea991/D5P/Oc4ZkvXR/oz3vdu4ezXvHO5u7+tW9733D2P79jeO4/v31423s+cNJvb3vvB4fnve6Kv3vVv753eO6r3j286A31fl725vcMz37FO4eLXv3Ok/77pf/yztW9nfOKdbr2Bz/8b8Plr33X8L4Pfnh4+3s/OJz9ines/X3gze/6wOp3/Wib8d4PfGg495XvHM5++duHD314GH7oSS8cvvk3LjvxuxPEu9//oeEd7/3QcOm/vGv4wIc+au5yj+79hW842Wn/rvd/ePVenv2Kdwxnvextw7mvfMdw4avfOfxrkbpYlsvnvOLtw1kvf8fwT+nva+C88119X99Z5bCDgBNgXNO4bi0qUWvVfJNfpVVIm1Oz7K/Vzrz2vPrTrmUetmjEdYUv2tzV4EQS16U/8iLQC9fVH33KTLrpYrEJqgp+jz0yagr+Te98//Ajf/BPw7Ufcu5wi8dePlznoecNP/UnL1kpuMATnvva4VoPv2S4/iMuGq75kHOHmzz68pN22n92+ZuHz7jv2cP9/uoVww0efv7wWT9z3vDp9z9veMwzPxpCRkn/zF+/fLj2Q88dbv7oS4fr/fx5w7c/4fnDK97y3tXvYwr+je/8wPC5Dzhn+F9PftFw+yc8b/jSR144fPp9nj189++8YHjTuz662PzJpW8abvSLF61+/5JHnD98+S9fPPz9iz/6rM9/3buGWz3u8uFT7332cL2HnT/86B++aLjFoy8evvOJH03MdctHXzzc/onPH77ucZeu+njX+z+0usZ3PPF5w2fd7+zhZo++bLjyA84efvzJL1r9Bi94/buHW//qpcNNfuni4VaPvXi45kPPXxUh+X8v+tfV7y98/buHr33cpcNVfvY5w5c/5tLhC372OcO9/uJlq3eyxx5TqCp4tni7ckeJu971rivbOyfEprCiyp1wl7vcZbjTne60ijetgY0LozTaifqo2aKZGTDloh2mWA3BZI3nWJq81IsXvOAFq3qTWHMSBjlG1vD85z9/1cYzeN5WuyVRU/BnPu2lw81/6cLh9e+4wiH8yn993/DFDz9/eODfXpHFz67zU+511vArZ79u+Nd3f2Cl7O79l/88fN4Dzhle+uYr7OV/9fy3DP/+Hs8dfuj3Xjg8/3XvXu32f+ZvXzlc7YHPGd7ykV3s757/+tX/v+y171rZSt/xvg8N3/Qblw3f9dvPP+neagr+ze/+wPBZ9z17uOmjLvzICeKDw3mvfMfwcXd71vCg/3vFfb7kje9ZKdDfveD1K8Vp5/2wv3vVasF6zVuv8CV9za9cMtzwFy4cXvbm965210+++I3DZ/zMBcN3/84V9wBf8eiLhs/52fOHP7joDcNr3/6+gb/6f/zRi4brPuy84fmvf/fwzvd9cLjgVe8crvFz5w4/+cdXxGh/6MP/NrzzfR9aKXz9WuS+9fGXD+//0L+tnvVrHnvJcJNHXTT863s+OHzowx8e/voFbxk+6R7PGs6uPGsvjCPjyTwyvi6//PLcZAXOT+2MP+2M2xqc4I1jplvzc1ubP5t42R/eykFAGHNcl/7I5KpesIZ4d/SQ/Datk8gc0MNOH77Hne9859WJZOyEsabgmTVyuJWIGceaTZS8i2cbtxDLX/qlXzrJgWkRyI5HnmZHrlLJ19pxAGtXopaFkY8AeekoRIowk+Q81Wx1bIAlkD9yO2X9lma8ZmQF//b3fmi48S9cOPzoH714+PPnvWn440veuPr3Vo+9ZLjxL1ywanPvv3zZ8OW/fNFJ/bzjvR8cvvBBzx1+9dlXOKzs4D/t3metFGLgH1/yr6uF4YUfMdV81xOfP3zDr12+Ks5xxXXevLrup97rrJVyfNEb39NU8Hbwds9/dNHJtts7/vGLT9zn/372vwxX/7lzV4r5qZe9cfjTy940/NIzXj2ccednrnwO//yW9w6fc/+zh6deevJE+o4nPO8kE433cfc//6gSeu3b3r86tfz2eSebDH75Ga+5ooJUcYKAOz31xavFIN6FcWqRfOHr37VycjPveAdX+dnnDr/13NcN24xiyp2vqRxX4sqzkmeeNd7KdqJSspIXKZPJSdphTm8CSjE7PEXhZGbsrkF55pS86i5sopQx/2tkJz6ClhlpDPQvU08OAadfW+amkxS8h8jpB0I+/uM/frX6YGjNBcdJi3zxSZ/0SavMb5Q3ZdxqR8lrB9q1Ym7LKB8r7li7Vm6dgwJmXyt0i4MniCF2QGjmuU20O6icOZAV/Ove/v7heg87b7jd418w3PlPXzLc+U9fuvr3nn/1quH/nH/F4P2e33nByoRTwk71po+6aLj3X10xUf/s8jcNn3m/s4fXvv2jYaF/+8K3DB93t2cMl7/2Clv5bX/98uHmj75suMvTXOOK69z9L/95eNQzXr2yrTOfjCn4z77f2avqTiWYgK7/sPNW//vn/+6Vw1UedN5wp6dG/y8d7vpnLx/u99evWEXonPPytw3/+cHPHS55zcm2+//2O88fvuU3SwV/wXDvv/wo2/HCV71juObPnbt2X79/4RuHqz3ouSvFHXjCua8bPvHuzxqe/fKTnW8XvOodq5PK1z3ukuF//NGLh+/73RcOn3afc4bfeM5rN1bwxk1W7iHK28lVNNXOuHSyBGG/rXa3uc1thssu++g7moJ5KVCjxccRQrnpojEGUX/0R1buIfRJKxdODcKrpW3JaQpCOJZbPooa9CePTSs8XTRQdlRDN5PVDn8uzjrrrLXVppSb3vSmq3CiZzzjGaNx6ze+8Y1XC4F2tRDOkK/4iq9YrXKcPWOl88TPciQfFqaYrFG7daq0nxPKEmGcNVx2ws59hQJ69wc+PNzkURcOj/rHkwepHfrFH1GEP/z7/7SyR5fghLz2Q85b7ZDBDv5K93328Jq3fXQHT8F/wt2feULBf+//ecHwQ09aNwswtTBxhA1emb6M1Q7+vuu777s97aUrsw08/jmvXZmWMi55zbtWzlaK/cr3P3v46xecPPa/57fzDv6C4Z5/8VElwH7++T/73OEpl5x87V87+7UrM83rP7KoscN/xn2ePfzKWSeH4b3qre8brvlzzx3u8ecvPeEv8H6v/XNXnIA2VfD5ZJslTKg5l1OW2GBMMVRz/qcxYI6PEZPIEhFuzNK3uMUt1q4VQu/0RLixXNBvuZ8QerGHyaq/HB1VyqyarFNM1i/90i/tSnx/zjnnrCXuKeUrv/IrVwpeFEdrpSMIAxS8BWNsIcBEo+CF/I0tLHbPS6QgmIs5TFZwjBYzm38POciarByaTCLMF4F7/PnLhqs+6DnDyz/i7ORctdPkzASOwk+651nDUz/yN/yCj3nma1YmGfZ0WDlZ73PWmoL/+Ls9Y6W44Unnv35lsnnWR04P7OQ//ScvHb7o589b7eDtsj/1Xs8e/vL565sPZpDPvv85w7c9/vLhX97GLv5vK4X6Kfd69vAzf3PFKeKlb3rP8Fn3O2d4+N+/amU3h6dc/Mbh0+797BOLBvPLt/7W81YRLRYVJ5nPeeAFw3d+xA9wRZuTFbxIG++Cmeot775CQf/L294/3PCRF6x24q71hnd+YLjloy8afvQP1zMvstdT/E//pyscru/5wIeHX37Gq4f/dL/zhsdvYaKZqskaIdFMCfm3EOMyouZap+WQOJHOwVRNVoSjIDDtErg9iI35eiGHzWSdqskqd9ZkTdZzzz23eUQh4qV7FLwV5ZM/+ZPX+gmhuClkCr519CByOpiY2tXIVSFsiI54FPxYCgLHy8NU8AZ8vqdS2BrBBMq/lcIXUXNCL4H3ffDfhu/5necPH3PXs4ZfffYVR0GOv//6W5evzBe3+c0XrKJLRIKUoXw/9/R/Hq76oPOGr3rcZcOX/eKFw3UffvHwlEs+ukj88SVvGv7Dmc8cXvXWj5r+KOozzjxrFd8OFOFd/vSlw+f/zDnD1/3vy4cbPvL84UseefHwdx+JNHnvBz68UrQfe+ZZw28+52RbqZ3vVR/4nOF2v3HZ8FWPvXi4yaMvHT7l3s8evu23nje84SPOYXjS+a8brvXzFw03+6WLhq98zCXD1R9ywcoEFEpUCOM1HnrBcO2HXjDc4pcvWplnbvALF60cogFO2Tv96ckhiRYPCvw6Dz13+IZff95w9Qc/96Rr/8I/vGo4437PG77i0RcPt/m1S4ev/9VLh6/535cPf3DhG1bO3p/+k5cMn33/s4dv/PXnreLu7/iUFw9Xf8h5K0W/qYLPPqwswWWRmyj/VkqET4+lFiBOrHPBFDHGZCWRY2aXoODHmKz0Tq+CH2Oy0os2rHOhv7GarLhKkzVZKW95l2uJujgoxXD2OFrdFG90TSk7KfjwFLfjB491bbeKgRYDBMnhjne8Y9VMwwbI8ag/DgzkhNymbHdQirEGtrzW5GEGi2RKHEocPLkNud71rteV/GgXePf7Pzw85dI3D+e/6qM2Ze/bTv33Ln7zygHI6ZnBxPF7F71p+MOL3jC8/CPRMwG2/L95wVuG937wo9+D8qPkcyy6KJjfu+jNK5NH6ZQF8eRPufQtw0XJTs5E8zn3O3t42mVvWpmOfv+Stwx/88K3nNipl6CMf//CNwy/f9EbVyapjFe85T3DH1x0hUPZvXmW81750XfxzJe+beUPyLDz/vPL37S6d+/KCSAgdv5pz3vr8EcXv3H4vQvfMPzeBW9YvcuyH+/H+2OPh7Nf/rYVJ2BTGDctZcEsE1kYUfNbZgHjMmzSxmurHd9aTxy+eSluPJOhQpTt2zaqpQZ6TdROdigT+gZpsmbjboFlgt7KjmJCH4pcyqStMeivle2SvhZlVHO0rkXRcKJqXO6AHSd67Ggl7JQVHSiVMuWeo0XYxIX9lO3QfDPJSjs03/IBLQKR0CiATGAxKNtR7ksc7zaBRe37vu/7Tro/gzrvEixWuZ1amhiLe0zjDe/4wMp5+fsX9kctnMrgz7JJKMcV02BOYYt8Z9NRtmPiyVElFgO1gnO7TaJFANkoM1kFgPRYEDYBfZOZrD/1Uz81vOMd6/6dOaDnMpNVpoB3vnN9AzEHQr1LKwvTkfQyLYvEmoIHjSl0oYzCfMTBbhNaqCCsGxO9wlOdC0sH5rbj6LWaYcG5v1ZFIoNBPgj9SZXakyzoIGAyec54DpOuBu1wArCGte+x3Z3ueOt7Pjjc9tcvHf7+xVeYc/b4KIwj48m4Mr6ycg8Yl8ancWoetdoxoUZ/wpF7drw1CJaI65rDB1UJiT6J63ovPYElNdhURn/MX8xBm4Ie5pvTH/1MX44FjFQV/B577LHHHscfB6LgHeeYaST3kZXNLqBmA7czcNxg79LObqDWbi5UYGHb1584UatxDWyEWGZx3ZxYrRfi1zHX+AFcd1sGrThiZin9ub9sjuqFaKmf/MmfXPXnm0jYtMfpB+YI48k4wIzctnYrslP0x9walZwynKrNC+3Mk1bt1l3DqcJ1zXN6oadCU4boNacKZiP90Vs9ce0HhcUVPOWeSUxIThL5lA5b7XJ8rnaONZsoeQ7KXGCAL4FppzQ3KdeV43i1sxhsYpYyWDOJic+hVfB7CsgkmexU8znMhcVCeGrZH99E5OLe4/SA751tzaJILr30ZN7CXBjfOcQaAzuTkjgecztkqG3TGoyB/jDvc60LPoce8lJAf5jzOUJQuOi2ZqldY1EF72FbZIlIfxBM1lY78fG9aRLkrGiFbkmTgI4Mdu6t/OgGgxNED+OVMjZYc1+E99sOogd2VF/91V+91heJRaNnEbJzb4VuRXTRHqc+jJucViAECVBJzrkwf+WCavVncxKLBiVby49OkJtymoRdwPw131sETnoioobmQDQLfdTqr4wuOgpYVMHvismqBGBP/mTpSMeYrFGTVTxt/q2U3pqsUwQm8b09CplpJ/dRSi+Tdaomq6iHnvvb43gi1yHIYmMzF+bvVNz63JqsPYSoueCAHCMw0RMiduZCdB59lPsJocd6GK9LY1EFP8VkxfSyM7cQjDFZb37zm68ibObCCx4jTpU1WccWgt6arHbAY/0xGfWATTP3UUovk3Vfk3UPyGG3WVq+qhooeKaO3Ecpc2uybmp2HIMNWjaZlkJPtKL1arDRbJ2CCT2WQ50PE4sqeEzWseLccsdEqoKxnb4X2qPghTlJjpb7CfHBQaGAGmkqxE6/R8FzWo315zjYo0Cnarcya+1SwaOm99zfHscTU6kKeopzm79jiptEzpqxdubNEsnz7OBzNtZS6ImeAj9TCp4eO0rh2IsqePGjgvprTFa5ExzJKBTx6pkMFcI2bCfbo8jEyyIn5L6I8l6RT51jVzRJbkOQLCQ16nHw8qLnVMshUWu1BxzFrcmIpGIg9ShkDq/WbutGN7pRV/KjPY4v1G5tMVmNt56868YfZmyLyYp5Gil+mUKuc53rrLUholsEPOwa5i+Hci7XF4IM2VNrlR5iim0xXuXL35TctQQWVfBgBc3pD3jvs0MPs0uoYmniEC2yaQgfW1lmxn7hF37h2nFMO2FOZTuFgXO7ucBQZeoo0y4Y1FM1T1uwWOWkTze4wQ1mldmroVYLlnJnTtvj9IHvLXlgOQ7kqGmRmKaA8YphXfZn3GY6fm5nnlDuSytFu/SSGWvTST9syozNUUj0lpDPHkvDQWBxBQ9ovmLLsa/kSG45NbQTIxvMzp6jUw0+HrMExpec8i3nhxwOPPzaub9tbWgGq2Ou53BdjLxtUDJe3d+2O23xvyIL4j3XstDtceqD78v3F/KHfbqpcg8IljA+g3naChl0gjAvtDNP8iKwFMx/9+d5t2WUghN5MFTprZ5AkIPCgSj4PfbYY489Dh5HSsGzYUt0xn7ONo7xWot/ZyOUpTKYmHYBPbbyTaFMGcZfXHfTBGwBce5lf3wN2+Ciiy5avbvob4mohD1OHRgf5hmWtOyGUcnpqMCu2DgOpm1UkNoEfAWsCGzu5gjfYC1enY3dqT+uS8/UsmHSS07V3p/+6K2aD0E7ekx/TMGuW2O8qijlJBDX3RUz9sgoeLbm7GXn4X7EIx5xkoPVsS+3w3hVq3BJWFRypRkhoI62mwBzL5OYkKsM6k2AJJK9+8hQS0Qm7HH8YVxkRqmKRpsyWXcNm7Zcm+J2t7tdVdlOweaPks2h2Oou5HQF9E1mqNI3pbKljzDxP+ETPuGkdqLkSoct5f6whz1sLUKQr6Nsh4ylHGqO/NNuW/PVkVDwVtLs+Avxsh/ykIes2tXSCoQIx2RfsxLuGnbuOV1ACKVMyfcwXu2UsnIPkVrUTqPnRIKh2ipWwFG9bS6cPU4tOHm2mKfG0WH6ZMwj9vta3nOiZmzPTl5/dsZZuYfQJzZvdvi1AtllO4uBdvRRqz/pCkQNmb8PfehDV5vP3IaIZhPwYBGg3POiEoIZWzsZzMWRUPDC/cYqMIny8MI4cfJvpdiBiIrZNRQgyNcqpbcE4BRDFTNQfPFcWGByH6VECcA99oCc8ylLD5N11zCPWuk+Qnpqsorik34h9xEimobT13zDy8m/l6IGg907fZR/C8Fk1U5djbGarAhWF1544SqwRKW8/HvZ3zZBFUdCwYsyaa2IZG5NVpTkJRS8qJ9aLH+IfDY9hKgphurtb3/7LgUvIiD3UQpC1B57BFrcipAeJuuuseuarFMLBkUrdNNOGrEx/x4SipYeyqbQUugx7Sj4nNSvFOZdJ3kKfiz1AcvENvUfjoyCz3aqUm52s5utXqzY77GdvtwxSyn4WjnBEMe3HgU/VZOVLa9HwUtilvsohS1vjz0CU6kKhAwfFijklhmW4Kv01GSdSlXA7h0KvmU2JfQOCwI9JHVK/j2ESYaCZyoeK7pNcVPw+D9jJwJ6sad2a8aRUPDIQfe///2ru2SMsSjbhxmLDFWrGYupxpTSYwufC7YyHvCakkdiEl/bYzNXUxK5I/dFkE8MuB6GKttgJkOF3PjGN96YZLXHqQnjoaVUjKPseDxImEdIhpk0Rcw/USat+Poa9Mekk8v/EYsFslM4MukPZMjcjr5BYqKngD6qMWPpr6iNav4ic2Li53YWi/vc5z6rzSiTj2imnLqZODU84AEPqNZanYsjoeDBSovmWzJZvZzMZLVTlqy/XAx8lB673CbAUBNiVSr5SBewCSxWaNxlf+jerbJ9U7AI2amX/VksapXW99gDk/WGN7zhibFi3DDl9SjPJSH9QVkz1v0JH9z0hC4/VVnIO5R27o++wWSPdvSMTWUui6ddma6A0qaXcjtpUaRHiXaUts1sPvGLaiod3/qTAYCpZxscGQUP7FESbEUN1RbzFANNJEDUKOUkOQhYwdm747rbOD+AUi7728bWBiYnc43+vL+9ct9jDOeee+7K3m4McvznQtqHDZudqPHqHmMHvSmcjJmf9MUP1korwElqHkW7FkPVomGe0Vf0Vqs/J5Jop+BJq53+PK92rrtpoe8SowreMaPH9DCFXfe3a7i/HtPIcUY8666ed25/c9vNxa77m4u51911u6OOuc9BD0y12WN7VBU80hHG1R3ucIeVTU485zbx5XaWmHLRn3j1nuyQS0OZPWw+mSCZTXrSpR5H2NmrJckP4JuEj2NTcH7rz/vTX2TrzGD7lYjNdf3bEw1RA/NY9OfamyaI6wUnn3Hiup7bjq8GNl3vI563ZX6TuEo7z6Cm6bYnubmw63RfnoH5UdjeNkDSi+dgTmnVeLWLpge0wwRt1W7dNZwE4nuwvdeyZkat1RhX2m1CrjoqWFPwYcsNW9CY3WgOMMAyiYln+MEPfvBWi8auoFwX8kR5f0KdJCQ6SovQrnDBBResxeey/W1aTYcykt2y7K/mO7EI5HZsnZv6TkRe5dSz17jGNRZX8jkrIeE7cfwv4fmzw45PJEdE5KyExHtSS2Ep2DlT7lJ2l9c1LnrK9QX0x9STyUlIU2oAByINQG4nemVJBq0IGWSnXHxItE5ZM1aABuZpJh1hvEbK4+OGkxS8nXYrRpZTQs72HiVPubfyj1s0HvjAB3b1t2tgqLZiZCl5J40lonIOC3burZhbSr43Fw4fRCsag2MpTgaU2vWvf/21NkQ0Ql4MpsA3U4uyINe61rWa2Uq3hcWodJiVgqwSO3ntalEWxGIQSl70RC2vOFkyPz+mdKs2KrJPD5OVqWWs1iolHzlu2Jezkg0Rg97a8W8D81fmyhaj9La3ve1qJ+85pB8Ya9dTu/Wo4CQFTwG0qLrEJO0J2ZmqyXqTm9ykq79dgykh31MpvTVZjzp2XZPVbif3UYrjMEjDnH8rhXmgB0LMch+lOFYvAf3ma5XiVAqtYjMhdpPQCm0NUdx5CeySyYqvMRa3To56TVbpwaeYrEIqW0EfRxknKXg5TXIColIcMXsS5M+pydrT367BljpGnOqtyXrUMVWyr7cmqxNO7qMU3AGgMPJvpfDP9OBnf/Zn1/ooRbjtEhAul69VikRVc9pZaEFMd/6tFLlRlkDrlB7Sw2TdZU3WbX1BNeySybptnYjDwJqCz/axUjZR8GM1WeWO6elv16Dga+SqELb500nB23H3RDlRQLmPUuYq+N4d91FX8FLM5t9KCQXPoZp/K8XJZwn8wA/8wNq1SulR8BSj1Bq5j1LmKHjzcAkFb/7OZbKO5ayxAB1UOPYucZKCF+/p2J3TVhI2WjGcPTZp8eqcsyV5KYQjzgft6W/X4FA2GWu1YJEsOOx6FN5RB1tji6Yuv0avY0/0kWx3uS9isoQtlyOLoyq3iXY2Fj3guGsd96V0XiqvOQdk67gvvYQU0NGOeS+3iXZhy2USbbUT6FA6AHcJ0UzMo/maxCmux6HoxMfhjTGd+wrmKeY2IC+1asHaDOwi/3mG+7ORK0lOIRYVZCdMVu1EddXa0V8W96XLCi6BtSiayGHs6BIPyIHy5Cc/OTedBZEybJOZoSqE7CjAEY6JoGSA+sjHcbWeAz6PvIPbNHoCLJJSpJb9Mb3JT19C/uu806PcNw2Ro4TkBy/7k9J5aUcYpZt3ehavnNLV82flzZSRCzxbrLLtV9TZ0qQji2p2uP/QD/3QxvnHRUll5e2EkpmiNYc7H8zSJ3nzuVTelLtQ8EwmouRLJqvNn+Ibx/Ukv6bggV2NA/K3fuu3Vh73bZ0LHB0qkWOH8bgfNVuWk4awMffneLpU9MJRgdqbmMDiln3jbaMX7NDK/rJyDzhBBEPQv612c0GZu2bIUjveDCF9wQAlrdwtlHf5vLUKQqCd9+YZMEqX2MnWEExW9+ba+C/bwIkk+jMeWjteobXeiWuK3FpauQeCyer+OHRbDFUnnHiOsXbHAVUFv8cee+yxx/FHVcEH81TyIcKpVQsXdCzFAGXXZTPEeD2Io4ydGtteXJezr1a7ddew08JgFIXguphxtagTO2Isvbi/Vlk/pCOOzejPaekg4JjsOM5U4/s6XW0DO54f/MEfXD2H/pZwltXAR+KansO7bsW//8Vf/MXqd239i6xUg+N5tCNygxwEOCG9N9f0XVqM17mw6yz725YZa7dtfOpPaOem5rwAJ3P0hy26zQkSeUqeF/35dvTCpma/HjA9c6rHdTFyayc07YS7auebMEf1+Di2xZqCp9wz85S9SuxxqeTZErPtVTsZ0JZkqHo52cHGKfxzP/dziyp5pKjMeBUhJKa5ZLxaBHL5PKGijoalw5Z5IueLxkFwNKwtGruCyZkdbHwsHOibgPLItlfMzFa6gl2BY+/a1772SdfFHM3Km3kR+als5+84/Er4u0xOwpTNDNVdg29LWcXyupsyWY0bJp4cCcfHwhzTC+OVcs8kJoUsbE56oT+bnVxrla9iEyareWf+ZeapeSoAYCkwYdvM5pqsCv+U5jqbXZvjHLTCF3VQSv4kBc8224qKEC/Ok+wjUe6tkCcPYzHIaTN3ATbXb/iGb1i7JkGo2jZnTgt2BFlph4SSB0q71Y7ylv4ALrroolWIaG5DrnSlK612OEtE79SUcQjaOuXQs7hQfq1yY5R8LzN2LmrpAkI4yMKBbweelXaIxSB26NqXjrVSpD9wAlgCdtpZuYf4Tq0cNzWEcm/xWPTHEToX+rMpUXM490V6Fw39OWln5R5CyffkwhF9ZwfdImaKaS/TJOwKlLsc7S0CZyh5i8/P/MzPrCn33G5prDFZx+LWeb8pULvAsdJ52m3rsKlBcqla0Y0QSpPDdNeYqskqNA/kFcm/laLWKkyV7OutyToXc5isPQvLXCbrrjHFZA3ilImYfyvF76B9/q0U11sCu2Sy+m5TBCamjLmgQKcYrxzDc+H+jOvcRyk9TFbWhLGSeGTTyL8xiArK0Uel2Ajb+EzVZLVAHEQwxxrRqbUDIIhOFI+VdmwhEBO7abjVGBzLx5inwtdyWNYuMFWTVZgcWAhq1aZCnHqAjTr/VkpvTda5mEN06tnBz2Wy7hp2RvlapQh/A+G5+bdSIrWA9vm3UlxvCUwRnXqYrL6bGPbcRyk9WVLtQHM4bZYes577wwHIfYQIow5C1BxQ8K3TfPS3aSK7MYiomarJyocyVZPVyWNb38gcnKTgHbnGFLwESHbwFPxYkewlFXzryEMo+CVCmhzRxxS3gQsIFWPtxEGDUl75t1Io+CX8CVO1W5dKVbBrSFKXr1WKpHjwkIc8ZO23UvwO2uffSnG9JbDLVAVzFHxPrVUKnuM89xHiJC20eC7s4DMPopTeVAUUfPaJlWIeLqHgFevIvrNS+AOiJmvLXEv45Q5cwQv6Z9eqmV/YCkVbGEgKxdacDASJialiCQUlXtZxubaLZ0MVVbFEil+LFTp9i/Fq4QEVZ0QV5TaEDTTaIbHwpuc2JLII9ijaueDYEVWRr0mYt3qyCMIYM9Ziu4kjbg6e//znD9/6rd+6dk2C/BRRFBzjmQwVwlzgd9BetsDchjidud4SYOpsFXpmbqnlKx+D79cqCM0c1OvYY7NvmSMsTnx2PUA2avmAJGjLJLAxWDD4UDJpipinyue14vC3Af0i+2nNB2SRshlgRTB/W9lH6VfO1yXMyRlrUTRMA5S8lSjs3RxmeTUMxitbUrSr5QHfNayM0h94SXFdDLWlQ9osalHwO64r2iHb0SxCBqtFKNoxbWXlaRAoimBQRDvKfekye5isQj2ZnGLBotw5fjeBSckxr794Dg6zpZRiQIguJe+ansO/fCGZySp0jUOrbEdpZweXv5OUKrcLmv1S8J5ip+ea3qOQuh5lV8LpOpixnkN/TG9qAG8Ci1AsGu7P+Lc52TQLrPFtPkR/5on5sun9sXdH7Vb90QvSD7TK4u0K9E0oedfF/KeXcjg58y5HfdnuoMLJYU3BAyXPnoyNxpHSKizNzkShB4uxx+u/DXw8pwlx48wOWckuBSsuB6loBe8lK+0AJc9h5P7YvVshb3b8nkN/3t9SO94MobDBOhUGt23uFjs5x/V4joOIQwY7XNckxmCr8g7ehOeM582LQEA730w70ruD3hRCBOP+PMe2TFbfM/rzPbYtpG1c6st7Nv63rY0qCaH3rD/FprfdyZpfntO7Y+ZZWrkH6Lv4ZsKCW0rbySUYze6v1W4JVBX8EnBkcbxZwoSyCxz1+zssxDvZ1XvZdX9HHafb8+4a8e56orvGEP1NmUDntts15l53bruqgrfiO+YE25FdqRbX7pjL5qwdhwynVT6iRDvmiGA6OqIsESWyKcTLqksZjEhpWmtZLjHuMO/YMz2vqISpFzwGTu2yP6v8Nv3tGmyw8W19t1YYm2Mys4/n0L4VDeEk6B0H63VbMhTnt2uGbFvjddcQpuc5Pa/nPmo5mObCbtv9e8ccub3ZP0sY39JHB8vWvKsxWbUT1ms+ujYzU82MaJ4+5jGPWb1j/XHs1+LfKUNOa+NYfyKYIvtnCaZnwQNxXe1q5kam4oc//OEnrsvM1DpBzgH9iqwZLGrM2NoJUjtRXcFU5hscO/GtKXjH7UxiYneTY5sdumyXw56iHdNNgGMnp4oVCXPf+973QI8qLfjI2dHFTsYPUSp5ZoecRVAkkTJftcVgCo7RN7vZzU7qT+hpTzWdJcHslR1iyFCZvCRNQS6fJxLL0bsEB3PYSkM47nsiJ0pgqGZyEh+QSKajAIucFNvl/XEILs2M3SXsmm1ikO/K52CT30TJhzLOIdbZBxRl9jKJyfwrE9RRxuZfJh2Zz6VSjnQBmfEqzDIc7dEf52fuj2+nVN70m01vDkbRrpauYAr0oFDdHDzCx1Qqb0Ew2uX06/RrS8mfpOA5lHL6gRDOGoQQH51yb0UxeGg34WVxFLXIDR7msJU822dW2iGUNycyWARyStcQg9WK3xM1ZHJk5R5iMiGkHOaRntLOyj0EbT128pT2GJM12ukvpwsIiboAPSgdV1k4vpZ29E+Bcvdc+d6INAnHIRW1HbS0Alm5h0h30RMQoD/zJCv3EDHj4Qtygs7KPcQ8DKVsfrb6KxeDnP68FCmm+V7cnx10Vu5lO0peO3qr1Z80KrWTQQs2zfRlK/xbf/QyfcCq0grDbqU/WGOytl4ssQObw2RVWNhRwqrcehHkONRkBbvF/FspKsbUTFMtcC7lPkpZisk6F1Iv5HsqxbEVHFHzb6UEk3WqP+a7HsjPnfsopbdC1K7BTJDvqRTv7aiDQtk1k7UVshqCHwJ2wvm3UiJibizOnETKilaRFkJhWnBt0FqbuBBOVe+lVtwkxMa1J6JPyDR9mfsJoWeZcm2EayGhIfR2LZhjjcmaEwuVIrxpLtHJymSHPLZgeKEHlQu6BgMgH3dKcYQDttMxJqtVtkfBT6UqWIrJOhdTJfbYB2GqZJ9YaXAiyb+V0quQp5isYqAPE3e6053W7qmUHgLTYYEiG2OyCvnrYbJS8NmkW4p5GCevbNIthUKORHFjRCf9RXbROTVZzbexhYDixlD1XsaYrMxAPb4WKV3GFgx61oaaWeiGN7zh2u8hzKK1qL6TFLyOppisXoSd+ZiCR46wg+fsGCu67Vh2mAqeU6515CF25sAUMabgDcgeUxP7dO6jFIzXw1Twjub5nkrhWIe5O/OpHDiOnj2Yy2Q9LFiw8j2VEsnpjjIosjEmK2k53WuYw2SNHXf2AZZivoYCHUtVoF1kFh07OVDwduZzim4LOvAcrUSBhF7sMcEhY7XIZNGfMFUKfmwhoLdryd9OUvDiR9m/amaVq1zlKidspYz9jpk1e5UsfRxdbFV28SJraoxXDjLtNnFQ7goYquxpNSVfMk+RMJCcart9pxo25p7oF74Ju7waM5YDS5xwT3+7BlueqJh8b4QDKxxiHEqthFkmX9hURVG1spTaXdWiHsbAxtnyFS3JPJ0Lz9Mq9IzEVIuOOIowDmu7VeMW2amXyUqR1pSU04BFPhIUmk+13ar5p13E4VP0yIa5nfnMjBdMVtFb2cFP7Mox48NMrF0OGCDs49KgBxnLxjCnqo7+6Lses7ONHD1YY8bSr/Ss9Cv0ARNWjRlLXzsV1vJwrUXRWKHCGRKMvlp0ghU+lHywIqVmzbVWy3baEA6yHjvVkig92PEcbF2ZPKWdCCGDLNpR7opnbAKLKVOH/uK9GPy1Y9ZhwOJHyZss8bwcV2XUAZiUQraiDbEI1NpRbtpFW0pw07zdogY4+uOaRLqBo6I8LUJMCO4rnlno3RL0+SVh90jJx3MYD0ICa8pkDoxvyjv6M+8Eb+QcUnbLLAbRzjxhesvh2hYD8zUYyPozT3M75pWyHaWNeZrb8bdR8nFdO3cmwZyGXDtKOfqj30Tg5HZzQb/SnzGWP+mTPmkV+ZM3wBYXm+24LhO4iKPcLrCm4EFjqyMnpLwyLSXm2OCCbMqOa1kpBihHil87jMdWu8MCZcv+F89RO+oAxp1VFPtUu22Zp8xT3p9re9e9O9mlQSmLCPG8vlurhipHke8bz9FiiooG0BcTlXfdajcX+nPNkFz4+rAhOsNzel7PvXTag6XgxGa8ewan+J4dag18fcaTd0O/ZOUeYDKO6+IUtBivfIL6MQaYZXIh7YD+9BPtWn4zJxfXdX/aluHhJQSluK4xT+FvqtwDFqG4Lv9Bqz+Ln+dwXXp6LOKuquAPExYXxxayC/Za2d9hmj22BRshOUzb/EEivtmunnduf9GmJ+x1F4hr7uq6h/kch3HdPeqoKng7IaFenH0830tVaMpwXFfLNK7LmdZaxeYAOYmNWH9ss+Jhj5KStwPARmNP5lgSvVK7PzsK5g3tvJdWjdfDAtslG7v740jrSSNbg92VED3ivWTSVMCpwTW186/dVA12YcaAdv7NZsSA01m00182Sy4F0Sjem2sql9kThVGDnCf68xz627bG6xwYt0hMvpfnMK4PwtwYpKi4LrNiLbeSzSKTh/kT7bbJmcR68aAHPejEdTHSNzU39oAepo89h7EqkKEW/x5YU/AaZxITWxQnY+voswsgEeSwJ/Y0VXd6IlQCPl4Oe2In4wQpmbaHBeadXPGFx9wkKe1pFoFcQ1UZNZEpR2GXxBGtdml5f8F43eQERrlnEhObo+No9EeZaFdjspYkJ+1q5fjYTpnGysVU/8hZuZ0U1LVFdxfwPBbDHLnGBrwJ49VRXXK7XGaPr6inXF8vjFflKDPpyPjehPE6F8FQZa8urys+vjR3mu/So+R2m5b1Y9phl89cIIEFzHJLgSk5MtqW1xWmnbOjBk5S8BxXrRAlBn3hcZso2yl4Ka183JS8sLeenbwoihZDVX9W3sNUjmz8rdCossYr2yJHU24T7Vo7/oOCnWYt6oBQWrLs9aCm3EOufOUrn4jiopxbtVZFGcROnh3T4pDbRLuIk9a+1S6iwpaADIhZuYeI+ugJtwO5jLJyL/vjkNw1IsdLKxy6l/E6F+avily1SD4iBDuUN4Zqiyma0x9MwWJBH2XlHkKP9TBZ58LOnf7Nyj2EhaLmgzpJwTMFjBGTeKE3zds8BsSFnIehFNElPSlApyow+agtB8tBYA6TFaZK+zkajjlYlsaua7KKQsh9lBK1VoWs5d9q7aYIUVGKb6omq1DaJdAKRQ3pqclqoR8jJpGemqxzwd7eSkcSYiHbNczfuUzWsfh2eqInSd2cmqxLRAgKDR1jvLZKAHYzWZcgJjnm50RApYgN71HwPNq1WP6Q3tQCu4aogHxPpbCfwlQRb3bOw1Twuy7ZN1ViLxiqU0SnfU3Wuizhu6Hg2YLztUrpIUTNBUtCNumWIqzSRg/GUh/QE8xwczFVk7WXyToXIpeiUEpN6O2az2ONyeoonP84xMrVClXaBggQYycHx60e+z+nX7a3leIYdZgKXuihONZ8XyEcY6CK1lg7aUoPU8EjxeV7KiVSGszFVG4b5BVw5M6/lRI7bnbX/FspkUxO+/xbKbEQ7BocZPlapfQwXtnzpxYMJpxdg6nEeM3XCjF+bWh2DQp+LAWBnXQobjbq/HsIPWFDOBc2mlPFtIMguUuwnGRfXCn0di28+yQFT4lyltTsWmyedpRLKBTHHpO7ZifjwPOhehx2XgbnbM1Mw8xkhT1M27W4cYw8fo18f8FkBaQYSrLVbgnbZg/GGK9OSbU832PgaG8xXtHNw1bKZ9NKhCW6IGyg2rXymmgXDjHtW3lSXGep6AjRHi26vd34WHREDRz3EuTlvihZeddbKWW3gXkkyVWNvm/cnnnmmVtXlKrBdSnSmo/KvLdol4zXmnnDLp+5r6dCFT3kZFBjxtJfNg1LWDk4sulfPqF8XYuUzVaNT7AWRRMe8dJpwiEVeR2WgqOeHVdpqpFidtPV0ArPmVqaanzkWsa1wwCnCduvnUbs0kUdZPKUHYPcJgZttJOkTSK3owBHRycJkVZxf5TWpiQmaRyEhAajT3+RMrUEEhblG4w+/4r+yo4myiVMCNGfv8s1TynT2OlFf3amQZ9fCt5TmBpc03u0aG7q6+JYjPoG8Q4lfatN/l3C6T9SYHsO49ompkUS2hWQMEvThfkujDCf0Nmny9TW2tEPm4Z/00tlugJ66yAi9Gx2y3QF9LSTXitoZE3BAyXP8SkumDnhoJinwYwNpmjNadADg4uZI5iYh73jzbDSY6QFs7O14zXZhf9p63tsEtq1JJxIOISDsbntjleOE885xXil9L2TkKzcA0LIgkHr31ZIGSVvzEd/eVFZCk4S3p9r2qVtm87AiST6E/4p7cRBwIkkmLueY4mdbA02RcaLb0d/tBYVJgz3pp0Iqk2Ve8BJO65rA9wT6bcN8Bpc1zemp1tpCqCq4JeC402PqWUKh9Gfo+Eu2+0ah3XduXBfcY979CPe365MjDFWdtXfXMy97tx2u8ZhzaFdX7eq4O1w2OzExLNhil7oiWLJsEPBKGXn1J8kP/kI1QPmCYmb4v44wbY5Gok3L/tjR6tR2kUZObZHu1a5PjsFZoZop/zfNh8NSSXYrvoT7lYb8OKcy3aHHSefYdfk3oixsC3j1S5RX6KO/BsFIzaFXVH0Rw6qMpTCGd6HazMntZx+nKS+a7SrxckbZ8hO+vMMrXbGhXEU/TFbHcRJnQ/PvInrmic15yCTA4ZqtDPvalEi5qlw0mgnsiybOUF/nPPRTkhpzczJtFu201/tZG33z88X7ei3bbKY0q/8Br4bEWJci6dnaqOP47oc62NlAtcUvGNuLa5VettN7HgcZ5nExM7oJltHqTE4/meGaqQH3eSIhPGaK7kgMfjIpV3L8TO3kwaZ3a1sZ3BlbzentcHaspONgVkpp1gNxmvp8OZbyI4kHn2hcUs4xntAmThK5rJ9GK9Mcb2Ln/4sFjl1qhqolH7voqY9c0aOIBNYwKHW299ceG6ciFwWz3sqmazaKXyd2+Uar9r53plRKvV1ma7AeMCEzpFrxk8rseAuYPzb7OQgDvOlZLxqxx+XQ51vectbrjZjZbsaick8Lc2Y4Y/Lacv5Ksp29Af7fU4LLo6+zI5qc6odPZbbbcJk1R9/XA6moDdLc6JgFP64qXYlTlLwlPu3fMu3nPTHIToV1tXDZJW6tRWrSimj3fbs5L1kHzn3RXw8HvGenbwseTXvP4n0n2ARyEo2hAc7wu30l5V72a6HuAKUdqvmqUlMyYNJ2aqh+umf/uld4XZLAPGjxTyl5HsqAwG7cot5Kl1BK3dNC9q3aqhaRFxvCcgZ02KyUvJRuYhy9x1zG8LRJ8wYagWyy/6infHQYp4aR0swXi2StcLXIQIMQnmPtROqHdFU5mernXkdO2/tsnIPEfJop2xxZFnIi0oIvWNz6TnorVZ/9F3PTl7kIqXdYsYKBaWXLcr0b15UQmzKa0r+JAVvt5hX/1LQ0nu8+0wLrRdGfKye1KPi23MfpSAg9MTpT9VkxZSDqZqsiBQwRUwS6tezG0T1z32UIqQQHMnzb6U4ph8mpuLbFY/ogd1T7qMUp80eTJXYc70l0CqWEmK3C8yl+bdSmOJANFP+rZQgOrVCTHN/uwQFOlZZiYSJLZ/4s0R8+1wmaz7xl0JhCqNk6skn9CxRk7UWmhkieqhlYquhpyZrLTQzhN6uRQiepOB1NMZkVT2lxzPugvkYWIpVtqc/oUljKQ0cuXoKERgAtVj5EKsxGAD5WFSK8Lw5/bGt9Sh45ovcRylKqgEbbv6tFHbOw8QU47W3JivbZ+6jlN6arNrnPko5LCar2GawAObfSvm1X/u1VTsZDfNvpQTRib8p/1brb5eg4FtcA2LezKnJSiHPqcmqvzk1We3EmbmYe1r5q0jUZPUcOCj595BeJuucmqzMVywTU0zWWpTgSQqe/ZgdM/9xiGNUj0J2wc/8zM9c6yeEQu7pz9Ex2+9K8cF7/AQGQOtoRGJnPrWwxA55qj+Ooh4Fz3QwtmAgwwATR+voRuzsDhNMSfmeSnHk7cFUCoJgvM6F9rmPUpZisk4p7jDBjdV4FXPO1ANSQ+TfS4mcMC1yGjGOor9dgmIcY7yaN5HUbSz1gXbhNB5LQaBdcHdaZmdCIdMrFHyLdEbonajJOnZyYPrq4e4IiQ3+QE30x3RFwefss6XQ27XMnScpeJ5hx7gazT/K8fU47DhR7d5qSvma17zm6ijT0x9Pc835QpiPfKie/phzOF+yU4U4hkVUgUWDh7vWzuobRyP9tcwHPk7tCDUG8cuYgLV0BWyCES2AiYdUktsQu5JaVMFBQjx5yxyBXFSLFhiDqAFlAnNfRBQRx34PtG/VeLXbXaoMIFtyS0nZ3QcDlCPw1re+9VobgsQUZCztWrtQiwlzACAl1RivxDhaKm4er6WmzIxvGRrD/KtdLaGXTZb5FWZYO+qaucQ8ZXePzSPTSs1HZREw/+PUrx3HdW5H33DmxuaRT6lmLtGfYIoeK4KFhcmJPsz9WXyQTulRG0MLYE59TehrZrVaOpe1KJrwsHPWuGEvSwrXHrtSiZIZG/15ieHw6YX+ODUdXXjPfXQfb9P+2LYc+b3M6E/NyEgXELCCamexinaOajnEy0s2WL30eF7takUI5sCiRskbZK6rPyefnOLUoJfWQDvXdX/a9Th8loRFiJJ3b57Dv0xbmypPyooPouxP2FiL7DQFf8eEUPbHtBVKcSkgcUnrENdlMnAyy/T5aOf7RztOt+zDEhAgmsP3j3aUez7ZRkrtaGfcGD89PrZNIBCBr8xzeGbzxHzJ92demTdxf+adIIoclGHTRMlHO3pBu0xiMp9txuK62omAy/0x1zBF6y/a2VTmsOlYDKIdUzTncE+QRwmLBkd49EdfMtHlMGzt6ON4DhYS4a6tCL01BQ+UPIem0DFsqW2LBXg5Vqnor2Yr6oGPInyNU5Njxo5kGxgMzCvRn0FYA2VrFY12tfhYsOL6EFh1mLTbMk/tCBw3o7/Wjrds57S1LaN015AewLsjxsJY/O4c2OH6Hp6XYMBuA39f9pfTGSwFJ4hgsbJDt5iswVCNdnkRCGhnfE61sxhEO+OlJ0BhG4g/N469Y/OkFS5tUxT357vUdqjAhBHt6IWstANMGPH+tGtFBLqu9+H+6MGW0qbHgvnsOfIi0AuLVTwHP0NLaWvn/bnHcPy2UFXwexwcDB4DkvTY548aTJZ4jqOIuLdd3V/01VISgV1f9yjD+I1nbSnF0xF24fFeNuHqbIO9gl8AVnbmA0d+Dh5hgjUyDxsi2y9TBVs0f0VtNeYLiHqs+mPyqi0GjpdC4KIdJ12t3a5hNxQsZdddIi1tDXY7rhnsv1ZaWrs29xX312K8yqNS9mcnVYPwVd8r2rZqvGoX1/WNewpLHDcEQ9V78azGa+3kr535oJ13Z55se6LfJShhdnnP4P74YDY1r4L++O/EqesTg7Z1Ap8Dp3RBCTGu1LAe8zntFfyOwdaXw5mCDFXuarTLjh92RoO/PJqZJLmdmFeLQXkktFiU2e1IMF5bR71doEZiQsoRiVFb1HYFHIbP+7zPO+m6SENZyVPuuZ3aq47VJfxdJh1pV6Yr8DxCV3M7JClH5rIdclKOIOMgWzor62HA+DJuc3AGW3YZWOC0kzPGEvOlNwBhCVDGlCfbdnl/HNLZ5zUH/AqRMbbsT7ROyYydC05j/pQcMcc301LyewW/Q4zVWuXsCsarnBoGf25DKOUguPAttJis2gVD1SLQasf5E/HUuwblXvP+E3G5S4TbgZ31GJNVThmgdHMh7RD/PZSy9q12UfAb7PBbPBHKOyoICVtttZPPe4mSbocFO3LjtUWQpLxjh2781yLqyFK1W+eCchehk9MehCBB9Sh5fj3BEbXIOyIqqietgf6Ewbb4OEhktYCFvYLfIaZK8UWt1SkC09yarMFkZRLJv5WyFJN1qiareOsl0ApFDVmqJutUO6F08FM/9VNrv5USC/ipgDk1WSOp3FhlJbJEab+5sDtupS0hQjl7Igk5tltpS4iopZ7kbvqrhXCGiLqpnYL2Cn6HYNsdIyax6YEdY/6tFOF+MJX6gD0PDovJKuY3X6sUMdpLYEpx77oma+QkmmK8MlOAnVv+rZSeWqtHHRS8rJX5GUuJ3EBTTNY4eR0GRBBFoZSaMLP0MFSFr46lPnCy7knsNqcma+0EtFfwOwR7bbbflcIBCo78raMWCYXMeVcjOYUEk9UOaay/pZisUwzVn/7pn85/shNMFeeWNAqmcuCEQtY+/1YKuzFMnRxCcYvrzr+VIm75VAH7u/GanzHEuAx/x1gOHKaRllP7IMBePsZktePu4do4EYwtGHhGmWszhqmarLOYrHtsB6tsqxYs5mmQohy3amlJCfJJZNXTzq6x1s7gCe++uOl73OMeVSUvfcM2UQBjUOOzVTiah38pkpX4+VZiLQzXcDjJrtdivIqOiOx72rfaIWdFvD5eQWu3arGNClDa1fKpWKxFPRxUpaiDgCgt47WW0MuuVxqIiMPne6plgzW+LbJLMWjngC+BL6u2S45MsD1pVYJLVGO88p/ZDGRy1xj0x8eTU24T/g/5g2o1O/YKfscQKYBJZ8U3wIPJmslO2jENBCtWO4M/FyHQjvKOdi2Gapl2NPrTbpuQrDlwtJXkqrwuh08tdekuQRlQyvFOCF9DJjuh8ed2/n8mE/k7f1+2U+whKx3kKsrb756ZWARyO88vLC7a+ZdyPygy0UED6c/4jXdnvDrJ5Ph/49t8ME60C4ZqZp4eFtjFKfm4P8rdSa8WvjwHQpfZzqM/tnInuE37s2hc/epXX/VHmGakiW5FrM1W8EL8fISSuHEqiGfa9GW3QCkLW5R0iN2u5S2nlOXP0U4CpZoXHMS+cvAIsbOKz+1vW6boXNjZGMhxXTv7gwAl7ZohrQLZ/rv7ivsba1f2lxeBgLQGvgN2NsnKPVC28+1a/Z0qsJnwvJ4VE7O2owQnHPPCOzZPpshiBw0hjDFe7Oq3JW3JBYUp772YJ9syXjHtvT/3WLO7l5hU8GxsPhyHnp2ZXcmpJHJPIzY4Lh0EKei4oWSoHuT7OazrHmXYpcU72YVSnNvf3HaHBRu0uL9tlfFhYgnG66iCl+CIrbOWse1UEjHqyAwPfOADdzKAeccd4+WhlvhJtEbtlGA1x0jTjq3cUTAnF+qB45tQNP2Js0WG2kY52nFYAKO/ViEIzuBox1HlyLgNOOVkWYz30oqnF5aK5KGdf1uVocSvuy99+jeToQLK50V/5DCjOmrg1PYd3JvNVhS+2ASUNuZp9Gfc1KJEtBPWGe2ERG5T8cn4Nh/MC/2JrKkxXufCfBXlZJz4dnwkU7vaMciLIyw2+mO2K8sELgWmO5k847p8RHIFZWgnDNf3MJZtvMdyTjUVPDPAmFf5VBQMMc7PbY5QUp1m5ik7o8iPWDwoXe0yOSnIUL27EP1ZLGpMVmSo3t2ASU25ZxLTZ3zGZ6zSScf7iXY5hSkmq9j8Xgat/kRS5PJ5UdYv+qMktMvkJPZIyjwWU/9S5rmd/y90r2wnBjuTk7QT8VRbnA8S3rcMr7lsH4eb99+yv7ZgfHHyZXLSda5zndWxPzYF2tXK5xnfzBe9mwc7U1yBGuN1EyXPvMo5myPXco3XuaDchbjmIAn535cKVAAmWMEKOUiCsi+VtyCOGtlJu5avrargOYisImUnp4sYLJw+vUoRRAnUvPCE0yniru0wWqQFi4GwvB6lInyr5q0nJpN49R6EIyf3RUx2JQKBcsHMzG0IZdRbGQizNCv3sr/YodcKZIdYDCh5oJxzWoEQ/71kqPq73Ia4Tit3zUGhVaOB+E5R4Wgu7Nxb/RlHsUM3blrMU/UXeog6QLnXajmQWoruMVj0bMZatVExynuyzEbQA0do7ovIY58DJXYBfgrpB2qRckR0En1sUyOYISv3EPq65sNbU/BWglZxgdNFKHnHtFYa0xbmMlnntOs5Rdjd5T5KkfipB1Ib5D5KUYwCpuLM73CHO+SuR+GonfsoJRiqFuD8W63dFCGql8l6WPAe8z2V0puKYqyyEomFeSy+nSDYzYVTxhTjtYfJavc+VlmJ9CzMu2ayzsVUTVYbw6jJ2toUEsSpSSar/NdTBW9PF7GSO/71HEOlFsjHu1LY5WEOk7VHwU8V3e5lsgrjyn2UEkWyp2qt9jJZpwhMUWt1aiHYNZMVt+EwMVW7NUr7zcVUTVaJ0kDN3/xbKS2fRw3mUY0bENLLZKXgp2qylonipjDFZLXDdrLdNebUZHUSoeBb1gHCvMiCkHGSgmcXzna501m+8iu/souMwMTQOoIS8dfANNA6kkW7Hvs15+BYf707aQtGzlhXCjslcLq2jozkTne6U+56FEwHY8zdYKiyC+ffau04B/NvpUROmLlM1sOC95jvKcR36jWFicfP/YQYR6G4xxYW7SIFwRzYwbfIZMS8CZPZHFB4YycCppsouj0H5vlYcW6myR4m61wIsR07OchIyv7PH6ISVv49hGmzZpI6oeDF7IoyGNuBnm6ClGDyz91N2wXYXdbeocUiHD9oxy3GKyarD9pzcsAURCqpKVu2uVblqRYcG3nqa/2J3ohUp058yrzlNkR0RMvx04L4eYzQ3BdBcw+GqrHaKhxdMlS1a+1WkZiivJ/2rXYWx1e84hUn3edBA6mtdrL2fXyn3rKCxkMtgEJ/xlGUAdSuxlA1bkuG6lwwNZgHtf6Yy3rKBZofTBI1pcesYVHuYZ5agES/1XbJlLvNR89mby742ji2a+YXficRaU4rnlfUFEd4bmdTLqihRhY7oeCFAmVv+V7OWIVz9djiRQoYrFEz1k6HrTAzT+1A2HbLWrCOiLXQqDlAcpLLmvMsrmsS1xwvc8Czb+doZ2U3pD8hnZnEpB3PftSM9Rz4BZvS8SkNStU1if4o90wSogyE8EbdUf8yRWUSkx0SU4N+oj9/l8lJ/o5tuuwPQ7VHSSwJ710oo+/g/rxvvoNNlY7FsqzxatwYP7ksnigOppBoty3z1Pim5KM/ysl86ZljJZCIytqtNmVMfb2RaAFWDCaTsj8RR9uEL8+BqCSO67hui6Ea0XLeH1+h4ADKvXV/JxQ8CnEOE9tEDDxKy4A5THEPLY94j1BWlHYPDH6rsrzfIk1aO1mTM2q3qjk5Fs86Bzzy7IRx3VYRgLmwk8NMdNQV695aLChl7eI5tt3x6o9DK9i7eVEJOEFE/VQijUANUWvVc/i31c5/L/s7qJqsc+F7+g6ew/vu2fHWoD/v13gRA5+Ve8D4jRql2m+6qAScAOO65knv/MoQ3VLWUN2WyyLve9wfhbpJRN0mwFCN64pQakXSsQRoZ0fv1JEXgRI7U/Bsp+JZea6tRkK3DlOEerHV5tjhXtlEwS+BqN1q8Rj7oHNRMkUPEnHNg77uYeF0el5mhEhnsukOeo/dYicKHmFHLPGSZIBNYJBR9OxxrXjeKdlEwSNtiBhgN3UMlgqhx2maYXfF9h1M0Rbj1cLmGB+sUk7EWjs7wGjj/pChau12DYu/a/L1uK6jZc3XoJ37i3s8qBqvu4Tn4qz2nMHKzWUCDxO+t3Hk/rxn42abKBG7XPPM+AxmrI1eBn+W+RDXNU964+mXhFMM02mMU76kyAK7JJyWmdziusyNOfFgtOP3inE1VeN1awWPTXeUPlANQcsei3BpSY+CN6kdmbLDhKmI87X36Ki/GonJc7AzhvNXO5Mpk5PYaj13LC7aWQSucY1rrPWH1LKUkvf+RUjkMnvsm+yMcRTVTqhpJh1h0Iq5bh1ZjxrcJ3KS2OTyOa561auuQvd2cQLbBsYN5Z7ng/FjM1FbdMdg3CAxsR2X/ZkHkolFf+aReZCZp+LAbYp6r7trOH2oYZAjyDhy+SiXuj9+rBqJScBFWbuV6VIEVK1dy7y7lYKneJYIHVoCBiFnSR6EU9Kj4GuFtENcNyoDzYWFM6cfCHEiobzBN6jliSZ8EVHYgr0zF8gOoYyixuuuwTaqIEG+JlH4IAgzYzVUKfknPOEJuesjCTt3z5WfgSgA7n0cJmrpB0KMo1pOmhYsZpS7oILcFxH1EZWLjP8W85R5l4PzsGCO1wpuh3C89kajzQG/Gb5IK8xZjixZYekvwQdZuYdwhNd8bhspePZ2H26bpEOHAS+J2aI1GGvSo+DFBee/L4WZpWcX8MQnPnGtj1KiJusU0SlqsoqXzr+VInRwid3lFOM1Kj9RFPm3Unrj6g8LooryvZcSC+5hYayyEmkllavBaWCq1mrUZB2LWyeRYuIwIMR5LB79sJisFhwEpq2ZrD0K3i7Q0es4wo6DrTA/U0t6FPwcJmuPgjcxch+l9NZklZUx/1aK2PKe+5uLqdqtQZyaIjBFu6MOC1a+91IwgA8TY4Qj0kOcouAxr3MfpUT2zikmaw9xatc4TCbrWLZeJy1RM/yJtRj9kMmarHMVvJUM+WEu+ecowuLUOqJm6VHwc5isPQqUs7F1dCM/9mM/tmpn5zPWLpisU7Vb7Tx77m8u7AjztUqJXC9yqozdn/jr44Cx1AfmT88OeQlMMVmdHOeCf6dFEov+otbq2MLSy2TdNYR+clrm+wpZismK3zFWnJupT/gkJ/bYCYN/a5TJOlfBh43uuDi8avAx7Srn2ON7FDxnCednTdlyhPhQPUCywXitxfPzogcpKtrVlCOzUJCseOCV/6udMpCY5P9fAgax/DW1NATMTBE3bzfDHpnbEEpk2/j6gwJmbC2hl+cXAZFJWwcN46bFjDWOeuLrbQjEjdeYscwLaixEmcKx2q3Mc4dJKqPPmEJkocz3h4zFP7Vt/H8NzMZM3Tl1OOF3khcoSGVOEDUzjVBwi3KNfNat4LHQWoSI4wTHmTm2+B4FD2xlwsDYxKz6nKHb1EbVn3QJBln0J5QqK2NMQMo7t8vkJM/C1OHZg5DGhlpz0OwSkfM6SGj+pdwziUmkgIgCbeI5tDtspdgLTF627nheYpHzHo4CjAvjw/t1b8aNk8emjFKbCFlooz/j32KR546oEPMh2omkMl9qyukwIFBCauC4P8rTyXIJ31QJhCoBGkHUpIuZyvJ1nSIoefennaAEJtrcLtCt4D18b+6LGjat8epvdhHOJ1zQC8rPl6VXwYPjFIcHU5APsm1tVJ52ETDuGcstK+2AdyMSwXXtClrpAvQnLE2UjnYtZueuEQxVz+Hf1nXt5Nxb3F9OP3Bc4L7dfzzLUSu4LReP+zNejJttlWzurzVvjF/zQjsK9aCYonOh2FE8h43gNhyWHojSCQa3yKOWlQRz1/0RqRrGcOAK3o7US2MSkOdFeE+PMHXYgdrRbeMHWFLBg0XIwJi6R8c+uzqTfxcDae51tQkZg3uL+9vFwjoXc+9vDkyUeA7S2u3Mhf68j+hvzG+xy+eYC9+pvL8xxL3t6tvO7c/4nGpH8cdztAp4g760I2PtbCqj3ZQVIp6jpWQPE8ZbvL+psXygCh7Tlce9ZkfqETY7DgcmiU2PlEsqeCsr27cFTByro2ptgrOpOSazSzq2bst4lZ9Cf66rP+X/agNAPhaLpSO1BZM/otZOfg9t9CdhGh7BQUDUhevG/W1b41X8vH48h3+lV94GCqx4v/pzj63oD+1cTxvfuKcAxabwHYUCl/dXi7vXTjRZvBfjxulwUwRDNfpj46/F0xvf5oN5oZ15UnNeUsbRzrtzf7XIPacOmS2jnVDMWvk//TFBGcfukVmylj+d4ld3IJ7DRrTW7rDAP8JP5ft6Xr6esQSFB6bg9T/mLd5EMM5Efmyi5JdS8GxpmXTEmcuOXu4uME8ziYlTSrue6wVMzkxi8nyUfPRnUtfK7GlnssdRWTuMy8w8ZVcV4tfLyJ0L15WLvMZkFes/dSrJoEzYJ3PZPv1zSvUupq7PLup+cn+qEcUiqd2jH/3olX25bMdeSskvtSv0/Tj5c1oONXPL2q3GQy19h/GjXS/0JyNkJjEZ30yLAePf+M6RZlELNkDJ2rzl/pChSiXv9IuclIMaOCyDXAVOAApaZxKT8MSSXKU/fqIchHDTm950oxqvuwaTn1DmHEzBL8rRXcOBKHgrTC1v8y5EZIK446kjV8YSCp7dvXU6MQijRJxBlZV7iEFtJ9SjBEyOXCA7xGSi5KMdunxuQziUgsnqZJEXixDvrLeC0FwIp2sxXi0uUWloLoSPKpiQ+yLGei+xxvVbBXEwVKOCEL5BTlMQosarE9Su4dhu8W2Nad894riNh6w8Q4yjnnhv49R4zYtFCOUdO2rjvxYRRpB9Io7bzj0r4xDzK3Je2Wm3+rMYhH3aYpHTD4RgqFKOnqNWcDvEYrAEk3Uu6Dfpq7NyD3FSy4EXsLiC9zF2vXPP4uM5tvSEMS2h4KdqrToWzm3Xs1uV9yT3UUrUZJ1ivMqbDlM1XhXlWAJC6vK1SullsirKnPsoxe89GKusRIT6gSIc+bdSlmCyUvCIb/lapYSpa9dMVmaM3EcpUWt1ivEaydhqIZylhCmJWSb/VgoTI4zVmLbxYkryHLe85S3Xfg+hWJdgss6F+gWtzSNxWtwJk7VHwfOqj720XQolb0Ufc9qUWELBO363dgBEZjrYdU1W2RZzH6VEqcApJmso7qmFIIpu7xpTqQp6max2grmPUnprrbp+7qMUTFxgDsi/lbIEk5WCnyrO7bvCGDGJ9DBZmbluf/vbr/VRSvgoppiscQIy5/LvIea5uQtjilu7KNnHfp9/D3GSYS4139jd8+8hsRAcFkSgOZXk+wrZGZO1R8FznmR725Li3nKlnhaWUPCO3q2jKjGxAOO1dbQkdmI99mEM1WyHLEVcOTBJ5N9KiZww7OCtoyChwJYAJ26+VilRa3UuplIfhEKei6narezugHGbfyvFCWnXoOBb5RNDIicMBnT+LcQ46nFCG6djxbmN81DcYwuLeaOICUitkX8PoU/CKTu2EOgvFoKxVAp2vkxINoZjuXLwRg4z95bQ4TEmKxNcLWRyMQXP7u4I1bJ9LSE+gmP0nLjaJRQ8Zw77Zo0ha7cRNjwfy261ZgdFlx7ziteAocq+WVPy7j9Sjkbt1pp90+kibHjaOQ3V+rNbq9n6dgEVlDi5MuPV/6dEotbqXCBR2dXm/ixe6PqZZDUF16+ZQYKhGvNCO+Ss3M4udZMaqnMhfrum9HzvsoYqUlLNXBJ+oqjJOhds2DWzivH94Ac/+ARD1fgXvVVrx+kbPAFm3dpu2ny1KIcplkKr5Y/RDjkpQkTlc68pR/pCuwh+0E75v9zOIsDv1GMC3jU4yJ0gatlq+Zlsymo8hsUUvGiSsV3qUuJD1h40YwkFD3Y0BitnXNT2NFizUrRjYHPm3Ix2Bn8rr/MUhIGxKXum6M+ky/R+i59wsai1SjxjbueZKflopz87oTnffhuY5CKj4t6InV+v0gnoj+mp7I9yn4oPb4GSZPLyPqI/i1Luz3ui5Mvr2nzMGZvbAKmO8o778/0o97zpsQjZsUY749DJY9NKTJjaxm/Zn/GdTY0WIfMh2nFGlxFcAYtG2U5/ZW2DAL0liiTaYZ4K+81BCshBdEPZ7rGPfeyaSTeUfNmOT6IWRnwYcNpgi4/749yn3Fv3t5iCFymSw8kOQgyyOQp5KQUPBqvYWaFaPkhr52mys5t5V9r17igzhIsKI7O4sitmpR2gjBw3o52apTXYsUQ7ETgtZuyuYcfnGB73t21tVKQ4fYVsm/bA3/tevhvJyj3gvt1/XLcnx8s2MI7iur5f6/608xzGKUZp7zjPMM7jupi7rcXMIhTXNU+ycg8Yv9HOPGktPmV/FHReBAJOssax+9M2Lz4Bm6x4Dt+3dX+HBSchz+Eevb8xot1ewVf6KGUTBQ9eulU17yQy5rbb42jBNwvZFr69xZSpYIyJuQRc2zOMKYklMPe6u253GLBA+L6ktegthb2Cr/RRyiYK3uqKZSb23/tiEqntAlRFZ0PUzrFQVMdSJKI9dgd8Ad/LkZ84Im8KJgKmB/0ZB6LORFktDbtcJpS4Ln9ZjfG6a9iF8wOZF66LLVqLTqEItYv7M09qNV7FhyM7RTtZLWvM2MOCUxuTo/sjfGw1Z+hS2Cv4Sh+l9Ch4uwjKPZOY+CLYx4OM1WrHCSdS46BX+T3mgXISAZMZqpiyYr1bpoEWLOacfHkcsqvKjd7b31wYXzUnP4azSJalTpPGv3mQgxCQoSj5OA05xbQYqswmZbsaOQlpiglmF6erbSCij/8nR6TZFGDGHsRpY6/gK32U0qPgDSqDNfdBDNYg1rAXoo/nNsTgt5NfapLtsTnEh3P25W9GzB0VvXogLLTVH0avcNolUFPuIZT8NjlpWqDMjP9aBBcxb/gBYKydNCDyyoNw3VYgB0dk9HcY4A8TjpqVewg9GnUalsRewVf6KKVHwU8xVEUtwFQ8unYtB9Aeh4cpJmtvUXXU89xHKUswXqFWjKQU0SW7ht30WJw5iWRstZDLUpg2YYrJGszYw4BoKzls8j2FiNPniF4aewVf6aOUHgVvBzcW9z+XyardXsEfPUwxWSNVwVwgoOU+ShHutwTGSueRbbN31mAHP8ZkNW+iZF8tlj/Ejnguk/UwSwAK663F3oeIwS8Toi2FvYKv9FFKj4LnpGoduUnkesF4bR2Ro91S9tc9NgcSUP5WIezA7Ok9GEtpwKQnx9ASaJVFJMblNk7jFuzgxxivFF5ksvz+7//+td9DzK9glNoI5d9r/R0GhPoqq5nvK4Sf5SDSEO8VfKWPUnoUPCeSiIiaXZB3H9kCOIcw8rKzifCyI40chANmjz7IrfRDP/RDa98Mk5X5pje+Xtx4jZZvlyqCZFNy1xSMr9ou2SKFedqKm98WdEyrdqsc9hGEYJ60mKxONZEeXI3jFpMV8/SgQ05LWNAk/5KtMt8f5qk01nP1yjbYK/hKH6X0KHgQDmmwiqwQbWHHIdlRJjsxwWDw+djaYb6yPbbK8e1xNCDsje3cDtF3w3Sk3DdVinJ8Y7z6/vozZzCIN6lx0APkNjvgeA7jkA+hZ6xvAqQk8yGua56YLzk82CJkB1zenxNSPtlyVApJ1g4rVjpm7Y6KifP8889fhW/G/akJUNYOWBp7BV/po5ReBQ8Gq0iZYIC2lLZ+OVrE7YrxtUPc4+jD+Pe9fDfmgsi1simC8Rr9HVTOE+MtrjvGPN01bHaCCYx52lLGwWTVDpO1xiUBaUBK5mmrv8OC3FLBoBXZc5ARcosq+Ctd6Uprf7+0HAUFvwQoEUd2MjaA57Y7FWAXZEcdz9uaOP6736Ntq92pArvceCfbLj49MN7iulMFxnEKKOy8I8+Idgc5ll0znuOgFlugZ+K6Y+Ylp7s57WAxBS8nyljq3KVE6NScnchxUvDyWrM1SqrEM8/ZV9vNiJsu24mnr7U7FcBHIS4d89Pz+ldSqKy8tRMVouiMdv6VF/1U9XFQTqJ54nnNh4MIFzRH7nvf+67Gnesym0Q+9hJOt5jd0U4kTK2QBiXGDxHPgfHaU2lqU1gQpc12f8aUDeNBhDPSqZLgua5nZq51usnQjokw2tFPUeGqhsUUvCMVT3H++yWFc0omvWzPq+E4KHg7VMzCTIrilDKZwk6rncnEvle24+xlV52z4B0noPcrXsL+XT4vf4fIk8gQ6F/KPTNP/Z3FIWcSPO6g3C3+mSSktq7FPy9+u0KkFcjBBcYt0lTYm/kplM/LzNOrX/3qKyVftuPXyEzW613veitTx1L268g8mslJN7zhDVcWiaU2BZzzMqbm69K1HMlxXcnhhLjW2lHytftbTMFTiqrZj4UD7lpQmWurXg3HQcGzK7Zqo4rAibjrsRqq3r+cI6cSFKRo+Xf8dxWugDMrLwIh/rvC26cKTG6RWa1TM2ZsbUe9LSyS0gy3CvtgxkZuGGmLs9IOkbYj4sJbNQsIJusSDFWL1B3veMe1xSdE+oNg0O4SFhXhoy3+DLIUH4P3XFPuIbe61a2qqcYXU/Ag93PeVS4p3/Ed3zF7l3IcFDwFlO+nFCF2MFWyz3s5lTBVazUqTo3FrZPemqxHGRR8rRhJKUswVNnGa8VDStl1TdYlUjgwzYzVjhYKWzMlbQu61MY0Xy/ERs6mlVXCIpN/DzmUmqxuCmlCKFTuZ9fCXiZP8tzj23FQ8Eqs5fspBSEEHv/4x6/9VoowvFMJU6XzmAHgQQ960Npvpdh5niqg4H/4h3947RlLWaJUIAU/RjgiUnjAXCbrWBFvO1hEwV3DTnos9YGd/RI+ALqUCShfL4SOkpiM+W2sJquAlgOvyRpQdHfJiJpQ7j04DgregB8zcakkBFIf1EhTIZIenUqQo6V1VPXfkXVAMq+xdkvlejkMUPDKAebnDOmttToXomDGFhbjMnbcU0zWyDEzxWSNVAW7hGiUGvkrxA55CWernDU1UlcI0xrdbCFlhsm/h/B31ExIB6LgwTFtiZ28Y1XUHO3BcVDwnE0tu6rdUMTXR7ua3fI7v/M7m3H4xxXIQXe+852rypsdNcYn55X/X6vJqoaqfk4lqLj1Xd/1XWvvxCbBaWapkMmXvOQl1d25+YXZHaF8SEk184vxbTEOJqt2NcYropBc/NFul3Dyt0m0WczXtTllBl3iukzKTDC1xGRIWzbHETSCE3CjG91ord3nfM7nrBK11fTUgSl4YHL4gi/4gqZDpkcw/4QEuu9NcBwUPHCuUN6YfByIdhKOxLl8nnBIztSynUnXKsd33CE+mfL2rCFOKrksnsXPScfvJqp/KfeDjG8+SISS50SOZ+aLWDqOPGrBxnXpEgXo83WRnKTjCNYu5fSLv/iLa+04DC0G0U5/j370o2ebYDdFFPyO61KylPvS12VeoVvj/Yl8qjFe5a+R/iBY1CKQJDnM7QIHquCtVlZnccgUvRW5nKBzxBHNB9i2RiiHyXFQ8GDwY8PJ0WGXgeBQAyU/p92pAjsqz0qM39YOy85V5IVJ5N+ldrJHBU4mHG6el0I4qDBZBS58B9/DOGyRmNwfRaqt03crMMIJzDjWH71xUGGtmMWu6/6kTGgpz11DGKRrEgEqLWD4xv2JsBnDgSr4gA/KcSAsSnxpj7CDjT38XOhnLPPjUVLwYJKKe6fExgbcnHb+u8lDTLYWGcp3ina+eavocfSnL5J3YwET1O/RttWuB5415LjCe4h35920vttRh/s27nyLsUXFOIh2Y3PL+JvTn9/i/e1iUzP3/uaCicr8cX/5hFnCghjXHePyGC/akdacDHQreDbv474DMnB44o/LDt69Yq7d5CY3WdnghPfVlKMws7IdMlStHbuehZrdz3GvdYQX/RDtePo5L2vKRzindq6rv4c85CHVXZkMel/2ZV924rqSTNX6mwtRIa6pP/+yz9bIHkcZ3hM+g/fhGbzHJdL1Lg1KFkM1noMtuxbOSHHd5S53WY0n7TgOa2l9KTnhrsaxdvROzbnK1Mbkpp2xxWy7TbSLBUIN1XgO1gKs/E3BiYo85Xn1iblb4+pYAGQqjetKtFZLJ6wdUlQ8LzPWWI3XbgXvBqaOBUcdTgJiSrPzrSaHqeDtJP70T/90jcQkMsFkCjsyJfEnf/Ina8xh7YQURjs7BItA5iZEmcDYBWvH/seDX7Zz4qHkwxRiUeBXyeOG04z9NXZd2iG9ZSe7/vgXet+vXQszH5Nd2R+/jDSxU7uaowLvW0bR7JOKGq+1RfcowviSATOTdZCckKtisbd7VTQlk52iXSz2NpA10pGyfiXjlTLWLl8XaWoTxitlLA1Adt4LT3Ti7+3vNa95TZWhSoHTQQEmIZyW3M7GpazdyiQt5Dm30592NXQreB/HStM61h8H2DHk52rJYSp4g5SvIt8TMfiDoWpnwymT2xDfyw4dhKFlJRtCyVO2ID0C51duQ9DRRTzAU57ylGZ/lJYICrCTazFKLQaUcg+cGPhvcl/Ef1+iItEScIJphcF6rweRQ2Zb2IQ4UeY0BSFXvepVV1kUwaYkK6eQa1zjGieYrHgMY+2k4AU791a7khk7BzYjCqG0+pMmoRaG2AKzzB3ucIdmfzbKottsRoSFttrZpTNJ23TVlHuIEw5/QUa3gifXve51j3VqWyFFY3HjpRymghe3nO+nlLlMVlEVYNebfyvFwg3yueTfSjERgILKv5XiaApMJ/m3UuzCesD0lPsoRQjlcQAFkO+9lOMQp++UMUZMIr1M1tvd7nZrv5USRcFrxT5q/c2BU0MtRDKEYu1hsk7VZGUetmA4DX/Jl3zJ2u8hNkpzmKw2UDthshLx1pSGI8hxg93E2AvNcpgKfldM1lgIJOjKv5VC4YBEXPm3UoJgpbpO/q2UIFgJb8u/lSKxVA+mmKzMAMcBh1WTdZeg4OcyWceIRMwsToQwtmCUKQNkmMy/l/311GTFZB0jEvUyWSl4hT5yPyGIXaHga7HtIcyYzC8U/Jje2hmTtZTb3/72K/vRcYHkXTkz45QcpoJn2sj22VIcUcGJpEaGCgmFLF422z9LCcVoQo6dcCKHi5ND62hOHMmBSaV1tCTs/z0QN93yn/jvvcWvDwvs1vn+Q7zXSJp2lMFE46SW7z/EuIzUAmOMV6a1UNy1sogh/CzBKEXiy7+HiBPv2XEzqYwtVBQootFcWDDGTiJMr0I/mYbGiodrJ0yUSXzsxHLNa16zmjZ4KwVPjouSp9w5afL9T8lhKnjOK8f0WrTPt3/7t59gqBqc2tXsuex20c6go/xqi4Z2YXbTjtLNSp7ydGqIdpxm2tUYtCa9uN5oR9nndvrTrpeMJdzMYpSdcBYRdP3jwlDlNKspPe+J32QspO4oQdCF8Zifw7hVPi+c8mLea7tzu1TtwinPlqysX25nEeCvifko1r7WjnJnjhwLrayBDqwpUXpRBFhPKC7HqJ13bRePPOV0Hn7MVjvBEDZvETTAMVsz+wiuYI6qBRdsreDJd3/3d6/oyrULHDZ8ZMpdmtF833PkMBU82CHZsfo27GyOdrJDZi4CJ4yIjLIdM1pWdvoTCSMCRTuThgkn9xfMWDuX6E8ukRwiqx2beLTTn0iEHI+snXSxwcDTjglnqvJPC74JW3v0518nlePGUPWe7Fi9D8/hPTJBHbcgBuQbzGk7bM/BSc/ElMNWLWrf9E3ftFLq2onUYsLLpCibEu2MO+04nfmGciQLB6SQwqhpSylysud2c3H55ZevTD/Rnx20E+im/dGrCpZETVYRcZR27i9qt8Z1WRpqDFUhkaJmoj87d6ao3C6wEwVvJ8YBYGJbzTHaKIzDFDawpz/96auPlcMMe+SwFTyY7Jhrkv+z2yHD1MAeWrbzHWrwPI5z0S4r44Adi1hctj0OnLxYBHJ/eREISBugr2CU+kbbwMnFNUOmypcdVfhOwbT1vnt2ikcJxqXv71vQJ60wTyd+iko75ocWQ9ViEIxcCrC16PEFui6hoGscjB5Ip+B7EH227m8unHg9r76YZfKiF7BJjuuax6120kLE+6vlgC+xEwVfCkfAzW9+89VR4jDFaii+Nt9fr9gd9B71IGqjUmK7ONkY3PoZY7hBb7td3Bvsur+5iGuOXdeE9y2marLObWe36btqR1oT8bAQNVkP4/7iW7SUO7gf43Oq3VzM7c9GxHfzbmw2Dgp213Puby6MS/2RfPLJOKHgrQat2OLTVXjiERWmlGXGn/3Zn60YidhrX/qlX7oKA9xmV8a+Jh6Wt11/nHO1RQdDtWwnnrh2+hB+KQ5XO/coL3qt3VyI4in7Y9pp7bZ2BZOG3dY1Q5gE8oDXTty++4r7qzFe/Z2wz7Id00FuZ3Jh6nq/cd1tTAK7hnHBZBb357uw9y4NpyfM03h/zAi1MEXzQHBA3J/N4Db53S1gwnajP0zuSDtcgilQ1JJ27lFIpBP+0mBNYNqM68o5X5KcesGvxbkc/cm6WWO8Bk4oeEcHJIJWdMLpKAYBx1Ce5C04yiEJIXeU/XinCvn22pspHQzV3B/n4t3udrcTJgnt2OE4b8p2ImZEvEQ7uwd2vcxQ1V9Z43UuKHHKQwbLsj/OWUqwtgjtAhZc9ti8IRGxQXnHguxfSppds2wXzrqyncUiO5/ZQinvaGcRRN7KTm/9ceqNnSIOAr6f752ZnZxwvvsudo818HsYjzlSimmU8o5F16mW3yTrGO1sinpNIaHcc3/s0kiC0R8TmILW+f7wecp2u4bggRpDlWJGwurdFDAd8b/l/mzqOGpr/Z1Q8D6+whFzEnCdLiKtae2ltfCP//iPTXu/SRel5OZC3G1W2iGUMmccIH5kpR0i3C4qF1l8Mr0/RAQO5+vcxQyMl1Z/lGUwY3cN8fycTPmaxH+n/EF6hNZ49t/9Dtq3+rM4OKGARSEvAiEWg4PYKbfgu8n5niOfQnynWm6YbeFEI0KqFS5rcaFEQeRTVk4h5k0wXufA5kLOmBxJFWKzGsQfzvfWdTFea/Hj20LkkBKKretKf8D/MBc2aSIWW/2xGNTqYpxQ8MB4v0ko4akqolB6dmVMJLmPUkQF9CjQg2ayGpA990eB5z5KCSbrrjHFZI14/qmarJHCQfv8WymxQEqSlX8rhYI9LPhuYxWTyFI1WWuhj6XMZbI+6UlPyt034TQ1VmKPyOMEY3HmTrlLFCOfw2TtqRClvzEmqw3GKJMVfCxHpZyM6nQUWdpquR3GYEfbWmGJidCjQGUVzH2Uwj8AU0xWYawwtRCIguo5sUylKliqVOAUk5WPAqZqsoZCHiMckSBiTS0Eh0mwMq58v3xPpRx2TdYxJqt5E+3mgIIfY7Lqjy6DWnWoEJwDJ9tdY4rJ6gTZQ5zS3xSTVfRNxkkKPuCBdxGBclwFeWKTMneSmLWSahE72h4FbwfSMjEQdn3gzBprF4xXdtgaGYqwYzIh9dyfBaPVnwl2r3vdK//JTsBp2mLk+u/4AMCkMtYukpxpP9aOfR74FbK9N4Rp5Fd+5VdOus+DhO/mhNG6P98pdtK7BPv6WMoF4zIU7RjjlQmpZyftZF0rT1j2h/8C3/u937v2ewgTaI9paC7428ZOLExSkTRtDvQ3tqAxNQmUyagqePBRcvrZ00GERW6aSI0zzi6pljbA7qW3UAknJWWWnXqEJx25BOxmkKEyU5Qw40Q7dkFmlZpSdhrozS3EuSZipmYHNelFECwBzjW77nxaotw48SKu37+UXm4X/pCynXw4+Rm0Y18ORqk4b/bcrES1Q+LqdaLvGr5fTZmFP2QpnkA4//J1KXdO7ojQErNd28WbLxbHnmg1Cxqbc63GK6e3U21EcmG8fv3Xf/1aO4sAhmrPdefC/Yl7l+UxX5e/zGm/x/yrvyjrl/ujp20Ga5FrTQUPVlR2nxyFcCqKSBC5I5ANtgGPPCVvhfYhMfDQuHuVZ0B/IkOYzaI/kzgrTx9XugLMO+0wCbXLpKhgvBoU0Y7ttkVimoLJwYQR/dkRiVhYmmYvYoTJxDVDnGhyfDOlJsLDfcX9WRyCPh/wd9IclP1plyOLLGqce96bNp6bTyD3d1iIsLy4P+NGbv6lIkUCEb4X15W+2skncwlElpgPODfamSfmy6b3Z77ybcV1MUD5mnJ/TuTmt+saA9pxiveYJDeBxcXO27x1XYz6MebpFOzSLRqeV3/Xv/71V8q91d+ogge7Ts5DoUfsPF7QqSSeyQBhD8tKc1NQopidjmBSffbmWsmw0tsNRH8tZTy3nR0VJly0azFe58JJo+xvaeUeoGxdMyQr94D/LoxMG/+OtSv7a6U98HyeUxvPnReBw4bvWd7fNhyHHhhvcV2KqLajBPMh2pknWRn3ouwPAzQvKgEnc+2MAe1aSnHXcMKJ6/ZEzrQgW0D0J7x9DJMKPsDhGIVyTyXxTMchWdoee+yxRy9mK/g99thjjz2OF/YKfo899tjjFMX/D49SNdLSdCi3AAAAAElFTkSuQmCC
        """
        
        # Position relative to main window
        x = self.root.winfo_rootx() + 100
        y = self.root.winfo_rooty() + 50
        about_win.geometry(f"550x500+{x}+{y}")
        
        # Main frame
        main_frame = tk.Frame(about_win, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header (icon and title)
        header_frame = tk.Frame(main_frame, bg="#f0f0f0")
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Base64 Icon - replaced unicode warning symbol with base64 icon
        icon_data2 = """ 
        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"""
    
        
        
        try:
            # Load the icon image
            custom_icon = tk.PhotoImage(data=icon_data2)
            
            # Create a label with the icon image
            icon_label = tk.Label(header_frame, image=custom_icon, bg="#f0f0f0")
            icon_label.image = custom_icon  # Keep a reference to avoid garbage collection
            icon_label.pack(side=tk.LEFT, padx=(0, 15))
        except Exception as e:
            # Fallback to text if image loading fails
            print(f"Failed to load icon image: {e}")
            icon_label = tk.Label(header_frame, text="\u26A1", font=("Arial", 40), 
                                fg="#FF5733", bg="#f0f0f0")
            icon_label.pack(side=tk.LEFT, padx=(0, 15))
        
        # Title and version
        title_frame = tk.Frame(header_frame, bg="#f0f0f0")
        title_frame.pack(side=tk.LEFT)
        
        app_title = "IP Port Network Scanner" if self.language_var.get() == "en" else "Escáner de Red"
        title_label = tk.Label(title_frame, text=app_title, 
                            font=("Helvetica", 22, "bold"), 
                            fg="#333333", bg="#f0f0f0")
        title_label.pack(anchor=tk.W)
        
        version_label = tk.Label(title_frame, text="Version 1.0", 
                            font=("Helvetica", 12), 
                            fg="#555555", bg="#f0f0f0")
        version_label.pack(anchor=tk.W)
        
        # Two-column layout
        content_frame = tk.Frame(main_frame, bg="#f0f0f0")
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Left column (text content)
        left_col = tk.Frame(content_frame, bg="#f0f0f0")
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Right column (QR code)
        right_col = tk.Frame(content_frame, bg="#f0f0f0")
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(10, 0))
        
        # Description section
        separator = tk.Frame(left_col, height=2, bg="#dddddd")
        separator.pack(fill=tk.X, pady=10)
        
        desc_frame = tk.Frame(left_col, bg="white", bd=1, relief=tk.GROOVE, padx=15, pady=15)
        desc_frame.pack(fill=tk.X, pady=10)
        
        desc_title_text = "Description" if self.language_var.get() == "en" else "Descripción"
        desc_title = tk.Label(desc_frame, text=desc_title_text, 
                            font=("Helvetica", 12, "bold"), 
                            fg="#333333", bg="white")
        desc_title.pack(anchor=tk.W, pady=(0, 10))
        
        if self.language_var.get() == "en":
            description_text = ("A comprehensive network scanning tool that\n"
                            "allows scanning of TCP/UDP ports and ICMP\n"
                            "Features include proxy support, jump server\n"
                            "capability, and multilingual interface.\n")
        else:
            description_text = ("Una herramienta completa de escaneo de red\n"
                            "que permite escanear puertos TCP/UDP e ICMP.\n"
                            "Las características incluyen soporte de proxy,\n"
                            "capacidad de jump server e interfaz multilingüe.\n")
        
        description = tk.Label(
            desc_frame,
            text=description_text,
            justify=tk.LEFT,
            font=("Helvetica", 10),
            bg="white",
            fg="#333333"
        )
        description.pack(anchor=tk.W)
        
        # Additional info
        info_frame = tk.Frame(left_col, bg="#f0f0f0")
        info_frame.pack(fill=tk.X, pady=10)
        
        dev_text = "Developed by: lgp" if self.language_var.get() == "en" else "Desarrollado por: lgp"
        dev_info = tk.Label(
            info_frame, 
            text=dev_text,
            font=("Helvetica", 10, "bold"),
            fg="#555555",
            bg="#f0f0f0"
        )
        dev_info.pack(anchor=tk.W)
        
        date_text = "Date: Mar 2024" if self.language_var.get() == "en" else "Fecha: Mar 2024"
        date_info = tk.Label(
            info_frame,
            text=date_text,
            font=("Helvetica", 10),
            fg="#555555",
            bg="#f0f0f0"
        )
        date_info.pack(anchor=tk.W)
        
        tech_text = "Technology: Python & Tkinter" if self.language_var.get() == "en" else "Tecnología: Python & Tkinter"
        tech_info = tk.Label(
            info_frame,
            text=tech_text,
            font=("Helvetica", 10),
            fg="#555555",
            bg="#f0f0f0"
        )
        tech_info.pack(anchor=tk.W)
        
        # QR Code section
        qr_text = "For more information:" if self.language_var.get() == "en" else "Para más información:"
        qr_label = tk.Label(right_col, text=qr_text, 
                        font=("Helvetica", 10, "bold"), fg="#333333", bg="#f0f0f0")
        qr_label.pack(pady=(0, 10))
        
        try:
            # Create QR code image
            qr_image = tk.PhotoImage(data=qr_base64)
            qr_image = qr_image.subsample(2, 2)  # Resize to half
            
            # Display QR code
            qr_display = tk.Label(right_col, image=qr_image, bg="#f0f0f0", 
                                relief=tk.RIDGE, bd=1, padx=5, pady=5)
            qr_display.image = qr_image  # Keep a reference
            qr_display.pack(pady=5)
        except Exception as e:
            # If QR code fails, display a text message instead
            print(f"QR code couldn't be loaded: {e}")
            qr_error_text = "QR Code not available" if self.language_var.get() == "en" else "Código QR no disponible"
            qr_error = tk.Label(right_col, text=qr_error_text, 
                            font=("Helvetica", 10), fg="red", bg="#f0f0f0")
            qr_error.pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg="#f0f0f0")
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        website_text = "Website" if self.language_var.get() == "en" else "Sitio Web"
        website_url = "https://www.leonelpedroza.com"  # Replace with your actual website URL

        def open_website():
            try:
                webbrowser.open(website_url)
            except Exception as e:
                error_msg = f"Could not open website: {e}" if self.language_var.get() == "en" else f"No se pudo abrir el sitio web: {e}"
                messagebox.showerror("Error", error_msg)

        website_button = tk.Button(
            button_frame,
            text=website_text,
            font=("Helvetica", 10),
            bg="#4CAF50",
            fg="white",
            relief=tk.RAISED,
            padx=10,
            command=open_website  # Add this line
        )
        website_button.pack(side=tk.LEFT, padx=(0, 10))
        
        close_text = "Close" if self.language_var.get() == "en" else "Cerrar"
        exit_button = tk.Button(
            button_frame,
            text=close_text,
            font=("Helvetica", 10),
            command=about_win.destroy,
            bg="#f44336",
            fg="white",
            relief=tk.RAISED,
            padx=10
        )
        exit_button.pack(side=tk.LEFT)
        
        # Footer
        footer_frame = tk.Frame(main_frame, bg="#f0f0f0")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(20, 0))
        
        copyright_text = "© 2024 IP Port Network Scanner. MIT license." if self.language_var.get() == "en" else "© 2024 Escáner de Red. Licencia MIT."
        copyright_label = tk.Label(
            footer_frame,
            text=copyright_text,
            font=("Helvetica", 8),
            fg="#888888",
            bg="#f0f0f0"
        )
        copyright_label.pack()

        
    def _update_widget_text_recursive(self, widget):
        """Actualiza recursivamente los textos de los widgets"""
        # Actualizar LabelFrames
        if isinstance(widget, ttk.LabelFrame):
            text = widget.cget("text")
            # Intentar traducir textos conocidos
            if text == "Configuración Básica" or text == "Basic Configuration":
                widget.configure(text=self._get_text("basic_config"))
            elif text == "Puertos TCP Comunes" or text == "Common TCP Ports":
                widget.configure(text=self._get_text("common_tcp_ports"))
            elif text == "Opciones Avanzadas" or text == "Advanced Options":
                widget.configure(text=self._get_text("advanced_options"))
            elif text == "Resultados" or text == "Results":
                widget.configure(text=self._get_text("results"))
            elif text == "Idioma" or text == "Language":
                widget.configure(text=self._get_text("language"))
            elif text == "Apariencia" or text == "Appearance":
                widget.configure(text=self._get_text("appearance"))
                
        # Actualizar Labels
        elif isinstance(widget, ttk.Label):
            text = widget.cget("text")
            # Actualizar solo textos estáticos conocidos (excluyendo valores dinámicos)
            if text in ["IP/Rango:", "IP/Range:"]:
                widget.configure(text=self._get_text("ip_range"))
            elif text in ["Puertos TCP adicionales:", "Additional TCP Ports:"]:
                widget.configure(text=self._get_text("tcp_ports_additional"))
            elif text in ["Puertos UDP:", "UDP Ports:"]:
                widget.configure(text=self._get_text("udp_ports"))
            elif text in ["Ejemplos: 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24", 
                         "Examples: 192.168.1.1, 192.168.1.1-10, 192.168.1.0/24"]:
                widget.configure(text=self._get_text("ip_examples"))
            elif text in ["Ejemplos: 80,443,8080, 1000-2000", 
                        "Examples: 80,443,8080, 1000-2000"]:
                widget.configure(text=self._get_text("tcp_examples"))
            elif text in ["Ejemplos: 53,67,68, 100-200", 
                        "Examples: 53,67,68, 100-200"]:
                widget.configure(text=self._get_text("udp_examples"))
            elif text in ["Hilos:", "Threads:"]:
                widget.configure(text=self._get_text("threads"))
            elif text in ["Delay (ms):"]:
                widget.configure(text=self._get_text("delay"))
            elif text in ["Timeout (s):"]:
                widget.configure(text=self._get_text("timeout"))
            elif text in ["Tipo:", "Type:"]:
                widget.configure(text=self._get_text("proxy_type"))
            elif text in ["Host:"]:
                widget.configure(text=self._get_text("host"))
            elif text in ["Puerto:", "Port:"]:
                widget.configure(text=self._get_text("port"))
            elif text in ["Usuario:", "Username:"]:
                widget.configure(text=self._get_text("username"))
            elif text in ["Contraseña:", "Password:"]:
                widget.configure(text=self._get_text("password"))
                
        # Actualizar botones
        elif isinstance(widget, ttk.Button) and not widget in [self.start_button, self.stop_button]:
            text = widget.cget("text")
            if text in ["Seleccionar Todos", "Select All"]:
                widget.configure(text=self._get_text("select_all"))
            elif text in ["Deseleccionar Todos", "Deselect All"]:
                widget.configure(text=self._get_text("deselect_all"))
            elif text in ["Guardar Configuración", "Save Configuration"]:
                widget.configure(text=self._get_text("save_config"))
            elif text in ["Cargar Configuración", "Load Configuration"]:
                widget.configure(text=self._get_text("load_config"))
                
        # Actualizar Radiobutton
        elif isinstance(widget, ttk.Radiobutton):
            text = widget.cget("text")
            if text in ["Inglés", "English"]:
                widget.configure(text=self._get_text("english"))
            elif text in ["Español", "Spanish"]:
                widget.configure(text=self._get_text("spanish"))
        
        # Recursivamente actualizar los hijos de este widget
        for child in widget.winfo_children():
            self._update_widget_text_recursive(child)
        
    def _apply_result_filters(self):
        """Aplica los filtros a la tabla de resultados"""
        # Limpiar tabla
        for item in self.results_table.get_children():
            self.results_table.delete(item)
        
        # Aplicar filtros a los resultados
        for result in self.scanner.get_results():
            # Verificar si pasa los filtros
            show_result = True
            
            # "Mostrar todo" tiene precedencia
            if not self.show_all_var.get():
                # Filtrar por estado (abierto/habilitado) - usando strings en minúsculas para comparación
                if self.show_open_only_var.get():
                    # Lista de posibles estados "abiertos" en minúsculas (en ambos idiomas)
                    open_states = ["open", "abierto", "enabled", "habilitado", "possibly open", "posiblemente abierto"]
                    if result['status'].lower() not in open_states:
                        show_result = False
                
                # Filtrar por protocolo (TCP)
                if self.show_tcp_only_var.get() and result['protocol'] != 'TCP':
                    show_result = False
                
                # Filtrar por protocolo (UDP)
                if self.show_udp_only_var.get() and result['protocol'] != 'UDP':
                    show_result = False
                
                # Si no hay filtros seleccionados, mostrar todos
                if not (self.show_open_only_var.get() or self.show_tcp_only_var.get() or self.show_udp_only_var.get()):
                    show_result = True
            
            # Si pasa todos los filtros, agregar a la tabla
            if show_result:
                values = (
                    result['ip'],
                    result['port'],
                    result['protocol'],
                    result['status'],
                    result['service'],
                    result['version'],
                    result['response_time']
                )
                self.results_table.insert("", "end", values=values)
        
    def _on_tab_change(self, event):
        """Maneja el cambio de pestañas"""
        pass  # Para implementar funcionalidad adicional cuando se cambia de pestaña
        
    def _toggle_all_tcp_ports(self, state):
        """Selecciona o deselecciona todos los puertos TCP comunes"""
        for port in self.tcp_port_vars:
            self.tcp_port_vars[port].set(state)
            
    def _toggle_proxy_options(self):
        """Muestra u oculta las opciones de proxy"""
        if self.use_proxy_var.get():
            self.proxy_frame.pack(fill="x", padx=5, pady=5)  # Changed from grid() to pack()
            # Desactivar jump server si está activado
            if self.use_jump_var.get():
                self.use_jump_var.set(False)
                self.jump_frame.pack_forget()  # Changed from grid_remove() to pack_forget()
        else:
            self.proxy_frame.pack_forget()  # Changed from grid_remove() to pack_forget()
            # Ocultar autenticación
            self.proxy_auth_frame.pack_forget()
            self.proxy_auth_var.set(False)
            
    def _toggle_proxy_auth(self):
        """Muestra u oculta las opciones de autenticación de proxy"""
        if self.proxy_auth_var.get():
            self.proxy_auth_frame.pack(side="left", padx=5)
        else:
            self.proxy_auth_frame.pack_forget()
            
    def _toggle_jump_options(self):
        """Muestra u oculta las opciones de jump server"""
        if self.use_jump_var.get():
            self.jump_frame.pack(fill="x", padx=5, pady=5)  # Changed from grid() to pack()
            # Desactivar proxy si está activado
            if self.use_proxy_var.get():
                self.use_proxy_var.set(False)
                self.proxy_frame.pack_forget()  # Changed from grid_remove() to pack_forget()
                self.proxy_auth_frame.pack_forget()
                self.proxy_auth_var.set(False)
        else:
            self.jump_frame.pack_forget()  # Changed from grid_remove() to pack_forget()
            
    def start_scan(self):
        """Inicia el escaneo de red"""
        if self.scanning:
            messagebox.showinfo("Escaneo en progreso", "Ya hay un escaneo en progreso.")
            return
            
        # Recopilar datos para el escaneo
        ip_range = self.ip_range_var.get().strip()
        if not ip_range:
            messagebox.showerror("Error", "Debe especificar una dirección IP o rango.")
            return
            
        # Recopilar puertos TCP (comunes + personalizados)
        tcp_ports = []
        
        # Agregar puertos TCP comunes seleccionados
        for port, var in self.tcp_port_vars.items():
            if var.get():
                tcp_ports.append(port)
                
        # Agregar puertos TCP personalizados
        custom_tcp = self.custom_tcp_ports_var.get().strip()
        if custom_tcp:
            custom_tcp_ports = self.scanner.parse_port_range(custom_tcp)
            if custom_tcp_ports is None:  # Error en el formato
                return
            tcp_ports.extend(custom_tcp_ports)
            
        # Eliminar duplicados y ordenar
        tcp_ports = sorted(list(set(tcp_ports)))
        
        # Recopilar puertos UDP
        udp_ports = []
        custom_udp = self.custom_udp_ports_var.get().strip()
        if custom_udp:
            udp_ports = self.scanner.parse_port_range(custom_udp)
            if udp_ports is None:  # Error en el formato
                return
                
        # Verificar ICMP
        scan_icmp = self.scan_icmp_var.get()
        
        # Verificar que haya algo para escanear
        if not tcp_ports and not udp_ports and not scan_icmp:
            messagebox.showerror("Error", "No hay puertos o protocolos seleccionados para escanear.")
            return
            
        # Validar límites
        num_threads = self.threads_var.get()
        if num_threads < MIN_THREADS:
            self.threads_var.set(MIN_THREADS)
            num_threads = MIN_THREADS
        elif num_threads > MAX_THREADS:
            self.threads_var.set(MAX_THREADS)
            num_threads = MAX_THREADS
            
        delay = self.delay_var.get()
        if delay < MIN_DELAY:
            self.delay_var.set(MIN_DELAY)
            delay = MIN_DELAY
        elif delay > MAX_DELAY:
            self.delay_var.set(MAX_DELAY)
            delay = MAX_DELAY
            
        # Actualizar UI para modo de escaneo
        self._clear_results()  # Limpiar resultados anteriores
        self.scanning = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress_var.set(0)
        self.progress_label.configure(text="Iniciando escaneo...")
        
        # Iniciar escaneo en un hilo separado
        scan_thread = threading.Thread(
            target=self._run_scan,
            args=(ip_range, tcp_ports, udp_ports, scan_icmp, num_threads)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
    def _run_scan(self, ip_range, tcp_ports, udp_ports, scan_icmp, num_threads):
        """Ejecuta el escaneo (en un hilo separado)"""
        try:
            # Iniciar el escaneo
            success = self.scanner.start_scan(
                ip_range, tcp_ports, udp_ports, scan_icmp, num_threads
            )
            
            if not success:
                self.root.after(0, self.scan_completed)
                
        except Exception as e:
            messagebox.showerror("Error de escaneo", f"Error al iniciar el escaneo: {str(e)}")
            self.root.after(0, self.scan_completed)
            
    def stop_scan(self):
        """Detiene el escaneo en curso"""
        if not self.scanning:
            return
            
        # Actualizar etiqueta
        self.progress_label.configure(text="Deteniendo escaneo...")
        
        # Detener escaneo
        self.scanner.stop_current_scan()
        
    def scan_completed(self):
        """Llamado cuando el escaneo ha terminado"""
        self.scanning = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.progress_label.configure(text=self._get_text("scan_completed"))
        
        # Verificar si hay resultados para guardar
        results = self.scanner.get_results()
        if results:
            # Aplicar los filtros a los resultados
            self._apply_result_filters()
            
            # Preguntar si guardar resultados
            if messagebox.askyesno(self._get_text("saved"), self._get_text("save_results_question")):
                self._save_results_csv()
                
    def update_progress(self, value):
        """Actualiza la barra de progreso"""
        self.progress_var.set(value)
        self.progress_label.configure(text=self._get_text("progress").format(value))
        
    def update_results_table(self, result):
        """Actualiza la tabla de resultados con un nuevo resultado"""
        values = (
            result['ip'],
            result['port'],
            result['protocol'],
            result['status'],
            result['service'],
            result['version'],
            result['response_time']
        )
        
        self.results_table.insert("", "end", values=values)
        
        # Hacer scroll al final
        self.results_table.yview_moveto(1.0)
        
    def _clear_results(self):
        """Limpia la tabla de resultados"""
        for item in self.results_table.get_children():
            self.results_table.delete(item)
            
    def _show_context_menu(self, event):
        """Muestra el menú contextual en la tabla de resultados"""
        if self.results_table.get_children():  # Solo si hay resultados
            self.results_menu.post(event.x_root, event.y_root)
            
    def _get_default_filename(self, extension):
        """Genera un nombre de archivo predeterminado con fecha y hora"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = socket.gethostname().replace(" ", "_")
        return f"scan_results_{hostname}_{timestamp}.{extension}"
            
    def _save_results_csv(self):
        """Guarda los resultados en un archivo CSV"""
        # Verificar que haya resultados
        if not self.results_table.get_children():
            messagebox.showinfo("Sin datos", "No hay resultados para guardar.")
            return
            
        # Solicitar ubicación del archivo
        default_filename = self._get_default_filename("csv")
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=default_filename
        )
        
        if not filename:
            return
            
        try:
            # Escribir CSV
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Encabezados
                headers = ["IP", "Puerto", "Protocolo", "Estado", "Servicio", "Versión", "Tiempo de Respuesta (ms)"]
                writer.writerow(headers)
                
                # Datos
                for item in self.results_table.get_children():
                    values = self.results_table.item(item, 'values')
                    writer.writerow(values)
                    
            messagebox.showinfo("Guardado", f"Resultados guardados en {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar el archivo: {str(e)}")
            
    def _save_results_html(self):
        """Guarda los resultados en un archivo HTML"""
        # Verificar que haya resultados
        if not self.results_table.get_children():
            messagebox.showinfo("Sin datos", "No hay resultados para guardar.")
            return
            
        # Solicitar ubicación del archivo
        default_filename = self._get_default_filename("html")
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html"), ("All Files", "*.*")],
            initialfile=default_filename
        )
        
        if not filename:
            return
            
        try:
            # Generar HTML
            html_content = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resultados de Escaneo de Red</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .info {
            margin: 20px 0;
            padding: 10px;
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
        }
        table {
            width: 100%%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #e9f7fe;
        }
        .open {
            color: green;
            font-weight: bold;
        }
        .closed {
            color: #999;
        }
        .filtered {
            color: orange;
        }
        footer {
            margin-top: 30px;
            font-size: 0.8em;
            color: #666;
            border-top: 1px solid #ddd;
            padding-top: 10px;
        }
    </style>
</head>
<body>
    <h1>%s</h1>
    
    <div class="info">
        <p><strong>%s:</strong> %s</p>
        <p><strong>%s:</strong> %s</p>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>%s</th>
                <th>%s</th>
                <th>%s</th>
                <th>%s</th>
                <th>%s</th>
                <th>%s</th>
                <th>%s</th>
            </tr>
        </thead>
        <tbody>
""" % (
    self._get_text("report_title"),
    self._get_text("date_time"), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    self._get_text("computer"), socket.gethostname(),
    self._get_text("ip"), self._get_text("port"), self._get_text("protocol"),
    self._get_text("status"), self._get_text("service"), self._get_text("version"),
    self._get_text("response_time")
    )

            # Añadir filas de la tabla
            for item in self.results_table.get_children():
                values = self.results_table.item(item, 'values')
                
                # Determinar clase CSS según el estado
                status_class = ""
                if values[3].lower() in ["abierto", "habilitado", "posiblemente abierto"]:
                    status_class = "open"
                elif values[3].lower() in ["cerrado", "deshabilitado"]:
                    status_class = "closed"
                elif "filtrado" in values[3].lower():
                    status_class = "filtered"
                
                # Añadir fila
                html_content += f"""            <tr>
                <td>{values[0]}</td>
                <td>{values[1]}</td>
                <td>{values[2]}</td>
                <td class="{status_class}">{values[3]}</td>
                <td>{values[4]}</td>
                <td>{values[5]}</td>
                <td>{values[6]}</td>
            </tr>
"""
                
            # Cerrar HTML
            html_content += """        </tbody>
    </table>
    
    <footer>
        <p>Generado por Escáner de Red</p>
    </footer>
</body>
</html>"""
            
            # Escribir archivo
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            messagebox.showinfo("Guardado", f"Informe HTML guardado en {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar el archivo HTML: {str(e)}")
            
    def _save_config(self):
        """Guarda la configuración actual"""
        # Recopilar configuración
        config = {
            "language": self.language_var.get(),
            "ip_range": self.ip_range_var.get(),
            "custom_tcp_ports": self.custom_tcp_ports_var.get(),
            "custom_udp_ports": self.custom_udp_ports_var.get(),
            "scan_icmp": self.scan_icmp_var.get(),
            "threads": self.threads_var.get(),
            "delay": self.delay_var.get(),
            "timeout": self.timeout_var.get(),
            "tcp_ports": {str(port): var.get() for port, var in self.tcp_port_vars.items()},
            "use_proxy": self.use_proxy_var.get(),
            "proxy_type": self.proxy_type_var.get(),
            "proxy_host": self.proxy_host_var.get(),
            "proxy_port": self.proxy_port_var.get(),
            "proxy_auth": self.proxy_auth_var.get(),
            "proxy_username": self.proxy_username_var.get(),
            "proxy_password": self.proxy_password_var.get(),
            "use_jump": self.use_jump_var.get(),
            "jump_type": self.jump_type_var.get(),
            "jump_host": self.jump_host_var.get(),
            "jump_port": self.jump_port_var.get(),
            "jump_username": self.jump_username_var.get(),
            "jump_password": self.jump_password_var.get()
        }
        
        # Solicitar ubicación del archivo
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            initialfile="scanner_config.json"
        )
        
        if not filename:
            return
            
        try:
            # Guardar configuración
            with open(filename, 'w') as f:
                json.dump(config, f, indent=4)
                
            messagebox.showinfo(self._get_text("saved"), self._get_text("config_saved").format(filename))
            
        except Exception as e:
            messagebox.showerror(self._get_text("error"), self._get_text("config_save_error").format(str(e)))
            
    def _load_config_dialog(self):
        """Abre un diálogo para cargar configuración"""
        filename = filedialog.askopenfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        
        if not filename:
            return
            
        try:
            # Cargar configuración
            with open(filename, 'r') as f:
                config = json.load(f)
                
            # Aplicar configuración
            self._apply_config(config)
            
            messagebox.showinfo(self._get_text("loaded"), self._get_text("config_loaded").format(filename))
            
        except Exception as e:
            messagebox.showerror(self._get_text("error"), self._get_text("config_load_error").format(str(e)))
            
    def _load_config(self):
        """Carga la configuración por defecto si existe"""
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_config.json")
        
        if os.path.exists(default_path):
            try:
                with open(default_path, 'r') as f:
                    config = json.load(f)
                    
                # Aplicar configuración
                self._apply_config(config)
                
            except Exception as e:
                print(f"Error al cargar configuración por defecto: {str(e)}")
                
    def _apply_config(self, config):
        """Aplica la configuración cargada"""
        # Idioma
        if "language" in config:
            self._set_language(config["language"])
            
        # Configuración básica
        if "ip_range" in config:
            self.ip_range_var.set(config["ip_range"])
        if "custom_tcp_ports" in config:
            self.custom_tcp_ports_var.set(config["custom_tcp_ports"])
        if "custom_udp_ports" in config:
            self.custom_udp_ports_var.set(config["custom_udp_ports"])
        if "scan_icmp" in config:
            self.scan_icmp_var.set(config["scan_icmp"])
        if "threads" in config:
            self.threads_var.set(config["threads"])
        if "delay" in config:
            self.delay_var.set(config["delay"])
        if "timeout" in config:
            self.timeout_var.set(config["timeout"])
            
        # Puertos TCP comunes
        if "tcp_ports" in config:
            for port_str, value in config["tcp_ports"].items():
                port = int(port_str)
                if port in self.tcp_port_vars:
                    self.tcp_port_vars[port].set(value)
                    
        # Proxy
        if "use_proxy" in config:
            self.use_proxy_var.set(config["use_proxy"])
            self._toggle_proxy_options()
        if "proxy_type" in config:
            self.proxy_type_var.set(config["proxy_type"])
        if "proxy_host" in config:
            self.proxy_host_var.set(config["proxy_host"])
        if "proxy_port" in config:
            self.proxy_port_var.set(config["proxy_port"])
        if "proxy_auth" in config:
            self.proxy_auth_var.set(config["proxy_auth"])
            self._toggle_proxy_auth()
        if "proxy_username" in config:
            self.proxy_username_var.set(config["proxy_username"])
        if "proxy_password" in config:
            self.proxy_password_var.set(config["proxy_password"])
            
        # Jump Server
        if "use_jump" in config:
            self.use_jump_var.set(config["use_jump"])
            self._toggle_jump_options()
        if "jump_type" in config:
            self.jump_type_var.set(config["jump_type"])
        if "jump_host" in config:
            self.jump_host_var.set(config["jump_host"])
        if "jump_port" in config:
            self.jump_port_var.set(config["jump_port"])
        if "jump_username" in config:
            self.jump_username_var.set(config["jump_username"])
        if "jump_password" in config:
            self.jump_password_var.set(config["jump_password"])


def main():
    """Función principal"""
    root = tk.Tk()
    

    # Agregar el icono personalizado
    # Set icon
    icondata = '''
    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
    '''
    icon = tk.PhotoImage(data=icondata)
    root.iconphoto(True, icon)
    app = NetworkScannerUI(root)
    # Crear archivo de configuración por defecto si no existe
    
    default_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_config.json")
    if not os.path.exists(default_config_path):
        default_config = {
            "language": "en",  # Inglés por defecto
            "ip_range": "192.168.1.1",
            "custom_tcp_ports": "",
            "custom_udp_ports": "53,67,68",
            "scan_icmp": True,
            "threads": DEFAULT_THREADS,
            "delay": DEFAULT_DELAY,
            "timeout": DEFAULT_TIMEOUT,
            "tcp_ports": {str(port): True for port, _ in COMMON_TCP_PORTS},
            "use_proxy": False,
            "proxy_type": "HTTP",
            "proxy_host": "",
            "proxy_port": "8080",
            "proxy_auth": False,
            "proxy_username": "",
            "proxy_password": "",
            "use_jump": False,
            "jump_type": "SSH",
            "jump_host": "",
            "jump_port": "22",
            "jump_username": "",
            "jump_password": ""
        }
        try:
            with open(default_config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
        except Exception as e:
            print(f"Error al crear la configuración por defecto: {str(e)}")
    
    root.mainloop()
    
if __name__ == "__main__":
    main()