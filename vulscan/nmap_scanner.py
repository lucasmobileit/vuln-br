"""
Módulo para executar e processar scans do Nmap, com suporte a dispositivos IoT/OT e consulta de vulnerabilidades via NVD API.
"""

import os
import sys
import tempfile
import subprocess
import shutil
import logging
import xml.etree.ElementTree as ET
import ipaddress
from typing import Dict, List, Union
from datetime import datetime

# Configuração do logger personalizado para exibir logs coloridos no console
class ColoredFormatter(logging.Formatter):
    """Formatador personalizado que adiciona cores aos níveis de log no console."""
    
    COLORS = {
        'DEBUG': '\033[94m',    # Azul
        'INFO': '\033[92m',     # Verde
        'WARNING': '\033[93m',  # Amarelo
        'ERROR': '\033[91m',    # Vermelho
        'CRITICAL': '\033[95m', # Magenta
        'RESET': '\033[0m'      # Reset para cores padrão
    }

    def format(self, record):
        """Aplica cores ao nível do log e formata a mensagem."""
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

# Configuração do logger para o módulo
logger = logging.getLogger('NmapScanner')
logger.setLevel(logging.DEBUG)  # Captura todos os níveis de log

# Handler para console (mostra INFO ou superior)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Handler para arquivo (registra DEBUG ou superior em um arquivo com timestamp)
file_handler = logging.FileHandler(f'nmap_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

class NmapScanner:
    """Classe para realizar scans do Nmap e processar resultados, com suporte a IoT/OT."""

    # Portas comuns para dispositivos IoT/OT (ex.: HTTP, Modbus, BACnet, etc.)
    IOT_OT_PORTS = [
        "21,22,23,25,80,102,443,502,771,789,1010,1089,1091,1911,1962,2222,2404,4000,4840,4843,4911,9600,20000,44818,47808,1883,5683,8883"
    ]
    
    # Scripts NSE do Nmap para detecção de protocolos IoT/OT
    IOT_OT_SCRIPTS = [
        "modbus-discover",  # Detecta dispositivos Modbus
        "bacnet-info",      # Identifica dispositivos BACnet
        "iec-identify",     # Protocolos IEC 61850
        "s7-info",          # Siemens S7 PLCs
        "coap-resources",   # Protocolo CoAP para IoT
        "mqtt-subscribe",   # Protocolo MQTT
        "dnp3-info"         # Protocolo DNP3
    ]
    
    # Configurações de timeout para scans (controla a velocidade do scan)
    TIMEOUTS = {
        'fast': '-T4',      # Rápido, para redes grandes
        'normal': '-T3',    # Padrão, equilíbrio entre velocidade e precisão
        'slow': '-T2',      # Lento, para dispositivos sensíveis
        'paranoid': '-T1'   # Muito lento, para máxima discrição
    }
    
    def __init__(self, nvd_api, timeout: str = 'normal'):
        """
        Inicializa o scanner Nmap com API NVD e configurações de timeout.

        Args:
            nvd_api: Instância da API NVD para consulta de vulnerabilidades.
            timeout: Nível de timeout ('fast', 'normal', 'slow', 'paranoid').
        """
        self.nvd_api = nvd_api  # Armazena a API NVD para consultas
        self.timeout = self.TIMEOUTS.get(timeout, self.TIMEOUTS['normal'])  # Define o timeout padrão
        self.scan_history = []  # Lista para armazenar histórico de scans
        logger.info(f"Inicializando NmapScanner com timeout {timeout}")

    def check_nmap_installed(self) -> bool:
        """Verifica se o Nmap está instalado no sistema."""
        is_installed = shutil.which("nmap") is not None
        if not is_installed:
            logger.error("Nmap não está instalado no sistema")
        return is_installed
    
    def is_valid_network(self, target: str) -> bool:
        """
        Verifica se o alvo é uma rede válida (notação CIDR ou range).

        Args:
            target: Endereço IP, range (ex.: 192.168.1.1-10) ou CIDR (ex.: 192.168.1.0/24).

        Returns:
            bool: True se for uma rede válida, False caso contrário.
        """
        try:
            if '/' in target:  # Verifica notação CIDR
                ipaddress.ip_network(target, strict=False)
                return True
            elif '-' in target:  # Verifica range de IPs
                base, range_end = target.rsplit('.', 1)
                ipaddress.ip_address(base + ".0")  # Valida endereço base
                if '-' in range_end:
                    start, end = range_end.split('-')
                    if start.isdigit() and end.isdigit() and 0 <= int(start) <= 255 and 0 <= int(end) <= 255:
                        return True
            return False
        except ValueError as e:
            logger.debug(f"Erro ao validar rede {target}: {e}")
            return False
        
    def scan(self, target: str, is_iot_scan: bool = False, custom_ports: str = None) -> str:
        """
        Executa um scan Nmap no alvo especificado (host único ou rede).

        Args:
            target: IP, hostname, CIDR ou range.
            is_iot_scan: Usa configurações específicas para IoT/OT se True.
            custom_ports: Portas personalizadas (ex.: "80,443").

        Returns:
            str: Caminho do arquivo XML com resultados.

        Raises:
            SystemExit: Se o Nmap não estiver instalado ou o scan falhar.
        """
        # Verifica se o Nmap está instalado
        if not self.check_nmap_installed():
            logger.error("Nmap não encontrado. Por favor, instale o Nmap antes de continuar.")
            sys.exit(1)

        # Registra o início do scan
        scan_start = datetime.now()
        logger.info(f"Iniciando scan em {target}")
        
        # Verifica se o alvo é uma rede
        is_network = self.is_valid_network(target)
        if is_network:
            logger.info(f"Escaneando rede {target}. Isso pode levar mais tempo...")
            
        # Cria arquivo temporário para armazenar resultados
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmpfile:
            try:
                # Monta o comando base do Nmap
                cmd = ['nmap', '-sV', self.timeout]  # -sV: detecta serviços e versões

                # Ajusta para redes (menos portas, mais rápido)
                if is_network and not is_iot_scan:
                    cmd.extend(['--top-ports', '100'])

                # Configurações para dispositivos IoT/OT
                if is_iot_scan:
                    logger.info("Aplicando configurações para dispositivos IoT/OT...")
                    cmd.extend(['--open'])  # Mostra apenas portas abertas
                    cmd.extend(['-p', ','.join(self.IOT_OT_PORTS)])  # Portas IoT/OT
                    script_list = ','.join(self.IOT_OT_SCRIPTS)  # Scripts NSE
                    cmd.extend(['--script', script_list])
                    logger.info("Usando scripts NSE para detecção de protocolos IoT/OT...")

                # Adiciona portas personalizadas, se fornecidas
                if custom_ports:
                    logger.info(f"Usando portas personalizadas: {custom_ports}")
                    cmd.extend(['-p', custom_ports])

                # Define o formato de saída (XML) e o alvo
                cmd.extend(['-oX', tmpfile.name, target])
                logger.debug(f"Comando Nmap: {' '.join(cmd)}")

                # Executa o comando Nmap
                process = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Registra informações do scan no histórico
                scan_duration = (datetime.now() - scan_start).total_seconds()
                scan_info = {
                    'target': target,
                    'timestamp': scan_start,
                    'duration': scan_duration,
                    'is_iot_scan': is_iot_scan,
                    'is_network': is_network,
                    'command': ' '.join(cmd)
                }
                self.scan_history.append(scan_info)
                
                logger.info(f"Scan concluído em {scan_duration:.2f} segundos")
                return tmpfile.name

            except subprocess.CalledProcessError as e:
                logger.error(f"Erro ao executar o Nmap: {e}")
                logger.error(f"Saída de erro: {e.stderr}")
                if os.path.exists(tmpfile.name):
                    os.remove(tmpfile.name)
                sys.exit(1)
    
    def get_scan_history(self) -> List[Dict]:
        """
        Retorna o histórico de scans realizados.

        Returns:
            List[Dict]: Lista com detalhes de cada scan (alvo, tempo, duração, etc.).
        """
        return self.scan_history
    
    def parse_results(self, xml_file: str) -> List[Dict[str, str]]:
        """
        Analisa o arquivo XML do Nmap e consulta vulnerabilidades via NVD API.

        Args:
            xml_file: Caminho para o arquivo XML gerado pelo Nmap.

        Returns:
            List[Dict[str, str]]: Lista de dicionários com informações de serviços e CVEs.
        """
        # Tenta carregar e analisar o arquivo XML
        try:
            logger.debug(f"Analisando arquivo XML: {xml_file}")
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Erro ao analisar o arquivo XML do Nmap: {e}")
            return []
        finally:
            # Remove o arquivo temporário após uso
            if os.path.exists(xml_file):
                os.remove(xml_file)
                logger.debug("Arquivo XML temporário removido")
                
        vulnerabilities = []
        hosts = root.findall('.//host')  # Encontra todos os hosts no XML
        
        if not hosts:
            logger.warning("Nenhum host encontrado nos resultados do Nmap.")
            return []
        
        # Informa quantos hosts foram encontrados
        host_count = len(hosts)
        if host_count > 1:
            logger.info(f"Encontrados {host_count} hosts ativos.")
            
        # Processa cada host
        for host in hosts:
            # Obtém o endereço IP
            address = host.find('./address').get('addr', 'desconhecido')
            logger.debug(f"Analisando host: {address}")
            
            # Tenta identificar o fabricante via endereço MAC
            vendor = None
            vendor_elem = host.find('./address[@addrtype="mac"]')
            if vendor_elem is not None:
                vendor = vendor_elem.get('vendor', None)
                if vendor:
                    logger.info(f"Host {address} - Fabricante: {vendor}")
            
            # Informa o IP atual se houver múltiplos hosts
            if host_count > 1:
                logger.info(f"Analisando host: {address}")
                
            # Verifica resultados de scripts IoT/OT
            scripts = host.findall('.//script')
            for script in scripts:
                if script.get('id') in self.IOT_OT_SCRIPTS:
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    if output and len(output) > 5:  # Ignora saídas curtas
                        logger.info(f"Protocolo industrial detectado via {script_id}:")
                        logger.info(f"    {output}")
                
            # Processa cada porta aberta
            for port in host.findall('.//port'):
                service = port.find('service')
                if service is not None:
                    port_id = port.get('portid', 'desconhecido')
                    service_name = service.get('name', 'desconhecido')
                    version = service.get('version', '')
                    product = service.get('product', '')
                    device_type = service.get('devicetype', '')
                    
                    # Formata informações do serviço
                    service_info = service_name
                    if product:
                        service_info = f"{product} ({service_name})"
                    
                    # Coleta informações adicionais (fabricante, tipo de dispositivo)
                    additional_info = []
                    if vendor:
                        additional_info.append(f"Fabricante: {vendor}")
                    if device_type:
                        additional_info.append(f"Tipo: {device_type}")
                        logger.info(f"Tipo de dispositivo detectado: {device_type}")
                    
                    additional_info_str = ", ".join(additional_info)
                    if additional_info_str:
                        logger.info(f"Informações adicionais: {additional_info_str}")
                    
                    logger.info(f"Porta {port_id} | Serviço: {service_info} | Versão: {version or 'desconhecida'}")
                    
                    # Verifica resultados de scripts para a porta
                    port_scripts = port.findall('.//script')
                    for script in port_scripts:
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        if output and len(output) > 5 and script_id in self.IOT_OT_SCRIPTS:
                            logger.info(f"Detalhes do protocolo ({script_id}):")
                            logger.info(f"    {output}")
                    
                    # Consulta vulnerabilidades usando a API NVD
                    search_term = product if product else service_name
                    cve_info = self.nvd_api.get_cve_info(search_term, version)
                    
                    # Armazena informações do serviço e vulnerabilidades
                    vulnerabilities.append({
                        'host': address,
                        'port': port_id,
                        'service': service_info,
                        'version': version,
                        'cve_id': cve_info['id'],
                        'cve_desc': cve_info['description'],
                        'device_type': device_type,
                        'vendor': vendor
                    })
                
        return vulnerabilities
