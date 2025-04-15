"""
Módulo para executar e processar scans do Nmap.
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

# Configuração do logger personalizado
class ColoredFormatter(logging.Formatter):
    """Formatador personalizado com cores para diferentes níveis de log"""
    
    COLORS = {
        'DEBUG': '\033[94m',    # Azul
        'INFO': '\033[92m',     # Verde
        'WARNING': '\033[93m',  # Amarelo
        'ERROR': '\033[91m',    # Vermelho
        'CRITICAL': '\033[95m', # Magenta
        'RESET': '\033[0m'      # Reset
    }

    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

# Configuração do logger
logger = logging.getLogger('NmapScanner')
logger.setLevel(logging.DEBUG)

# Handler para console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Handler para arquivo
file_handler = logging.FileHandler(f'nmap_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

class NmapScanner:
    """Classe para realizar e processar scans do Nmap."""
    
    # Portas comuns para dispositivos IoT/OT
    IOT_OT_PORTS = [
        "21","22","23","25","80","102","443","502","771","789","1010","1089","1091","1911","1962","2222","2404","4000","4840","4843","4911","9600","20000","44818","47808","1883","5683","8883"
    ]
    
    # Scripts NSE para detecção de dispositivos IoT/OT
    IOT_OT_SCRIPTS = [
        "modbus-discover",
        "bacnet-info",
        "iec-identify",
        "s7-info",
        "coap-resources",
        "mqtt-subscribe",
        "dnp3-info"
    ]
    
    # Timeouts para diferentes tipos de scan
    TIMEOUTS = {
        'fast': '-T4',
        'normal': '-T3',
        'slow': '-T2',
        'paranoid': '-T1'
    }
    
    def __init__(self, nvd_api, timeout='normal'):
        """
        Inicializa o scanner Nmap.

        Args:
            nvd_api: Instância da API NVD para consulta de vulnerabilidades
            timeout: Nível de timeout para os scans ('fast', 'normal', 'slow', 'paranoid')
        """
        self.nvd_api = nvd_api
        self.timeout = self.TIMEOUTS.get(timeout, self.TIMEOUTS['normal'])
        self.scan_history = []
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
            target: Endereço IP, range ou notação CIDR
            
        Returns:
            True se for uma rede válida, False caso contrário
        """
        try:
            # Verifica se é uma notação CIDR válida
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return True
            # Verifica se é um range de IP (ex: 192.168.1.1-10)
            elif '-' in target:
                base, range_end = target.rsplit('.', 1)
                try:
                    ipaddress.ip_address(base + ".0")  # Verifica se o endereço base é válido
                except ValueError as e:
                    logger.debug(f"Erro ao validar rede {target}: {e}")
                    return False
                if '-' in range_end:
                    start, end = range_end.split('-')
                    if start.isdigit() and end.isdigit() and 0 <= int(start) <= 255 and 0 <= int(end) <= 255:
                        return True
            return False
        except ValueError:
            return False
        
    def scan(self, target: str, is_iot_scan: bool = False, custom_ports: str = None) -> str:
        """
        Executa o scan Nmap no alvo especificado (host único ou rede).
        
        Args:
            target: IP, hostname, notação CIDR (192.168.1.0/24) ou range (192.168.1.1-10)
            is_iot_scan: Se True, usa configurações específicas para dispositivos IoT/OT
            custom_ports: String com portas personalizadas para scan (ex: "80,443,8080")
            
        Returns:
            Caminho para o arquivo XML com resultados
            
        Raises:
            SystemExit: Se houver erro na execução do Nmap
        """
        if not self.check_nmap_installed():
            logger.error("Nmap não encontrado. Por favor, instale o Nmap antes de continuar.")
            sys.exit(1)

        # Registra o início do scan
        scan_start = datetime.now()
        logger.info(f"Iniciando scan em {target}")
        
        # Identifica se é um scan de rede ou host único
        is_network = self.is_valid_network(target)
        if is_network:
            logger.info(f"Escaneando rede {target}. Isso pode levar mais tempo...")
            
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmpfile:
            try:
                # Comando base
                cmd = ['nmap', '-sV', self.timeout]

                # Se for uma rede, ajusta o timing e limita a verificação de versão
                if is_network and not is_iot_scan:
                    cmd.extend(['--top-ports', '100'])

                # Se for scan IoT/OT, usa configurações específicas
                if is_iot_scan:
                    logger.info("Aplicando configurações para dispositivos IoT/OT...")
                    cmd.extend(['--open'])
                    cmd.extend(['-p', ','.join(self.IOT_OT_PORTS)])
                    script_list = ','.join(self.IOT_OT_SCRIPTS)
                    cmd.extend(['--script', script_list])
                    logger.info("Usando scripts NSE para detecção de protocolos IoT/OT...")

                # Adiciona portas personalizadas se especificadas
                if custom_ports:
                    logger.info(f"Usando portas personalizadas: {custom_ports}")
                    cmd.extend(['-p', custom_ports])

                # Adiciona o output XML e o alvo
                cmd.extend(['-oX', tmpfile.name, target])
                logger.debug(f"Comando Nmap: {' '.join(cmd)}")

                # Executa o scan
                process = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Registra o resultado do scan
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
            Lista com informações dos scans realizados
        """
        return self.scan_history
    
    def parse_results(self, xml_file: str) -> List[Dict[str, str]]:
        """
        Analisa o arquivo XML do Nmap e consulta vulnerabilidades.
        
        Args:
            xml_file: Caminho para o arquivo XML gerado pelo Nmap
            
        Returns:
            Lista de dicionários com informações dos serviços e CVEs
        """
        try:
            logger.debug(f"Analisando arquivo XML: {xml_file}")
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Erro ao analisar o arquivo XML do Nmap: {e}")
            return []
        finally:
            if os.path.exists(xml_file):
                os.remove(xml_file)
                logger.debug("Arquivo XML temporário removido")
                
        vulnerabilities = []
        hosts = root.findall('.//host')
        
        if not hosts:
            logger.warning("Nenhum host encontrado nos resultados do Nmap.")
            return []
        
        host_count = len(hosts)
        if host_count > 1:
            logger.info(f"Encontrados {host_count} hosts ativos.")
            
        for host in hosts:
            # Obtém o endereço IP do host
            address = host.find('./address').get('addr', 'desconhecido')
            logger.debug(f"Analisando host: {address}")
            
            # Tenta identificar o fabricante/vendor do dispositivo
            vendor = None
            vendor_elem = host.find('./address[@addrtype="mac"]')
            if vendor_elem is not None:
                vendor = vendor_elem.get('vendor', None)
                if vendor:
                    logger.info(f"Host {address} - Fabricante: {vendor}")
            
            # Se temos múltiplos hosts, mostra o IP atual
            if host_count > 1:
                logger.info(f"Analisando host: {address}")
                
            # Verifica se há informações de scripts IoT/OT
            scripts = host.findall('.//script')
            for script in scripts:
                if script.get('id') in self.IOT_OT_SCRIPTS:
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    if output and len(output) > 5:
                        logger.info(f"Protocolo industrial detectado via {script_id}:")
                        logger.info(f"    {output}")
                
            for port in host.findall('.//port'):
                service = port.find('service')
                if service is not None:
                    port_id = port.get('portid', 'desconhecido')
                    service_name = service.get('name', 'desconhecido')
                    version = service.get('version', '')
                    product = service.get('product', '')
                    device_type = service.get('devicetype', '')
                    
                    service_info = service_name
                    if product:
                        service_info = f"{product} ({service_name})"
                    
                    # Informações adicionais para dispositivos IoT/OT
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
                    
                    # Consulta scripts específicos para a porta
                    port_scripts = port.findall('.//script')
                    for script in port_scripts:
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        if output and len(output) > 5 and script_id in self.IOT_OT_SCRIPTS:
                            logger.info(f"Detalhes do protocolo ({script_id}):")
                            logger.info(f"    {output}")
                    
                    # Usa o produto se disponível, senão usa o nome do serviço
                    search_term = product if product else service_name
                    cve_info = self.nvd_api.get_cve_info(search_term, version)
                    
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
