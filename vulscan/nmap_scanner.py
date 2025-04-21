"""
Módulo para executar e processar scans do Nmap.
"""

import os
import sys
import tempfile
import subprocess
import shutil
import xml.etree.ElementTree as ET
import ipaddress
from typing import Dict, List, Union
import logging

# Configuração do logger
logger = logging.getLogger(__name__)

class NmapScanner:
    """Classe para realizar e processar scans do Nmap."""
    
    IOT_OT_PORTS = [
        "21,22,23,25,80,102,443,502,771,789,1010,1089,1091,1911,1962,2222,2404,4000,4840,4843,4911,9600,20000,44818,47808,1883,5683,8883"
    ]
    
    IOT_OT_SCRIPTS = [
        "modbus-discover",
        "bacnet-info",
        "iec-identify",
        "s7-info",
        "coap-resources",
        "mqtt-subscribe",
        "dnp3-info"
    ]
    
    def __init__(self, nvd_api):
        self.nvd_api = nvd_api
        
    def check_nmap_installed(self) -> bool:
        """Verifica se o Nmap está instalado no sistema."""
        return shutil.which("nmap") is not None
    
    def check_nse_scripts(self) -> List[str]:
        """Verifica quais scripts NSE estão disponíveis."""
        available_scripts = []
        for script in self.IOT_OT_SCRIPTS:
            try:
                result = subprocess.run(
                    ['nmap', '--script', script, '--version'],
                    capture_output=True, text=True, check=True
                )
                if 'NSE: failed to initialize' not in result.stderr:
                    available_scripts.append(script)
            except subprocess.CalledProcessError:
                logger.warning(f"Script NSE {script} não disponível.")
        return available_scripts
    
    def is_valid_network(self, target: str) -> bool:
        """
        Verifica se o alvo é uma rede válida (notação CIDR ou range).
        
        Args:
            target: Endereço IP, range ou notação CIDR
            
        Returns:
            True se for uma rede válida, False caso contrário
        """
        try:
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return True
            elif '-' in target:
                base, range_end = target.rsplit('.', 1)[0], target.rsplit('.', 1)[1]
                if '-' in range_end:
                    start, end = range_end.split('-')
                    if start.isdigit() and end.isdigit() and 0 <= int(start) <= 255 and 0 <= int(end) <= 255:
                        return True
            return False
        except ValueError:
            return False
        
    def scan(self, target: str, is_iot_scan: bool = False) -> str:
        """
        Executa o scan Nmap no alvo especificado (host único ou rede).
        
        Args:
            target: IP, hostname, notação CIDR ou range
            is_iot_scan: Se True, usa configurações específicas para IoT/OT
            
        Returns:
            Caminho para o arquivo XML com resultados
            
        Raises:
            SystemExit: Se houver erro na execução do Nmap
        """
        if not self.check_nmap_installed():
            logger.error("Nmap não encontrado. Por favor, instale o Nmap.")
            sys.exit(1)

        is_network = self.is_valid_network(target)
        if is_network:
            logger.info(f"Escaneando rede {target}. Isso pode levar mais tempo...")
            
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmpfile:
            try:
                logger.info(f"Executando Nmap em {target}...")
                
                cmd = ['nmap', '-sV']
                if is_network and not is_iot_scan:
                    cmd.extend(['-T4', '--top-ports', '100'])
                
                if is_iot_scan:
                    logger.info("Aplicando configurações para dispositivos IoT/OT...")
                    cmd.extend(['-T2', '--open'])
                    cmd.extend(['-p', ','.join(self.IOT_OT_PORTS)])
                    available_scripts = self.check_nse_scripts()
                    if available_scripts:
                        cmd.extend(['--script', ','.join(available_scripts)])
                    else:
                        logger.warning("Nenhum script NSE IoT/OT disponível.")
                
                cmd.extend(['-oX', tmpfile.name, target])
                
                debug = os.getenv("VULSCAN_DEBUG", "0") == "1"
                logger.debug(f"Comando Nmap: {' '.join(cmd)}")
                
                result = subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.PIPE if debug else subprocess.DEVNULL,
                    stderr=subprocess.PIPE if debug else subprocess.DEVNULL,
                    text=True
                )
                if debug:
                    logger.debug(f"Nmap stdout: {result.stdout}")
                    logger.debug(f"Nmap stderr: {result.stderr}")
                return tmpfile.name
            except subprocess.CalledProcessError as e:
                logger.error(f"Erro ao executar o Nmap: {e}")
                if os.path.exists(tmpfile.name):
                    os.remove(tmpfile.name)
                sys.exit(1)
    
    def parse_results(self, xml_file: str) -> List[Dict[str, str]]:
        """
        Analisa o arquivo XML do Nmap e consulta vulnerabilidades.
        
        Args:
            xml_file: Caminho para o arquivo XML gerado pelo Nmap
            
        Returns:
            Lista de dicionários com informações dos serviços e CVEs
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Erro ao analisar o arquivo XML do Nmap: {e}")
            return []
        finally:
            if os.path.exists(xml_file):
                os.remove(xml_file)
                
        vulnerabilities = []
        hosts = root.findall('.//host')
        
        if not hosts:
            logger.warning("Nenhum host encontrado nos resultados do Nmap.")
            return []
        
        host_count = len(hosts)
        if host_count > 1:
            logger.info(f"Encontrados {host_count} hosts ativos.")
            
        for host in hosts:
            address_elem = host.find('./address')
            if address_elem is None:
                logger.warning("Host sem endereço encontrado, ignorando.")
                continue
            address = address_elem.get('addr', 'desconhecido')
            
            vendor = None
            vendor_elem = host.find('./address[@addrtype="mac"]')
            if vendor_elem is not None:
                vendor = vendor_elem.get('vendor')
                if vendor:
                    logger.info(f"Host {address} - Fabricante: {vendor}")
            
            if host_count > 1:
                logger.info(f"Analisando host: {address}")
                
            scripts = host.findall('.//script')
            for script in scripts:
                script_id = script.get('id', '')
                output = script.get('output', '')
                if output and len(output) > 5 and script_id in self.IOT_OT_SCRIPTS:
                    logger.info(f"Protocolo industrial detectado via {script_id}:")
                    logger.info(f"    {output}")
                
            for port in host.findall('.//port'):
                service = port.find('service')
                if service is None:
                    logger.debug(f"Porta {port.get('portid')} sem serviço, ignorando.")
                    continue
                    
                port_id = port.get('portid', 'desconhecido')
                service_name = service.get('name', 'desconhecido')
                version = service.get('version', '')
                product = service.get('product', '')
                device_type = service.get('devicetype', '')
                
                service_info = product if product else service_name
                
                additional_info = []
                if vendor:
                    additional_info.append(f"Fabricante: {vendor}")
                if device_type:
                    additional_info.append(f"Tipo: {device_type}")
                    logger.info(f"Tipo de dispositivo detectado: {device_type}")
                
                if additional_info:
                    logger.info(f"Informações adicionais: {', '.join(additional_info)}")
                
                logger.info(f"Porta {port_id} | Serviço: {service_info} | Versão: {version or 'desconhecida'}")
                
                port_scripts = port.findall('.//script')
                for script in port_scripts:
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    if output and len(output) > 5 and script_id in self.IOT_OT_SCRIPTS:
                        logger.info(f"Detalhes do protocolo ({script_id}):")
                        logger.info(f"    {output}")
                
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