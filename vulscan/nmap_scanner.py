
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

class NmapScanner:
    """Classe para realizar e processar scans do Nmap."""
    
    # Portas comuns para dispositivos IoT/OT
    IOT_OT_PORTS = [
        "21,22,23,25,80,102,443,502,771,789,1010,1089,1091,1911,1962,2222,2404,4000,4840,4843,4911,9600,20000,44818,47808,1883,5683,8883"
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
    
    def __init__(self, nvd_api):
        self.nvd_api = nvd_api
        
    def check_nmap_installed(self) -> bool:
        """Verifica se o Nmap está instalado no sistema."""
        return shutil.which("nmap") is not None
    
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
            target: IP, hostname, notação CIDR (192.168.1.0/24) ou range (192.168.1.1-10)
            is_iot_scan: Se True, usa configurações específicas para dispositivos IoT/OT
            
        Returns:
            Caminho para o arquivo XML com resultados
            
        Raises:
            SystemExit: Se houver erro na execução do Nmap
        """
        if not self.check_nmap_installed():
            print("[!] Nmap não encontrado. Por favor, instale o Nmap antes de continuar.")
            sys.exit(1)

        # Identifica se é um scan de rede ou host único
        is_network = self.is_valid_network(target)
        if is_network:
            print(f"[~] Escaneando rede {target}. Isso pode levar mais tempo...")
            
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmpfile:
            try:
                print(f"[~] Executando Nmap em {target}...")
                
                # Comando base
                cmd = ['nmap', '-sV']

                # Se for uma rede, ajusta o timing para ser mais rápido (-T4)
                # e limita a verificação de versão a portas comuns
                if is_network and not is_iot_scan:
                    cmd.extend(['-T4', '--top-ports', '100'])
                
                # Se for scan IoT/OT, usa configurações específicas
                if is_iot_scan:
                    print("[~] Aplicando configurações para dispositivos IoT/OT...")
                    # Usa timing mais lento para não afetar dispositivos sensíveis
                    cmd.extend(['-T2', '--open'])
                    
                    # Adiciona portas específicas para IoT/OT
                    cmd.extend(['-p', ','.join(self.IOT_OT_PORTS)])
                    
                    # Adiciona scripts NSE específicos
                    script_list = ','.join(self.IOT_OT_SCRIPTS)
                    cmd.extend(['--script', script_list])
                    
                    print(f"[~] Escaneando portas de protocolos industriais e IoT...")
                    print(f"[~] Usando scripts NSE para detecção de protocolos IoT/OT...")
                
                # Adiciona o output XML e o alvo
                cmd.extend(['-oX', tmpfile.name, target])
                
                print(f"[~] Executando comando: {' '.join(cmd)}")
                
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return tmpfile.name
            except subprocess.CalledProcessError as e:
                print(f"[!] Erro ao executar o Nmap: {e}")
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
            print(f"[!] Erro ao analisar o arquivo XML do Nmap: {e}")
            return []
        finally:
            # Limpa o arquivo temporário
            if os.path.exists(xml_file):
                os.remove(xml_file)
                
        vulnerabilities = []
        hosts = root.findall('.//host')
        
        if not hosts:
            print("[!] Nenhum host encontrado nos resultados do Nmap.")
            return []
        
        host_count = len(hosts)
        if host_count > 1:
            print(f"[+] Encontrados {host_count} hosts ativos.")
            
        for host in hosts:
            # Obtém o endereço IP do host
            address = host.find('./address').get('addr', 'desconhecido')
            
            # Tenta identificar o fabricante/vendor do dispositivo (útil para IoT/OT)
            vendor = None
            vendor_elem = host.find('./address[@addrtype="mac"]')
            if vendor_elem is not None:
                vendor = vendor_elem.get('vendor', None)
                if vendor:
                    print(f"[+] Host {address} - Fabricante: {vendor}")
            
            # Se temos múltiplos hosts, mostra o IP atual
            if host_count > 1:
                print(f"\n[+] Analisando host: {address}")
                
            # Verifica se há informações de scripts IoT/OT
            scripts = host.findall('.//script')
            for script in scripts:
                if script.get('id') in self.IOT_OT_SCRIPTS:
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    if output and len(output) > 5:  # ignorar saídas vazias ou muito pequenas
                        print(f"[+] Protocolo industrial detectado via {script_id}:")
                        print(f"    {output}")
                
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
                        print(f"[+] Tipo de dispositivo detectado: {device_type}")
                    
                    additional_info_str = ", ".join(additional_info)
                    if additional_info_str:
                        print(f"[+] Informações adicionais: {additional_info_str}")
                    
                    print(f"\n[+] Porta {port_id} | Serviço: {service_info} | Versão: {version or 'desconhecida'}")
                    
                    # Consulta scripts específicos para a porta
                    port_scripts = port.findall('.//script')
                    for script in port_scripts:
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        if output and len(output) > 5 and script_id in self.IOT_OT_SCRIPTS:
                            print(f"[+] Detalhes do protocolo ({script_id}):")
                            print(f"    {output}")
                    
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