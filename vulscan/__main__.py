
"""
Módulo principal do VulScan, unifica todas as funcionalidades.
"""

import os
import sys
import re
from dotenv import load_dotenv

from vulscan.nvd_api import NvdApi
from vulscan.nmap_scanner import NmapScanner
from vulscan.exporter import ResultExporter

def validate_target(input_target: str) -> bool:
    """
    Valida se o alvo é um IP, hostname, range ou CIDR válido.
    
    Args:
        input_target: O alvo a ser validado
        
    Returns:
        True se o alvo for válido, False caso contrário
    """
    # Validar IP simples (simplificado)
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # Validar CIDR
    cidr_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
    # Validar range de IPs
    range_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"
    # Validar hostname
    hostname_pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9.]{0,253}[a-zA-Z0-9]$"
    
    return (re.match(ip_pattern, input_target) is not None or
            re.match(cidr_pattern, input_target) is not None or
            re.match(range_pattern, input_target) is not None or
            re.match(hostname_pattern, input_target) is not None)

def main():
    """Função principal do programa."""
    print("🛡️  VulScan - Scanner de Serviços + Consulta de CVEs")
    print("---------------------------------------------------")
    
    # Carrega variáveis de ambiente
    load_dotenv()
    api_key = os.getenv("NVD_API_KEY")
    
    if not api_key:
        print("[!] API Key da NVD não encontrada! Defina em um arquivo .env como NVD_API_KEY.")
        sys.exit(1)
    
    # Obtém o alvo do scan
    print("\nOpções de alvos:")
    print("  - IP único (ex: 192.168.1.1)")
    print("  - Hostname (ex: example.com)")
    print("  - Rede CIDR (ex: 192.168.1.0/24)")
    print("  - Range de IPs (ex: 192.168.1.1-10)")
    
    target = input("\nDigite o IP, hostname ou rede a ser analisado: ").strip()
    if not target or not validate_target(target):
        print("[!] Alvo inválido. Por favor, forneça um IP, hostname, notação CIDR ou range válido.")
        return
    
    # Adiciona opção para escolher o tipo de dispositivo a ser escaneado
    print("\nTipo de dispositivos a serem escaneados:")
    print("  1. Padrão (servidores, PCs, dispositivos de rede)")
    print("  2. IoT/OT (dispositivos industriais, sensores, PLCs)")
    
    scan_type = input("\nEscolha uma opção (1/2) [1]: ").strip() or "1"
    is_iot_scan = scan_type == "2"
    
    if is_iot_scan:
        print("\n[*] Modo de escaneamento IoT/OT selecionado.")
        print("[*] Este modo detecta dispositivos industriais, protocolos comuns e sensores IoT.")
        print("[*] Atenção: O escaneamento será mais lento para evitar impactos em dispositivos sensíveis.")
        
    try:
        # Inicializa as classes
        nvd_api = NvdApi(api_key)
        scanner = NmapScanner(nvd_api)
        exporter = ResultExporter()
        
        # Executa o scan
        print(f"\n[~] Iniciando análise de {target}...")
        xml_file = scanner.scan(target, is_iot_scan)
        
        # Analisa os resultados
        results = scanner.parse_results(xml_file)
        
        if not results:
            print("\n[!] Nenhum serviço vulnerável encontrado ou scan sem resultados.")
            return
        
        # Identifica se é uma rede ou um host único
        is_network = scanner.is_valid_network(target)
            
        # Exibe os resultados
        print(f"\n🔍 Resultados para {target}:\n")
        
        # Agrupa resultados por host se for uma rede
        if is_network:
            hosts = set(item['host'] for item in results)
            for host in hosts:
                print(f"\n[Host: {host}]")
                host_results = [item for item in results if item['host'] == host]
                for item in host_results:
                    print(f"[Porta {item['port']}] {item['service']} ({item['version'] or 'versão desconhecida'})")
                    print(f"  CVE: {item['cve_id']}")
                    print(f"  Desc: {item['cve_desc']}\n")
        else:
            for item in results:
                print(f"[Porta {item['port']}] {item['service']} ({item['version'] or 'versão desconhecida'})")
                print(f"  CVE: {item['cve_id']}")
                print(f"  Desc: {item['cve_desc']}\n")
            
        # Exporta os resultados
        json_file = exporter.export_json(results, target)
        csv_file = exporter.export_csv(results, target)
        html_file = exporter.export_html(results, target)
        
        print(f"\n[✔] Resultados exportados para:")
        print(f"  - {json_file} (JSON)")
        print(f"  - {csv_file} (CSV)")
        print(f"  - {html_file} (HTML)")
        
    except KeyboardInterrupt:
        print("\n\n[!] Operação cancelada pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erro inesperado: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()