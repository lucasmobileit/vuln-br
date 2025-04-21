"""
Módulo principal do VulScan, unifica todas as funcionalidades.
"""

import os
import sys
import re
import argparse
from dotenv import load_dotenv
from tabulate import tabulate
import logging

from nvd_api import NvdApi
from nmap_scanner import NmapScanner
from exporter import ResultExporter

# Configuração do logger
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

def validate_target(input_target: str) -> bool:
    """
    Valida se o alvo é um IP, hostname, range ou CIDR válido.
    
    Args:
        input_target: O alvo a ser validado
        
    Returns:
        True se o alvo for válido, False caso contrário
    """
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    cidr_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
    range_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"
    hostname_pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9.]{0,253}[a-zA-Z0-9]$"
    
    return (re.match(ip_pattern, input_target) is not None or
            re.match(cidr_pattern, input_target) is not None or
            re.match(range_pattern, input_target) is not None or
            re.match(hostname_pattern, input_target) is not None)

def parse_args():
    """Parseia argumentos de linha de comando."""
    parser = argparse.ArgumentParser(description="VulScan - Scanner de Serviços + Consulta de CVEs")
    parser.add_argument("target", help="IP, hostname, CIDR ou range (ex: 192.168.1.1, 192.168.1.0/24)")
    parser.add_argument("--iot", action="store_true", help="Escaneamento para dispositivos IoT/OT")
    parser.add_argument("--output-dir", default=".", help="Diretório para salvar os resultados")
    parser.add_argument("--verbose", action="store_true", help="Ativa modo verboso (logging DEBUG)")
    return parser.parse_args()

def main():
    """Função principal do programa."""
    args = parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("🛡️  VulScan - Scanner de Serviços + Consulta de CVEs")
    logger.info("---------------------------------------------------")
    logger.info(f"Arquivos serão salvos em: {os.path.abspath(args.output_dir)}")
    
    load_dotenv()
    api_key = os.getenv("NVD_API_KEY")
    
    if not api_key:
        logger.error("API Key da NVD não encontrada! Defina em um arquivo .env como NVD_API_KEY.")
        sys.exit(1)
    
    target = args.target.strip()
    if not target or not validate_target(target):
        logger.error("Alvo inválido. Forneça um IP, hostname, notação CIDR ou range válido.")
        sys.exit(1)
    
    is_iot_scan = args.iot
    if is_iot_scan:
        logger.info("Modo de escaneamento IoT/OT selecionado.")
        logger.info("Este modo detecta dispositivos industriais, protocolos comuns e sensores IoT.")
        logger.info("Atenção: O escaneamento será mais lento para evitar impactos em dispositivos sensíveis.")
        
    try:
        nvd_api = NvdApi(api_key)
        scanner = NmapScanner(nvd_api)
        exporter = ResultExporter()
        
        logger.info(f"Iniciando análise de {target}...")
        xml_file = scanner.scan(target, is_iot_scan)
        
        logger.debug("Analisando resultados do scan...")
        results = scanner.parse_results(xml_file)
        
        if not results:
            logger.warning("Nenhum serviço vulnerável encontrado ou scan sem resultados.")
            return
        
        logger.debug(f"Resultados do scan: {results}")
        is_network = scanner.is_valid_network(target)
            
        logger.info(f"\n🔍 Resultados para {target}:\n")
        
        if is_network:
            hosts = set(item['host'] for item in results)
            for host in hosts:
                logger.info(f"\n[Host: {host}]")
                host_results = [item for item in results if item['host'] == host]
                table = [
                    [item['port'], item['service'], item['version'] or 'desconhecida', item['cve_id'], item['cve_desc']]
                    for item in host_results
                ]
                logger.info(tabulate(table, headers=['Porta', 'Serviço', 'Versão', 'CVE', 'Descrição'], tablefmt='grid'))
        else:
            table = [
                [item['port'], item['service'], item['version'] or 'desconhecida', item['cve_id'], item['cve_desc']]
                for item in results
            ]
            logger.info(tabulate(table, headers=['Porta', 'Serviço', 'Versão', 'CVE', 'Descrição'], tablefmt='grid'))
            
        json_file = exporter.export_json(results, target, args.output_dir)
        csv_file = exporter.export_csv(results, target, args.output_dir)
        html_file = exporter.export_html(results, target, args.output_dir)
        
        logger.info("\n[✔] Resultados exportados para:")
        if json_file:
            logger.info(f"  - {json_file} (JSON)")
        if csv_file:
            logger.info(f"  - {csv_file} (CSV)")
        if html_file:
            logger.info(f"  - {html_file} (HTML)")
        
    except KeyboardInterrupt:
        logger.warning("\nOperação cancelada pelo usuário.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Erro inesperado: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()