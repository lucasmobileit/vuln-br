"""
scan_it.py (versão aprimorada com ThreadPoolExecutor e tratamento de erros)
- Scanner ativo para ambientes IT (TI)
- Alinhado ao MITRE ATT&CK T1046, NIST SP 800-115, CIS Controls
"""

import socket
import threading
import logging
import argparse
import json
import csv
from datetime import datetime
import re
from concurrent.futures import ThreadPoolExecutor, as_completed # Importando o Pool de Threads

# --- Constantes ---
DEFAULT_PORTS = [21, 22, 23, 25, 80, 443, 3389, 8080, 445, 139]
DEFAULT_TIMEOUT = 2
DEFAULT_THREADS = 50

# --- Configuração do logger ---
logging.basicConfig(level=logging.INFO, format='[%(asctime)s - %(levelname)s] %(message)s')
logger = logging.getLogger("scan_it")

# --- Validação de IP ---
def is_valid_ip(ip):
    """Valida se uma string é um endereço IP válido."""
    try:
        socket.inet_aton(ip) # Tenta converter o IP para formato binário
        return True
    except socket.error:
        logger.error(f"IP inválido: {ip}")
        return False

# --- Função para escanear portas ---
def scan_port_worker(ip, port, timeout):
    """
    Função de worker para escanear uma única porta.
    Retorna a porta se estiver aberta, caso contrário retorna None.
    """
    try:
        # Usa 'with' para garantir que o socket seja fechado automaticamente
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return port # Retorna a porta se a conexão for bem-sucedida
    except socket.timeout:
        # logger.debug(f"Port {port} on {ip}: Timeout.") # Debug para portas filtradas/lentas
        pass # Ignora timeout, indica porta fechada/filtrada
    except ConnectionRefusedError:
        # logger.debug(f"Port {port} on {ip}: Connection refused.") # Debug para portas fechadas ativamente
        pass # Ignora conexão recusada, indica porta fechada
    except socket.error as e:
        # logger.debug(f"Port {port} on {ip}: Socket error - {e}") # Outros erros de socket
        pass
    return None # Retorna None se a porta não estiver aberta ou ocorrer um erro

def scan_ports(ip, ports, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
    """
    Escaneia uma lista de portas em um IP usando um pool de threads.
    Retorna uma lista de portas abertas.
    """
    logger.info(f"Iniciando varredura de portas em {ip} para {len(ports)} portas com {threads} threads...")
    open_ports = []
    # Usa ThreadPoolExecutor para gerenciar o pool de threads
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Mapeia a função scan_port_worker para cada porta
        future_to_port = {executor.submit(scan_port_worker, ip, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result_port = future.result()
                if result_port is not None:
                    open_ports.append(result_port)
                    logger.info(f"Porta {result_port} está ABERTA.")
            except Exception as exc:
                logger.warning(f"Erro ao escanear porta {port}: {exc}")
    logger.info(f"Varredura de portas em {ip} concluída. Portas abertas: {len(open_ports)}")
    return open_ports

# --- Função para coleta de banner ---
def banner_grab(ip, port, timeout=DEFAULT_TIMEOUT):
    """
    Tenta coletar o banner de um serviço em uma porta.
    Retorna o banner decodificado ou None em caso de falha.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Envia probes mais robustas e comuns para serviços específicos
            if port == 80 or port == 8080:
                s.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n") # Adicionado Host para HTTP/1.0
            elif port == 443:
                # HTTPS requer TLS, banner grab simples não funciona facilmente sem SSL/TLS handshake
                # Para HTTPS, seria necessário usar ssl.wrap_socket
                logger.debug(f"Port {port} (HTTPS) - Banner grab simples não aplicável sem TLS handshake.")
                return "[HTTPS - Requer TLS]" # Indicação de que é HTTPS
            elif port == 25: # SMTP
                s.sendall(b"EHLO test.com\r\n")
            elif port == 21: # FTP
                s.sendall(b"USER anonymous\r\n") # Tenta iniciar uma sessão para pegar banner
            elif port == 22: # SSH
                # SSH envia seu banner automaticamente na conexão
                pass
            else:
                # Para outras portas, tenta ler o que o serviço envia inicialmente
                pass

            banner = s.recv(4096) # Aumentado o buffer para banners maiores
            return banner.decode(errors='ignore').strip()
    except socket.timeout:
        logger.debug(f"Banner grab timeout for {ip}:{port}")
    except ConnectionRefusedError:
        logger.debug(f"Banner grab connection refused for {ip}:{port}")
    except Exception as e:
        logger.debug(f"Erro ao coletar banner de {ip}:{port}: {e}")
    return None

# --- Detecta serviço com base no banner ---
def identify_service(banner, port):
    """
    Identifica o serviço com base no banner e na porta.
    """
    if not banner:
        if port == 443: return "HTTPS" # Se não teve banner mas é 443, assume HTTPS
        return "Desconhecido"

    banner = banner.lower()
    patterns = {
        "HTTP (Apache)": r"apache",
        "HTTP (Nginx)": r"nginx",
        "HTTP (IIS)": r"iis",
        "OpenSSH": r"ssh-\d\.\d", # Mais específico para SSH
        "FTP": r"ftp|vsftpd|proftpd",
        "SMTP (ESMTP)": r"smtp|postfix|sendmail|esmtp",
        "Telnet": r"telnet",
        "RDP": r"ms-wbt-server|rdp", # Padrão para RDP em banners
        "NetBIOS/SMB": r"samba|smbd", # Para portas 139/445
    }
    for service, pattern in patterns.items():
        if re.search(pattern, banner):
            return service
    
    # Heurísticas baseadas na porta se o banner não for conclusivo
    if port == 21: return "FTP"
    if port == 22: return "SSH"
    if port == 23: return "Telnet"
    if port == 25: return "SMTP"
    if port == 80: return "HTTP"
    if port == 443: return "HTTPS"
    if port == 3389: return "RDP"
    if port == 8080: return "HTTP (Proxy/Alt)"
    if port == 445 or port == 139: return "SMB/NetBIOS"


    return "Desconhecido"

# --- Exporta JSON ---
def export_json(data, filename_prefix="scan_result"):
    """Exporta os dados do scan para um arquivo JSON."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.json"
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Resultado exportado para {filename}")
    except IOError as e:
        logger.error(f"Erro ao exportar JSON para {filename}: {e}")

# --- Exporta CSV ---
def export_csv(data, filename_prefix="scan_result"):
    """Exporta os dados do scan para um arquivo CSV."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.csv"
    try:
        with open(filename, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Porta", "Banner", "Serviço"])
            for ip, results in data.items():
                for port, info in results.items():
                    writer.writerow([ip, port, info["banner"], info["service"]])
        logger.info(f"Resultado exportado para {filename}")
    except IOError as e:
        logger.error(f"Erro ao exportar CSV para {filename}: {e}")


# --- Função principal do Scanner ---
def scan_it(ip, ports, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
    """
    Executa a varredura completa de portas e coleta de banners para um único IP.
    """
    logger.info(f"Iniciando scan em {ip}...")
    results = {}
    open_ports = scan_ports(ip, ports, timeout, threads) # Chama a função aprimorada
    
    if not open_ports:
        logger.info(f"Nenhuma porta aberta encontrada em {ip} no intervalo especificado.")
        return {ip: {}} # Retorna um dicionário vazio para este IP

    # Coleta de banners para portas abertas
    logger.info(f"Coletando banners para as portas abertas em {ip}...")
    banner_results = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_banner = {executor.submit(banner_grab, ip, port, timeout): port for port in open_ports}
        for future in as_completed(future_to_banner):
            port = future_to_banner[future]
            try:
                banner = future.result()
                service = identify_service(banner, port)
                banner_results[port] = {"banner": banner, "service": service}
                logger.info(f"Porta {port}: {service} | Banner: {banner}")
            except Exception as exc:
                logger.warning(f"Erro ao coletar banner/serviço para porta {port}: {exc}")
    
    results[ip] = banner_results
    logger.info(f"Scan em {ip} concluído.")
    return results

# --- CLI (Command Line Interface) ---
def main():
    parser = argparse.ArgumentParser(
        description="Scanner IT ativo com varredura de portas e banner grabbing.",
        formatter_class=argparse.RawTextHelpFormatter # Preserva quebras de linha na descrição
    )
    parser.add_argument("ip", help="IP(s) de destino (ex: 192.168.1.1 ou 192.168.1.0/24 ou 192.168.1.1-10).")
    parser.add_argument("--ports", 
                        help="Portas a escanear (ex: 22,80,443 ou 1-1024).\n"
                             "Padrão: 21,22,23,25,80,443,3389,8080,445,139.", 
                        default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Tempo limite da conexão em segundos (padrão: {DEFAULT_TIMEOUT}).")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Número máximo de threads para o scan (padrão: {DEFAULT_THREADS}).")
    parser.add_argument("--json", action="store_true",
                        help="Exportar resultados para um arquivo JSON.")
    parser.add_argument("--csv", action="store_true",
                        help="Exportar resultados para um arquivo CSV.")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Define o nível de log (padrão: INFO).")

    args = parser.parse_args()

    # Configura o nível de log
    logger.setLevel(getattr(logging, args.log_level.upper()))

    # Processar IPs de entrada
    target_ips = []
    if '-' in args.ip: # Range de IPs
        try:
            ip_parts = args.ip.split('-')
            start_ip = [int(x) for x in ip_parts[0].split('.')]
            end_ip = [int(x) for x in ip_parts[1].split('.')]
            if len(start_ip) != 4 or len(end_ip) != 4: raise ValueError
            
            # Simple check for /24 ranges to avoid complex IP math for now
            if start_ip[0:3] != end_ip[0:3]:
                logger.error("A varredura de faixa de IP atual suporta apenas o último octeto (ex: 192.168.1.1-254).")
                return

            for i in range(start_ip[3], end_ip[3] + 1):
                ip_addr = f"{start_ip[0]}.{start_ip[1]}.{start_ip[2]}.{i}"
                if is_valid_ip(ip_addr):
                    target_ips.append(ip_addr)
        except ValueError:
            logger.error(f"Formato de faixa de IP inválido: {args.ip}. Use 192.168.1.1-254.")
            return
    elif '/' in args.ip: # Notação CIDR (simplificada para /24)
        try:
            ip_network, cidr_suffix = args.ip.split('/')
            cidr_suffix = int(cidr_suffix)
            if cidr_suffix != 24: # Suporta apenas /24 por enquanto para simplicidade
                logger.error("A varredura CIDR atual suporta apenas a notação /24.")
                return
            
            network_parts = [int(x) for x in ip_network.split('.')]
            if len(network_parts) != 4: raise ValueError
            
            for i in range(1, 255): # Itera de .1 a .254
                ip_addr = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.{i}"
                if is_valid_ip(ip_addr):
                    target_ips.append(ip_addr)
        except (ValueError, IndexError):
            logger.error(f"Formato CIDR inválido: {args.ip}. Use 192.168.1.0/24.")
            return
    else: # IP único
        if is_valid_ip(args.ip):
            target_ips.append(args.ip)
        else:
            return # is_valid_ip já logou o erro

    if not target_ips:
        logger.error("Nenhum IP alvo válido para escanear.")
        return

    # Processar portas de entrada
    ports_to_scan = []
    if args.ports:
        # Suporta ranges de porta como "1-1000"
        if '-' in args.ports:
            try:
                start_port, end_port = map(int, args.ports.split('-'))
                if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                    raise ValueError
                ports_to_scan = list(range(start_port, end_port + 1))
            except ValueError:
                logger.error(f"Formato de faixa de portas inválido: {args.ports}. Use 1-1024.")
                return
        else: # Lista de portas separadas por vírgula
            ports_to_scan = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit() and 0 < int(p.strip()) <= 65535]
            if not ports_to_scan:
                logger.error(f"Nenhuma porta válida especificada em --ports: {args.ports}.")
                return
    else:
        ports_to_scan = DEFAULT_PORTS

    overall_results = {}
    for ip in target_ips:
        current_ip_results = scan_it(ip, ports_to_scan, args.timeout, args.threads)
        overall_results.update(current_ip_results) # Atualiza o dicionário geral

    if args.json:
        export_json(overall_results)
    if args.csv:
        export_csv(overall_results)

if __name__ == "__main__":
    main()
