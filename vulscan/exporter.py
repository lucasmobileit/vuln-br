"""
Módulo para exportar os resultados do VulScan.
"""

import json
import csv
import os
from typing import List, Dict
import logging

# Configuração do logger
logger = logging.getLogger(__name__)

class ResultExporter:
    """Classe para exportar resultados do scan para diferentes formatos."""
    
    @staticmethod
    def export_json(data: List[Dict], target: str, output_dir: str = ".") -> str:
        """
        Exporta os resultados para um arquivo JSON.
        
        Args:
            data: Lista de dicionários com os resultados do scan
            target: O alvo do scan (IP, hostname ou rede)
            output_dir: Diretório para salvar o arquivo
            
        Returns:
            Caminho do arquivo JSON gerado ou vazio em caso de erro
        """
        if not data:
            logger.warning("Nenhum dado para exportar para JSON.")
            return ""
            
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = os.path.join(output_dir, f"resultados_{safe_target}.json")
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=2, ensure_ascii=False)
            logger.info(f"JSON gerado: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Erro ao exportar JSON: {e}")
            return ""
    
    @staticmethod
    def export_csv(data: List[Dict], target: str, output_dir: str = ".") -> str:
        """
        Exporta os resultados para um arquivo CSV.
        
        Args:
            data: Lista de dicionários com os resultados do scan
            target: O alvo do scan (IP, hostname ou rede)
            output_dir: Diretório para salvar o arquivo
            
        Returns:
            Caminho do arquivo CSV gerado ou vazio em caso de erro
        """
        if not data:
            logger.warning("Nenhum dado para exportar para CSV.")
            return ""
            
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = os.path.join(output_dir, f"resultados_{safe_target}.csv")
        os.makedirs(output_dir, exist_ok=True)
        
        fieldnames = ['host', 'port', 'service', 'version', 'cve_id', 'cve_desc'] if data and 'host' in data[0] else ['port', 'service', 'version', 'cve_id', 'cve_desc']
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                # Normaliza 'version' para evitar None
                normalized_data = [
                    {**item, 'version': item.get('version') or 'Desconhecida'}
                    for item in data
                ]
                writer.writerows(normalized_data)
            logger.info(f"CSV gerado: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Erro ao exportar CSV: {e}")
            return ""
    
    @staticmethod
    def export_html(data: List[Dict], target: str, output_dir: str = ".") -> str:
        """
        Exporta os resultados para um arquivo HTML.
        
        Args:
            data: Lista de dicionários com os resultados do scan
            target: O alvo do scan (IP, hostname ou rede)
            output_dir: Diretório para salvar o arquivo
            
        Returns:
            Caminho do arquivo HTML gerado ou vazio em caso de erro
        """
        if not data:
            logger.warning("Nenhum dado para exportar para HTML.")
            return ""
            
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = os.path.join(output_dir, f"resultados_{safe_target}.html")
        os.makedirs(output_dir, exist_ok=True)
        
        html_content = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Resultados do VulScan</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
                h1 { color: #333; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
                tr:hover { background-color: #f5f5f5; }
                .cve-high { color: #d9534f; }
                .cve-medium { color: #f0ad4e; }
                .cve-low { color: #5bc0de; }
                .container { max-width: 1200px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Resultados do VulScan</h1>
                <p><strong>Alvo:</strong> TARGET_PLACEHOLDER</p>
                <p><strong>Data:</strong> DATA_PLACEHOLDER</p>
                
                <table>
                    <thead>
                        <tr>
                            HEADERS_PLACEHOLDER
                        </tr>
                    </thead>
                    <tbody>
                        ROWS_PLACEHOLDER
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        from datetime import datetime
        
        html_content = html_content.replace("TARGET_PLACEHOLDER", target)
        html_content = html_content.replace("DATA_PLACEHOLDER", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        
        if data and 'host' in data[0]:
            headers = "<th>Host</th><th>Porta</th><th>Serviço</th><th>Versão</th><th>CVE</th><th>Descrição</th>"
        else:
            headers = "<th>Porta</th><th>Serviço</th><th>Versão</th><th>CVE</th><th>Descrição</th>"
            
        html_content = html_content.replace("HEADERS_PLACEHOLDER", headers)
        
        rows = ""
        for item in data:
            row = "<tr>"
            if 'host' in item:
                row += f"<td>{item['host']}</td>"
            row += f"<td>{item['port']}</td>"
            row += f"<td>{item['service']}</td>"
            row += f"<td>{item.get('version', 'Desconhecida')}</td>"
            row += f"<td>{item['cve_id']}</td>"
            row += f"<td>{item['cve_desc']}</td>"
            row += "</tr>"
            rows += row
            
        html_content = html_content.replace("ROWS_PLACEHOLDER", rows)
        
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(html_content)
            logger.info(f"HTML gerado: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Erro ao exportar HTML: {e}")
            return ""