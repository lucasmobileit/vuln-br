
"""
Módulo para exportar os resultados do VulScan.
"""

import json
import csv
import os
from typing import List, Dict

class ResultExporter:
    """Classe para exportar resultados do scan para diferentes formatos."""
    
    @staticmethod
    def export_json(data: List[Dict], target: str) -> str:
        """
        Exporta os resultados para um arquivo JSON.
        
        Args:
            data: Lista de dicionários com os resultados do scan
            target: O alvo do scan (IP, hostname ou rede)
            
        Returns:
            Caminho do arquivo JSON gerado
        """
        # Remove caracteres inválidos para nome de arquivo
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"resultados_{safe_target}.json"
        
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
            
        return filename
    
    @staticmethod
    def export_csv(data: List[Dict], target: str) -> str:
        """
        Exporta os resultados para um arquivo CSV.
        
        Args:
            data: Lista de dicionários com os resultados do scan
            target: O alvo do scan (IP, hostname ou rede)
            
        Returns:
            Caminho do arquivo CSV gerado
        """
        # Remove caracteres inválidos para nome de arquivo
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"resultados_{safe_target}.csv"
        
        # Define os campos do CSV
        if data and 'host' in data[0]:
            fieldnames = ['host', 'port', 'service', 'version', 'cve_id', 'cve_desc']
        else:
            fieldnames = ['port', 'service', 'version', 'cve_id', 'cve_desc']
        
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
            
        return filename
    
    @staticmethod
    def export_html(data: List[Dict], target: str) -> str:
        """
        Exporta os resultados para um arquivo HTML.
        
        Args:
            data: Lista de dicionários com os resultados do scan
            target: O alvo do scan (IP, hostname ou rede)
            
        Returns:
            Caminho do arquivo HTML gerado
        """
        # Remove caracteres inválidos para nome de arquivo
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"resultados_{safe_target}.html"
        
        # Cria o conteúdo HTML
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
        
        # Substitui os placeholders
        from datetime import datetime
        
        html_content = html_content.replace("TARGET_PLACEHOLDER", target)
        html_content = html_content.replace("DATA_PLACEHOLDER", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        
        # Cria os cabeçalhos
        if data and 'host' in data[0]:
            headers = "<th>Host</th><th>Porta</th><th>Serviço</th><th>Versão</th><th>CVE</th><th>Descrição</th>"
        else:
            headers = "<th>Porta</th><th>Serviço</th><th>Versão</th><th>CVE</th><th>Descrição</th>"
            
        html_content = html_content.replace("HEADERS_PLACEHOLDER", headers)
        
        # Cria as linhas
        rows = ""
        for item in data:
            row = "<tr>"
            
            if 'host' in item:
                row += f"<td>{item['host']}</td>"
                
            row += f"<td>{item['port']}</td>"
            row += f"<td>{item['service']}</td>"
            row += f"<td>{item['version'] or 'Desconhecida'}</td>"
            row += f"<td>{item['cve_id']}</td>"
            row += f"<td>{item['cve_desc']}</td>"
            row += "</tr>"
            rows += row
            
        html_content = html_content.replace("ROWS_PLACEHOLDER", rows)
        
        # Escreve o arquivo HTML
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(html_content)
            
        return filename
