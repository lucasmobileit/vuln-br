""
"""  
Módulo para exportar os resultados do VulScan.  
"""

import json
import csv
import os
from typing import List, Dict
from datetime import datetime

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
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"resultados_{safe_target}.csv"

        if not data:
            print("[!] Nenhum dado para exportar.")
            return filename

        # Coleta todos os campos dinamicamente
        fieldnames = sorted({key for item in data for key in item.keys()})

        # Garante que o arquivo sempre seja reescrito
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction='ignore')
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
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"resultados_{safe_target}.html"

        # Coleta todos os campos dinamicamente
        fieldnames = sorted({key for item in data for key in item.keys()})

        # Cabeçalho HTML e estilos básicos
        html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resultados do VulScan</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Resultados do VulScan</h1>
        <p><strong>Alvo:</strong> {target}</p>
        <p><strong>Data:</strong> {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</p>
        <table>
            <thead>
                <tr>
                    {''.join(f"<th>{header.capitalize()}</th>" for header in fieldnames)}
                </tr>
            </thead>
            <tbody>
                {''.join(
                    '<tr>' +
                    ''.join(f"<td>{item.get(col, '')}</td>" for col in fieldnames) +
                    '</tr>'
                    for item in data
                )}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as file:
            file.write(html_content)

        return filename
""
