"""
Módulo para exportar o resumo com detalhes de CVEs.
"""
import json
import csv
import os
from typing import List, Dict
from datetime import datetime

class ResultExporter:
    @staticmethod
    def export_json(data: List[Dict], target: str) -> str:
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"summary_{safe_target}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filename

    @staticmethod
    def export_csv(data: List[Dict], target: str) -> str:
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"summary_{safe_target}.csv"
        if not data:
            return filename
        # todas as colunas dinâmicas
        fieldnames = sorted({k for row in data for k in row.keys()})
        # converte lista details para string
        for row in data:
            if isinstance(row.get('details'), list):
                row['details'] = ';'.join(row['details'])
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        return filename

    @staticmethod
    def export_html(data: List[Dict], target: str) -> str:
        safe_target = target.replace('.', '_').replace('/', '_').replace('-', '_')
        filename = f"summary_{safe_target}.html"
        html = f"""<!DOCTYPE html>
<html lang='pt-BR'>
<head><meta charset='UTF-8'/><title>Resumo VulScan</title></head>
<body>
  <h1>Resumo de CVEs (detalhes)</h1>
  <p>Alvo: {target}</p>
  <p>Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
  <table border='1' cellspacing='0' cellpadding='5'>
"""
        for item in data:
            svc = item['service']
            tot, hi, me = item['total'], item['high'], item['medium']
            html += f"<tr><td colspan='3'><details><summary>{svc}: {tot} CVEs ({hi} alto, {me} médio)</summary><ul>"
            for d in item.get('details', []):
                html += f"<li>{d}</li>"
            html += "</ul></details></td></tr>"
        html += "</table></body></html>"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        return filename
