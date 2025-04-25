#!/usr/bin/env python3
import argparse
import logging
from nmap_scanner import NmapScanner
from nvd_api import NvdApi
from exporter import ResultExporter
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

def summarize_by_service(results: Any, threshold: float) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = {}
    for item in results:
        svc = item['service']
        details = item.get('cve_details', []) or []
        filtered = [c for c in details if c.get('score') is not None and c['score'] >= threshold]
        if not filtered:
            continue
        high = sum(1 for c in filtered if c['score'] >= 7)
        med = sum(1 for c in filtered if threshold <= c['score'] < 7)
        summary[svc] = {'total': len(filtered), 'high': high, 'medium': med}
    return summary


def main():
    parser = argparse.ArgumentParser(description='VulScan: Scanner de vulnerabilidades')
    parser.add_argument('target', help='IP, range ou CIDR')
    parser.add_argument('--api-key', required=True, help='Chave da NVD API')
    parser.add_argument('--output', choices=['json','csv','html'], default='json')
    parser.add_argument('--threshold', type=float, default=5.0, help='CVSS score mínimo para reporte')
    args = parser.parse_args()

    scanner = NmapScanner()
    xml = scanner.scan(args.target)
    results = scanner.parse_results(xml)

    enricher = NvdApi(args.api_key)
    enriched = []
    for item in results:
        info = enricher.get_cve_info(item['service'], item.get('version'))
        item.update({
            'cve_details': info['cve_details'],
            'confidence': info['confidence'],
            'cve_desc': info['description']
        })
        enriched.append(item)

    summary = summarize_by_service(enriched, args.threshold)
    logging.info("Resumo por serviço (CVSS ≥ %s):", args.threshold)
    for svc, data in summary.items():
        logging.info("  Serviço %s: %d CVEs ( %d alto, %d médio )", svc, data['total'], data['high'], data['medium'])

    summary_list = [
        {'service': svc, 'total': vals['total'], 'high': vals['high'], 'medium': vals['medium']}
        for svc, vals in summary.items()
    ]

    exporter = ResultExporter()
    file = getattr(exporter, f'export_{args.output}')(summary_list, args.target + '_summary')
    logging.info(f"Arquivo de resumo gerado: {file}")

if __name__ == '__main__':
    main()
