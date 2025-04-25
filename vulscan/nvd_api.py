import time
import requests
import logging
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class NvdApi:
    BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    def __init__(self, api_key: str, rate_limit_delay: float = 0.6):
        self.api_key = api_key
        self.last = 0.0
        self.delay = rate_limit_delay

    def _delay(self) -> None:
        elapsed = time.time() - self.last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last = time.time()

    def search(self, query: str) -> Optional[List[Dict[str, Any]]]:
        self._delay()
        headers = {'apiKey': self.api_key}
        params = {'keywordSearch': query}
        try:
            resp = requests.get(self.BASE_URL, params=params, headers=headers, timeout=10)
            if resp.status_code == 429:
                retry = int(resp.headers.get('Retry-After', 1))
                logger.warning(f"Rate limit atingido, aguardando {retry}s")
                time.sleep(retry)
                return self.search(query)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get('vulnerabilities', [])
            result: List[Dict[str, Any]] = []
            for item in vulns:
                c = item['cve']
                desc = next((d['value'] for d in c.get('descriptions', []) if d.get('lang') == 'en'), '')
                metrics_v3 = c.get('metrics', {}).get('cvssMetricV3', [])
                metrics_v2 = c.get('metrics', {}).get('cvssMetricV2', [])
                score = None
                if metrics_v3:
                    score = metrics_v3[0].get('cvssData', {}).get('baseScore')
                elif metrics_v2:
                    score = metrics_v2[0].get('cvssData', {}).get('baseScore')
                result.append({'id': c['id'], 'description': desc, 'score': score})
            return result or None
        except Exception as e:
            logger.error(f"Erro ao consultar NVD: {e}")
            return None

    def get_cve_info(self, service: str, version: Optional[str] = None) -> Dict[str, Any]:
        if not service:
            return {'cve_details': [], 'confidence': 'Baixa', 'description': 'Serviço não identificado.'}
        query = f"{service} {version}" if version else service
        res = self.search(query)
        if res:
            return {'cve_details': res, 'confidence': 'Alta', 'description': f"{len(res)} CVEs encontrados."}
        if version:
            res2 = self.search(service)
            if res2:
                return {'cve_details': res2, 'confidence': 'Média', 'description': f"{len(res2)} CVEs (sem versão)."}
        return {'cve_details': [], 'confidence': 'Baixa', 'description': 'Nenhum CVE correspondente encontrado.'}
