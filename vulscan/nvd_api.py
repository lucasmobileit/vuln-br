
"""
Módulo para interagir com a API da NVD (National Vulnerability Database).
"""

import time
import requests
from typing import Dict, Optional

class NvdApi:
    """Classe para interagir com a API da NVD."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.last_request_time = 0
        self.rate_limit_delay = 0.6  # 600ms entre requisições para respeitar o rate limit
    
    def _rate_limit(self) -> None:
        """Implementa rate limiting para evitar bloqueio da API."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def search(self, query: str) -> Optional[Dict[str, str]]:
        """
        Busca CVEs relacionadas a um serviço/versão.
        
        Args:
            query: Texto para busca de CVEs
            
        Returns:
            Dicionário com id e descrição da CVE ou None se não encontrar
        """
        self._rate_limit()
        url = f"{self.BASE_URL}?keywordSearch={query}"
        headers = {'apiKey': self.api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('totalResults', 0) > 0:
                cve = data['vulnerabilities'][0]['cve']
                description = cve['descriptions'][0]['value']
                
                return {
                    'id': cve['id'],
                    'description': description
                }
        except requests.exceptions.RequestException as e:
            print(f"  [!] Erro na requisição à API da NVD: {e}")
        except (KeyError, IndexError) as e:
            print(f"  [!] Erro ao processar resposta da API: {e}")
        except Exception as e:
            print(f"  [!] Erro inesperado ao consultar CVE: {e}")
            
        return None

    def get_cve_info(self, service: str, version: str) -> Dict[str, str]:
        """
        Obtém informações de CVE para um serviço e versão.
        Tenta com serviço+versão primeiro, depois só com serviço.
        
        Args:
            service: Nome do serviço
            version: Versão do serviço
            
        Returns:
            Dicionário com informações da CVE ou mensagem de não encontrado
        """
        # Primeiro tenta buscar com serviço e versão juntos
        if version:
            result = self.search(f"{service} {version}")
            if result:
                return result
                
        # Se não encontrou ou não tem versão, tenta só com o serviço
        if service:
            result = self.search(service)
            if result:
                return result
                
        # Se nada foi encontrado, retorna mensagem padrão
        return {
            'id': 'Nenhum CVE encontrado',
            'description': 'Sem vulnerabilidades conhecidas ou não encontradas na API.'
        }