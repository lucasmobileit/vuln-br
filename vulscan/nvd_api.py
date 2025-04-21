"""
Módulo para interagir com a API da NVD (National Vulnerability Database).
"""

import time
import requests
from typing import Dict, Optional
import logging

# Configuração do logger
logger = logging.getLogger(__name__)

class NvdApi:
    """Classe para interagir com a API da NVD."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.last_request_time = 0
        self.rate_limit_delay = 0.6  # 600ms entre requisições
        self.cache = {}  # Cache para resultados de busca
    
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
        if query in self.cache:
            logger.debug(f"Cache hit para query: {query}")
            return self.cache[query]
            
        self._rate_limit()
        url = f"{self.BASE_URL}?keywordSearch={query}"
        headers = {'apiKey': self.api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if 'Retry-After' in response.headers:
                self.rate_limit_delay = float(response.headers.get('Retry-After', 0.6))
            response.raise_for_status()
            data = response.json()
            
            if data.get('totalResults', 0) > 0:
                cve = data['vulnerabilities'][0]['cve']
                description = cve['descriptions'][0]['value']
                result = {
                    'id': cve['id'],
                    'description': description
                }
                self.cache[query] = result
                return result
        except requests.exceptions.RequestException as e:
            logger.error(f"Erro na requisição à API da NVD: {e}")
        except (KeyError, IndexError) as e:
            logger.error(f"Erro ao processar resposta da API: {e}")
        except Exception as e:
            logger.error(f"Erro inesperado ao consultar CVE: {e}")
            
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
        if version:
            result = self.search(f"{service} {version}")
            if result:
                return result
                
        if service:
            result = self.search(service)
            if result:
                return result
                
        return {
            'id': 'Nenhum CVE encontrado',
            'description': 'Sem vulnerabilidades conhecidas ou não encontradas na API.'
        }