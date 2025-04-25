import ipaddress
import subprocess
import logging
import yaml
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, config_path: str = 'config.yaml'):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.cfg = yaml.safe_load(f)['services']

    def validate_target(self, target: str) -> bool:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            logger.error(f"Alvo inválido: {target}")
            return False

    def scan(self, target: str) -> str:
        if not self.validate_target(target):
            raise ValueError(f"Alvo inválido: {target}")
        cmd = ['nmap'] + self.cfg['default_args'].split() + [target]
        logger.info(f"Executando: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return proc.stdout

    def parse_results(self, xml_data: str) -> List[Dict[str, Any]]:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_data)
        vulnerabilities: List[Dict[str, Any]] = []
        for host in root.findall('.//host'):
            addr = host.find('address').get('addr')
            for port in host.findall('.//port'):
                svc = port.find('service')
                vulnerabilities.append({
                    'host': addr,
                    'port': port.get('portid'),
                    'service': svc.get('name'),
                    'version': svc.get('version')
                })
        return vulnerabilities
