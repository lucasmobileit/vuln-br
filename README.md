# Vuln-BR

Scanner de vulnerabilidades que integra Nmap + NVD API, exportando resumos executivos e detalhes técnicos.

## Módulos
- **config.yaml** – define portas, scripts NSE e parâmetros de scan
- **nmap_scanner.py** – executa Nmap em host ou rede e retorna XML parseado
- **nvd_api.py** – consulta a NVD, coleta múltiplas CVEs com pontuação CVSS v3/v2
- **exporter.py** – exporta resumo (`summary_*`) e detalhes em JSON, CSV e HTML
- **__main__.py** – CLI com `argparse` (`target`, `--api-key`, `--threshold`, `--output`)

## Pré-requisitos
- Python 3.8+
- Dependências:
  ```bash
  pip install -r requirements.txt 
  ```
  - requests
  - pyyaml

## Configuração
Edite o arquivo **config.yaml** para ajustar portas e scripts NSE antes de rodar.

## Instalação
```bash
git clone https://github.com/lucasmobileit/vulscan_ip.git
cd vulscan_ip
pip install -r requirements.txt
```

## Uso
```bash
python -m vulscan_ip.__main__ <TARGET> \
  --api-key SUA_NVD_API_KEY \
  --threshold 5 \
  --output {json,csv,html}
```
- `<TARGET>`: IP, hostname ou CIDR
- `--threshold`: CVSS mínimo (default 5.0)
- `--output`: formato de saída

## Saída
- **JSON**: array de objetos `{ service, total, high, medium, details }`
- **CSV**: mesmas colunas; `details` como lista separada por `;`
- **HTML**: tabela com `<details>` nativo para “Ver detalhes”

## Exemplo de resumo (HTML)
<details>
<summary>ssh: 2 CVEs (1 alto, 1 médio)</summary>
<ul>
<li>CVE-2021-1234</li>
<li>CVE-2020-5678</li>
</ul>
</details>
