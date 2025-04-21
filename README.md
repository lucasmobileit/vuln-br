# VulScan

VulScan é uma ferramenta Python para escanear serviços de rede e consultar vulnerabilidades (CVEs) usando o Nmap e a API da National Vulnerability Database (NVD). Ele suporta escaneamento de hosts individuais, redes (CIDR ou ranges) e dispositivos IoT/OT, com exportação de resultados em formatos JSON, CSV e HTML.

## Funcionalidades

- **Escaneamento de Rede**: Escaneia IPs, hostnames, notações CIDR (ex.: `192.168.1.0/24`) ou ranges (ex.: `192.168.1.1-10`) usando o Nmap.
- **Consulta de Vulnerabilidades**: Integra com a API da NVD para identificar CVEs associadas a serviços e versões detectados.
- **Modo IoT/OT**: Configurações específicas para escanear dispositivos industriais e IoT, incluindo portas e scripts NSE especializados.
- **Exportação de Resultados**: Gera relatórios em JSON, CSV e HTML com detalhes dos serviços e vulnerabilidades encontrados.
- **Interface Flexível**: Suporta argumentos de linha de comando para personalizar alvos, diretórios de saída e modo verboso.

## Pré-requisitos

- **Python 3.8+**
- **Nmap** instalado no sistema (disponível em [nmap.org](https://nmap.org/))
- **Chave de API da NVD** (obtenha em [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key))
- Dependências Python:
  - `requests`
  - `python-dotenv`
  - `tabulate`

## Instalação

1. **Clone o repositório** (se aplicável):
   ```bash
   git clone <URL_DO_REPOSITORIO>
   cd vulscan
   ```

2. **Instale as dependências**:
   ```bash
   pip install requests python-dotenv tabulate
   ```

3. **Instale o Nmap**:
   - No Linux:
     ```bash
     sudo apt-get install nmap
     ```
   - No macOS:
     ```bash
     brew install nmap
     ```
   - No Windows: Baixe e instale a partir de [nmap.org](https://nmap.org/download.html).

4. **Configure a chave de API da NVD**:
   - Crie um arquivo `.env` na raiz do projeto com o seguinte conteúdo:
     ```plaintext
     NVD_API_KEY="sua-chave-aqui"
     ```
   - Obtenha sua chave em [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
   - **Nota de Segurança**: Não compartilhe o arquivo `.env` nem o inclua em repositórios públicos. Adicione `.env` ao `.gitignore`.

## Uso

Execute o VulScan via linha de comando:

```bash
python -m vulscan <alvo> [opções]
```

### Exemplos

1. **Escanear um host único**:
   ```bash
   python -m vulscan scanme.nmap.org
   ```

2. **Escanear uma rede CIDR**:
   ```bash
   python -m vulscan 192.168.1.0/24 --output-dir ./resultados
   ```

3. **Escanear dispositivos IoT/OT**:
   ```bash
   python -m vulscan 192.168.1.1 --iot
   ```

4. **Modo verboso para debugging**:
   ```bash
   python -m vulscan 192.168.1.1 --verbose
   ```

5. **Debug detalhado do Nmap**:
   ```bash
   VULSCAN_DEBUG=1 python -m vulscan scanme.nmap.org
   ```

### Opções

- `alvo`: IP, hostname, CIDR ou range (ex.: `192.168.1.1`, `example.com`, `192.168.1.0/24`, `192.168.1.1-10`).
- `--iot`: Ativa o modo de escaneamento para dispositivos IoT/OT.
- `--output-dir <diretório>`: Especifica o diretório para salvar os arquivos de saída (padrão: diretório atual).
- `--verbose`: Ativa logs detalhados (nível DEBUG).

### Saída

Os resultados são salvos no diretório especificado (ou atual) nos formatos:
- `resultados_<alvo>.json`
- `resultados_<alvo>.csv`
- `resultados_<alvo>.html`

Os logs são exibidos no console, incluindo uma tabela com os serviços detectados, versões e CVEs.

## Estrutura do Projeto

- `__init__.py`: Metadados do projeto.
- `__main__.py`: Ponto de entrada, gerencia a interface de linha de comando e orquestra o escaneamento.
- `nmap_scanner.py`: Executa e processa scans do Nmap.
- `nvd_api.py`: Interage com a API da NVD para consultar CVEs.
- `exporter.py`: Exporta resultados para JSON, CSV e HTML.
- `.env`: Armazena a chave de API da NVD (não incluído no controle de versão).

## Notas de Segurança

- **Chave de API**: Mantenha o arquivo `.env` privado. Use `.gitignore` para evitar exposição.
- **Escaneamento Responsável**: Apenas escaneie redes e dispositivos que você tem permissão para analisar. Escaneamentos não autorizados podem ser ilegais.
- **Dispositivos IoT/OT**: O modo IoT/OT usa configurações mais lentas para evitar impactos em dispositivos sensíveis, mas tome cuidado ao escanear sistemas críticos.

## Contribuição

1. Faça um fork do repositório.
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`).
3. Commit suas mudanças (`git commit -m "Adiciona nova funcionalidade"`).
4. Push para a branch (`git push origin feature/nova-funcionalidade`).
5. Abra um Pull Request.

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo `LICENSE` para detalhes (adicione um se necessário).

## Suporte

Se encontrar problemas ou tiver sugestões, abra uma issue no repositório ou entre em contato com o mantenedor.

---

**VulScan v1.0.0** - Desenvolvido para ajudar na identificação de vulnerabilidades de forma segura e eficiente.