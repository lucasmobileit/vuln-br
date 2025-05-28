# Importando a biblioteca nmap
import nmap

# Criando objeto scanner
scanner = nmap.PortScanner()

# Definindo o alvo
target = "scanme.nmap.org"

# Opções do Nmap
options = "-sS -sV -O -p 1-1000"

# Executando o scan
scanner.scan(target, arguments=options)

# Imprimindo os resultados
for host in scanner.all_hosts():
    print("Host:", host)
    print("State:", scanner[host].state())
    for proto in scanner[host].all_protocols():
        print("Protocol:", proto)
        ports = scanner[host][proto].keys()
        for port in ports:
            print("Port:", port, "State:", scanner[host][proto][port]['state'])
