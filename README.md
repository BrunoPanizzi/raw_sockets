# Network Traffic Monitor – RAW Sockets / PCAP (Go)

Este projeto implementa um **Monitor de Tráfego de Rede em Tempo Real**, usando **Go**, com suporte a:

- Captura de pacotes via **PCAP** (Npcap/WinPcap)
- Parsing manual das camadas:
  - Loopback header (Npcap)
  - IPv4
  - TCP
  - UDP
  - ICMP
- Coleta e agregação de estatísticas por host
- Exportação para CSV:
  - internet.csv → tráfego nível IP
  - transporte.csv → TCP/UDP
  - aplicacao.csv → eventos detectados (DNS, etc.)
- Execução em Windows via **Npcap**

---

## 📌 Requisitos

### **Windows**
- Instalar **Npcap**  
  🔗 https://npcap.com/

**IMPORTANTE:** marque a opção:

✔️ *Install Npcap in WinPcap API-compatible Mode*

Sem isso o GoPCAP não funciona.

---

## 📦 Instalação das dependências

O projeto usa Go Modules. Basta rodar:

```sh
go mod tidy

🚀 EXECUÇÃO

1. Descobrir o nome das interfaces PCAP

```sh

go run .\tools\list.go

Exemplo de saída

Nome: \Device\NPF_{92477B0A-EA87-479E-A216-A482A3C4F06C}
Descrição: Intel(R) Wi-Fi 6 AX201 160MHz
  IP: 192.168.100.103

2. Rodar o monitor:

```sh
go run . --iface "\Device\NPF_Loopback" --mode pcap

3. Captura de tráfego loopback

```sh
go run . --iface "\Device\NPF_{92477B0A-EA87-479E-A216-A482A3C4F06C}" --mode pcap

📁 Saída gerada

Os arquivos CSV são criados automaticamente em:

bash
./logs/

🧩 Arquitetura dos Arquivos

main.go                 → pipeline principal, goroutines, CSV, stats
parser.go               → parse manual de Ethernet / Loopback / IPv4 / TCP / UDP / ICMP
capturer.go             → captura raw (Linux) – não usado no Windows
raw_socket_windows.go   → stub garantindo compatibilidade
stats.go                → agregação de estatísticas por host
writer.go               → writer assíncrono para CSV
tools/list.go           → utilitário para listar adapters PCAP

🔧 Como testar tráfego
Loopback (Windows)

Use:
ping 127.0.0.1

DNS (gera aplicação.csv)

nslookup google.com
ping google.com

HTTP/HTTPS

Abra qualquer página no navegador enquanto captura pela interface Wi-Fi.
