// main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket/pcap"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	iface := flag.String("iface", "lo", "Interface de rede")
	mode := flag.String("mode", "pcap", "Modo de captura: pcap")
	csvDir := flag.String("csv-dir", "./logs", "Diretório para salvar os logs de arquivos CSV")
	flag.Parse()

	if runtime.GOOS == "windows" {
		*mode = "pcap"
		log.Printf("Windows detectado, usando modo pcap")
	}

	os.MkdirAll(*csvDir, 0755)

	// canais
	chRawPackets := make(chan []byte, 100)
	chParsedPackets := make(chan *Packet, 100)

	// csv writers
	csvInternet, err := NewCSVWriter(*csvDir+"/internet.csv",
		[]string{"timestamp", "protocolo", "src_ip", "dst_ip", "bytes"},
		200)
	if err != nil {
		log.Fatalf("Erro ao criar CSV internet: %v", err)
	}

	csvTransporte, err := NewCSVWriter(*csvDir+"/transporte.csv",
		[]string{"timestamp", "proto", "src_ip", "src_port", "dst_ip", "dst_port", "bytes"},
		200)
	if err != nil {
		log.Fatalf("Erro ao criar CSV transporte: %v", err)
	}

	csvAplicacao, err := NewCSVWriter(*csvDir+"/aplicacao.csv",
		[]string{"timestamp", "protocolo", "info"},
		200)
	if err != nil {
		log.Fatalf("Erro ao criar CSV aplicacao: %v", err)
	}

	defer csvInternet.Close()
	defer csvTransporte.Close()
	defer csvAplicacao.Close()

	// stats
	stats := NewGlobalStats()

	// goroutine de captura
	go func() {
		handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("Erro ao abrir interface pcap %s: %v", *iface, err)
		}
		defer handle.Close()

		log.Printf("[CAPTURA] pcap iniciado em %s", *iface)

		for {
			data, _, err := handle.ReadPacketData()
			log.Printf("PACOTE RECEBIDO TAM: %d | HEX: % X", len(data), data[:min(32, len(data))])
			chRawPackets <- data
			if err == nil {
				chRawPackets <- data
			}
		}
	}()

	// goroutine de parsing dos pacotes
	go func() {
		for raw := range chRawPackets {
			p, err := ParsePacket(raw)
			if err == nil {
				chParsedPackets <- p
			}
		}
	}()

	// goroutine de logging e stats
	go func() {
		for p := range chParsedPackets {
			// internet
			if p.IsIPv4 {
				csvInternet.Write([]string{
					p.Timestamp.Format(time.RFC3339Nano),
					"IPv4",
					p.IPv4.SrcIP.String(),
					p.IPv4.DstIP.String(),
					fmt.Sprint(len(p.Raw)),
				})

				// atualizar stats
				c := stats.GetOrCreateClient(p.IPv4.SrcIP.String())
				c.AddPacket("IPv4", uint64(len(p.Raw)), p.IPv4.DstIP)
			}

			// transporte
			if p.TCP != nil {
				csvTransporte.Write([]string{
					p.Timestamp.Format(time.RFC3339Nano),
					"TCP",
					p.IPv4.SrcIP.String(),
					fmt.Sprint(p.TCP.SrcPort),
					p.IPv4.DstIP.String(),
					fmt.Sprint(p.TCP.DstPort),
					fmt.Sprint(len(p.Raw)),
				})

				c := stats.GetOrCreateClient(p.IPv4.SrcIP.String())
				c.AddPacket("TCP", uint64(len(p.Raw)), p.IPv4.DstIP)
			}

			if p.UDP != nil {
				csvTransporte.Write([]string{
					p.Timestamp.Format(time.RFC3339Nano),
					"UDP",
					p.IPv4.SrcIP.String(),
					fmt.Sprint(p.UDP.SrcPort),
					p.IPv4.DstIP.String(),
					fmt.Sprint(p.UDP.DstPort),
					fmt.Sprint(len(p.Raw)),
				})

				c := stats.GetOrCreateClient(p.IPv4.SrcIP.String())
				c.AddPacket("UDP", uint64(len(p.Raw)), p.IPv4.DstIP)
			}

			// camada de aplicação
			if p.UDP != nil && p.UDP.DstPort == 53 {
				csvAplicacao.Write([]string{
					p.Timestamp.Format(time.RFC3339Nano),
					"DNS",
					"consulta DNS detectada",
				})
			}
		}
	}()

	// user interface
	for {
		time.Sleep(2 * time.Second)
		fmt.Println("==== ESTATÍSTICAS ====")

		stats.mu.RLock()
		for _, cli := range stats.clients {
			fmt.Printf("Cliente %s | Packets=%d | Bytes=%d\n",
				cli.IP, cli.Packets, cli.Bytes)
		}
		stats.mu.RUnlock()
	}
}
