package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	// Nome da interface de rede (tun0)
	interfaceName := "tun0"

	// Abre a interface em modo promíscuo
	handle, err := pcap.OpenLive(
		interfaceName, // Interface de rede
		1600,           // Tamanho do snapshot (max bytes por pacote)
		true,           // Modo promíscuo
		pcap.BlockForever, // Timeout (nunca bloqueia)
	)
	if err != nil {
		log.Fatalf("Erro ao abrir interface %s: %v", interfaceName, err)
	}
	defer handle.Close()

	fmt.Println("Capturando pacotes em tun0...")


	// Loop para capturar pacotes
	for {
		// Lê um pacote
		n, _, err := handle.ReadPacketData()
		if err != nil {
			log.Printf("Erro ao ler pacote: %v", err)
			continue
		}

		// packetData[:n] contém os bytes brutos do pacote
		fmt.Printf("Pacote capturado (%d bytes)\n", n)
	}
}

