package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	fmt.Println("=== Interfaces PCAP Detectadas ===")
	for _, d := range devices {
		fmt.Printf("Nome: %s\nDescrição: %s\n", d.Name, d.Description)
		for _, addr := range d.Addresses {
			fmt.Printf("  IP: %v\n", addr.IP)
		}
		fmt.Println()
	}
}
