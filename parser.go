package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
)

type EthernetFrame struct {
	DestinationMAC [6]byte
	SourceMAC      [6]byte
	EtherType      uint16
}

type IPV4Packet struct {
	Version       uint8
	IHL           uint8
	TotalLength   uint16
	Protocol      uint16
	SourceIP      net.IP
	DestinationIP net.IP
	Payload       []byte
}

type UDPHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

func ParseEthernetFrame(data []byte) (*EthernetFrame, []byte) {
	f := &EthernetFrame{
		DestinationMAC: [6]byte{data[0], data[1], data[2], data[3], data[4], data[5]},
		SourceMAC:      [6]byte{data[6], data[7], data[8], data[9], data[10], data[11]},
		EtherType:      uint16(data[12])<<8 | uint16(data[13]),
	}
	return f, data[14:]
}

func ParseIPv4Packet(data []byte) (*IPV4Packet, []byte) {
	version := data[0] >> 4
	ihl := data[0] & 0x0F
	headerLength := int(ihl * 4)

	p := &IPV4Packet{
		Version:       version,
		IHL:           ihl,
		TotalLength:   uint16(data[2])<<8 | uint16(data[3]),
		Protocol:      uint16(data[9]),
		SourceIP:      net.IPv4(data[12], data[13], data[14], data[15]),
		DestinationIP: net.IPv4(data[16], data[17], data[18], data[19]),
	}

	payloadStart := headerLength
	p.Payload = data[payloadStart:p.TotalLength]

	return p, data[p.TotalLength:]
}

func ParseUDP(data []byte) *UDPHeader {
	return &UDPHeader{
		SourcePort:      uint16(data[0])<<8 | uint16(data[1]),
		DestinationPort: uint16(data[2])<<8 | uint16(data[3]),
		Length:          uint16(data[4])<<8 | uint16(data[5]),
		Checksum:        uint16(data[6])<<8 | uint16(data[7]),
	}
}

func formatMACBytes(b [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

func NormalizeHexDump(rawHex string) string {
	rawHex = strings.ReplaceAll(rawHex, "\n", "")
	rawHex = strings.ReplaceAll(rawHex, " ", "")
	return rawHex
}

func main() {

	rawHex := "" +
		`ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 
05 94 00 00 00 00 32 ff be 11 c0 a8 ff 01 c0 a8 
ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 
45 00 05 72 00 00 00 00 32 ff b8 33 c0 a8 ff 01 
c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 
08 00 45 00 05 50 00 00 00 00 32 ff b8 55 c0 a8 
ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc 
dd ee 08 00 45 00 05 2e 00 00 00 00 32 ff b8 77 
c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa 
bb cc dd ee 08 00 45 00 05 0c 00 00 00 00 32 ff 
b8 99 c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 
00 aa bb cc dd ee 08 00 45 00 04 ea 00 00 00 00 
32 ff bd bb c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff 
ff ff 00 aa bb cc dd ee 08 00 45 00 04 c8 00 00 
00 00 32 ff bd dd c0 a8 ff 01 c0 a8 ff 0a ff ff 
ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 04 a6 
00 00 00 00 32 ff bd ff c0 a8 ff 01 c0 a8 ff 0a 
ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 
04 84 00 00 00 00 32 ff be 21 c0 a8 ff 01 c0 a8 
ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 
45 00 04 62 00 00 00 00 32 ff b9 43 c0 a8 ff 01 
c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 
08 00 45 00 04 40 00 00 00 00 32 ff b9 65 c0 a8 
ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc 
dd ee 08 00 45 00 04 1e 00 00 00 00 32 ff b9 87 
c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa 
bb cc dd ee 08 00 45 00 03 fc 00 00 00 00 32 ff 
bd a9 c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 
00 aa bb cc dd ee 08 00 45 00 03 da 00 00 00 00 
32 ff bd cb c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff 
ff ff 00 aa bb cc dd ee 08 00 45 00 03 b8 00 00 
00 00 32 ff bd ed c0 a8 ff 01 c0 a8 ff 0a ff ff 
ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 03 96 
00 00 00 00 32 ff be 0f c0 a8 ff 01 c0 a8 ff 0a 
ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 
03 74 00 00 00 00 32 ff ba 31 c0 a8 ff 01 c0 a8 
ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 
45 00 03 52 00 00 00 00 32 ff ba 53 c0 a8 ff 01 
c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 
08 00 45 00 03 30 00 00 00 00 32 ff ba 75 c0 a8 
ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc 
dd ee 08 00 45 00 03 0e 00 00 00 00 32 ff ba 97 
c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa 
bb cc dd ee 08 00 45 00 02 ec 00 00 00 00 32 ff 
bd b9 c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 
00 aa bb cc dd ee 08 00 45 00 02 ca 00 00 00 00 
32 ff bd db c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff 
ff ff 00 aa bb cc dd ee 08 00 45 00 02 a8 00 00 
00 00 32 ff bd fd c0 a8 ff 01 c0 a8 ff 0a ff ff 
ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 02 86 
00 00 00 00 32 ff be 1f c0 a8 ff 01 c0 a8 ff 0a 
ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 
02 64 00 00 00 00 32 ff bb 41 c0 a8 ff 01 c0 a8 
ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 
45 00 02 42 00 00 00 00 32 ff bb 63 c0 a8 ff 01 
c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 
08 00 45 00 02 20 00 00 00 00 32 ff bb 85 c0 a8 
ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc 
dd ee 08 00 45 00 01 fe 00 00 00 00 32 ff bd a7 
c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa 
bb cc dd ee 08 00 45 00 01 dc 00 00 00 00 32 ff 
bd c9 c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 
00 aa bb cc dd ee 08 00 45 00 01 ba 00 00 00 00 
32 ff bd eb c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff 
ff ff 00 aa bb cc dd ee 08 00 45 00 01 98 00 00 
00 00 32 ff be 0d c0 a8 ff 01 c0 a8 ff 0a ff ff 
ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 01 76 
00 00 00 00 32 ff bc 2f c0 a8 ff 01 c0 a8 ff 0a 
ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 
01 54 00 00 00 00 32 ff bc 51 c0 a8 ff 01 c0 a8 
ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 
45 00 01 32 00 00 00 00 32 ff bc 73 c0 a8 ff 01 
c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc dd ee 
08 00 45 00 01 10 00 00 00 00 32 ff bc 95 c0 a8 
ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa bb cc 
dd ee 08 00 45 00 00 ee 00 00 00 00 32 ff bd b7 
c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 00 aa 
bb cc dd ee 08 00 45 00 00 cc 00 00 00 00 32 ff 
bd d9 c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff ff ff 
00 aa bb cc dd ee 08 00 45 00 00 aa 00 00 00 00 
32 ff bd fb c0 a8 ff 01 c0 a8 ff 0a ff ff ff ff 
ff ff 00 aa bb cc dd ee 08 00 45 00 00 88 00 00 
00 00 32 ff be 1d c0 a8 ff 01 c0 a8 ff 0a ff ff 
ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 00 66 
00 00 00 00 32 ff bd 3f c0 a8 ff 01 c0 a8 ff 0a 
ff ff ff ff ff ff 00 aa bb cc dd ee 08 00 45 00 
00 44 00 00 00 00 32 ff bd 61 c0 a8 ff 01 c0 a8 
ff 0a 60 00 00 00 00 08 3a ff fe 80 00 00 00 00 
00 00 2e e0 82 c6 2c 5c 74 32 ff 02 00 00 00 00 
00 00 00 00 00 00 00 00 00 02 85 00 2b 02 00 00 
00 00 
`

	normalizedHex := NormalizeHexDump(rawHex)

	data, err := hex.DecodeString(normalizedHex)
	if err != nil {
		log.Fatal("Erro ao decodificar hex: ", err)
	}

	// Parse
	eth, afterEth := ParseEthernetFrame(data)
	ip, afterIP := ParseIPv4Packet(afterEth)
	udp := ParseUDP(ip.Payload)

	// ---------------------------
	// OUTPUT
	// ---------------------------

	fmt.Println("========== PARSER ==========")

	fmt.Println("\n---- Ethernet ----")
	fmt.Println("Dst MAC:", formatMACBytes(eth.DestinationMAC))
	fmt.Println("Src MAC:", formatMACBytes(eth.SourceMAC))
	fmt.Printf("EtherType: 0x%04x\n", eth.EtherType)

	fmt.Println("\n---- IPv4 ----")
	fmt.Println("Version:", ip.Version)
	fmt.Println("IHL:", ip.IHL)
	fmt.Println("Total Length:", ip.TotalLength)
	fmt.Println("Protocol:", ip.Protocol, "(11 = UDP)")
	fmt.Println("Src IP:", ip.SourceIP)
	fmt.Println("Dst IP:", ip.DestinationIP)

	fmt.Println("\n---- UDP ----")
	fmt.Println("Src Port:", udp.SourcePort)
	fmt.Println("Dst Port:", udp.DestinationPort)
	fmt.Println("Length:", udp.Length)
	fmt.Println("Checksum:", fmt.Sprintf("0x%04x", udp.Checksum))

	fmt.Println("\n---- UDP Payload (raw hex) ----")
	fmt.Println(hex.EncodeToString(ip.Payload[8:]))

	fmt.Println("\n(OBS: payload ainda não está sendo interpretado)")
	_ = afterIP // apenas para evitar unused
}
