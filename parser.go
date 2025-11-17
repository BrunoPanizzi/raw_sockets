// parser.go
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrTooShort = errors.New("buffer muito curto para parsear")

type Packet struct {
	Timestamp time.Time
	IfName    string
	Raw       []byte

	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16

	IsIPv4 bool
	IPv4   *IPv4Header

	TCP  *TCPHeader
	UDP  *UDPHeader
	ICMP *ICMPHeader
}

type IPv4Header struct {
	Version   uint8
	IHL       uint8
	TOS       uint8
	TotalLen  uint16
	ID        uint16
	FlagsFrag uint16
	TTL       uint8
	Protocol  uint8
	Checksum  uint16
	SrcIP     net.IP
	DstIP     net.IP
	Payload   []byte
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint16
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Payload    []byte
}

type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Rest     []byte
}

func ParseEthernet(data []byte, p *Packet) (int, error) {
	if len(data) < 14 {
		return 0, ErrTooShort
	}
	p.DstMAC = net.HardwareAddr(data[0:6])
	p.SrcMAC = net.HardwareAddr(data[6:12])
	p.EtherType = binary.BigEndian.Uint16(data[12:14])
	return 14, nil
}

func ParseIPv4(data []byte, p *Packet) (int, error) {
	if len(data) < 20 {
		return 0, ErrTooShort
	}
	versionIhl := data[0]
	version := versionIhl >> 4
	ihl := versionIhl & 0x0F
	headerLen := int(ihl) * 4
	if version != 4 || headerLen < 20 {
		return 0, fmt.Errorf("não é um cabeçalho IPv4 válido")
	}
	if len(data) < headerLen {
		return 0, ErrTooShort
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen > len(data) {
		totalLen = len(data)
	}
	ip := &IPv4Header{
		Version:   version,
		IHL:       ihl,
		TOS:       data[1],
		TotalLen:  uint16(totalLen),
		ID:        binary.BigEndian.Uint16(data[4:6]),
		FlagsFrag: binary.BigEndian.Uint16(data[6:8]),
		TTL:       data[8],
		Protocol:  data[9],
		Checksum:  binary.BigEndian.Uint16(data[10:12]),
		SrcIP:     net.IPv4(data[12], data[13], data[14], data[15]),
		DstIP:     net.IPv4(data[16], data[17], data[18], data[19]),
	}

	payloadStart := headerLen
	if totalLen > payloadStart {
		ip.Payload = data[payloadStart:totalLen]
	} else {
		ip.Payload = []byte{}
	}

	p.IsIPv4 = true
	p.IPv4 = ip
	return totalLen, nil
}

func ParseUDPHeader(b []byte) (*UDPHeader, error) {
	if len(b) < 8 {
		return nil, ErrTooShort
	}
	h := &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(b[0:2]),
		DstPort:  binary.BigEndian.Uint16(b[2:4]),
		Length:   binary.BigEndian.Uint16(b[4:6]),
		Checksum: binary.BigEndian.Uint16(b[6:8]),
	}
	if int(h.Length) > len(b) {
		h.Payload = b[8:]
	} else {
		h.Payload = b[8:int(h.Length)]
	}
	return h, nil
}

func ParseTCPHeader(b []byte) (*TCPHeader, error) {
	if len(b) < 20 {
		return nil, ErrTooShort
	}
	hdrLen := (b[12] >> 4) * 4
	if len(b) < int(hdrLen) {
		hdrLen = 20
	}
	t := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(b[0:2]),
		DstPort:    binary.BigEndian.Uint16(b[2:4]),
		Seq:        binary.BigEndian.Uint32(b[4:8]),
		Ack:        binary.BigEndian.Uint32(b[8:12]),
		DataOffset: b[12] >> 4,
		Flags:      binary.BigEndian.Uint16([]byte{0, b[13]}),
		Window:     binary.BigEndian.Uint16(b[14:16]),
		Checksum:   binary.BigEndian.Uint16(b[16:18]),
		Urgent:     binary.BigEndian.Uint16(b[18:20]),
	}
	if int(hdrLen) > len(b) {
		t.Payload = []byte{}
	} else {
		t.Payload = b[hdrLen:]
	}
	return t, nil
}

func ParseICMPHeader(b []byte) (*ICMPHeader, error) {
	if len(b) < 4 {
		return nil, ErrTooShort
	}
	h := &ICMPHeader{
		Type:     b[0],
		Code:     b[1],
		Checksum: binary.BigEndian.Uint16(b[2:4]),
	}
	if len(b) > 4 {
		h.Rest = b[4:]
	}
	return h, nil
}

func ParsePacket(raw []byte) (*Packet, error) {
	p := &Packet{
		Timestamp: time.Now(),
		Raw:       raw,
	}

	// windows loopback header
	if len(raw) >= 4 && raw[0] == 0x02 && raw[1] == 0x00 && raw[2] == 0x00 && raw[3] == 0x00 {
		ip := raw[4:] // pula o cabeçalho loopback

		// só aceita IPv4
		if len(ip) > 0 && (ip[0]>>4) == 4 {
			if _, err := ParseIPv4(ip, p); err == nil {
				parseTransport(p)
				return p, nil
			}
		}
	}

	// ethernet
	off, err := ParseEthernet(raw, p)
	if err != nil {
		return nil, err
	}

	if len(raw) <= off {
		return p, nil
	}

	if p.EtherType == 0x0800 {
		if _, err := ParseIPv4(raw[off:], p); err == nil {
			parseTransport(p)
		}
	}

	return p, nil
}

func parseTransport(p *Packet) {
	ipPay := p.IPv4.Payload

	switch p.IPv4.Protocol {
	case 6: // tcp
		if tcp, err := ParseTCPHeader(ipPay); err == nil {
			p.TCP = tcp
		}
	case 17: // udp
		if udp, err := ParseUDPHeader(ipPay); err == nil {
			p.UDP = udp
		}
	case 1: // icmp
		if icmp, err := ParseICMPHeader(ipPay); err == nil {
			p.ICMP = icmp
		}
	}
}
