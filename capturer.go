//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"net"
	"syscall"
)

const (
	ETH_P_ALL = 0x0003 // captura todos protocolos de rede ethernet
)

func OpenRawSocket(interfaceName string) (int, error) {

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("erro ao capturar socket: %w", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("erro ao obter interface %s: %w", interfaceName, err)
	}

	var sll syscall.SockaddrLinklayer
	sll.Protocol = htons(ETH_P_ALL)
	sll.Ifindex = iface.Index
	sll.Hatype = syscall.ARPHRD_ETHER
	sll.Pkttype = syscall.PACKET_HOST
	sll.Halen = 6

	if err := syscall.Bind(fd, &sll); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("erro ao vincular socket à interface %s: %w", interfaceName, err)
	}

	return fd, nil

}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | (i>>8)&0x00ff
}

func ReadPackets(fd int, chRawPackets chan<- []byte) error {
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}

		if n > 0 {
			packet := make([]byte, n)
			copy(packet, buf[:n])
			chRawPackets <- packet
		}
	}
}
