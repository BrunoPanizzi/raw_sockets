//go:build windows
// +build windows

package main

import (
	"fmt"
)

func OpenRawSocket(interfaceName string) (int, error) {
	return -1, fmt.Errorf("raw socket não suportado no Windows")
}

func ReadPackets(fd int, handler func([]byte)) error {
	return fmt.Errorf("raw socket não suportado no Windows")
}
