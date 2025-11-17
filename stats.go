// stats.go
package main

import (
	"net"
	"sync"
	"sync/atomic"
)

type RemoteInfo struct {
	Bytes   uint64
	Packets uint64
}

type ClientStats struct {
	IP         string
	Bytes      uint64
	Packets    uint64
	ByProtocol map[string]uint64
	Remotes    map[string]*RemoteInfo
	mu         sync.RWMutex
}

func NewClientStats(ip string) *ClientStats {
	return &ClientStats{
		IP:         ip,
		ByProtocol: make(map[string]uint64),
		Remotes:    make(map[string]*RemoteInfo),
	}
}

func (c *ClientStats) AddPacket(proto string, bytes uint64, remoteIP net.IP) {
	atomic.AddUint64(&c.Bytes, bytes)
	atomic.AddUint64(&c.Packets, 1)
	c.mu.Lock()
	c.ByProtocol[proto] += 1
	rip := remoteIP.String()
	ri, ok := c.Remotes[rip]
	if !ok {
		ri = &RemoteInfo{}
		c.Remotes[rip] = ri
	}
	ri.Bytes += bytes
	ri.Packets += 1
	c.mu.Unlock()
}

type GlobalStats struct {
	clients map[string]*ClientStats
	mu      sync.RWMutex
}

func NewGlobalStats() *GlobalStats {
	return &GlobalStats{
		clients: make(map[string]*ClientStats),
	}
}

func (g *GlobalStats) GetOrCreateClient(ip string) *ClientStats {
	g.mu.RLock()
	c, ok := g.clients[ip]
	g.mu.RUnlock()
	if ok {
		return c
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok = g.clients[ip]
	if ok {
		return c
	}
	c = NewClientStats(ip)
	g.clients[ip] = c
	return c
}
