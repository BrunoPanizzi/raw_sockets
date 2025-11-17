// writer.go
package main

import (
	"encoding/csv"
	"os"
	"sync"
	"time"
)

type CSVWriter struct {
	file   *os.File
	writer *csv.Writer
	input  chan []string
	closed chan struct{}
	mu     sync.Mutex
}

func NewCSVWriter(path string, header []string, buf int) (*CSVWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)

	fi, err := f.Stat()
	if err == nil && fi.Size() == 0 && header != nil {
		if err := w.Write(header); err != nil {
			f.Close()
			return nil, err
		}
		w.Flush()
	}
	c := &CSVWriter{
		file:   f,
		writer: w,
		input:  make(chan []string, buf),
		closed: make(chan struct{}),
	}
	go c.loop()
	return c, nil
}

func (c *CSVWriter) loop() {
	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()
	for {
		select {
		case row, ok := <-c.input:
			if !ok {
				c.writer.Flush()
				c.file.Close()
				close(c.closed)
				return
			}
			c.mu.Lock()
			_ = c.writer.Write(row)
			c.mu.Unlock()
		case <-flushTicker.C:
			c.mu.Lock()
			c.writer.Flush()
			c.mu.Unlock()
		}
	}
}

func (c *CSVWriter) Write(row []string) {
	select {
	case c.input <- row:
	default:
		c.input <- row
	}
}

func (c *CSVWriter) Close() {
	close(c.input)
	<-c.closed
}
