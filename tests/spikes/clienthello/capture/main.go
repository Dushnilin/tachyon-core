// Capture TLS ClientHello from a single connection (F0 spike B, ADR-0004).
// Usage: go run . [output.bin]
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	out := "clienthello.bin"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	ln, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println("listening on", ln.Addr())
	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("accepted from", conn.RemoteAddr())
	buf := make([]byte, 16384)
	n, err := io.ReadAtLeast(conn, buf, 5)
	if err != nil {
		panic(err)
	}
	if buf[0] != 0x16 {
		panic(fmt.Sprintf("not a handshake record: type=%#x", buf[0]))
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	total := 5 + recLen
	if total > len(buf) {
		panic("record too large")
	}
	for n < total {
		m, err := conn.Read(buf[n:total])
		if err != nil {
			panic(err)
		}
		n += m
	}
	record := buf[:total]
	if err := os.WriteFile(out, record, 0644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %d bytes to %s\n", len(record), out)
	fmt.Println(hex.Dump(record[:128]))
}
