// tcpfwd forwards a local port to another address. Test helper for
// scripts/console-smoke.sh: the daemon in the test container reaches the
// control plane on the host through 127.0.0.1.
package main

import (
	"io"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: tcpfwd LISTEN TARGET")
	}
	ln, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			t, err := net.Dial("tcp", os.Args[2])
			if err != nil {
				log.Print(err)
				return
			}
			defer t.Close()
			go func() { _, _ = io.Copy(t, c) }()
			_, _ = io.Copy(c, t)
		}(c)
	}
}
