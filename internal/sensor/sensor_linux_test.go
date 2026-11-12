//go:build linux

package sensor

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseDNS(t *testing.T) {
	name := dnsmessage.MustNewName("api.openai.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	cname := dnsmessage.MustNewName("api.openai.com.cdn.cloudflare.net.")
	_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.CNAMEResource{CNAME: cname})
	_ = b.AResource(dnsmessage.ResourceHeader{Name: cname, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{162, 159, 140, 245}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	// Wrap in IPv4 (20-byte header) + UDP (8 bytes), as the packet socket delivers it.
	pkt := append(append([]byte{0x45}, make([]byte, 27)...), msg...)
	a, ok := ParseDNSPacket(pkt)
	if !ok || a.Name != "api.openai.com" || len(a.IPs) != 1 || !a.IPs[0].Equal(net.ParseIP("162.159.140.245")) || a.TTL != time.Minute {
		t.Errorf("got %+v %v", a, ok)
	}
	if _, ok := ParseDNSPacket([]byte{0x45, 0, 0}); ok {
		t.Error("short packet parsed")
	}
}

func TestDecodeMatchesCLayout(t *testing.T) {
	var raw rawEvent
	if binary.Size(raw) != 320 {
		t.Fatalf("rawEvent is %d bytes; struct event in sensor.c is 320", binary.Size(raw))
	}
	raw.Type, raw.PID, raw.Family, raw.DPort = uint32(Connect), 42, 2, 443
	copy(raw.DAddr[:], []byte{160, 79, 104, 10})
	copy(raw.Comm[:], "claude")
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, &raw)
	var back rawEvent
	_ = binary.Read(&buf, binary.LittleEndian, &back)
	e := decode(&back, time.Unix(0, 0))
	if e.Type != Connect || e.PID != 42 || e.DstPort != 443 || e.DstIP.String() != "160.79.104.10" || e.Comm != "claude" {
		t.Errorf("decoded %+v", e)
	}
	if !Writes(0x241) || Writes(0) || !OpensDirectory(0x10000|0x80000) && !OpensDirectory(0x4000) {
		t.Error("flag helpers")
	}
}
