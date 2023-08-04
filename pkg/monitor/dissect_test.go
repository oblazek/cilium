// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"fmt"
	"net"
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MonitorSuite struct{}

var _ = Suite(&MonitorSuite{})

func (s *MonitorSuite) TestDissectSummary(c *C) {

	srcMAC := "01:23:45:67:89:ab"
	dstMAC := "02:33:45:67:89:ab"

	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}

	summary := GetDissectSummary(packetData)

	c.Assert(summary.Ethernet, Not(Equals), "")
	c.Assert(summary.IPv4, Not(Equals), "")
	c.Assert(summary.TCP, Not(Equals), "")

	c.Assert(summary.L2.Src, Equals, srcMAC)
	c.Assert(summary.L2.Dst, Equals, dstMAC)

	c.Assert(summary.L3.Src, Equals, srcIP)
	c.Assert(summary.L3.Dst, Equals, dstIP)

	c.Assert(summary.L4.Src, Equals, sport)
	c.Assert(summary.L4.Dst, Equals, dport)
}

func (s *MonitorSuite) TestConnectionSummary(c *C) {
	srcIP := "1.2.3.4"
	dstIP := "5.6.7.8"

	sport := "80"
	dport := "443"

	// Generated in scapy:
	// Ether(src="01:23:45:67:89:ab", dst="02:33:45:67:89:ab")/IP(src="1.2.3.4",dst="5.6.7.8")/TCP(sport=80,dport=443)
	packetData := []byte{2, 51, 69, 103, 137, 171, 1, 35, 69, 103, 137, 171, 8, 0, 69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 106, 188, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 1, 187, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 125, 196, 0, 0}

	summary := GetConnectionSummary(packetData)

	expect := fmt.Sprintf("%s -> %s %s",
		net.JoinHostPort(srcIP, sport),
		net.JoinHostPort(dstIP, dport),
		"tcp SYN")
	c.Assert(summary, Equals, expect)
}

func (s *MonitorSuite) TestConnectionSummaryWithoutL2(c *C) {
	testCases := []struct {
		name       string
		expect     string
		packetData []byte
	}{
		{
			name:   "IPv4 + TCP",
			expect: "1.1.1.1:8080 -> 2.2.2.2:9090 tcp SYN",
			// Generated in scapy:
			// IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=8080, dport=9090)
			packetData: []byte{69, 0, 0, 40, 0, 1, 0, 0, 64, 6, 116, 202, 1, 1, 1, 1, 2, 2, 2, 2, 31, 144, 35, 130, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 70, 203, 0, 0},
		}, {
			name:   "IPv6 + TCP",
			expect: "[1:1:1:1::1]:8080 -> [2:2:2:2::2]:9090 tcp SYN",
			// Generated in scapy:
			// IPv6(src="1:1:1:1::1", dst="2:2:2:2::2")/TCP(sport=8080, dport=9090)
			packetData: []byte{96, 0, 0, 0, 0, 20, 6, 64, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 2, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 31, 144, 35, 130, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 32, 0, 76, 194, 0, 0},
		}, {
			name:   "IPv4 + ICMP",
			expect: "1.1.1.1 -> 2.2.2.2 EchoRequest",
			// Generated in scapy:
			// IP(src="1.1.1.1", dst="2.2.2.2")/ICMP()
			packetData: []byte{69, 0, 0, 28, 0, 1, 0, 0, 64, 1, 116, 219, 1, 1, 1, 1, 2, 2, 2, 2, 8, 0, 247, 255, 0, 0, 0, 0},
		},
	}

	for _, tc := range testCases {
		summary := GetConnectionSummary(tc.packetData)
		c.Assert(summary, Equals, tc.expect)
	}
}
