package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "lo0", "Interface to get packets from")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Disable kernel ICMP responses with this:
// sudo sh -c 'echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all'
//
// send pings on BSD/OS X with a specified outbound ip
// ping yahoo.com -S $(ipconfig getifaddr en0) -c 1

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	log.Printf("Starting capture on interface %q", *iface)
	const snapLen int32 = 1600
	handle, err = pcap.OpenLive(*iface, snapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter("icmp"); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	timeout := time.NewTimer(2 * time.Second)
	for {
		select {
		case packet := <-packets:
			fmt.Println("")
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
				fmt.Println("NetworkLayer")
				fmt.Println(packet.NetworkLayer().LayerContents())
				fmt.Println(packet.NetworkLayer().LayerPayload())
				fmt.Println(packet.NetworkLayer().NetworkFlow())
				src, dest := packet.NetworkLayer().NetworkFlow().Endpoints()
				fmt.Println("src:", src, src.EndpointType())
				fmt.Println("dest:", dest, dest.EndpointType())
				fmt.Println("")
				fmt.Println("Whole packet:", packet.String())
				fmt.Println("")
				fmt.Println("Dump packet:", packet.Dump())
				if packet.TransportLayer() != nil {
					log.Println("unexpected TransportLayer: ", packet.TransportLayer())
				}
				continue
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println(packet.NetworkLayer().LayerType())
				log.Println("Unusable packet")
				fmt.Printf("WHOLE PACKET main.go:103 %#v\n", packet)
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			fmt.Printf("main.go:68 %#v\n", tcp)

		case <-timeout.C:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			return
		}
	}
}
