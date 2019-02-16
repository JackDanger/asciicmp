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
			if packet.TransportLayer() != nil {
				log.Println("TransportLayer:", packet.TransportLayer())
			}
			if packet.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
				fmt.Println(packet.NetworkLayer().LayerContents())
				fmt.Println(packet.NetworkLayer().LayerPayload())
				fmt.Println(packet.NetworkLayer().NetworkFlow(), packet.NetworkLayer().NetworkFlow().EndpointType())
				src, _ := packet.NetworkLayer().NetworkFlow().Endpoints()

				if src.Raw()[0] == 10 || src.Raw()[0] == 192 || src.Raw()[0] == 72 || src.Raw()[0] == 127 {
					fmt.Println("Internal source – outbound", src)
					fmt.Println("")
					fmt.Println("Dump packet:", packet.Dump())
					fmt.Printf("Layer count: %d\n", len(packet.Layers()))
					layer1 := packet.Layers()[0]
					layer2 := packet.Layers()[1]
					fmt.Printf("main.go:69 %#v\n", layer2)
					layer3 := packet.Layers()[2]
					fmt.Printf("main.go:71 %#v\n", layer3)
					layer4 := packet.Layers()[3]
					fmt.Printf("main.go:73 %#v\n", layer4)

				} else {
					fmt.Println("External source – inbound", src.Raw())
				}

				if packet.TransportLayer() != nil {
					log.Println("unexpected TransportLayer: ", packet.TransportLayer())
				}
			}

		case <-timeout.C:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			return
		}
	}
}
