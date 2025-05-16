package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	PCAP_IF_LOOPBACK                         = uint32(0x00000001)
	PCAP_IF_UP                               = uint32(0x00000002)
	PCAP_IF_RUNNING                          = uint32(0x00000004)
	PCAP_IF_WIRELESS                         = uint32(0x00000008)
	PCAP_IF_CONNECTION_STATUS_UNKNOWN        = uint32(0x00000000)
	PCAP_IF_CONNECTION_STATUS_CONNECTED      = uint32(0x00000010)
	PCAP_IF_CONNECTION_STATUS_DISCONNECTED   = uint32(0x00000020)
	PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = uint32(0x00000030)
	PCAP_GTG_FLAGS                           = uint32(PCAP_IF_UP | PCAP_IF_RUNNING | PCAP_IF_CONNECTION_STATUS_CONNECTED)
)

func main() {

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return
	}

	waitGroup := new(sync.WaitGroup)
	devIps := make(map[string]string)

	for _, dev := range devs {
		if (dev.Flags & PCAP_GTG_FLAGS) != PCAP_GTG_FLAGS {
			continue
		}

		ips := make([]string, 0)
		for _, addr := range dev.Addresses {
			if addr.IP.IsMulticast() {
				continue
			}
			ips = append(ips, addr.IP.String())
		}
		if len(ips) > 0 {
			devIps[dev.Name+":"+strconv.FormatInt(int64(dev.Flags), 16)] = strings.Join(ips, ",")

			waitGroup.Add(1)
			go processDeviceMsgs(&dev, waitGroup)
		}
	}

	for k, v := range devIps {
		fmt.Printf("%s: %s\n", k, v)
	}

	waitGroup.Wait()
}

func processDeviceMsgs(ifc *pcap.Interface, waitGroup *sync.WaitGroup) {

	defer waitGroup.Done()

	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenLive(ifc.Name, 1600, false, 1*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Can't open stream %s\n", err)
		return
	}
	defer handle.Close()
	handle.SetBPFFilter("tcp")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCh := packetSource.Packets()

	var totalBytes uint64

	for range 10 {
		p, ok := <-packetCh
		if !ok {
			break
		}

		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			fmt.Fprintf(os.Stderr, "No TCP{ layer???\n")
			break
		}
		tcp := tcpLayer.(*layers.TCP)

		fmt.Printf("%s: %v -> %v : %d\n", ifc.Name, tcp.SrcPort, tcp.DstPort, len(p.Data()))

		totalBytes += uint64(len(p.Data()))
	}

	fmt.Printf("In total %d bytes were sent\n", totalBytes)
}
