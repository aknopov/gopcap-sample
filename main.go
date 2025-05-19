package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"main/watcher"

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

var (
	bytesSent   atomic.Uint64
	bytesRcvd   atomic.Uint64
	packetsSent atomic.Uint64
	packetsRcvd atomic.Uint64
	errors      atomic.Uint64
	waitGroup   *sync.WaitGroup = new(sync.WaitGroup)
	sigStop     chan os.Signal  = make(chan os.Signal, 1) //UC should have N capacity for each "dev"
)

func main() {

	if len(os.Args) != 2 { //UC "-i" - connections refresh interval
		fmt.Fprintf(os.Stderr, "Usage: %s <program_or_pid>\n", os.Args[0])
		os.Exit(1)
	}

	signal.Notify(sigStop, syscall.SIGINT, syscall.SIGTERM)

	watcher.StartWatch(time.Second, os.Args[1])

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return
	}

	devIps := make(map[string]string) // UC findActiveDevices() []pcap.Interface

	for idx, dev := range devs {
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
			devIps[strconv.Itoa(idx)+" ["+dev.Name+"]:"+strconv.FormatInt(int64(dev.Flags), 16)] = strings.Join(ips, ",") // UC

			waitGroup.Add(1)
			go processDeviceMsgs(&dev, idx)
		}
	}

	for k, v := range devIps { //UC
		fmt.Printf("%s: %s\n", k, v)
	}

	waitGroup.Wait()
	watcher.StopWatch()

	// UC
	fmt.Printf("Sent %d bytes [%d], Received %d bytes [%d] with %d errors\n", bytesSent.Load(), packetsSent.Load(), bytesRcvd.Load(), packetsRcvd.Load(), errors.Load())
}

func processDeviceMsgs(dev *pcap.Interface, idx int) {

	defer waitGroup.Done()

	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenLive(dev.Name, 1600, false, 1*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Can't open stream: %s\n", err)
		return
	}
	defer handle.Close()

	if handle.SetBPFFilter("tcp||udp") != nil {
		fmt.Fprintf(os.Stderr, "Can't filter TCP protocol: %s\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCh := packetSource.Packets()

package_loop:
	for {
		select {
		case <-sigStop:
			sigStop <- syscall.SIGINT // for other thread(s)
			break package_loop
		default:
		}

		p, ok := <-packetCh
		if !ok {
			break
		}

		errLayer := p.ErrorLayer()
		if errLayer != nil {
			errors.Add(1)
			fmt.Fprintf(os.Stderr, "Error detected: %v\n", errLayer) // UC
			continue
		}

		var dstPort, srcPort int
		if decodeTcp(p, &srcPort, &dstPort) || decodeUdp(p, &srcPort, &dstPort) {
			if watcher.IsObserved(srcPort) {
				bytesSent.Add(uint64(len(p.Data())))
				packetsSent.Add(1)
				fmt.Printf("%d: %v Sent %v -> %v : %d\n", idx, p.Metadata().Timestamp, srcPort, dstPort, len(p.Data())) // UC
			} else if watcher.IsObserved(dstPort) {
				bytesRcvd.Add(uint64(len(p.Data())))
				packetsRcvd.Add(1)
				fmt.Printf("%d: %v Received %v -> %v : %d\n", idx, p.Metadata().Timestamp, srcPort, dstPort, len(p.Data())) // UC
			}
		}
	}
}

func decodeTcp(p gopacket.Packet, srcPort *int, dstPort *int) bool {
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	*srcPort = int(tcp.SrcPort)
	*dstPort = int(tcp.DstPort)
	return true
}

func decodeUdp(p gopacket.Packet, srcPort *int, dstPort *int) bool {
	udpLayer := p.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return false
	}

	udp := udpLayer.(*layers.UDP)
	*srcPort = int(udp.SrcPort)
	*dstPort = int(udp.DstPort)
	return true
}
