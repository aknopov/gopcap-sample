package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"main/set"

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

var pid = 13756

func main() {

	ports := getOpenPorts(pid)
	// fmt.Printf("Process %d has open ports: %v\n\n", pid, ports) //UC

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return
	}

	waitGroup := new(sync.WaitGroup)
	sigStop := make(chan os.Signal, 1)
	signal.Notify(sigStop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	devIps := make(map[string]string) // UC

	for idx, dev := range devs {
		if (dev.Flags & PCAP_GTG_FLAGS) != PCAP_GTG_FLAGS { //  || (dev.Flags & PCAP_IF_LOOPBACK) == 0
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
			go processDeviceMsgs(&dev, idx, ports, waitGroup, sigStop)
		}
	}

	for k, v := range devIps {
		fmt.Printf("%s: %s\n", k, v)
	}

	waitGroup.Wait()
}

func processDeviceMsgs(dev *pcap.Interface, idx int, ports *set.Set[int], waitGroup *sync.WaitGroup, sigStop chan os.Signal) {

	defer waitGroup.Done()

	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenLive(dev.Name, 1600, false, 1*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Can't open stream: %s\n", err)
		return
	}
	defer handle.Close()

	if handle.SetBPFFilter("tcp") != nil {
		fmt.Fprintf(os.Stderr, "Can't filter TCP protocol: %s\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCh := packetSource.Packets()

	var bytesSent uint64
	var bytesRcvd uint64
	var packetsSent uint64
	var packetsRcvd uint64
	var errors uint64

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
			errors++
			fmt.Fprintf(os.Stderr, "Error detected: %v\n", errLayer) // UC
			continue
		}

		tcpLayer := p.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			fmt.Fprintln(os.Stderr, "Failed to decode TCP layer") // UC
			continue
		}
		tcp := tcpLayer.(*layers.TCP)

		if ports.Contains(int(tcp.SrcPort)) {
			bytesSent += uint64(len(p.Data()))
			packetsSent++
			fmt.Printf("%d: %v Sent %v -> %v : %d\n", idx, p.Metadata().Timestamp, tcp.SrcPort, tcp.DstPort, len(p.Data())) // UC
		} else if ports.Contains(int(tcp.DstPort)) {
			bytesRcvd += uint64(len(p.Data()))
			packetsRcvd++
			fmt.Printf("%d: %v Received %v -> %v : %d\n", idx, p.Metadata().Timestamp, tcp.SrcPort, tcp.DstPort, len(p.Data())) // UC
		}
	}

	// UC
	fmt.Printf("'%s' Sent %d bytes [%d], Received %d bytes [%d with %d errors\n", dev.Name, bytesSent, packetsSent, bytesRcvd, packetsRcvd, errors)
}
