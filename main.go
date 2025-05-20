package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	bytesSent   atomic.Uint64
	bytesRcvd   atomic.Uint64
	packetsSent atomic.Uint64
	packetsRcvd atomic.Uint64
	errors      atomic.Uint64

	waitGroup *sync.WaitGroup
)

func main() {

	refrInvl := 1.0

	flagSet := flag.NewFlagSet("", flag.ExitOnError)
	flagSet.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: main [-r=refresh_secs] prog_or_pid")
	}
	flagSet.Float64Var(&refrInvl, "r", 1.0, "ports scanning interval (sec)")
	err := flagSet.Parse(os.Args[1:])

	otherArgs := flagSet.Args()
	if len(otherArgs) != 1 || err != nil {
		flagSet.Usage()
		os.Exit(1)
	}

	done := make(chan struct{})
	waitGroup = new(sync.WaitGroup)

	sigStop := make(chan os.Signal, 1)
	signal.Notify(sigStop, syscall.SIGINT, syscall.SIGTERM)

	devs := findActiveDevices()
	if len(devs) == 0 {
		fmt.Fprintf(os.Stderr, "No active network devices found\n")
		return
	}

	startPortsWatch(time.Duration(int64(refrInvl*1e+9)), otherArgs[0], done)

	for idx, dev := range devs {
		waitGroup.Add(1)
		go processDeviceMsgs(&dev, idx, sigStop, done)
	}

	<-sigStop
	close(done)

	waitGroup.Wait()

	fmt.Printf("Sent %d bytes [%d], Received %d bytes [%d] with %d errors\n", bytesSent.Load(), packetsSent.Load(), bytesRcvd.Load(), packetsRcvd.Load(), errors.Load())
}

func processDeviceMsgs(dev *pcap.Interface, idx int, sigStop chan os.Signal, done chan struct{}) {

	defer waitGroup.Done()

	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenLive(dev.Name, 1600, false, 1*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Can't open stream: %s\n", err)
		sigStop <- syscall.SIGINT
		return
	}
	defer handle.Close()

	if handle.SetBPFFilter("tcp||udp") != nil {
		fmt.Fprintf(os.Stderr, "Can't filter protocols: %s\n", err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCh := packetSource.Packets()

	for keepGoing(done) {

		p := waitNextPacket(packetCh)
		if p == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		errLayer := p.ErrorLayer()
		if errLayer != nil {
			errors.Add(1)
			continue
		}

		var dstPort, srcPort int
		if decodeTcp(p, &srcPort, &dstPort) || decodeUdp(p, &srcPort, &dstPort) {
			if IsObserved(srcPort) {
				bytesSent.Add(uint64(len(p.Data())))
				packetsSent.Add(1)
				fmt.Printf("%d: %v Sent %v -> %v : %d\n", idx, p.Metadata().Timestamp, srcPort, dstPort, len(p.Data())) // UC
			} else if IsObserved(dstPort) {
				bytesRcvd.Add(uint64(len(p.Data())))
				packetsRcvd.Add(1)
				fmt.Printf("%d: %v Received %v -> %v : %d\n", idx, p.Metadata().Timestamp, srcPort, dstPort, len(p.Data())) // UC
			}
		}
	}
}

func keepGoing(done chan struct{}) bool {
	select {
	case <-done:
		return false
	default:
		return true
	}
}

func waitNextPacket(packetCh chan gopacket.Packet) gopacket.Packet {
	select {
	case p := <-packetCh:
		return p
	default:
		return nil
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
