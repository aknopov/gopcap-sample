package main

import (
	"fmt"

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

func findActiveDevices() map[int]pcap.Interface {
	ret := make(map[int]pcap.Interface)

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return ret
	}

	fmt.Println("Tracked devices:")
	for idx, dev := range devs {
		if (dev.Flags&PCAP_GTG_FLAGS) == PCAP_GTG_FLAGS && len(dev.Addresses) > 0 {
			ret[idx+1] = dev

			fmt.Printf("\t%d: %s - %v\n", idx+1, dev.Name, addr2String(dev.Addresses))
		}
	}
	
	fmt.Println()

	return ret
}

func addr2String(ifAddress []pcap.InterfaceAddress) string {

	ret := ""
	for _, addr := range ifAddress {
		if !addr.IP.IsMulticast() && ret != "" {
			ret += ","
		}
		ret += addr.IP.String()
	}
	return ret
}
