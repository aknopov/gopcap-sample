package main

import (
	"fmt"
	"os"

	"main/set"

	"github.com/sokurenko/go-netstat/netstat"
)

var (
	// 0x0c = DeleteTcb (not in Linux)
	inactiveStates = set.New(netstat.TimeWait, netstat.Close, netstat.Closing, 0x0c)
)

func filter(s *netstat.SockTabEntry) bool {
	return !inactiveStates.Contains(s.State)
}

func enumeratePorts(fn func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error)) []netstat.SockTabEntry {
	tab, err := fn(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't enumerate ports: %s\n", err)
	}
	return tab
}

func getOpenPorts(pid int) *set.Set[int] {

	ports := set.New[int]()

	tcpTab := enumeratePorts(netstat.TCPSocks)
	tcpTab = append(tcpTab, enumeratePorts(netstat.TCP6Socks)...)

	for _, e := range tcpTab {
		if e.Process != nil && e.Process.Pid == pid {
			ports.Add(int(e.LocalAddr.Port))
		}
	}

	return ports
}
