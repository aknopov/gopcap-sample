package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aknopov/gopcap/set"
	"github.com/sokurenko/go-netstat/netstat"
)

var (
	watchPorts = set.New[int]()
	watchLock  sync.RWMutex
	watchProg  string
	watchPid   int = -1

	// 0x0c = DeleteTcb (not in Linux)
	inactiveStates = set.New(netstat.TimeWait, netstat.Close, netstat.Closing, netstat.SkState(0x0c))
)

// Unit test substitutes
var (
	tcpSocksFn  = netstat.TCPSocks
	tcp6SocksFn = netstat.TCP6Socks
	udpSocksFn  = netstat.UDPSocks
	udp6SocksFn = netstat.UDP6Socks
)

func startPortsWatch(intvl time.Duration, prog string, done chan struct{}) {
	if p, err := strconv.Atoi(prog); err == nil {
		watchPid = p
	} else {
		watchProg = prog
	}

	go func() {
		watchTicker := time.NewTicker(intvl)
		for range watchTicker.C {
			select {
			case <-done:
				return
			default:
				updatePorts()
			}
		}
	}()
}

func IsObserved(port int) bool {
	watchLock.RLock()
	defer watchLock.RUnlock()

	return watchPorts.Contains(port)
}

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

func updatePorts() {
	ipTab := enumeratePorts(tcpSocksFn)
	ipTab = append(ipTab, enumeratePorts(tcp6SocksFn)...)
	ipTab = append(ipTab, enumeratePorts(udpSocksFn)...)
	ipTab = append(ipTab, enumeratePorts(udp6SocksFn)...)

	watchLock.Lock()
	defer watchLock.Unlock()

	watchPorts.Clear()
	for _, e := range ipTab {
		if e.Process == nil {
			continue
		}
		if watchPid != -1 && e.Process.Pid == watchPid {
			watchPorts.Add(int(e.LocalAddr.Port))
		} else if watchProg != "" && e.Process.Name == watchProg {
			watchPorts.Add(int(e.LocalAddr.Port))
		}
	}
}
