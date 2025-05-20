package main

import (
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/aknopov/gopcap/set"
	"github.com/sokurenko/go-netstat/netstat"
	"github.com/stretchr/testify/assert"
)

var doneTest chan struct{}

func initT() {
	watchProg = ""
	watchPid = -1
	doneTest = make(chan struct{})
}

func TestUsingProg(t *testing.T) {
	assertT := assert.New(t)
	initT()

	startPortsWatch(time.Millisecond, "foo", doneTest)
	time.Sleep(5 * time.Millisecond)

	assertT.Equal("foo", watchProg)
	assertT.Equal(-1, watchPid)

	close(doneTest)
}

func TestUsingPid(t *testing.T) {
	assertT := assert.New(t)
	initT()

	startPortsWatch(time.Millisecond, "123", doneTest)
	time.Sleep(5 * time.Millisecond)

	assertT.Equal("", watchProg)
	assertT.Equal(123, watchPid)

	close(doneTest)
}

var (
	process    = netstat.Process{Pid: 666}
	process2   = netstat.Process{Pid: 777}
	tabEntries = []netstat.SockTabEntry{
		{LocalAddr: &netstat.SockAddr{Port: 123}, Process: &process},
		{LocalAddr: &netstat.SockAddr{Port: 321}, Process: &process2}}
	noProcess = []netstat.SockTabEntry{
		{LocalAddr: &netstat.SockAddr{Port: 567}},
	}
)

func TestUpdatePorts(t *testing.T) {
	assertT := assert.New(t)

	defer replaceFun(netstat.TCPSocks, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) { return tabEntries, nil })()
	defer replaceFun(netstat.TCP6Socks, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) { return noProcess, nil })()
	defer replaceFun(netstat.UDPSocks, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) { return noProcess, nil })()
	defer replaceFun(netstat.UDP6Socks, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) { return noProcess, nil })()
	defer replaceVar(watchPorts, *set.New(333))()
	defer replaceVar(&watchPid, 666)()

	assertT.Equal(set.New(333), watchPorts)
	updatePorts()
	assertT.Equal(set.New(123), watchPorts)
}

func BenchmarkUpdatePorts(b *testing.B) {

	for range b.N {
		updatePorts()
	}
}

func replaceFun[Fn any](target Fn, replacement Fn) func() {
	patches := gomonkey.NewPatches()
	p := patches.ApplyFunc(target, replacement)

	return func() {
		p.Reset()
	}
}

func replaceVar[V any](target *V, replacement V) func() {
	patches := gomonkey.NewPatches()
	p := patches.ApplyGlobalVar(target, replacement)

	return func() {
		p.Reset()
	}
}
