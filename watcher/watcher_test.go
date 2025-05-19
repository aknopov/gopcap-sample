package watcher

import (
	"main/set"
	"testing"
	"time"

	"github.com/sokurenko/go-netstat/netstat"
	"github.com/stretchr/testify/assert"
)

func TestProgSewtting(t *testing.T) {
	assertT := assert.New(t)
	watchProg = ""
	watchPid = -1

	StartWatch(time.Millisecond, "foo")

	assertT.Equal("foo", watchProg)
	assertT.Equal(-1, watchPid)

	StopWatch()
}

func TestPidParsing(t *testing.T) {
	assertT := assert.New(t)
	watchProg = ""
	watchPid = -1

	StartWatch(time.Millisecond, "123")

	assertT.Equal("", watchProg)
	assertT.Equal(123, watchPid)

	StopWatch()
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

//UC https://github.com/awterman/monkey/blob/2942abf7dbe961b3b90d9d3ebceb27a9b6c39765/monkey_test.go
func TestUpdatePorts(t *testing.T) {
	assertT := assert.New(t)

	ReplaceItem(&tcpSocksFn, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) {return tabEntries, nil})
	ReplaceItem(&tcp6SocksFn, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) {return noProcess, nil})
	ReplaceItem(&udpSocksFn, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) {return noProcess, nil})
	ReplaceItem(&udp6SocksFn, func(accept netstat.AcceptFn) ([]netstat.SockTabEntry, error) {return noProcess, nil})
	ReplaceItem(&watchPorts, set.New(333))
	ReplaceItem(&watchPid, 666)

	assertT.Equal(set.New(333), watchPorts)
	updatePorts()
	assertT.Equal(set.New(123), watchPorts)
}

func BenchmarkUpdatePorts(b *testing.B) {

	for _ = range b.N {
		updatePorts()
	}
}

// Tests quite often require to replace original functions or variables by the mock ones.
// Function below preserves and restores an item (function or variable).
// It should be used like this (note extra brackets) -
//
//	defer mocker.ReplaceItem(&orgVal, newVal)()
func ReplaceItem[T any](orgVal *T, newVal T) func() {
	saveVal := *orgVal
	*orgVal = newVal
	return func() { *orgVal = saveVal }
}
