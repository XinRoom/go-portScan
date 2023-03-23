package tcp

import (
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/iprange"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTcpScanner_Scan(t *testing.T) {

	single := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	go func() {
		for ret := range retChan {
			log.Println(ret)
		}
		single <- struct{}{}
	}()

	// 解析端口字符串并且优先发送 TopTcpPorts 中的端口, eg: 1-65535,top1000
	ports, err := port.ShuffleParseAndMergeTopPorts("top1000")
	if err != nil {
		t.Fatal(err)
	}

	// parse Ip
	it, _, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := NewTcpScanner(retChan, DefaultTcpOption)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := uint64(0); i < it.TotalNum(); i++ { // ip索引
		ip := make(net.IP, len(it.GetIpByIndex(0)))
		copy(ip, it.GetIpByIndex(i))             // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
		if !host.IsLive(ip.String(), false, 0) { // ping
			continue
		}
		for _, _port := range ports { // port
			ss.WaitLimiter()
			wg.Add(1)
			go func(ip net.IP, port uint16) {
				ss.Scan(ip, port)
				wg.Done()
			}(ip, _port)
		}
	}
	ss.Wait()
	ss.Close()
	<-single
	t.Log(time.Since(start))
}
