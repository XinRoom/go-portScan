package syn

import (
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/iprange"
	"github.com/panjf2000/ants/v2"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSynScanner_Scan(t *testing.T) {

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

	// parse ip
	it, startIp, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := NewSynScanner(startIp, retChan, DefaultSynOption)
	if err != nil {
		t.Fatal(err)
	}

	// port scan func
	portScan := func(ip net.IP) {
		for _, _port := range ports { // port
			ss.WaitLimiter()
			ss.Scan(ip, _port) // syn 不能并发，默认以网卡和驱动最高性能发包
		}
	}

	// Pool - ping and port scan
	var wgPing sync.WaitGroup
	poolPing, _ := ants.NewPoolWithFunc(50, func(ip interface{}) {
		_ip := ip.(net.IP)
		if host.IsLive(_ip.String(), true, 800*time.Millisecond) {
			portScan(_ip)
		}
		wgPing.Done()
	})
	defer poolPing.Release()

	start := time.Now()
	for i := uint64(0); i < it.TotalNum(); i++ { // ip索引
		ip := make(net.IP, len(it.GetIpByIndex(0)))
		copy(ip, it.GetIpByIndex(i)) // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
		wgPing.Add(1)
		poolPing.Invoke(ip)
	}

	wgPing.Wait()
	ss.Wait()
	ss.Close()
	<-single
	t.Log(time.Since(start))
}
