package syn

import (
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/iprange"
	"log"
	"testing"
	"time"
)

func TestSynScanner_Scan(t *testing.T) {

	single := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	go func() {
		for {
			select {
			case ret := <-retChan:
				if ret.Port == 0 {
					single <- struct{}{}
					return
				}
				log.Println(ret)
			default:
				time.Sleep(time.Millisecond * 10)
			}
		}
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

	start := time.Now()
	for i := uint64(0); i < it.TotalNum(); i++ { // ip索引
		ip := it.GetIpByIndex(i)
		if !host.IsLive(ip.String()) { // ping
			continue
		}
		for _, _port := range ports { // port
			ss.WaitLimiter()
			ss.Scan(ip, _port) // syn 不能并发，默认以网卡和驱动最高性能发包
		}
	}
	ss.Close()
	<-single
	t.Log(time.Since(start))
}
