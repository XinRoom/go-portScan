# go-portScan

高性能端口扫描器

High-performance port scanner.

## Feature

- Syn stateless scan
- Syn Automatic ARP detection on the Intranet
- Scanning for large address segments has low occupancy (by iprange)
- Scanning the address is shuffled
- Concurrent high performance (by ants)
- TCP scan
- Port Fingerprint Identification

## Use as a library

### 1. SYN scanner

```go
package main

import (
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/syn"
	"github.com/XinRoom/iprange"
	"log"
	"time"
)

func main() {
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
		log.Fatal(err)
	}

	// parse ip
	it, startIp, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := syn.NewSynScanner(startIp, retChan, syn.DefaultSynOption)
	if err != nil {
		log.Fatal(err)
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
	log.Println(time.Since(start))
}
```

### 2. TCP scanner

```go
package main

import (
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/iprange"
	"log"
	"net"
	"sync"
	"time"
)

func main() {
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
		log.Fatal(err)
	}

	// parse Ip
	it, _, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := port.NewTcpScanner(retChan, port.DefaultTcpOption)
	if err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := uint64(0); i < it.TotalNum(); i++ { // ip索引
		ip := make(net.IP, len(it.GetIpByIndex(0)))
		copy(ip, it.GetIpByIndex(i))   // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
		if !host.IsLive(ip.String()) { // ping
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
	ss.Close()
	<-single
	log.Println(time.Since(start))
}
```

### 3. For More

To see [./cmd/go-portScan.go](./cmd/go-portScan.go)

## Cmd Build

```
git clone https://github.com/XinRoom/go-portScan
cd go-portScan
go get
go build cmd/go-portScan.go
```

## Cmd Usage

`.\go-portScan.exe -ip 1.1.1.1/30 [-nP] [-sT] [-sV] [-rate num] [-rateP num] [-timeout num(ms)]`

```
 .\go-portScan.exe -h
Usage of D:\pc\sync\projects\Porject\go-portScan\go-portScan.exe:
  -ip string
        target ip, eg: "1.1.1.1/30,1.1.1.1-1.1.1.2,1.1.1.1-2"
  -nP
        no ping probe
  -port string
        eg: "top1000,5612,65120" (default "top1000")
  -rate int
        number of packets sent per second. If set -1, TCP-mode is 1000, SYN-mode is 2000(SYN-mode is restricted by the network adapter) (default -1)
  -rateP int
        concurrent num when ping probe each ip (default 300)
  -sT
        TCP-mode(support IPv4 and IPv6); Use SYN-mode(Only IPv4) if not set
  -sV
        port service identify
  -timeout int
        TCP-mode timeout. unit is ms. If set -1, 800ms. (default -1)

```