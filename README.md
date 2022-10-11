# go-portScan

[![Go Reference](https://pkg.go.dev/badge/github.com/XinRoom/go-portScan.svg)](https://pkg.go.dev/github.com/XinRoom/go-portScan)

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
- HTTP Service Detection

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

`.\go-portScan.exe -ip 1.1.1.1/30 [-p str] [-Pn] [-sT] [-sV] [-rate num] [-rateP num] [-timeout num(ms)]`

```
NAME:
   PortScan - A new cli application

USAGE:
   PortScan [global options] command [command options] [arguments...]

DESCRIPTION:
   High-performance port scanner

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --ip value                   target ip, eg: "1.1.1.1/30,1.1.1.1-1.1.1.2,1.1.1.1-2"
   --iL value                   target ip file, eg: "ips.txt"
   --port value, -p value       eg: "top1000,5612,65120,-" (default: "top1000")
   --Pn                         no ping probe (default: false)
   --rateP value, --rp value    concurrent num when ping probe each ip (default: 300)
   --sT                         TCP-mode(support IPv4 and IPv6) (default: false)
   --timeout value, --to value  TCP-mode SYN-mode timeout. unit is ms. (default: 800)
   --sS                         Use SYN-mode(Only IPv4) (default: true)
   --dev value                  specified pcap dev name
   --rate value, -r value       number of packets sent per second. If set -1, TCP-mode is 1000, SYN-mode is 2000(SYN-mode is restricted by the network adapter, 2000=1M) (default: -1)
   --devices, --ld              list devices name (default: false)
   --sV                         port service identify (default: false)
   --httpx                      http server identify (default: false)
   --netLive                    Detect live C-class networks, eg: -ip 192.168.0.0/16,172.16.0.0/12,10.0.0.0/8 (default: false)
   --help, -h                   show help (default: false)
```