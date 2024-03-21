# go-portScan

[![Go Reference](https://pkg.go.dev/badge/github.com/XinRoom/go-portScan.svg)](https://pkg.go.dev/github.com/XinRoom/go-portScan)

高性能端口扫描器

High-performance port scanner.

> *免责声明:*  
> 本工具由网络公开资料编写而成，仅进行网络信息状态验证，不具备侵害计算机系统的能力；若由本工具或衍生工具造成的任何直接或间接后果及损失，均由使用者本人负责，作者不承担任何责任。  
> *安全警示:*  
> 使用本工具必须遵守相关网络安全法律，禁止进行非授权的侵入性测试。

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
	"github.com/panjf2000/ants/v2"
	"log"
	"net"
	"sync"
	"time"
)

func main() {
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
		log.Fatal(err)
	}

	// parse ip
	it, startIp, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := syn.NewSynScanner(startIp, retChan, syn.DefaultSynOption)
	if err != nil {
		log.Fatal(err)
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
	"github.com/XinRoom/go-portScan/core/port/tcp"
	"github.com/XinRoom/iprange"
	"github.com/panjf2000/ants/v2"
	"log"
	"net"
	"sync"
	"time"
)

func main() {
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
		log.Fatal(err)
	}

	// parse Ip
	it, _, _ := iprange.NewIter("1.1.1.1/30")

	// scanner
	ss, err := tcp.NewTcpScanner(retChan, tcp.DefaultTcpOption)
	if err != nil {
		log.Fatal(err)
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
	ss.Close()
	<-single
	log.Println(time.Since(start))
}
```

### 3. Http/Port Finger
Http Web Cms Finger
```go
// "github.com/XinRoom/go-portScan/core/port/fingerprint"
func ProbeHttpInfo(host string, _port uint16, dialTimeout time.Duration) (httpInfo *port.HttpInfo, banner []byte, isDailErr bool) {}
func WebHttpInfo(url2 string, dialTimeout time.Duration) (httpInfo *port.HttpInfo, banner []byte, isDailErr bool) {}

// "github.com/XinRoom/go-portScan/core/port/fingerprint/webfinger"
func WebFingerIdent(resp *http.Response) (names []string) {}
```
Tcp Port Service Finger

```go
// "github.com/XinRoom/go-portScan/core/port/fingerprint"
func PortIdentify(network string, ip net.IP, _port uint16, dailTimeout time.Duration) (serviceName string, banner []byte, isDailErr bool) {}
```

### 4. For More

To see [./cmd/go-portScan.go](./cmd/go-portScan.go)

## Cmd Build

普通编译

```
git clone https://github.com/XinRoom/go-portScan
cd go-portScan
go get -d -u ./...
go build -trimpath -ldflags="-s -w" -tags urfave_cli_no_docs cmd/go-portScan.go
```

Linux静态链接编译（需要docker环境）

```
sh ./build/build_static_alpine.sh
```

禁用syn模块，只保留tcp的编译(以便能在未安装pcap的windows机子上运行)

```
go build -trimpath -ldflags="-s -w" -tags urfave_cli_no_docs,nosyn cmd/go-portScan.go
```

## Cmd Usage

`.\go-portScan.exe -ip 1.1.1.1/30 [-p str] [-Pn] [-sT] [-sV] [-httpx] [-rate num] [-rateP num] [-timeout num(ms)]`

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
   --ip value                        target ip, eg: "1.1.1.1/30,1.1.1.1-1.1.1.2,1.1.1.1-2"
   --iL value                        target ip file, eg: "ips.txt"
   --port value, -p value            eg: "top1000,5612,65120,-" (default: "top1000")
   --Pn                              no ping probe (default: false)
   --rateP value, --rp value         concurrent num when ping probe each ip (default: 300)
   --PT                              use TCP-PING mode (default: false)
   --sT                              TCP-mode(support IPv4 and IPv6) (default: false)
   --timeout value, --to value       TCP-mode SYN-mode timeout. unit is ms. (default: 800)
   --sS                              Use SYN-mode(Only IPv4) (default: true)
   --nexthop value, --nh value       specified nexthop gw add to pcap dev
   --rate value, -r value            number of packets sent per second. If set -1, TCP-mode is 1000, SYN-mode is 1500(SYN-mode is restricted by the network adapter, 2000=1M) (default: -1)
   --devices, --ld                   list devices name (default: false)
   --sV                              port service identify (default: false)
   --httpx                           http server identify (default: false)
   --netLive                         Detect live C-class networks, eg: -ip 192.168.0.0/16,172.16.0.0/12,10.0.0.0/8 (default: false)
   --maxOpenPort value, --mop value  Stop the ip scan, when the number of open-port is maxOpenPort (default: 0)
   --oCsv value, --oC value          output csv file
   --oFile value, -o value           output to file
   --help, -h                        show help (default: false)
```

关键参数说明：

```
--Pn 在目标禁止PING时使用
--rate 在网络不稳定时（互联网）可以适当减少（互联网下建议500~1500）
--timeout 在网络不稳定时（互联网）可以适当增加
--nexthop 用于在syn扫描模式下，找不到路由网卡情况时，指定下一跳网关地址（需要是本地网卡上绑定的网关地址）
--PT ICMP不通时，使用常见端口的TCP探测主机是否存活

--sV 用于判断端口的服务（主要是探测风险比较大的服务）
--netLive 用于抽取网络内6个左右IP进行存活探测
--httpx 用于探测http服务的title等信息
--mop 用于目标组内存在防扫描防火墙的情况，单个IP扫描到开放的端口到达该值就停止对该IP扫描，避免浪费时间（建议值500）
```