package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	"github.com/XinRoom/go-portScan/core/port/syn"
	"github.com/XinRoom/go-portScan/util"
	"github.com/XinRoom/iprange"
	"github.com/google/gopacket/pcap"
	"github.com/panjf2000/ants/v2"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ipStr   string
	portStr string
	Pn      bool
	sT      bool
	rate    int
	sV      bool
	timeout int
	rateP   int
	iL      string
	devices bool
	dev     string
)

func parseFlag() {
	flag.StringVar(&ipStr, "ip", "", "target ip, eg: \"1.1.1.1/30,1.1.1.1-1.1.1.2,1.1.1.1-2\"")
	flag.StringVar(&iL, "iL", "", "target ip file, eg: \"ips.txt\"")
	flag.StringVar(&portStr, "port", "top1000", "eg: \"top1000,5612,65120\"")
	flag.StringVar(&dev, "dev", "", "specified pcap dev name")
	flag.BoolVar(&Pn, "Pn", false, "no ping probe")
	flag.IntVar(&rateP, "rateP", 300, "concurrent num when ping probe each ip")
	flag.BoolVar(&sT, "sT", false, "TCP-mode(support IPv4 and IPv6); Use SYN-mode(Only IPv4) if not set")
	flag.BoolVar(&sV, "sV", false, "port service identify")
	flag.BoolVar(&devices, "devices", false, "list devices name")
	flag.IntVar(&rate, "rate", -1, fmt.Sprintf("number of packets sent per second. If set -1, TCP-mode is %d, SYN-mode is %d(SYN-mode is restricted by the network adapter, 2000=1M)", port.DefaultTcpOption.Rate, syn.DefaultSynOption.Rate))
	flag.IntVar(&timeout, "timeout", -1, "TCP-mode timeout. unit is ms. If set -1, 800ms.")
	flag.Parse()
}

func main() {
	parseFlag()
	if devices {
		pcapDevices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("list pcapDevices failed: %s", err.Error())
		}
		for _, dev := range pcapDevices {
			fmt.Println(dev.Name, "\t", dev.Description)
		}
		os.Exit(0)
	}
	if ipStr == "" && iL == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}
	if portStr == "-" {
		portStr = "1-65535"
	}
	ipRangeGroup := make([]*iprange.Iter, 0)
	// ip parse
	var firstIp net.IP
	var ips []string
	if ipStr != "" {
		ips = strings.Split(ipStr, ",")
	}
	if iL != "" {
		file, err := os.Open(iL)
		if err != nil {
			log.Fatalf("open file failed: %s", err.Error())
		}
		scanner := bufio.NewScanner(file)
		var line string
		for scanner.Scan() {
			line = strings.TrimSpace(scanner.Text())
			if line != "" {
				ips = append(ips, line)
			}
		}
		file.Close()
	}
	for _, _ip := range ips {
		it, startIp, err := iprange.NewIter(_ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] %s is not ip!\n", _ip)
			os.Exit(-1)
		}
		if firstIp == nil {
			firstIp = startIp
		}
		ipRangeGroup = append(ipRangeGroup, it)
	}
	// port parse
	ports, err := port.ShuffleParseAndMergeTopPorts(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] %s is not port!", err)
		os.Exit(-1)
	}

	// recv
	single := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	// port fingerprint
	var wgPortIdentify sync.WaitGroup
	poolPortIdentify, _ := ants.NewPoolWithFunc(500, func(ipPort interface{}) {
		ret := ipPort.(port.OpenIpPort)
		fmt.Printf("%s:%d %s\n", ret.Ip, ret.Port, fingerprint.PortIdentify("tcp", ret.Ip, ret.Port))
		wgPortIdentify.Done()
	})
	defer poolPortIdentify.Release()
	go func() {
		for {
			select {
			case ret := <-retChan:
				if ret.Port == 0 {
					single <- struct{}{}
					return
				}
				if sV {
					// port fingerprint
					wgPortIdentify.Add(1)
					poolPortIdentify.Invoke(ret)
				} else {
					fmt.Printf("%v:%d\n", ret.Ip, ret.Port)
				}
			default:
				time.Sleep(time.Millisecond * 10)
			}
		}
	}()

	// Initialize the Scanner
	var s port.Scanner
	option := port.Option{
		Rate:    rate,
		Timeout: timeout,
		Dev:     dev,
	}
	if sT {
		// tcp
		if option.Rate == -1 {
			option.Rate = port.DefaultTcpOption.Rate
		}
		if option.Timeout == -1 {
			option.Timeout = port.DefaultTcpOption.Timeout
		}
		s, err = port.NewTcpScanner(retChan, option)
	} else {
		// syn
		if option.Rate == -1 {
			option.Rate = syn.DefaultSynOption.Rate
		}
		s, err = syn.NewSynScanner(firstIp, retChan, option)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] Initialize Scanner: %s", err)
		os.Exit(-1)
	}

	start := time.Now()
	var wgScan sync.WaitGroup
	var wgPing sync.WaitGroup

	// Pool - port scan
	size := option.Rate
	if !sT {
		// syn-mode Concurrency is not recommended !!!
		// The default nic is sent at the maximum rate
		size = 1
	}
	poolScan, _ := ants.NewPoolWithFunc(size, func(ipPort interface{}) {
		_ipPort := ipPort.(port.OpenIpPort)
		s.Scan(_ipPort.Ip, _ipPort.Port)
		wgScan.Done()
	})
	defer poolScan.Release()

	// port scan func
	portScan := func(ip net.IP) {
		for _, _port := range ports { // port
			s.WaitLimiter() // limit rate
			wgScan.Add(1)
			_ = poolScan.Invoke(port.OpenIpPort{
				Ip:   ip,
				Port: _port,
			})
		}
	}

	// Pool - ping and port scan
	poolPing, _ := ants.NewPoolWithFunc(rateP, func(ip interface{}) {
		_ip := ip.(net.IP)
		if host.IsLive(_ip.String()) {
			portScan(_ip)
		}
		wgPing.Done()
	})
	defer poolPing.Release()

	// start scan
	for _, ir := range ipRangeGroup { // ip group
		shuffle := util.NewShuffle(ir.TotalNum())    // shuffle
		for i := uint64(0); i < ir.TotalNum(); i++ { // ip index
			ip := make(net.IP, len(ir.GetIpByIndex(0)))
			copy(ip, ir.GetIpByIndex(shuffle.Get(i))) // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
			if !Pn {                                  // ping
				wgPing.Add(1)
				_ = poolPing.Invoke(ip)
			} else {
				portScan(ip)
			}
		}
	}
	wgScan.Wait()         // 扫描器-发
	wgPing.Wait()         // PING组
	s.Close()             // 扫描器-收
	<-single              // 接收器-收
	wgPortIdentify.Wait() // 识别器-收
	fmt.Printf("[*] const time: %s\n", time.Since(start))
}
