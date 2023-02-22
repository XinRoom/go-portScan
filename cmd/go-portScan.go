package main

import (
	"fmt"
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	"github.com/XinRoom/go-portScan/core/port/syn"
	"github.com/XinRoom/go-portScan/util"
	"github.com/XinRoom/iprange"
	"github.com/panjf2000/ants/v2"
	"github.com/urfave/cli/v2"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ipStr       string
	portStr     string
	pn          bool
	sT          bool
	rate        int
	sV          bool
	timeout     int
	rateP       int
	iL          string
	devices     bool
	nexthop     string
	httpx       bool
	netLive     bool
	bp          bool
	user        string
	passwd      string
	service     string
	threadNum   int
	maxOpenPort int
)

func parseFlag(c *cli.Context) {
	ipStr = c.String("ip")
	iL = c.String("iL")
	portStr = c.String("port")
	nexthop = c.String("nexthop")
	devices = c.Bool("devices")
	pn = c.Bool("Pn")
	rateP = c.Int("rateP")
	rate = c.Int("rate")
	sT = c.Bool("sT")
	sV = c.Bool("sV")
	timeout = c.Int("timeout")
	httpx = c.Bool("httpx")
	netLive = c.Bool("netLive")
	maxOpenPort = c.Int("maxOpenPort")
}

func run(c *cli.Context) error {
	myLog := util.NewLogger("output.log", true)
	if c.NumFlags() == 0 {
		cli.ShowAppHelpAndExit(c, 0)
	}
	parseFlag(c)
	if devices {
		if r, err := syn.GetAllDevs(); err != nil {
			myLog.Fatal(err.Error())
		} else {
			myLog.Print(r)
		}
		os.Exit(0)
	}
	if ipStr == "" && iL == "" {
		cli.ShowAppHelpAndExit(c, 0)
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
		var err error
		ips, err = util.GetLines(iL)
		if err != nil {
			myLog.Fatalf("open file failed: %s", err.Error())
		}
	}
	for _, _ip := range ips {
		it, startIp, err := iprange.NewIter(_ip)
		if err != nil {
			myLog.Fatalf("[error] %s is not ip!\n", _ip)
		}
		if firstIp == nil {
			firstIp = startIp
		}
		ipRangeGroup = append(ipRangeGroup, it)
	}

	// netLive
	var wgIpsLive sync.WaitGroup
	// Pool - ipsLive
	poolIpsLive, _ := ants.NewPoolWithFunc(rateP, func(ip interface{}) {
		_ip := ip.([]net.IP)
		for _, ip2 := range _ip {
			if host.IsLive(ip2.String()) {
				myLog.Printf("[+] %s is live\n", ip2.String())
				break
			}
		}
		wgIpsLive.Done()
	})
	defer poolIpsLive.Release()

	if netLive {
		// 按c段探测
		for _, ir := range ipRangeGroup { // ip group
			for i := uint64(0); i < ir.TotalNum(); i = i + 256 { // ip index
				ip := make(net.IP, len(ir.GetIpByIndex(0)))
				copy(ip, ir.GetIpByIndex(i)) // Note: dup copy []byte when concurrent (GetIpByIndex not to do dup copy)
				ipLastByte := []byte{1, 2, 254, 253, byte(100 + rand.Intn(20)), byte(200 + rand.Intn(20))}
				ips2 := make([]net.IP, 6)
				for j := 0; j < 6; j++ {
					ips2[j] = make(net.IP, len(ip))
					ip[3] = ipLastByte[j]
					copy(ips2[j], ip)
				}
				wgIpsLive.Add(1)
				poolIpsLive.Invoke(ips2)
			}
		}
		wgIpsLive.Wait()
		return nil
	}

	// port parse
	ports, err := port.ShuffleParseAndMergeTopPorts(portStr)
	if err != nil {
		myLog.Fatalf("[error] %s is not port!\n", err)
	}

	// recv
	single := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	// port fingerprint
	var wgPortIdentify sync.WaitGroup
	poolPortIdentify, _ := ants.NewPoolWithFunc(500, func(ipPort interface{}) {
		ret := ipPort.(port.OpenIpPort)
		if httpx {
			_buf := fingerprint.ProbeHttpInfo(ret.Ip, ret.Port)
			if _buf != nil {
				myLog.Printf("[HttpInfo]%s\n", _buf)
			}
		}
		if sV {
			myLog.Printf("%s:%d %s\n", ret.Ip, ret.Port, fingerprint.PortIdentify("tcp", ret.Ip, ret.Port))
		}

		wgPortIdentify.Done()
	})
	defer poolPortIdentify.Release()

	// ip port num status
	ipPortNumMap := make(map[string]int) // 记录该IP端口开放数量
	var ipPortNumRW sync.RWMutex

	go func() {
		for {
			select {
			case ret := <-retChan:
				if ret.Port == 0 {
					single <- struct{}{}
					return
				}
				if maxOpenPort > 0 {
					ipPortNumRW.Lock()
					if _, ok := ipPortNumMap[ret.Ip.String()]; ok {
						ipPortNumMap[ret.Ip.String()] += 1
					}
					ipPortNumRW.Unlock()
				}
				if sV || httpx {
					// port fingerprint
					wgPortIdentify.Add(1)
					poolPortIdentify.Invoke(ret)
				}
				if !sV {
					myLog.Printf("%v:%d\n", ret.Ip, ret.Port)
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
		NextHop: nexthop,
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
		if option.Timeout == -1 {
			option.Timeout = syn.DefaultSynOption.Timeout
		}
		s, err = syn.NewSynScanner(firstIp, retChan, option)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] Initialize Scanner: %s\n", err)
		os.Exit(-1)
		myLog.Fatalf("[error] Initialize Scanner: %s\n", err)
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
		var ipPortNum int
		var ipPortNumOk bool
		if maxOpenPort > 0 {
			ipPortNumRW.Lock()
			ipPortNumMap[ip.String()] = 0
			ipPortNumRW.Unlock()
		}
		for _, _port := range ports { // port
			s.WaitLimiter() // limit rate

			if maxOpenPort > 0 {
				ipPortNumRW.RLock()
				ipPortNum, ipPortNumOk = ipPortNumMap[ip.String()]
				ipPortNumRW.RUnlock()
				if ipPortNumOk && ipPortNum >= maxOpenPort {
					break
				}
			}

			wgScan.Add(1)
			_ = poolScan.Invoke(port.OpenIpPort{
				Ip:   ip,
				Port: _port,
			})
		}
		if maxOpenPort > 0 {
			ipPortNumRW.Lock()
			delete(ipPortNumMap, ip.String())
			ipPortNumRW.Unlock()
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
			if !pn {                                  // ping
				wgPing.Add(1)
				_ = poolPing.Invoke(ip)
			} else {
				portScan(ip)
			}
		}
	}
	wgPing.Wait()         // PING组
	wgScan.Wait()         // 扫描器-发
	s.Wait()              // 扫描器-等
	s.Close()             // 扫描器-收
	<-single              // 接收器-收
	wgPortIdentify.Wait() // 识别器-收
	myLog.Printf("[*] elapsed time: %s\n", time.Since(start))
	return nil
}

func main() {
	app := &cli.App{
		Name:        "PortScan",
		Description: "High-performance port scanner",
		Action:      run,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "ip",
				Usage:    "target ip, eg: \"1.1.1.1/30,1.1.1.1-1.1.1.2,1.1.1.1-2\"",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:     "iL",
				Usage:    "target ip file, eg: \"ips.txt\"",
				Required: false,
				Value:    "",
			},
			&cli.StringFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "eg: \"top1000,5612,65120,-\"",
				Value:   "top1000",
			},
			&cli.BoolFlag{
				Name:  "Pn",
				Usage: "no ping probe",
				Value: false,
			},
			&cli.IntFlag{
				Name:    "rateP",
				Aliases: []string{"rp"},
				Usage:   "concurrent num when ping probe each ip",
				Value:   300,
			},
			&cli.BoolFlag{
				Name:  "sT",
				Usage: "TCP-mode(support IPv4 and IPv6)",
				Value: false,
			},
			&cli.IntFlag{
				Name:    "timeout",
				Aliases: []string{"to"},
				Usage:   "TCP-mode SYN-mode timeout. unit is ms.",
				Value:   800,
			},
			&cli.BoolFlag{
				Name:  "sS",
				Usage: "Use SYN-mode(Only IPv4)",
				Value: true,
			},
			&cli.StringFlag{
				Name:    "nexthop",
				Aliases: []string{"nh"},
				Usage:   "specified nexthop gw add to pcap dev",
				Value:   "",
			},
			&cli.IntFlag{
				Name:    "rate",
				Aliases: []string{"r"},
				Usage:   fmt.Sprintf("number of packets sent per second. If set -1, TCP-mode is %d, SYN-mode is %d(SYN-mode is restricted by the network adapter, 2000=1M)", port.DefaultTcpOption.Rate, syn.DefaultSynOption.Rate),
				Value:   -1,
			},
			&cli.BoolFlag{
				Name:    "devices",
				Aliases: []string{"ld"},
				Usage:   "list devices name",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:  "sV",
				Usage: "port service identify",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "httpx",
				Usage: "http server identify",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "netLive",
				Usage: "Detect live C-class networks, eg: -ip 192.168.0.0/16,172.16.0.0/12,10.0.0.0/8",
				Value: false,
			},
			&cli.IntFlag{
				Name:  "maxOpenPort",
				Usage: "Stop the ip scan, when the number of open-port is maxOpenPort",
				Value: 0,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("err:", err)
	}
}
