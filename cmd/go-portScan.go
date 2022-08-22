package main

import (
	"bufio"
	"fmt"
	"github.com/XinRoom/go-portScan/core/host"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	"github.com/XinRoom/go-portScan/core/port/syn"
	"github.com/XinRoom/go-portScan/util"
	"github.com/XinRoom/iprange"
	"github.com/google/gopacket/pcap"
	"github.com/panjf2000/ants/v2"
	"github.com/urfave/cli/v2"
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
	pn      bool
	sT      bool
	rate    int
	sV      bool
	timeout int
	rateP   int
	iL      string
	devices bool
	dev     string
	httpx   bool
)

func parseFlag(c *cli.Context) {
	ipStr = c.String("ip")
	iL = c.String("iL")
	portStr = c.String("port")
	dev = c.String("dev")
	devices = c.Bool("devices")
	pn = c.Bool("Pn")
	rateP = c.Int("rateP")
	rate = c.Int("rate")
	sT = c.Bool("sT")
	sV = c.Bool("sV")
	timeout = c.Int("timeout")
	httpx = c.Bool("httpx")
}

func run(c *cli.Context) error {
	if c.NumFlags() == 0 {
		cli.ShowAppHelpAndExit(c, 0)
	}
	parseFlag(c)
	if devices {
		pcapDevices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatalf("list pcapDevices failed: %s", err.Error())
		}
		for _, dev := range pcapDevices {
			fmt.Println("Dev:", dev.Name, "\tDes:", dev.Description)
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
	single1 := make(chan struct{})
	single2 := make(chan struct{})
	retChan := make(chan port.OpenIpPort, 65535)
	// port fingerprint
	var httpxFile *os.File
	var httpxFileLooker sync.Mutex
	if httpx {
		httpxFile, err = os.OpenFile("httpInfo.txt", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err == nil {
			defer httpxFile.Close()
		}
	}
	var wgPortIdentify sync.WaitGroup
	poolPortIdentify, _ := ants.NewPoolWithFunc(500, func(ipPort interface{}) {
		ret := ipPort.(port.OpenIpPort)
		if httpx {
			_buf := fingerprint.ProbeHttpInfo(ret.Ip, ret.Port)
			if _buf != nil {
				buf := fmt.Sprintf("[HttpInfo]%s\n", _buf)
				if httpxFile != nil {
					httpxFileLooker.Lock()
					httpxFile.WriteString(buf)
					httpxFile.Sync()
					httpxFileLooker.Unlock()
				}
				fmt.Print(buf)
			}
		}
		if sV {
			fmt.Printf("%s:%d %s\n", ret.Ip, ret.Port, fingerprint.PortIdentify("tcp", ret.Ip, ret.Port))
		}

		wgPortIdentify.Done()
	})
	defer poolPortIdentify.Release()
	go func() {
		for {
			select {
			case <-single1:
				single2 <- struct{}{}
				return
			case ret := <-retChan:
				if sV || httpx {
					// port fingerprint
					wgPortIdentify.Add(1)
					poolPortIdentify.Invoke(ret)
				}
				if !sV {
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
		if option.Timeout == -1 {
			option.Timeout = syn.DefaultSynOption.Timeout
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
			if !pn {                                  // ping
				wgPing.Add(1)
				_ = poolPing.Invoke(ip)
			} else {
				portScan(ip)
			}
		}
	}
	wgScan.Wait()         // 扫描器-发
	wgPing.Wait()         // PING组
	s.Wait()              // 扫描器-等
	s.Close()             // 扫描器-收
	single1 <- struct{}{} // 告知接收器没有新端口输出了
	<-single2             // 接收器-收
	wgPortIdentify.Wait() // 识别器-收
	fmt.Printf("[*] elapsed time: %s\n", time.Since(start))
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
				Name:  "dev",
				Usage: "specified pcap dev name",
				Value: "",
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
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println("err:", err)
	}
}
