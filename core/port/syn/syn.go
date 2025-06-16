//go:build !nosyn

package syn

import (
	"context"
	"errors"
	"fmt"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	"github.com/XinRoom/go-portScan/util/iputil"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	limiter "golang.org/x/time/rate"
	"io"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

type SynScanner struct {
	srcMac, gwMac net.HardwareAddr // macAddr
	devName       string           // eth dev(pcap)

	// gateway (if applicable), and source IP addresses to use.
	srcIp, srcIp6 net.IP

	// pcap
	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send() method.
	opts gopacket.SerializeOptions

	// Buffer复用
	bufPool *sync.Pool

	//
	option         port.ScannerOption
	openPortChan   chan port.OpenIpPort // inside chan
	portProbeWg    sync.WaitGroup
	retChan        chan port.OpenIpPort // results chan
	limiter        *limiter.Limiter
	ctx            context.Context
	watchIpStatusT *watchIpStatusTable // IpStatusCacheTable
	watchMacCacheT *watchMacCacheTable // MacCaches
	isDone         bool

	// stat
	lastStatProbeTime time.Time
	lastRate          int
}

// NewSynScanner firstIp: Used to select routes; openPortChan: Result return channel
func NewSynScanner(firstIp net.IP, retChan chan port.OpenIpPort, option port.ScannerOption) (ss *SynScanner, err error) {
	// option verify
	if option.Rate < 10 {
		err = errors.New("rate can not set < 10")
		return
	}

	var devName string
	var srcIp, srcIp6 net.IP
	var srcMac net.HardwareAddr
	var gw net.IP

	// specify dev
	if option.NextHop != "" {
		gw = net.ParseIP(option.NextHop)
		srcIp, srcIp6, srcMac, devName, err = GetMacByGw(gw)
	} else {
		// get router info
		srcIp, srcIp6, srcMac, gw, devName, err = GetRouter(firstIp)
	}
	if err != nil {
		return
	}

	if devName == "" {
		err = errors.New("get router info fail: no dev name")
		return
	}

	rand.Seed(time.Now().Unix())

	ss = &SynScanner{
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		srcIp:   srcIp,
		srcIp6:  srcIp6,
		srcMac:  srcMac,
		devName: devName,
		bufPool: &sync.Pool{
			New: func() interface{} {
				return gopacket.NewSerializeBuffer()
			},
		},
		option:         option,
		openPortChan:   make(chan port.OpenIpPort, cap(retChan)),
		retChan:        retChan,
		limiter:        limiter.NewLimiter(limiter.Every(time.Second/time.Duration(option.Rate)), option.Rate/10),
		ctx:            context.Background(),
		watchIpStatusT: newWatchIpStatusTable(time.Duration(option.Timeout)),
		watchMacCacheT: newWatchMacCacheTable(),
	}
	go ss.portProbeHandle()

	// Pcap
	// 每个包最大读取长度1024, 不开启混杂模式, no TimeOut
	handle, err := pcap.OpenLive(devName, 1024, false, pcap.BlockForever)
	if err != nil {
		return
	}
	// Set filter, Reduce the number of monitoring packets
	handle.SetBPFFilter(fmt.Sprintf("ether dst %s && (arp || tcp[tcpflags] == tcp-syn|tcp-ack || ((ip6[6] = 6) && (ip6[53] & 0x03 != 0)))", srcMac.String()))
	ss.handle = handle

	// start listen recv
	go ss.recv()

	if gw != nil {
		// get gateway mac addr
		var dstMac net.HardwareAddr
		dstMac, err = ss.getHwAddr(gw)
		if err != nil {
			return
		}
		ss.gwMac = dstMac
	}

	return
}

// Scan scans the dst IP address and port of this scanner.
func (ss *SynScanner) Scan(dstIp net.IP, dst uint16, ipOption port.IpOption) (err error) {
	if ss.isDone {
		return io.EOF
	}

	ss.changeLimiter()

	// watchIp, first
	ipStr := dstIp.String()
	ss.watchIpStatusT.CreateOrUpdateLastTime(ipStr, ipOption)

	// First off, get the MAC address we should be sending packets to.
	var dstMac net.HardwareAddr
	if ss.gwMac != nil {
		dstMac = ss.gwMac
	} else {
		// 内网IP
		mac := ss.watchMacCacheT.GetMac(ipStr)
		if mac != nil {
			dstMac = mac
		} else {
			dstMac, err = ss.getHwAddr(dstIp)
			if err != nil {
				return
			}
		}
	}

	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	var ip4 *layers.IPv4
	var ip6 *layers.IPv6
	if dstIp.To4() != nil {
		ip4 = &layers.IPv4{
			SrcIP:    ss.srcIp,
			DstIP:    dstIp,
			Version:  4,
			TTL:      128,
			Id:       uint16(40000 + rand.Intn(10000)),
			Flags:    layers.IPv4DontFragment,
			Protocol: layers.IPProtocolTCP,
		}
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 = &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolTCP,
			HopLimit:   64,
			SrcIP:      ss.srcIp6,
			DstIP:      dstIp,
		}
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(49000 + rand.Intn(10000)), // Random source port and used to determine recv dst port range
		DstPort: layers.TCPPort(dst),
		SYN:     true,
		Window:  65280,
		Seq:     uint32(500000 + rand.Intn(10000)),
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0x50}, // 1360
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x08},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}
	// Send one packet per loop iteration until we've sent packets
	if ip4 != nil {
		tcp.SetNetworkLayerForChecksum(ip4)
		ss.send(&eth, ip4, &tcp)
	} else if ip6 != nil {
		tcp.SetNetworkLayerForChecksum(ip6)
		ss.send(&eth, ip6, &tcp)
	}
	return
}

func (ss *SynScanner) Wait() {
	// Delay 2s for a reply from the last packet
	for i := 0; i < 20; i++ {
		if ss.watchIpStatusT.IsEmpty() {
			break
		}
		time.Sleep(time.Millisecond * 100)
	}
	// wait inside chan is empty
	for len(ss.openPortChan) != 0 {
		time.Sleep(time.Millisecond * 20)
	}
	// wait portProbe task
	ss.portProbeWg.Wait()
}

// Close cleans up the handle and chan.
func (ss *SynScanner) Close() {
	ss.isDone = true
	if ss.handle != nil {
		// In linux, pcap can not stop when no packets to sniff with BlockForever
		// ref:https://github.com/google/gopacket/issues/890
		// ref:https://github.com/google/gopacket/issues/1089
		if runtime.GOOS == "linux" {
			eth := layers.Ethernet{
				SrcMAC:       ss.srcMac,
				DstMAC:       ss.srcMac,
				EthernetType: layers.EthernetTypeARP,
			}
			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPReply,
				SourceHwAddress:   []byte(ss.srcMac),
				SourceProtAddress: []byte(ss.srcIp),
				DstHwAddress:      []byte(ss.srcMac),
				DstProtAddress:    []byte(ss.srcIp),
			}
			handle, _ := pcap.OpenLive(ss.devName, 1024, false, time.Second)
			buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
			gopacket.SerializeLayers(buf, ss.opts, &eth, &arp)
			handle.WritePacketData(buf.Bytes())
			handle.Close()
			buf.Clear()
			ss.bufPool.Put(buf)
		}
		ss.handle.Close()
	}
	if ss.watchMacCacheT != nil {
		ss.watchMacCacheT.Close()
	}
	if ss.watchIpStatusT != nil {
		ss.watchIpStatusT.Close()
	}
	ss.watchMacCacheT = nil
	ss.watchIpStatusT = nil
	close(ss.openPortChan)
	close(ss.retChan)
}

// WaitLimiter Waiting for the speed limit
func (ss *SynScanner) WaitLimiter() error {
	return ss.limiter.Wait(ss.ctx)
}

// GetDevName Get the device name after the route selection
func (ss *SynScanner) GetDevName() string {
	return ss.devName
}

// changeLimiter
func (ss *SynScanner) changeLimiter() {
	// 忽略第一次执行
	if ss.lastStatProbeTime.Equal(time.Time{}) {
		ss.lastRate = ss.option.Rate
		ss.lastStatProbeTime = time.Now()
		return
	}
	// 每 2s 判断一次
	if time.Since(ss.lastStatProbeTime) < 2*time.Second {
		return
	}
	ss.lastStatProbeTime = time.Now()

	if ss.option.Debug {
		fmt.Println("[d] limiter tokens:", ss.limiter.Tokens())
	}

	var setLimit = func(rate int) {
		if rate <= 0 {
			rate = 10
		}
		if rate > ss.option.Rate {
			rate = ss.option.Rate
		} else if rate < ss.option.MiniRate {
			rate = ss.option.MiniRate
		}
		ss.lastRate = rate
		if ss.option.Debug {
			fmt.Printf("[d] syn rate:%d packets/s\n", rate)
		}
		ss.limiter.SetLimit(limiter.Every(time.Second / time.Duration(rate)))
	}

	// 与recv协同，当队列缓冲区到达80%时降半速，90%将为10/s
	if len(ss.openPortChan)*10 >= cap(ss.openPortChan)*9 {
		setLimit(10)
	} else if len(ss.openPortChan)*10 >= cap(ss.openPortChan)*8 {
		setLimit(ss.lastRate / 2)
	} else if ss.limiter.Tokens() > 0 { // 通过判断limiter是否还有可使用Tokens，判断发送速度是否是贴着网卡最大发送速度，理想情况下应该为网卡最大处理速度小一点
		setLimit(ss.lastRate - int(ss.limiter.Tokens()) - 10)
	} else if ss.limiter.Tokens() < -50 { // 恢复速度到使端口发包等待30个组(tokens 会为负数)
		setLimit(ss.lastRate - int(ss.limiter.Tokens()) - 10)
	}
}

func (ss *SynScanner) portProbeHandle() {
	for openIpPort := range ss.openPortChan {
		ss.portProbeWg.Add(1)
		if !openIpPort.FingerPrint && !openIpPort.Httpx {
			ss.retChan <- openIpPort
			ss.portProbeWg.Done()
		} else {
			go func(_openIpPort port.OpenIpPort) {
				if _openIpPort.Port != 0 {
					if _openIpPort.FingerPrint {
						ss.WaitLimiter()
						_openIpPort.Service, _openIpPort.Banner, _ = fingerprint.PortIdentify("tcp", _openIpPort.Ip, _openIpPort.Port, time.Duration(ss.option.Timeout)*time.Millisecond)
					}
					if _openIpPort.Httpx && (_openIpPort.Service == "" || _openIpPort.Service == "http" || _openIpPort.Service == "https") {
						ss.WaitLimiter()
						_openIpPort.HttpInfo, _openIpPort.Banner, _ = fingerprint.ProbeHttpInfo(iputil.GetIpStr(_openIpPort.Ip), _openIpPort.Port, time.Duration(ss.option.Timeout)*time.Millisecond)
						if _openIpPort.HttpInfo != nil {
							if strings.HasPrefix(_openIpPort.HttpInfo.Url, "https") {
								_openIpPort.Service = "https"
							} else {
								_openIpPort.Service = "http"
							}
						}
					}
				}
				ss.retChan <- _openIpPort
				ss.portProbeWg.Done()
			}(openIpPort)
		}
	}
}

func (ss *SynScanner) getHwAddr(arpDst net.IP) (mac net.HardwareAddr, err error) {
	if arpDst.To4() != nil {
		return ss.getHwAddrV4(arpDst)
	} else {
		return ss.getHwAddrV6(arpDst)
	}
}

// getHwAddrV4 get the destination hardware address for our packets.
func (ss *SynScanner) getHwAddrV4(arpDst net.IP) (mac net.HardwareAddr, err error) {
	ipStr := arpDst.String()
	if ss.watchMacCacheT.IsNeedWatch(ipStr) {
		return nil, errors.New("arp of this ip has been in monitoring")
	}
	ss.watchMacCacheT.UpdateLastTime(ipStr) // New one ip watch

	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(ss.srcMac),
		SourceProtAddress: []byte(ss.srcIp),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}

	if err = ss.sendArp(&eth, &arp); err != nil {
		return nil, err
	}

	start := time.Now()
	var retry int

	for {
		mac = ss.watchMacCacheT.GetMac(ipStr)
		if mac != nil {
			return mac, nil
		}
		// Wait 600 ms for an ARP reply.
		if time.Since(start) > time.Millisecond*600 {
			return nil, errors.New("timeout getting ARP reply")
		}
		retry += 1
		if retry%25 == 0 {
			if err = ss.send(&eth, &arp); err != nil {
				return nil, err
			}
		}

		time.Sleep(time.Millisecond * 10)
	}
}

// convertIPv6ToMac converts an IPv6 address that was generated via SLAAC
// to the corresponding MAC address.
func (ss *SynScanner) convertIPv6ToMac(ipv6 net.IP) (net.HardwareAddr, error) {
	if !((ipv6[0] == 0xfe && (ipv6[1]&0xc0 == 0x80)) || // fe80::/10
		(ipv6[0] == 0x20 && ipv6[1] == 0x02) || // 2002::/16
		(ipv6[0] == 0xff)) { // ff00::/8
		return nil, errors.New("no SLAAC adder")
	}

	// Extract the interface identifier from the last 8 bytes of the IPv6 address
	interfaceIdentifier := ipv6[8:16]
	if (interfaceIdentifier[0] & 0x02) != 0x02 {
		return nil, errors.New("no SLAAC adder")
	}

	// Convert EUI-64 to MAC address
	mac := make(net.HardwareAddr, 6)
	copy(mac, interfaceIdentifier[:3])
	copy(mac[3:], interfaceIdentifier[5:])

	// Flip the U/L bit in the first octet of the MAC address
	mac[0] = mac[0] ^ 0x02
	return mac, nil
}

// getHwAddrV6 get the destination hardware address for our packets.
func (ss *SynScanner) getHwAddrV6(arpDst net.IP) (mac net.HardwareAddr, err error) {
	mac, err = ss.convertIPv6ToMac(arpDst)
	if mac != nil {
		return
	}

	ipStr := arpDst.String()
	if ss.watchMacCacheT.IsNeedWatch(ipStr) {
		return nil, errors.New("arp of this ip has been in monitoring")
	}
	ss.watchMacCacheT.UpdateLastTime(ipStr) // New one ip watch

	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       []byte{51, 51, 255, arpDst[13], arpDst[14], arpDst[15]},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ipv6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      ss.srcIp,
		DstIP:      arpDst,
	}
	icmpv6 := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0),
	}
	icmpv6Payload := layers.ICMPv6NeighborSolicitation{
		TargetAddress: arpDst,
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: ss.srcMac,
			},
		},
	}

	icmpv6.SetNetworkLayerForChecksum(&ipv6)

	//start := time.Now()
	var retry int

	for {
		mac = ss.watchMacCacheT.GetMac(ipStr)
		if mac != nil {
			return mac, nil
		}
		// Wait 600 ms for an ARP reply.
		//if time.Since(start) > time.Millisecond*600 {
		//	return nil, errors.New("timeout getting ICMP V6 NA reply")
		//}
		retry += 1
		if retry%25 == 0 {
			if err = ss.send(&eth, &ipv6, &icmpv6, &icmpv6Payload); err != nil {
				return nil, err
			}
		}

		time.Sleep(time.Millisecond * 10)
	}
}

// send sends the given layers as a single packet on the network.
func (ss *SynScanner) send(l ...gopacket.SerializableLayer) error {
	buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		buf.Clear()
		ss.bufPool.Put(buf)
	}()
	if err := gopacket.SerializeLayers(buf, ss.opts, l...); err != nil {
		return err
	}
	return ss.handle.WritePacketData(buf.Bytes())
}

// send sends the given layers as a single packet on the network., need fix padding
func (ss *SynScanner) sendArp(l ...gopacket.SerializableLayer) error {
	buf := ss.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		buf.Clear()
		ss.bufPool.Put(buf)
	}()
	if err := gopacket.SerializeLayers(buf, ss.opts, l...); err != nil {
		return err
	}
	return ss.handle.WritePacketData(buf.Bytes()[:42]) // need fix padding
}

// recv packet on the network.
func (ss *SynScanner) recv() {
	eth := layers.Ethernet{
		SrcMAC:       ss.srcMac,
		DstMAC:       nil,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    ss.srcIp,
		DstIP:    []byte{},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	ip6 := layers.IPv6{
		SrcIP:      ss.srcIp,
		DstIP:      []byte{},
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: 0,
		DstPort: 0,
		RST:     true,
		ACK:     true,
		Seq:     1,
	}

	// Decode
	var ipLayer layers.IPv4
	var ipv6Layer layers.IPv6
	var ipv6IcmpNALayer layers.ICMPv6NeighborAdvertisement
	var tcpLayer layers.TCP
	var arpLayer layers.ARP
	var ethLayer layers.Ethernet
	var foundLayerTypes []gopacket.LayerType

	// Parse the packet.
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&ipv6Layer,
		&tcpLayer,
		&arpLayer,
		&ipv6IcmpNALayer,
	)

	// global var
	var err error
	var data []byte
	var ipStr string
	var _port uint16
	var disIp net.IP

	for {
		// Read in the next packet.
		data, _, err = ss.handle.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}

		// is done
		if ss.isDone {
			return
		}

		// Decode TCP or ARP Packet
		err = parser.DecodeLayers(data, &foundLayerTypes)
		if len(foundLayerTypes) == 0 {
			continue
		}

		// arp
		if arpLayer.SourceProtAddress != nil {
			ipStr = net.IP(arpLayer.SourceProtAddress).String()
			if ss.watchMacCacheT.IsNeedWatch(ipStr) {
				ss.watchMacCacheT.SetMac(ipStr, arpLayer.SourceHwAddress)
			}
			arpLayer.SourceProtAddress = nil // clean arp parse status
			continue
		}

		// ipv6NA
		if len(ipv6IcmpNALayer.Options) != 0 {
			ipStr = net.IP(arpLayer.SourceProtAddress).String()
			if ss.watchMacCacheT.IsNeedWatch(ipStr) {
				ss.watchMacCacheT.SetMac(ipStr, arpLayer.SourceHwAddress)
			}
			ipv6IcmpNALayer.Options = []layers.ICMPv6Option{} // clean arp parse status
			continue
		}

		if ethLayer.EthernetType == layers.EthernetTypeIPv6 {
			disIp = ipv6Layer.SrcIP
			ip6.DstIP = disIp
			eth.EthernetType = layers.EthernetTypeIPv6
		} else {
			disIp = ipLayer.SrcIP
			ip4.DstIP = disIp
		}

		// tcp Match ip and port
		if tcpLayer.DstPort != 0 && tcpLayer.DstPort >= 49000 && tcpLayer.DstPort <= 59000 {
			ipStr = disIp.String()
			_port = uint16(tcpLayer.SrcPort)
			ipOption, has := ss.watchIpStatusT.GetIpOption(ipStr)
			if !has { // IP
				continue
			} else {
				if ss.watchIpStatusT.HasPort(ipStr, _port) { // PORT
					continue
				} else {
					ss.watchIpStatusT.RecordPort(ipStr, _port) // record
				}
			}

			if tcpLayer.SYN && tcpLayer.ACK {
				ss.openPortChan <- port.OpenIpPort{
					Ip:       disIp,
					Port:     _port,
					IpOption: ipOption,
				}
				// reply to target
				eth.DstMAC = ethLayer.SrcMAC
				tcp.DstPort = tcpLayer.SrcPort
				tcp.SrcPort = tcpLayer.DstPort
				// RST && ACK
				tcp.Ack = tcpLayer.Seq + 1
				tcp.Seq = tcpLayer.Ack
				if ethLayer.EthernetType == layers.EthernetTypeIPv6 {
					tcp.SetNetworkLayerForChecksum(&ip6)
					ss.send(&eth, &ip6, &tcp)
				} else {
					tcp.SetNetworkLayerForChecksum(&ip4)
					ss.send(&eth, &ip4, &tcp)
				}
			}
			tcpLayer.DstPort = 0 // clean tcp parse status
		}
	}
}
