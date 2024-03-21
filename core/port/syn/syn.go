//go:build !nosyn

package syn

import (
	"context"
	"errors"
	"fmt"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
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
	gw, srcIp net.IP

	// pcap
	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send() method.
	opts gopacket.SerializeOptions

	// Buffer复用
	bufPool *sync.Pool

	//
	option         port.Option
	openPortChan   chan port.OpenIpPort // inside chan
	portProbeWg    sync.WaitGroup
	retChan        chan port.OpenIpPort // results chan
	limiter        *limiter.Limiter
	ctx            context.Context
	watchIpStatusT *watchIpStatusTable // IpStatusCacheTable
	watchMacCacheT *watchMacCacheTable // MacCaches
	isDone         bool
}

// NewSynScanner firstIp: Used to select routes; openPortChan: Result return channel
func NewSynScanner(firstIp net.IP, retChan chan port.OpenIpPort, option port.Option) (ss *SynScanner, err error) {
	// option verify
	if option.Rate < 10 {
		err = errors.New("rate can not set < 10")
		return
	}

	var devName string
	var srcIp net.IP
	var srcMac net.HardwareAddr
	var gw net.IP

	// specify dev
	if option.NextHop != "" {
		gw = net.ParseIP(option.NextHop).To4()
		srcIp, srcMac, devName, err = GetMacByGw(gw)
	} else {
		// get router info
		srcIp, srcMac, gw, devName, err = GetRouterV4(firstIp)
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
	if ss.option.FingerPrint || ss.option.Httpx {
		go ss.portProbeHandle()
	} else {
		go func() {
			for t := range ss.openPortChan {
				ss.portProbeWg.Add(1)
				ss.retChan <- t
				ss.portProbeWg.Done()
			}
		}()
	}

	// Pcap
	// 每个包最大读取长度1024, 不开启混杂模式, no TimeOut
	handle, err := pcap.OpenLive(devName, 1024, false, pcap.BlockForever)
	if err != nil {
		return
	}
	// Set filter, Reduce the number of monitoring packets
	handle.SetBPFFilter(fmt.Sprintf("ether dst %s && (arp || tcp[tcpflags] == tcp-syn|tcp-ack)", srcMac.String()))
	ss.handle = handle

	// start listen recv
	go ss.recv()

	if gw != nil {
		// get gateway mac addr
		var dstMac net.HardwareAddr
		dstMac, err = ss.getHwAddrV4(gw)
		if err != nil {
			return
		}
		ss.gwMac = dstMac
	}

	return
}

// Scan scans the dst IP address and port of this scanner.
func (ss *SynScanner) Scan(dstIp net.IP, dst uint16) (err error) {
	if ss.isDone {
		return io.EOF
	}

	// 与recv协同，当队列缓冲区到达80%时降半速，90%将为1/s
	if len(ss.openPortChan)*10 >= cap(ss.openPortChan)*8 {
		if ss.option.Rate/2 != 0 {
			ss.limiter.SetLimit(limiter.Every(time.Second / time.Duration(ss.option.Rate/2)))
		}
	} else if len(ss.openPortChan)*10 >= cap(ss.openPortChan)*9 {
		ss.limiter.SetLimit(1)
	} else {
		ss.limiter.SetLimit(limiter.Every(time.Second / time.Duration(ss.option.Rate)))
	}

	dstIp = dstIp.To4()
	if dstIp == nil {
		return errors.New("is not ipv4")
	}

	// watchIp, first
	ipStr := dstIp.String()
	ss.watchIpStatusT.UpdateLastTime(ipStr)

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
			dstMac, err = ss.getHwAddrV4(dstIp)
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
	ip4 := layers.IPv4{
		SrcIP:    ss.srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      128,
		Id:       uint16(40000 + rand.Intn(10000)),
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
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
	tcp.SetNetworkLayerForChecksum(&ip4)

	// Send one packet per loop iteration until we've sent packets
	ss.send(&eth, &ip4, &tcp)

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

func (ss *SynScanner) portProbeHandle() {
	for openIpPort := range ss.openPortChan {
		ss.portProbeWg.Add(1)
		go func(_openIpPort port.OpenIpPort) {
			if _openIpPort.Port != 0 {
				if ss.option.FingerPrint {
					ss.WaitLimiter()
					_openIpPort.Service, _openIpPort.Banner, _ = fingerprint.PortIdentify("tcp", _openIpPort.Ip, _openIpPort.Port, 2*time.Second)
				}
				if ss.option.Httpx && (_openIpPort.Service == "" || _openIpPort.Service == "http" || _openIpPort.Service == "https") {
					ss.WaitLimiter()
					_openIpPort.HttpInfo, _openIpPort.Banner, _ = fingerprint.ProbeHttpInfo(_openIpPort.Ip.String(), _openIpPort.Port, 2*time.Second)
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
	tcp := layers.TCP{
		SrcPort: 0,
		DstPort: 0,
		RST:     true,
		ACK:     true,
		Seq:     1,
	}

	// Decode
	var ipLayer layers.IPv4
	var tcpLayer layers.TCP
	var arpLayer layers.ARP
	var ethLayer layers.Ethernet
	var foundLayerTypes []gopacket.LayerType

	// Parse the packet.
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ipLayer,
		&tcpLayer,
		&arpLayer,
	)

	// global var
	var err error
	var data []byte
	var ipStr string
	var _port uint16

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

		// tcp Match ip and port
		if tcpLayer.DstPort != 0 && tcpLayer.DstPort >= 49000 && tcpLayer.DstPort <= 59000 {
			ipStr = ipLayer.SrcIP.String()
			_port = uint16(tcpLayer.SrcPort)
			if !ss.watchIpStatusT.HasIp(ipStr) { // IP
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
					Ip:   ipLayer.SrcIP,
					Port: _port,
				}
				// reply to target
				eth.DstMAC = ethLayer.SrcMAC
				ip4.DstIP = ipLayer.SrcIP
				tcp.DstPort = tcpLayer.SrcPort
				tcp.SrcPort = tcpLayer.DstPort
				// RST && ACK
				tcp.Ack = tcpLayer.Seq + 1
				tcp.Seq = tcpLayer.Ack
				tcp.SetNetworkLayerForChecksum(&ip4)
				ss.send(&eth, &ip4, &tcp)
			}
			tcpLayer.DstPort = 0 // clean tcp parse status
		}
	}
}
