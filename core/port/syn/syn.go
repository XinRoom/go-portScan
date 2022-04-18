package syn

import (
	"context"
	"errors"
	"fmt"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	limiter "golang.org/x/time/rate"
	"math/rand"
	"net"
	"sync"
	"time"
)

var DefaultSynOption = port.Option{
	Rate:    2000,
	Timeout: 0,
}

type synScanner struct {
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
	retChan        chan port.OpenIpPort // results chan
	limiter        *limiter.Limiter
	ctx            context.Context
	watchIpStatusT *watchIpStatusTable // IpStatusCacheTable
	watchMacCacheT *watchMacCacheTable // MacCaches
	isDone         bool
}

// NewSynScanner firstIp: Used to select routes; retChan: Result return channel
func NewSynScanner(firstIp net.IP, retChan chan port.OpenIpPort, option port.Option) (ss *synScanner, err error) {
	// option verify
	if option.Rate <= 0 {
		err = errors.New("rate can not set to 0")
		return
	}

	// get router info
	srcIp, srcMac, gw, devName, err := GetRouterV4(firstIp)
	if err != nil {
		return
	}
	if devName == "" && option.Dev == "" {
		err = errors.New("get router info fail: no dev name")
		return
	}
	if devName == "" {
		devName = option.Dev
	}

	rand.Seed(time.Now().Unix())

	ss = &synScanner{
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
		retChan:        retChan,
		limiter:        limiter.NewLimiter(limiter.Every(time.Second/time.Duration(option.Rate)), 10),
		ctx:            context.Background(),
		watchIpStatusT: newWatchIpStatusTable(),
		watchMacCacheT: newWatchMacCacheTable(),
	}

	// Pcap
	// 每个包最大读取长度1024, 不开启混杂模式, no TimeOut
	handle, err := pcap.OpenLive(devName, 1024, false, pcap.BlockForever)
	if err != nil {
		return
	}
	// Set filter, Reduce the number of monitoring packets
	handle.SetBPFFilter(fmt.Sprintf("ether dst %s && (arp || tcp)", srcMac.String()))
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
func (ss *synScanner) Scan(dstIp net.IP, dst uint16) (err error) {
	if ss.isDone {
		return errors.New("scanner is closed")
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
		Id:       uint16(50000 + rand.Intn(500)),
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(49000 + rand.Intn(5000)), // Random source port and used to determine recv dst port range
		DstPort: layers.TCPPort(dst),
		SYN:     true,
		Window:  65280,
		Seq:     uint32(500000 + rand.Intn(5000)),
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

// Close cleans up the handle and chan.
func (ss *synScanner) Close() {
	// Delay 2s for a reply from the last packet
	time.Sleep(time.Millisecond * 100)
	if !ss.watchIpStatusT.IsEmpty() {
		time.Sleep(time.Second * 2)
	}
	ss.isDone = true
	ss.handle.Close()
	ss.watchMacCacheT.Close()
	ss.watchIpStatusT.Close()
	ss.watchMacCacheT = nil
	ss.watchIpStatusT = nil
	close(ss.retChan)
}

// WaitLimiter Waiting for the speed limit
func (ss *synScanner) WaitLimiter() error {
	return ss.limiter.Wait(ss.ctx)
}

// GetDevName Get the device name after the route selection
func (ss synScanner) GetDevName() string {
	return ss.devName
}

// getHwAddrV4 get the destination hardware address for our packets.
func (ss *synScanner) getHwAddrV4(arpDst net.IP) (mac net.HardwareAddr, err error) {
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

	if err = ss.send(&eth, &arp); err != nil {
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
func (ss *synScanner) send(l ...gopacket.SerializableLayer) error {
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

// recv packet on the network.
func (ss *synScanner) recv() {
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
		if tcpLayer.DstPort != 0 && tcpLayer.DstPort >= 49000 && tcpLayer.DstPort <= 54000 {
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
				ss.retChan <- port.OpenIpPort{
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
				tcp.SetNetworkLayerForChecksum(&ip4)
				ss.send(&eth, &ip4, &tcp)
			}
			tcpLayer.DstPort = 0 // clean tcp parse status
		}
	}
}
