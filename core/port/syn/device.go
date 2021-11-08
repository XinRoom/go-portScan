package syn

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/jackpal/gateway"
	"net"
)

// GetDevByIp get dev name by dev ip (use pcap)
func GetDevByIp(ip net.IP) (devName string, err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	for _, d := range devices {
		for _, address := range d.Addresses {
			_ip := address.IP.To4()
			if _ip != nil && _ip.IsGlobalUnicast() && _ip.Equal(ip) {
				return d.Name, nil
			}
		}
	}
	return
}

// GetIfaceMac get interface mac addr by interface ip (use golang net)
func GetIfaceMac(ifaceAddr net.IP) (src net.IP, mac net.HardwareAddr) {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if addr.(*net.IPNet).Contains(ifaceAddr) {
					return addr.(*net.IPNet).IP, iface.HardwareAddr
				}
			}
		}
	}
	return nil, nil
}

// GetRouterV4 get ipv6 router by dst ip
func GetRouterV4(dst net.IP) (srcIp net.IP, srcMac net.HardwareAddr, gw net.IP, devName string, err error) {
	// 同网段
	srcIp, srcMac = GetIfaceMac(dst)
	if srcIp == nil {
		// 取第一个默认路由
		gw, err = gateway.DiscoverGateway()
		gw = gw.To4()
		if err == nil {
			srcIp, srcMac = GetIfaceMac(gw)
		}
	}
	srcIp = srcIp.To4()
	devName, err = GetDevByIp(srcIp)
	if srcIp == nil || err != nil {
		return nil, nil, nil, "", fmt.Errorf("no router, %s", err)
	}
	return
}
