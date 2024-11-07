//go:build !nosyn

package syn

import (
	"errors"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/jackpal/gateway"
	"github.com/libp2p/go-netroute"
	"net"
	"strings"
)

func GetAllDevs() (string, error) {
	pcapDevices, err := pcap.FindAllDevs()
	if err != nil {
		return "", errors.New(fmt.Sprintf("list pcapDevices failed: %s", err.Error()))
	}
	var buf strings.Builder
	for _, dev := range pcapDevices {
		buf.WriteString(fmt.Sprint("Dev:", dev.Name, "\tDes:", dev.Description))
		if len(dev.Addresses) > 0 {
			buf.WriteString(fmt.Sprint("\tAddr:", dev.Addresses[0].IP.String()))
		}
		buf.WriteString("\n")
	}
	return buf.String(), nil
}

// GetDevByIp get dev name by dev ip (use pcap)
func GetDevByIp(ip net.IP) (devName string, err error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return
	}
	for _, d := range devices {
		for _, address := range d.Addresses {
			_ip := address.IP
			if _ip != nil && (_ip.IsLoopback() || _ip.IsGlobalUnicast()) && _ip.Equal(ip) {
				return d.Name, nil
			}
		}
	}
	return "", errors.New("can not find dev")
}

// GetIfaceMac get interface mac addr by interface ip (use golang net)
func GetIfaceMac(ifaceAddr net.IP) (src net.IP, src6 net.IP, mac net.HardwareAddr) {
	interfaces, _ := net.Interfaces()
	var s4 = ifaceAddr.To4() != nil
	for _, iface := range interfaces {
		var ip, ip6 net.IP
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				var ipNet = addr.(*net.IPNet)
				if !ipNet.IP.IsLoopback() && !ipNet.IP.IsGlobalUnicast() {
					continue
				}
				if ipNet.IP.To4() != nil {
					if !s4 {
						ip = ipNet.IP.To4()
					}
				} else {
					if s4 {
						ip6 = ipNet.IP
					}
				}
				if ipNet.Contains(ifaceAddr) {
					if s4 {
						ip = ipNet.IP.To4()
					} else {
						ip6 = ipNet.IP
					}
					mac = iface.HardwareAddr
				}
			}
			if mac != nil {
				src = ip
				src6 = ip6
				return
			}
		}
	}
	return
}

// IsLocalIP 判断是否是本地网卡IP地址
func IsLocalIP(ifaceAddr net.IP) (src net.IP, src6 net.IP, ok bool) {
	interfaces, _ := net.Interfaces()
	var s4 = ifaceAddr.To4() != nil
	for _, iface := range interfaces {
		var ip, ip6 net.IP
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				var ipNet = addr.(*net.IPNet)
				if !ipNet.IP.IsLoopback() && !ipNet.IP.IsGlobalUnicast() {
					continue
				}
				if ipNet.IP.To4() != nil {
					if !s4 {
						ip = ipNet.IP.To4()
					}
				} else {
					if s4 {
						ip6 = ipNet.IP
					}
				}
				if ipNet.IP.Equal(ifaceAddr) {
					if s4 {
						ip = ipNet.IP.To4()
					} else {
						ip6 = ipNet.IP
					}
					ok = true
				}
			}
			if ok {
				src = ip
				src6 = ip6
				return
			}
		}
	}
	return
}

// GetMacByGw get srcIp srcMac devname by gw
func GetMacByGw(gw net.IP) (srcIp net.IP, srcIp6 net.IP, srcMac net.HardwareAddr, devname string, err error) {
	srcIp, srcIp6, srcMac = GetIfaceMac(gw)
	if srcIp == nil && srcIp6 == nil {
		err = errors.New("can not find this dev by gw")
		return
	}
	if srcIp != nil {
		devname, err = GetDevByIp(srcIp)
	} else {
		devname, err = GetDevByIp(srcIp6)
	}
	if err == nil {
		return
	}
	err = errors.New("can not find this dev")
	return
}

// GetRouter get ipv6 router by dst ip
func GetRouter(dst net.IP) (srcIp net.IP, srcIp6 net.IP, srcMac net.HardwareAddr, gw net.IP, devName string, err error) {
	// localIP
	srcIp, srcIp6, ok := IsLocalIP(dst)
	if ok {
		devName, _ = GetDevByIp(net.IP{127, 0, 0, 1})
		return
	}
	// 同网段
	srcIp, srcIp6, srcMac = GetIfaceMac(dst)
	if srcIp == nil {
		var r routing.Router
		r, err = netroute.New()
		if err == nil {
			var sip net.IP
			_, gw, sip, err = r.Route(dst)
			if err == nil {
				srcIp, srcIp6, srcMac = GetIfaceMac(sip)
			}
		}
		if err != nil || srcMac == nil {
			// 取第一个默认路由
			gw, err = gateway.DiscoverGateway()
			if err == nil {
				srcIp, srcIp6, srcMac = GetIfaceMac(gw)
			}
		}
	}
	if gw.To4() != nil {
		gw = gw.To4()
	}
	if srcIp.To4() != nil {
		srcIp = srcIp.To4()
	}
	devName, err = GetDevByIp(srcIp)
	if (srcIp == nil && srcIp6 == nil) || err != nil || srcMac == nil {
		if err == nil {
			err = fmt.Errorf("err")
		}
		return nil, nil, nil, nil, "", fmt.Errorf("no router, %s", err)
	}
	return
}
