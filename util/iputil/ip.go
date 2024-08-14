package iputil

import (
	"fmt"
	"net"
)

func GetIpStr(ip net.IP) string {
	if ip.To4() != nil {
		return ip.String()
	}
	return fmt.Sprintf("[%s]", ip)
}
