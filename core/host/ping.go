package host

import (
	"bytes"
	"github.com/go-ping/ping"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var CanIcmp bool

// 判断是否支持发送icmp包
func init() {
	if IcmpOK("localhost") {
		CanIcmp = true
	}
}

// IsLive 判断ip是否存活
func IsLive(ip string) bool {
	if CanIcmp {
		return IcmpOK(ip)
	} else {
		return PingOk(ip)
	}
}

// PingOk Ping命令模式
func PingOk(host string) bool {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		if strings.Contains(out.String(), "ttl=") {
			return true
		}
	case "windows":
		cmd := exec.Command("ping", "-n", "1", "-w", "500", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		if strings.Contains(out.String(), "TTL=") {
			return true
		}
	}
	return false
}

// IcmpOK 直接发ICMP包
func IcmpOK(host string) bool {
	pinger, err := ping.NewPinger(host)
	if err != nil {
		return false
	}
	pinger.SetPrivileged(true)
	pinger.Count = 1
	pinger.Timeout = 800 * time.Millisecond
	if pinger.Run() != nil { // Blocks until finished. return err
		return false
	}
	if stats := pinger.Statistics(); stats.PacketsRecv > 0 {
		return true
	}
	return false
}
