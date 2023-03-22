package host

import (
	"bytes"
	"context"
	"fmt"
	"github.com/go-ping/ping"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var CanIcmp bool

var TcpPingPorts = []uint16{80, 22, 445, 23, 443, 81, 161, 3389, 8080, 8081}

// 判断是否支持发送icmp包
func init() {
	if IcmpOK("127.0.0.1") {
		CanIcmp = true
	}
}

// IsLive 判断ip是否存活
func IsLive(ip string, tcpPing bool, tcpTimeout time.Duration) (ok bool) {
	if CanIcmp {
		ok = IcmpOK(ip)
	} else {
		ok = PingOk(ip)
	}
	if !ok && tcpPing {
		ok = TcpPing(ip, TcpPingPorts, tcpTimeout)
	}
	return
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
	case "darwin":
		cmd := exec.Command("ping", "-c", "1", "-t", "1", host)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Run()
		if strings.Contains(out.String(), "ttl=") {
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

// TcpPing 指定默认常见端口进行存活探测
func TcpPing(host string, ports []uint16, timeout time.Duration) (ok bool) {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	d := net.Dialer{
		Timeout:   timeout + time.Second,
		KeepAlive: 0,
	}
	for _, port := range ports {
		time.Sleep(10 * time.Millisecond)
		wg.Add(1)
		go func(_port uint16) {
			conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, _port))
			if conn != nil {
				conn.Close()
				ok = true
			} else if err != nil && strings.Contains(err.Error(), "refused it") { // 表明对端发送了RST包
				ok = true
			}
			if ok {
				cancel()
			}
			wg.Done()
		}(port)
	}
	wg.Wait()
	return
}
