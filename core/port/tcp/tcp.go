package tcp

import (
	"context"
	"errors"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint"
	limiter "golang.org/x/time/rate"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var DefaultTcpOption = port.ScannerOption{
	Rate:    1000,
	Timeout: 800,
}

type TcpScanner struct {
	ports   []uint16             // 指定端口
	retChan chan port.OpenIpPort // 返回值队列
	limiter *limiter.Limiter
	ctx     context.Context
	timeout time.Duration
	isDone  bool
	option  port.ScannerOption
	wg      sync.WaitGroup
}

// NewTcpScanner Tcp扫描器
func NewTcpScanner(retChan chan port.OpenIpPort, option port.ScannerOption) (ts *TcpScanner, err error) {
	// option verify
	if option.Rate < 10 {
		err = errors.New("rate can not set < 10")
		return
	}
	if option.Timeout <= 0 {
		err = errors.New("timeout can not set to 0")
		return
	}

	ts = &TcpScanner{
		retChan: retChan,
		limiter: limiter.NewLimiter(limiter.Every(time.Second/time.Duration(option.Rate)), option.Rate/10),
		ctx:     context.Background(),
		timeout: time.Duration(option.Timeout) * time.Millisecond,
		option:  option,
	}

	return
}

// Scan 对指定IP和dis port进行扫描
func (ts *TcpScanner) Scan(ip net.IP, dst uint16, ipOption port.IpOption) error {
	if ts.isDone {
		return errors.New("scanner is closed")
	}
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		//fmt.Println(1)
		openIpPort := port.OpenIpPort{
			Ip:   ip,
			Port: dst,
			IpOption: port.IpOption{
				Ext: ipOption.Ext,
			},
		}
		var isDailErr bool
		if ipOption.FingerPrint {
			openIpPort.Service, openIpPort.Banner, isDailErr = fingerprint.PortIdentify("tcp", ip, dst, time.Duration(ts.option.Timeout)*time.Millisecond)
			if isDailErr {
				return
			}
		}
		if ipOption.Httpx && (openIpPort.Service == "" || openIpPort.Service == "http" || openIpPort.Service == "https") {
			openIpPort.HttpInfo, openIpPort.Banner, isDailErr = fingerprint.ProbeHttpInfo(ip.String(), dst, openIpPort.Service, time.Duration(ts.option.Timeout)*time.Millisecond)
			if isDailErr {
				return
			}
			if openIpPort.HttpInfo != nil {
				if strings.HasPrefix(openIpPort.HttpInfo.Url, "https") {
					openIpPort.Service = "https"
				} else {
					openIpPort.Service = "http"
				}
			}
		}
		if !ipOption.FingerPrint && !ipOption.Httpx {
			conn, _ := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(dst))), ts.timeout)
			if conn != nil {
				conn.Close()
			} else {
				return
			}
		}
		ts.retChan <- openIpPort
	}()
	return nil
}

func (ts *TcpScanner) Wait() {
	ts.wg.Wait()
}

// Close chan
func (ts *TcpScanner) Close() {
	ts.isDone = true
	close(ts.retChan)
}

// WaitLimiter Waiting for the speed limit
func (ts *TcpScanner) WaitLimiter() error {
	return ts.limiter.Wait(ts.ctx)
}
