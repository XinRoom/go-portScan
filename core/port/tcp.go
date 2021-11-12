package port

import (
	"context"
	"errors"
	"fmt"
	limiter "golang.org/x/time/rate"
	"net"
	"time"
)

var DefaultTcpOption = Option{
	Rate:    2000,
	Timeout: 800,
}

type tcpScanner struct {
	ports   []uint16        // 指定端口
	retChan chan OpenIpPort // 返回值队列
	limiter *limiter.Limiter
	ctx     context.Context
	timeout time.Duration
	isDone  bool
}

// NewTcpScanner Tcp扫描器
func NewTcpScanner(retChan chan OpenIpPort, option Option) (ts *tcpScanner, err error) {
	// option verify
	if option.Rate <= 0 {
		err = errors.New("rate can not set to 0")
		return
	}
	if option.Timeout <= 0 {
		err = errors.New("timeout can not set to 0")
		return
	}

	ts = &tcpScanner{
		retChan: retChan,
		limiter: limiter.NewLimiter(limiter.Every(time.Second/time.Duration(option.Rate)), 10),
		ctx:     context.Background(),
		timeout: time.Duration(option.Timeout) * time.Millisecond,
	}

	return
}

// Scan 对指定IP和dis port进行扫描
func (ts *tcpScanner) Scan(ip net.IP, dst uint16) error {
	if ts.isDone {
		return errors.New("scanner is closed")
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, dst), ts.timeout)
	if err == nil && conn != nil {
		ts.retChan <- OpenIpPort{
			Ip:   ip,
			Port: dst,
		}
		conn.Close()
	}
	return nil
}

// Close chan
func (ts *tcpScanner) Close() {
	ts.isDone = true
	close(ts.retChan)
}

// WaitLimiter Waiting for the speed limit
func (ts *tcpScanner) WaitLimiter() error {
	return ts.limiter.Wait(ts.ctx)
}
