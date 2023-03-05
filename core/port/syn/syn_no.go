//go:build nosyn

package syn

import (
	"github.com/XinRoom/go-portScan/core/port"
	"net"
)

type synScanner struct {
}

// NewSynScanner firstIp: Used to select routes; openPortChan: Result return channel
func NewSynScanner(firstIp net.IP, retChan chan port.OpenIpPort, option port.Option) (ss *synScanner, err error) {
	return nil, ErrorNoSyn
}

func (ss *synScanner) Scan(dstIp net.IP, dst uint16) error {
	return nil
}
func (ss *synScanner) WaitLimiter() error {
	return nil
}
func (ss *synScanner) Wait()  {}
func (ss *synScanner) Close() {}

func GetAllDevs() (string, error) {
	return "", ErrorNoSyn
}
