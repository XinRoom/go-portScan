package fingerprint

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Action uint8

const (
	ActionRecv = Action(iota)
	ActionSend
)

//
type ruleData struct {
	Action  Action // send or recv
	Data    []byte // send or match data
	Regexps []*regexp.Regexp
}

type serviceRule struct {
	Tls       bool
	DataGroup []ruleData
}

var serviceRules = make(map[string]serviceRule)
var readBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

// PortIdentify 端口识别
func PortIdentify(network string, ip net.IP, _port uint16) string {

	matchedRule := make(map[string]struct{})

	unknown := "unknown"
	var matchStatus int

	// 优先判断port可能的服务
	if serviceNames, ok := portServiceOrder[_port]; ok {
		for _, service := range serviceNames {
			matchedRule[service] = struct{}{}
			matchStatus = matchRule(network, ip, _port, serviceRules[service])
			if matchStatus == 1 {
				return service
			} else if matchStatus == -1 {
				return unknown
			}
		}
	}

	// onlyRecv
	{
		var conn net.Conn
		var err error
		var n int
		buf := readBufPool.Get().([]byte)
		defer func() {
			readBufPool.Put(buf)
		}()
		address := fmt.Sprintf("%s:%d", ip, _port)
		for _, service := range onlyRecv {
			_, ok := matchedRule[service]
			if ok {
				continue
			}
			if conn == nil {
				conn, err = net.DialTimeout(network, address, time.Second*2)
				if err != nil {
					if strings.HasSuffix(err.Error(), "i/o timeout") {
						return unknown
					}
					continue
				}
				n, err = read(conn, buf)
				conn.Close()
				// read出错就退出
				if err != nil {
					if strings.HasSuffix(err.Error(), "i/o timeout") {
						break
					}
					continue
				}
			}

			matchStatus = matchRuleWhithBuf(buf[:n], ip, _port, serviceRules[service])
			if matchStatus == 1 {
				return service
			}
		}
		for _, service := range onlyRecv {
			matchedRule[service] = struct{}{}
		}
	}

	// 优先判断Top服务
	for _, service := range serviceOrder {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		matchedRule[service] = struct{}{}
		matchStatus = matchRule(network, ip, _port, serviceRules[service])
		if matchStatus == 1 {
			return service
		} else if matchStatus == -1 {
			return unknown
		}
	}

	// other
	for service, rule := range serviceRules {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		matchStatus = matchRule(network, ip, _port, rule)
		if matchStatus == 1 {
			return service
		} else if matchStatus == -1 {
			return unknown
		}
	}

	return unknown
}

// 指纹匹配函数
func matchRuleWhithBuf(buf, ip net.IP, _port uint16, serviceRule serviceRule) int {
	data := []byte("")
	// 逐个判断
	for _, rule := range serviceRule.DataGroup {
		if rule.Data != nil {
			data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
			data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
		}
		// 包含数据就正确
		if rule.Regexps != nil {
			for _, _regex := range rule.Regexps {
				if _regex.Match(buf) {
					return 1
				}
			}
		}
		if bytes.Compare(data, []byte("")) != 0 && bytes.Contains(buf, data) {
			return 1
		}
	}
	return 0
}

// 指纹匹配函数
func matchRule(network string, ip net.IP, _port uint16, serviceRule serviceRule) int {
	var err error
	var isTls bool
	var conn net.Conn
	var connTls *tls.Conn

	address := fmt.Sprintf("%s:%d", ip, _port)

	// 建立连接
	if serviceRule.Tls {
		// tls
		connTls, err = tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, network, address, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			if strings.HasSuffix(err.Error(), "i/o timeout") {
				return -1
			}
			return 0
		}
		defer connTls.Close()
		isTls = true
	} else {
		conn, err = net.DialTimeout(network, address, time.Second*2)
		if err != nil {
			if strings.HasSuffix(err.Error(), "i/o timeout") {
				return -1
			}
			return 0
		}
		defer conn.Close()
	}

	buf := readBufPool.Get().([]byte)
	defer func() {
		readBufPool.Put(buf)
	}()

	data := []byte("")
	// 逐个判断
	for _, rule := range serviceRule.DataGroup {
		if rule.Data != nil {
			data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
			data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
		}

		if rule.Action == ActionSend {
			if isTls {
				connTls.SetWriteDeadline(time.Now().Add(time.Second))
				_, err = connTls.Write(data)
			} else {
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				_, err = conn.Write(data)
			}
			if err != nil {
				// 出错就退出
				if strings.HasSuffix(err.Error(), "i/o timeout") {
					return -1
				}
				return 0
			}
		} else {
			var n int
			if isTls {
				n, err = read(connTls, buf)
			} else {
				n, err = read(conn, buf)
			}
			// 出错就退出
			if err != nil || n == 0 {
				return 0
			}
			// 包含数据就正确
			if rule.Regexps != nil {
				for _, _regex := range rule.Regexps {
					if _regex.Match(buf[:n]) {
						return 1
					}
				}
			}
			if bytes.Compare(data, []byte("")) != 0 && bytes.Contains(buf[:n], data) {
				return 1
			}
		}
	}

	return 0
}

func read(conn interface{}, buf []byte) (int, error) {
	switch conn.(type) {
	case net.Conn:
		conn.(net.Conn).SetReadDeadline(time.Now().Add(time.Second))
		return conn.(net.Conn).Read(buf[:])
	case *tls.Conn:
		conn.(*tls.Conn).SetReadDeadline(time.Now().Add(time.Second))
		return conn.(*tls.Conn).Read(buf[:])
	}
	return 0, errors.New("unknown type")
}
