package fingerprint

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
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

// PortIdentify 端口识别
func PortIdentify(network string, ip net.IP, _port uint16) string {

	matchedRule := make(map[string]struct{})

	// 优先判断port可能的服务
	if serviceNames, ok := portServiceOrder[_port]; ok {
		for _, serviceName := range serviceNames {
			matchedRule[serviceName] = struct{}{}
			if matchRule(network, ip, _port, serviceRules[serviceName]) {
				return serviceName
			}
		}
	}

	// 优先判断Top服务
	for _, service := range serviceOrder {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		matchedRule[service] = struct{}{}
		if matchRule(network, ip, _port, serviceRules[service]) {
			return service
		}
	}

	// other
	for service, rule := range serviceRules {
		_, ok := matchedRule[service]
		if ok {
			continue
		}
		if matchRule(network, ip, _port, rule) {
			return service
		}
	}

	return "unknown"
}

// 匹配规则
func matchRule(network string, ip net.IP, _port uint16, serviceRule serviceRule) bool {
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
		if err != nil || connTls == nil {
			return false
		}
		defer connTls.Close()
		isTls = true
	} else {
		conn, err = net.DialTimeout(network, address, time.Second*2)
		if err != nil || conn == nil {
			return false
		}
		defer conn.Close()
	}

	buf := make([]byte, 4096)

	// 读函数
	read := func() (int, error) {
		if isTls {
			connTls.SetReadDeadline(time.Now().Add(time.Second))
			return connTls.Read(buf[:])
		} else {
			conn.SetReadDeadline(time.Now().Add(time.Second))
			return conn.Read(buf[:])
		}
	}

	data := []byte("")
	// 逐个判断
	for _, rule := range serviceRule.DataGroup {
		if rule.Data != nil {
			data = rule.Data
		}
		data = bytes.Replace(rule.Data, []byte("{IP}"), []byte(ip.String()), -1)
		data = bytes.Replace(data, []byte("{PORT}"), []byte(strconv.Itoa(int(_port))), -1)
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
				return false
			}
		} else {
			var n int
			n, err = read()
			// 出错就退出
			if err != nil || n == 0 {
				return false
			}
			// 包含数据就正确
			if rule.Regexps != nil {
				for _, _regex := range rule.Regexps {
					if _regex.Match(buf[:n]) {
						return true
					}
				}
			}
			if bytes.Compare(data, []byte("")) != 0 && bytes.Contains(buf[:n], data) {
				return true
			}
		}
	}

	return false
}
