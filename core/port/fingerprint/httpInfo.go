package fingerprint

import (
	"fmt"
	"github.com/XinRoom/go-portScan/util"
	"net"
	"net/http"
	"strings"
)

// HttpInfo Http服务基础信息
type HttpInfo struct {
	StatusCode int      // 状态码
	ContentLen int      // 相应包大小
	Url        string   // Url
	Location   string   // 302、301重定向路径
	Title      string   // 标题
	TlsCN      string   // tls使用者名称
	TlsDNS     []string // tlsDNS列表
}

var httpsTopPort = []uint16{443, 4443, 1443, 8443}

var httpClient *http.Client

func (hi *HttpInfo) String() string {
	if hi == nil {
		return ""
	}
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("Url:%s StatusCode:%d ContentLen:%d Title:%s ", hi.Url, hi.StatusCode, hi.ContentLen, hi.Title))
	if hi.Location != "" {
		buf.WriteString("Location:" + hi.Location + " ")
	}
	if hi.TlsCN != "" {
		buf.WriteString("TlsCN:" + hi.TlsCN + " ")
	}
	if len(hi.TlsDNS) > 0 {
		buf.WriteString("TlsDNS:" + strings.Join(hi.TlsDNS, ",") + " ")
	}
	return buf.String()
}

func ProbeHttpInfo(ip net.IP, _port uint16) *HttpInfo {

	if httpClient == nil {
		httpClient = newHttpClient()
	}

	var err error
	var rewriteUrl string
	var body []byte
	var _body []byte
	var resp *http.Response
	var schemes []string
	var httpInfo *HttpInfo

	if util.IsUint16InList(_port, httpsTopPort) {
		schemes = []string{"https", "http"}
	} else {
		schemes = []string{"http", "https"}
	}

	for _, scheme := range schemes {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://%s:%d/", scheme, ip.String(), _port), http.NoBody)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		req.Close = true // disable keepalive
		resp, err = httpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.Body != http.NoBody && resp.Body != nil {
			body, _ = getBody(resp)
			_body, err = DecodeData(body, resp.Header)
			if err == nil {
				body = _body
			}
			if resp.ContentLength == -1 {
				resp.ContentLength = int64(len(body))
			}
			rewriteUrl2, _ := resp.Location()
			if rewriteUrl2 != nil {
				rewriteUrl = rewriteUrl2.String()
			} else {
				rewriteUrl = ""
			}
			location := GetLocation(body)
			if rewriteUrl == "" && location != "" {
				rewriteUrl = location
			}
			//
			httpInfo = new(HttpInfo)
			httpInfo.Url = resp.Request.URL.String()
			httpInfo.StatusCode = resp.StatusCode
			httpInfo.ContentLen = int(resp.ContentLength)
			httpInfo.Location = rewriteUrl
			httpInfo.Title = ExtractTitle(body)
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				httpInfo.TlsCN = resp.TLS.PeerCertificates[0].Subject.CommonName
				httpInfo.TlsDNS = resp.TLS.PeerCertificates[0].DNSNames
			}
			break
		}
	}

	return httpInfo
}
