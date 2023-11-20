package fingerprint

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/XinRoom/go-portScan/core/port"
	"github.com/XinRoom/go-portScan/core/port/fingerprint/webfinger"
	"github.com/XinRoom/go-portScan/util"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed webfinger/finger.json
var fD []byte

var httpsTopPort = []uint16{443, 4443, 1443, 8443}

var httpClient *http.Client

func ProbeHttpInfo(ip net.IP, _port uint16, dialTimeout time.Duration) (httpInfo *port.HttpInfo, isDailErr bool) {

	if httpClient == nil {
		httpClient = newHttpClient(dialTimeout)
	}

	var err error
	var rewriteUrl string
	var body []byte
	var resp *http.Response
	var schemes []string

	if util.IsUint16InList(_port, httpsTopPort) {
		schemes = []string{"https", "http"}
	} else {
		schemes = []string{"http", "https"}
	}

	for _, scheme := range schemes {
		var rewriteNum int
		url2 := fmt.Sprintf("%s://%s:%d/", scheme, ip.String(), _port)
	goReq:
		resp, body, err = getReq(url2)
		if err != nil {
			if strings.HasSuffix(err.Error(), ioTimeoutStr) || strings.Contains(err.Error(), refusedStr) {
				return nil, true
			}
			continue
		}
		if resp != nil {
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
			if location != "" && rewriteNum < 3 {
				if !strings.HasPrefix(location, "http") {
					location = resp.Request.URL.String() + location
				}
				url2 = location
				rewriteNum++
				goto goReq
			}
			//
			httpInfo = new(port.HttpInfo)
			httpInfo.Url = resp.Request.URL.String()
			httpInfo.StatusCode = resp.StatusCode
			httpInfo.ContentLen = int(resp.ContentLength)
			httpInfo.Location = rewriteUrl
			httpInfo.Server = resp.Header.Get("Server")
			httpInfo.Title = ExtractTitle(body)
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				httpInfo.TlsCN = resp.TLS.PeerCertificates[0].Subject.CommonName
				httpInfo.TlsDNS = resp.TLS.PeerCertificates[0].DNSNames
			}
			// finger
			err = webfinger.ParseWebFingerData(fD)
			if err == nil {
				resp.Body = io.NopCloser(bytes.NewReader(body))
				httpInfo.Fingers = webfinger.WebFingerIdent(resp)
				// favicon
				fau := webfinger.FindFaviconUrl(string(body))
				if fau != "" {
					if !strings.HasPrefix(fau, "http") {
						fau = resp.Request.URL.String() + fau
					}
					_, body2, err2 := getReq(fau)
					if err2 == nil && len(body2) != 0 {
						httpInfo.Fingers = append(httpInfo.Fingers, webfinger.WebFingerIdentByFavicon(body2)...)
					}
				}
			}
			if resp.StatusCode != 400 {
				break
			}
		}
	}

	return httpInfo, false
}

func getReq(url2 string) (resp *http.Response, body []byte, err error) {
	req, err := http.NewRequest(http.MethodGet, url2, http.NoBody)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Close = true // disable keepalive
	resp, err = httpClient.Do(req)
	if err != nil {
		return
	}
	if resp.Body != http.NoBody && resp.Body != nil {
		body, _ = getBody(resp)
		if contentTypes, _ := resp.Header["Content-Type"]; len(contentTypes) > 0 {
			if strings.Contains(contentTypes[0], "text") {
				_body, err2 := DecodeData(body, resp.Header)
				if err2 == nil {
					body = _body
				}
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}
	return
}
