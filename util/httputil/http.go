package httputil

import (
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

var ErrOverflow = errors.New("OverflowMax")

var DefHttpClient *http.Client

func NewHttpClient(dialTimeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
		DialContext: (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       100 * time.Millisecond,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		Proxy:                 http.ProxyFromEnvironment,
	}

	// proxy
	//if options.ProxyUrl != "" {
	//	proxyUrl, err := url.Parse(options.ProxyUrl)
	//	if err != nil {
	//		log.Fatalln(err)
	//	}
	//	transport.Proxy = http.ProxyURL(proxyUrl)
	//}

	return &http.Client{
		Timeout:   3 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// GetBody 识别响应Body的编码，读取body数据
func GetBody(resp *http.Response) (body []byte, err error) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	var reader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
	case "deflate":
		reader = flate.NewReader(resp.Body)
	//case "br":
	//	reader = brotli.NewReader(resp.Body)
	default:
		reader = resp.Body
	}
	if err == nil {
		body, err = readMaxSize(reader, 300*1024) // Max Size 300kb
	}
	return
}

// readMaxSize 读取io数据，限制最大读取尺寸
func readMaxSize(r io.Reader, maxsize int) ([]byte, error) {
	b := make([]byte, 0, 512)
	for {
		if len(b) >= maxsize {
			return b, ErrOverflow
		}
		if len(b) == cap(b) {
			// Add more capacity (let append pick how much).
			b = append(b, 0)[:len(b)]
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}
	}
}
