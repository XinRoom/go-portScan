package fingerprint

import (
	"testing"
	"time"
)

func TestName(t *testing.T) {
	t.Log(ProbeHttpInfo("www.baidu.com", 443, 5*time.Second))
}
