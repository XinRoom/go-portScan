package fingerprint

import (
	"net"
	"testing"
)

func TestName(t *testing.T) {
	t.Log(ProbeHttpInfo(net.ParseIP("14.215.177.39"), 443))
}
