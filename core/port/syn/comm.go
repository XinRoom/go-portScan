package syn

import (
	"errors"
	"github.com/XinRoom/go-portScan/core/port"
)

var ErrorNoSyn = errors.New("no syn support")

var DefaultSynOption = port.Option{
	Rate:    1500,
	Timeout: 800,
}
