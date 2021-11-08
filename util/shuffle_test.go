package util

import (
	"testing"
)

func TestShuffle_Next(t *testing.T) {
	size := 10001
	sf := NewShuffle(uint64(size))
	ret := make([]uint64, size)
	for i := 0; i < size; i++ {
		ret[i] = sf.Get(uint64(i))
	}
	if ret[size-1] != uint64(size-1) {
		t.Error(ret)
	}
}
