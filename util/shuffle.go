package util

import (
	"math/rand"
)

type Shuffle struct {
	rl   []uint16 // 乱序序列
	rl2  []uint16 // 最后一轮乱序序列(无法整除时使用)
	n    uint16   // 乱序精度
	size uint64
}

// NewShuffle 局部乱序
func NewShuffle(size uint64) *Shuffle {
	if size == 0 {
		return nil
	}
	sf := &Shuffle{size: size}
	if size > 100 {
		sf.n = 100
	} else {
		sf.n = uint16(size)
	}
	// 通用轮次
	sf.rl = make([]uint16, sf.n)
	for i := uint16(0); i < sf.n; i++ {
		sf.rl[i] = i
	}
	// 洗牌方法
	r := rand.New(rand.NewSource(int64(size)))
	r.Shuffle(int(sf.n), func(i, j int) {
		sf.rl[i], sf.rl[j] = sf.rl[j], sf.rl[i]
	})
	// 最后一轮无法整除时新建对应长度的rl2
	t := uint16(size % uint64(sf.n))
	if t != 0 {
		sf.rl2 = make([]uint16, t)
		for i := uint16(0); i < t; i++ {
			sf.rl2[i] = i
		}
		r.Shuffle(int(t), func(i, j int) {
			sf.rl2[i], sf.rl2[j] = sf.rl2[j], sf.rl2[i]
		})
	}
	return sf
}

// Get 根据索引获取转换后的索引值
func (sf *Shuffle) Get(index uint64) uint64 {
	t := index % uint64(sf.n)
	// 最后一轮无法整除时用rl2
	if index-t+uint64(sf.n) > sf.size {
		return index - t + uint64(sf.rl2[uint16(t)])
	}
	return index - t + uint64(sf.rl[uint16(t)])
}

func IsUint16InList(code uint16, list []uint16) bool {
	for _, e := range list {
		if e == code {
			return true
		}
	}
	return false
}
