//go:build !nosyn

package syn

import (
	"net"
	"sync"
	"time"
)

type watchMacCache struct {
	LastTime time.Time
	Mac      net.HardwareAddr
}

// Mac缓存和监听表
type watchMacCacheTable struct {
	watchMacC map[string]*watchMacCache
	lock      sync.RWMutex
	isDone    bool
}

func newWatchMacCacheTable() (w *watchMacCacheTable) {
	w = &watchMacCacheTable{
		watchMacC: make(map[string]*watchMacCache),
	}
	go w.cleanTimeout()
	return
}

// UpdateLastTime 新建或者更新LastTime
func (w *watchMacCacheTable) UpdateLastTime(ip string) {
	lastTime := time.Now()
	w.lock.Lock()
	wi, ok := w.watchMacC[ip]
	if ok {
		wi.LastTime = lastTime
	} else {
		w.watchMacC[ip] = &watchMacCache{LastTime: lastTime}
	}
	w.lock.Unlock()
}

// SetMac 设置Mac地址
func (w *watchMacCacheTable) SetMac(ip string, mac net.HardwareAddr) {
	lastTime := time.Now()
	w.lock.Lock()
	wi, ok := w.watchMacC[ip]
	if ok {
		wi.LastTime = lastTime
		wi.Mac = mac
	} else {
		w.watchMacC[ip] = &watchMacCache{LastTime: lastTime, Mac: mac}
		wi.Mac = mac
	}
	w.lock.Unlock()
}

// GetMac 获取Mac地址缓存
func (w *watchMacCacheTable) GetMac(ip string) (mac net.HardwareAddr) {
	w.lock.RLock()
	wi, ok := w.watchMacC[ip]
	if ok {
		mac = wi.Mac
	}
	w.lock.RUnlock()
	return
}

// IsNeedWatch 判断是否需要监视
func (w *watchMacCacheTable) IsNeedWatch(ip string) (has bool) {
	w.lock.RLock()
	wm, ok := w.watchMacC[ip]
	has = ok && wm.Mac == nil
	w.lock.RUnlock()
	return
}

// IsEmpty 判断目前表是否为空
func (w *watchMacCacheTable) IsEmpty() (empty bool) {
	w.lock.RLock()
	empty = len(w.watchMacC) == 0
	w.lock.RUnlock()
	return
}

func (w *watchMacCacheTable) Close() {
	w.isDone = true
}

// 清理过期数据
func (w *watchMacCacheTable) cleanTimeout() {
	var needDel map[string]struct{}
	for {
		needDel = make(map[string]struct{})
		if w.isDone {
			break
		}
		time.Sleep(2 * time.Second)
		w.lock.RLock()
		for k, v := range w.watchMacC {
			if time.Since(v.LastTime) > 10*time.Second {
				needDel[k] = struct{}{}
			}
		}
		w.lock.RUnlock()
		if len(needDel) > 0 {
			for k := range needDel {
				w.lock.Lock()
				delete(w.watchMacC, k)
				w.lock.Unlock()
			}
		}
	}
}
