package syn

import (
	"sync"
	"time"
)

type watchIpStatus struct {
	ReceivedPort map[uint16]struct{}
	LastTime     time.Time
}

// IP状态更新表
type watchIpStatusTable struct {
	watchIpS map[string]*watchIpStatus
	lock     sync.RWMutex
	isDone   bool
}

func newWatchIpStatusTable() (w *watchIpStatusTable) {
	w = &watchIpStatusTable{
		watchIpS: make(map[string]*watchIpStatus),
	}
	go w.cleanTimeout()
	return
}

// UpdateLastTime 新建或者更新LastTime
func (w *watchIpStatusTable) UpdateLastTime(ip string) {
	lastTime := time.Now()
	w.lock.Lock()
	wi, ok := w.watchIpS[ip]
	if ok {
		wi.LastTime = lastTime
	} else {
		w.watchIpS[ip] = &watchIpStatus{LastTime: lastTime, ReceivedPort: make(map[uint16]struct{})}
	}
	w.lock.Unlock()
}

// RecordPort 记录收到的端口
func (w *watchIpStatusTable) RecordPort(ip string, port uint16) {
	lastTime := time.Now()
	w.lock.Lock()
	wi, ok := w.watchIpS[ip]
	if ok {
		wi.LastTime = lastTime
		wi.ReceivedPort[port] = struct{}{}
	} else {
		w.watchIpS[ip] = &watchIpStatus{LastTime: lastTime, ReceivedPort: make(map[uint16]struct{})}
		w.watchIpS[ip].ReceivedPort[port] = struct{}{}
	}
	w.lock.Unlock()
}

// HasPort 判断是否检测过对应端口
func (w *watchIpStatusTable) HasPort(ip string, port uint16) (has bool) {
	w.lock.RLock()
	wi, ok := w.watchIpS[ip]
	if ok {
		_, has = wi.ReceivedPort[port]
	}
	w.lock.RUnlock()
	return
}

// HasIp 判断是否在监视对应IP
func (w *watchIpStatusTable) HasIp(ip string) (has bool) {
	w.lock.RLock()
	_, has = w.watchIpS[ip]
	w.lock.RUnlock()
	return
}

// IsEmpty 判断目前表是否为空
func (w *watchIpStatusTable) IsEmpty() (empty bool) {
	w.lock.RLock()
	if len(w.watchIpS) == 0 {
		empty = true
	}
	w.lock.RUnlock()
	return
}

func (w *watchIpStatusTable) Close() {
	w.isDone = true
}

// 清理过期数据
func (w *watchIpStatusTable) cleanTimeout() {
	for {
		if w.isDone {
			break
		}
		time.Sleep(3 * time.Second)
		w.lock.RLock()
		for k, v := range w.watchIpS {
			if time.Since(v.LastTime) > 5*time.Second {
				w.lock.Lock()
				delete(w.watchIpS, k)
				w.lock.Unlock()
			}
		}
		w.lock.RUnlock()
	}
}
