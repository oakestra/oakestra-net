// Package clock provides a coarse, 1Hz-updated Unix-seconds clock for code on
// the packet path. Recording "last used" on every packet doesn't need
// sub-second precision, and time.Now() is a vDSO call costing more than the
// cache lookup it would be timestamping - so a single ticker goroutine writes
// the timestamp and everyone else just reads it.
package clock

import (
	"sync/atomic"
	"time"
)

var now atomic.Int64

func init() {
	now.Store(time.Now().Unix())
	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			now.Store(time.Now().Unix())
		}
	}()
}

// Unix returns the current time in Unix seconds, accurate to within a second.
func Unix() int64 { return now.Load() }
