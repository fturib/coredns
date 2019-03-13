package throttle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

type sleepPlugin struct{}

func (s sleepPlugin) Name() string { return "sleep" }

func (s sleepPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)

	time.Sleep(10 * time.Millisecond)
	m.Rcode = dns.RcodeRefused
	w.WriteMsg(m)
	return 0, nil
}

func TestThrottle(t *testing.T) {

	tests := []struct {
		maxInflight int
		tries       int
		dropped     int
	}{
		{0, 10, 10},
		{1, 1, 0},
		{1, 2, 1},
		{10, 20, 10},
		{10, 9, 0},
	}

	for n, tst := range tests {

		th := Throttle{Next: sleepPlugin{}, workerLimit: int64(tst.maxInflight)}
		var written int32
		var dropped int32

		for i := 0; i < tst.tries; i++ {
			go func() {
				ctx := context.Background()
				w := dnstest.NewRecorder(&test.ResponseWriter{})
				m := new(dns.Msg)
				m.SetQuestion("aaa.example.com.", dns.TypeTXT)
				th.ServeDNS(ctx, w, m)
				if w.Msg == nil {
					atomic.AddInt32(&dropped, 1)
					return
				}
				atomic.AddInt32(&written, 1)
			}()
		}

		i := 0
		for {
			if atomic.LoadInt32(&written)+atomic.LoadInt32(&dropped) == int32(tst.tries) {
				break
			}

			if i > 5 {
				t.Fatalf("Test %d - Looped %d times 10ms, expected %d msg to be processed, got %d written and %d dropped", n, i, tst.tries, written, dropped)
			}
			// wait it is finished
			time.Sleep(10 * time.Millisecond)
			i++
		}

		if written > int32(th.workerLimit) {
			t.Errorf("Test %d - expected only %d msg to be written, got %d", n, th.workerLimit, written)
		}
		if dropped != int32(tst.dropped) {
			t.Errorf("Test %d - expected %d msg droppes, got %d", n, tst.dropped, dropped)
		}
	}
}
