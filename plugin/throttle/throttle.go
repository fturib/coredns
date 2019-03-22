package throttle

import (
	"context"
	"sync/atomic"

	"github.com/coredns/coredns/plugin/metrics"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// Throttle holds the count of queries currently in process and the upper limit expected
type Throttle struct {
	workerCount int64
	workerLimit int64
	Next        plugin.Handler
}

// ServeDNS implements the plugin.Handler interface.
func (t *Throttle) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	count := atomic.AddInt64(&(t.workerCount), 1)
	defer atomic.AddInt64(&(t.workerCount), -1)

	server := metrics.WithServer(ctx)
	throttleCount.WithLabelValues(server, incoming).Inc()
	flightCount.WithLabelValues(server).Set(float64(count))

	// just drop the queries when current inflight bucket is full
	if count > t.workerLimit {
		w.Close()
		// just return success w/o writing in the writer -> it is a drop
		// it is in purpose to not return a response as it would keep the goroutine alive the time of writing
		throttleCount.WithLabelValues(server, dropped).Inc()
		return dns.RcodeSuccess, nil
	}

	code, err := plugin.NextOrFailure(t.Name(), t.Next, ctx, w, r)
	throttleCount.WithLabelValues(server, served).Inc()
	return code, err
}

// Name implements the Handler interface.
func (t *Throttle) Name() string { return throttle }

var (
	throttleCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "throttle",
		Name:      "seen_queries",
		Help:      "Total queries seen by throttle mechanism.",
	}, []string{"server", "type"})
	flightCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: "throttle",
		Name:      "inflight_queries",
		Help:      "The number of simultaneous queries inside throttle mechanism.",
	}, []string{"server"})
)

const (
	incoming = "incoming"
	served   = "served"
	dropped  = "dropped"
)
