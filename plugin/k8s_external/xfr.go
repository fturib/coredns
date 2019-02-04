package external

import (
	"context"
	"net"
	"time"

	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const transferLength = 2000

// Serial implements the Transferer interface.
func (e *External) Serial(state request.Request) uint32 { return uint32(time.Now().Unix()) }

// MinTTL implements the Transferer interface.
func (e *External) MinTTL(state request.Request) uint32 { return e.ttl }

// Transfer implements the Transferer interface.
func (e *External) Transfer(ctx context.Context, state request.Request) (int, error) {

	if !e.transferAllowed(state) {
		return dns.RcodeRefused, nil
	}

	svc, rcode := e.externalFunc(state)

	m := new(dns.Msg)
	m.SetReply(state.Req)

	if len(svc) == 0 {
		m.Rcode = rcode
		m.Ns = []dns.RR{e.soa(state)}
		state.W.WriteMsg(m)
		return 0, nil
	}

	records := e.axfr(svc, state)

	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)

	soa := []dns.RR{e.soa(state)}
	ns := []dns.RR{e.ns(state)}

	records = append(ns, records...)
	records = append(soa, records...)
	records = append(records, soa...)

	go func(ch chan *dns.Envelope) {
		j, l := 0, 0
		log.Infof("Outgoing transfer of %d records of zone %s to %s started", len(records), state.Zone, state.IP())
		for i, r := range records {
			l += dns.Len(r)
			if l > transferLength {
				ch <- &dns.Envelope{RR: records[j:i]}
				l = 0
				j = i
			}
		}
		if j < len(records) {
			ch <- &dns.Envelope{RR: records[j:]}
		}
		close(ch)
	}(ch)

	tr.Out(state.W, state.Req, ch)
	// Defer closing to the client
	state.W.Hijack()
	return dns.RcodeSuccess, nil
}

// transferAllowed checks if incoming request for transferring the zone is allowed according to the ACLs.
// Note: This is copied from zone.transferAllowed, but should eventually be factored into a common transfer pkg.
func (e *External) transferAllowed(state request.Request) bool {
	for _, t := range e.transferTo {
		if t == "*" {
			return true
		}
		// If remote IP matches we accept.
		remote := state.IP()
		to, _, err := net.SplitHostPort(t)
		if err != nil {
			continue
		}
		if to == remote {
			return true
		}
	}
	return false
}
