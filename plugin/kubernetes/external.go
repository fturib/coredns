package kubernetes

import (
	"strings"

	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/kubernetes/object"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// External implements the ExternalFunc call from the external plugin.
// It returns any services matching in the services' ExternalIPs.
func (k *Kubernetes) External(state request.Request) ([]msg.Service, int) {
	base, _ := dnsutil.TrimZone(state.Name(), state.Zone)

	segs := dns.SplitDomainName(base)
	last := len(segs) - 1
	if last < 0 {
		// this is a request for the zone itself. Return all services that are in exposed namespaces
		if state.Name() == state.Zone {
			return k.externalAll(state)
		}
		return nil, dns.RcodeServerFailure
	}
	// We dealing with a fairly normal domain name here, but; we still need to have the service
	// and the namespace:
	// service.namespace.<base>
	//
	// for service (and SRV) you can also say _tcp, and port (i.e. _http), we need those be picked
	// up, unless they are not specified, then we use an internal wildcard.
	port := "*"
	protocol := "*"
	namespace := segs[last]
	if !k.namespaceExposed(namespace) || !k.namespace(namespace) {
		return nil, dns.RcodeNameError
	}

	last--
	if last < 0 {
		return nil, dns.RcodeSuccess
	}

	service := segs[last]
	last--
	if last == 1 {
		protocol = stripUnderscore(segs[last])
		port = stripUnderscore(segs[last-1])
		last -= 2
	}

	if last != -1 {
		// too long
		return nil, dns.RcodeNameError
	}

	idx := object.ServiceKey(service, namespace)
	serviceList := k.APIConn.SvcIndex(idx)

	services := []msg.Service{}
	zonePath := msg.Path(state.Zone, coredns)
	rcode := dns.RcodeNameError

	for _, svc := range serviceList {
		if namespace != svc.Namespace {
			continue
		}
		if service != svc.Name {
			continue
		}

		services = append(services, svcToMsg(svc, zonePath, port, protocol, k.ttl)...)
	}
	if len(services) > 0 {
		rcode = dns.RcodeSuccess
	}
	return services, rcode
}

func (k *Kubernetes) externalAll(state request.Request) ([]msg.Service, int) {

	serviceList := k.APIConn.ServiceList()

	services := []msg.Service{}
	zonePath := msg.Path(state.Zone, coredns)
	rcode := dns.RcodeNameError

	for _, svc := range serviceList {
		if !k.namespaceExposed(svc.Namespace) {
			continue
		}

		services = append(services, svcToMsg(svc, zonePath, "*", "*", k.ttl)...)
	}
	if len(services) > 0 {
		rcode = dns.RcodeSuccess
	}
	return services, rcode
}

func svcToMsg(svc *object.Service, zonePath string, port string, protocol string, ttl uint32) []msg.Service {
	services := []msg.Service{}
	for _, ip := range svc.ExternalIPs {
		for _, p := range svc.Ports {
			if !(match(port, p.Name) && match(protocol, string(p.Protocol))) {
				continue
			}
			s := msg.Service{Host: ip, Port: int(p.Port), TTL: ttl}
			s.Key = strings.Join([]string{zonePath, svc.Namespace, svc.Name}, "/")

			services = append(services, s)
		}
	}
	return services
}

// ExternalAddress returns the external service address(es) for the CoreDNS service.
func (k *Kubernetes) ExternalAddress(state request.Request) []dns.RR {
	// This is probably wrong, because of all the fallback behavior of k.nsAddr, i.e. can get
	// an address that isn't reacheable from outside the cluster.
	rrs := []dns.RR{k.nsAddr()}
	return rrs
}
