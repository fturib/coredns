package test

import (
	"testing"

	"github.com/miekg/dns"
)

// Start test server that has metrics enabled. Then tear it down again.
func TestFirewallWithServeralRules(t *testing.T) {
	corefile := `example.org:0 {
	firewall query {
        refuse [type] == 'AAAA'
        block [name] =~ '.*coredns.*'
        allow true
    }
	firewall response {
        allow [response_ip] =~ '10\..*'
        block true
    }
	# template will return a response
    template IN A  {
      match ^ip-(?P<b>[0-9]*)-.*$
      answer "{{ .Name }} 60 IN A {{ .Group.b }}.{{ .Group.b }}.{{ .Group.b }}.{{ .Group.b }}"
      rcode NOERROR
      fallthrough
    }
    template IN A  {
      answer "{{ .Name }} 60 IN A 172.45.45.10"
      rcode NOERROR
    }
    errors
    log .
}
`

	tests := []struct {
		domain    string
		qtype     uint16
		replyCode int
	}{
		{"www.example.org.", dns.TypeAAAA, dns.RcodeRefused},
		{"www.example.org.", dns.TypeA, dns.RcodeNameError},
		{"coredns.example.org.", dns.TypeA, dns.RcodeNameError},
		{"ip-10-.example.org.", dns.TypeA, dns.RcodeSuccess},
	}

	srv, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer srv.Stop()

	for i, tt := range tests {
		m := new(dns.Msg)
		m.SetQuestion(tt.domain, tt.qtype)

		reply, errmsg := dns.Exchange(m, udp)
		if errmsg != nil {
			t.Errorf("Test %d : domain %s - could not send message: %s", i, tt.domain, errmsg)
			continue
		}

		if reply.MsgHdr.Rcode != tt.replyCode {
			t.Errorf("Test %d : domain %s - expected returned code %s, got %s", i, tt.domain, dns.RcodeToString[tt.replyCode], dns.RcodeToString[reply.MsgHdr.Rcode])
		}

	}

}
