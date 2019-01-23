package rewrite

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// ResponseRule contains a rule to rewrite a response with.
type ResponseRule struct {
	Active      bool
	Type        string
	Pattern     *regexp.Regexp
	Replacement string
	Ttl         uint32
}

// ResponseReverter reverses the operations done on the question section of a packet.
// This is need because the client will otherwise disregards the response, i.e.
// dig will complain with ';; Question section mismatch: got example.org/HINFO/IN'
type ResponseReverter struct {
	dns.ResponseWriter
	receivedRequest *dns.Msg
	sharedRequest   *dns.Msg
	ResponseRewrite bool
	ResponseRules   []ResponseRule
}

func removeOPT(m *dns.Msg) {
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == dns.TypeOPT {
			copy(m.Extra[i:], m.Extra[i+1:])
			m.Extra[len(m.Extra)-1] = nil
			m.Extra = m.Extra[:len(m.Extra)-1]
			return
		}
	}
}

// replaceOPTHeader set the OPT Header with the one provided.
func replaceOPTHeader(m *dns.Msg, hdr *dns.RR_Header) {
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == dns.TypeOPT {
			m.Extra[i].(*dns.OPT).Hdr = *hdr
			return
		}
	}
	opt := dns.OPT{*hdr, make([]dns.EDNS0, 0)}
	m.Extra = append(m.Extra, &opt)
}

// NewResponseReverter returns a pointer to a new ResponseReverter.
func NewResponseReverter(w dns.ResponseWriter, r *dns.Msg) *ResponseReverter {
	rr := &ResponseReverter{
		ResponseWriter:  w,
		receivedRequest: r.Copy(),
		sharedRequest:   r,
	}
	return rr
}

// WriteMsg records the status code and calls the underlying ResponseWriter's WriteMsg method.
func (r *ResponseReverter) WriteMsg(resp *dns.Msg) error {
	receivedOpt := r.receivedRequest.IsEdns0()
	if receivedOpt != nil {
		replaceOPTHeader(r.sharedRequest, receivedOpt.Header())
	} else {
		removeOPT(r.sharedRequest)
		removeOPT(resp)
	}

	resp.Question[0] = r.receivedRequest.Question[0]

	if r.ResponseRewrite {

		// revert some rewritten fields and ONLY for the Active rules.
		for _, rr := range resp.Answer {
			var isNameRewritten bool = false
			var isTtlRewritten bool = false
			var name string = rr.Header().Name
			var ttl uint32 = rr.Header().Ttl
			for _, rule := range r.ResponseRules {
				if rule.Type == "" {
					rule.Type = "name"
				}
				switch rule.Type {
				case "name":
					regexGroups := rule.Pattern.FindStringSubmatch(name)
					if len(regexGroups) == 0 {
						continue
					}
					s := rule.Replacement
					for groupIndex, groupValue := range regexGroups {
						groupIndexStr := "{" + strconv.Itoa(groupIndex) + "}"
						if strings.Contains(s, groupIndexStr) {
							s = strings.Replace(s, groupIndexStr, groupValue, -1)
						}
					}
					name = s
					isNameRewritten = true
				case "ttl":
					ttl = rule.Ttl
					isTtlRewritten = true
				}
			}
			if isNameRewritten == true {
				rr.Header().Name = name
			}
			if isTtlRewritten == true {
				rr.Header().Ttl = ttl
			}
		}
	}
	return r.ResponseWriter.WriteMsg(resp)
}

// Write is a wrapper that records the size of the message that gets written.
func (r *ResponseReverter) Write(buf []byte) (int, error) {
	n, err := r.ResponseWriter.Write(buf)
	return n, err
}
