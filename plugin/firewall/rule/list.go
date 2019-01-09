package rule

import (
	"context"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin/firewall/policy"
	"github.com/coredns/coredns/request"
)

//Element is a structure that host a definition of policy Rule, and the Rule itself when created
type Element struct {
	Plugin string
	Name   string
	Params []string
	Rule   policy.Rule
}

//List of Rules checked in order of the list
type List struct {
	Reply         bool
	Rules         []*Element
	DefaultPolicy int
}

// NewList to create an empty new List of Rules
func NewList(ifNoResult int, isReply bool) (*List, error) {
	if ifNoResult >= policy.TypeCount {
		return nil, fmt.Errorf("invalid default rulelist parameters: %v", ifNoResult)
	}
	return &List{Reply: isReply, DefaultPolicy: ifNoResult}, nil
}

//BuildRules ensure that each Elements of the List have a real built policy Rule
func (p *List) BuildRules(engines map[string]policy.Engine) error {
	var err error
	for _, re := range p.Rules {
		if re.Rule == nil {
			e, ok := engines[re.Name]
			if !ok {
				return fmt.Errorf("unknown engine for Plugin %s and Name %s - cannot build the Rule", re.Plugin, re.Name)
			}
			re.Rule, err = e.BuildRule(re.Params)
			if err != nil {
				return fmt.Errorf("cannot build Rule for Plugin %s, Name %s and Params %s - error is %s", re.Plugin, re.Name, strings.Join(re.Params, ","), err)
			}
		}
	}
	return nil
}

func (p *List) buildQueryData(ctx context.Context, name string, state request.Request, data map[string]interface{}, engines map[string]policy.Engine) (interface{}, error) {
	if d, ok := data[name]; ok {
		return d, nil
	}
	if e, ok := engines[name]; ok {
		d, err := e.BuildQueryData(ctx, state)
		if err != nil {
			return nil, err
		}
		data[name] = d
		return d, nil
	}
	return nil, fmt.Errorf("unregistered engine instance %s", name)
}

func (p *List) buildReplyData(ctx context.Context, name string, state request.Request, queryData interface{}, data map[string]interface{}, engines map[string]policy.Engine) (interface{}, error) {
	if d, ok := data[name]; ok {
		return d, nil
	}
	if e, ok := engines[name]; ok {
		d, err := e.BuildReplyData(ctx, state, queryData)
		if err != nil {
			return nil, err
		}
		data[name] = d
		return d, nil
	}
	return nil, fmt.Errorf("unregistered engine instance %s", name)
}

//Evaluate all policy one by one until one provide a valid result
//if no Rule can provide a result, the DefaultPolicy of the list applies
func (p *List) Evaluate(ctx context.Context, state request.Request, data map[string]interface{}, engines map[string]policy.Engine) (int, error) {
	var dataReply = make(map[string]interface{}, 0)
	for i, r := range p.Rules {
		rd, err := p.buildQueryData(ctx, r.Name, state, data, engines)
		if err != nil {
			return policy.TypeNone, fmt.Errorf("rulelist Rule %v, with Name %s - cannot build query data for evaluation %s", i, r.Name, err)
		}
		if p.Reply {
			rd, err = p.buildReplyData(ctx, r.Name, state, rd, dataReply, engines)
			if err != nil {
				return policy.TypeNone, fmt.Errorf("rulelist Rule %v, with Name %s - cannot build Reply data for evaluation %s", i, r.Name, err)
			}
		}
		pr, err := r.Rule.Evaluate(rd)
		if err != nil {
			return policy.TypeNone, fmt.Errorf("rulelist Rule %v returned an error at evaluation %s", i, err)
		}
		if pr >= policy.TypeCount {
			return policy.TypeNone, fmt.Errorf("rulelist Rule %v returned an invalid value %v", i, pr)

		}
		if pr != policy.TypeNone {
			// Rule returned a valid value
			return pr, nil
		}
		// if no result just continue on next Rule
	}
	// if none of Rule make a statement, then we return the default policy
	return p.DefaultPolicy, nil
}
