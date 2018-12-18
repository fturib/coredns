package firewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/coredns/coredns/plugin/pkg/policy"
	"github.com/coredns/coredns/request"
)

type ruleElement struct {
	plugin string
	name   string
	params []string
	rule   policy.Rule
}

type ruleList struct {
	reply         bool
	ruleList      []*ruleElement
	defaultPolicy int
}

func newRuleList(ifNoResult int, isReply bool) (*ruleList, error) {
	if ifNoResult >= policy.TypeCount {
		return nil, fmt.Errorf("invalid default rulelist parameters: %v", ifNoResult)
	}
	return &ruleList{reply: isReply, defaultPolicy: ifNoResult}, nil
}

func (p *ruleList) addRuleElement(r *ruleElement) {
	p.ruleList = append(p.ruleList, r)
}

func (p *ruleList) ensureRules(engines map[string]policy.Engine) error {
	var err error
	for _, re := range p.ruleList {
		if re.rule == nil {
			e, ok := engines[re.name]
			if !ok {
				return fmt.Errorf("unknown engine for plugin %s and name %s - cannot build the rule", re.plugin, re.name)
			}
			re.rule, err = e.BuildRule(re.params)
			if err != nil {
				return fmt.Errorf("cannot build rule for plugin %s, name %s and params %s - error is %s", re.plugin, re.name, strings.Join(re.params, ","), err)
			}
		}
	}
	return nil
}

func (p *ruleList) ensureQueryData(ctx context.Context, name string, state request.Request, data map[string]interface{}, engines map[string]policy.Engine) (interface{}, error) {
	if d, ok := data[name]; ok {
		return d, nil
	}
	// first time this instance of enginer is triggered. Build the data
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

func (p *ruleList) ensureReplyData(ctx context.Context, name string, state request.Request, queryData interface{}, data map[string]interface{}, engines map[string]policy.Engine) (interface{}, error) {
	if d, ok := data[name]; ok {
		return d, nil
	}
	// first time this instance of enginer is triggered. Build the data
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

func (p *ruleList) evaluate(ctx context.Context, state request.Request, data map[string]interface{}, engines map[string]policy.Engine) (int, error) {
	// evaluate all policy one by one until one provide a valid result
	// else return the defaultPolicy value
	var dataReply = make(map[string]interface{}, 0)
	for i, r := range p.ruleList {
		rd, err := p.ensureQueryData(ctx, r.name, state, data, engines)
		if err != nil {
			return policy.TypeNone, fmt.Errorf("rulelist rule %v, with name %s - cannot build query data for evaluation %s", i, r.name, err)
		}
		if p.reply {
			rd, err = p.ensureReplyData(ctx, r.name, state, rd, dataReply, engines)
			if err != nil {
				return policy.TypeNone, fmt.Errorf("rulelist rule %v, with name %s - cannot build reply data for evaluation %s", i, r.name, err)
			}
		}
		pr, err := r.rule.Evaluate(rd)
		if err != nil {
			return policy.TypeNone, fmt.Errorf("rulelist rule %v returned an error at evaluation %s", i, err)
		}
		if pr >= policy.TypeCount {
			return policy.TypeNone, fmt.Errorf("rulelist rule %v returned an invalid value %v", i, pr)

		}
		if pr != policy.TypeNone {
			// rule returned a valid value
			return pr, nil
		}
		// if no result just continue on next rule
	}
	// if none of rule make a statement, then we return the default policy
	return p.defaultPolicy, nil
}
