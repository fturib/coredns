package firewall

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"

	"github.com/coredns/coredns/plugin/pkg/policy"

	"github.com/coredns/coredns/plugin/test"
)

// Stub Engine for test purposes

type RuleStubEngine struct {
	error  error
	result byte
}

func (r *RuleStubEngine) Evaluate(data interface{}) (byte, error) {
	return r.result, r.error
}

type StubEngine struct {
	name        string
	alwaysError bool
}

func (e *StubEngine) BuildQueryData(ctx context.Context, state request.Request) (interface{}, error) {
	if e.alwaysError {
		return nil, fmt.Errorf("engine %s is returning an error at buildQueryData", e.name)
	}
	return e.name, nil
}

func (e *StubEngine) BuildReplyData(ctx context.Context, state request.Request, query interface{}) (interface{}, error) {
	if e.alwaysError {
		return nil, fmt.Errorf("engine %s is returning an error at buildReplyData", e.name)
	}
	return e.name, nil
}

func (e *StubEngine) BuildRule(args []string) (policy.Rule, error) {
	if e.alwaysError {
		return nil, fmt.Errorf("engine %s is returning an error at BuildRule", e.name)
	}
	r := policy.TypeNone
	var err error
	if len(args) > 0 {
		v, errconv := strconv.Atoi(args[0])
		if errconv != nil {
			err = fmt.Errorf("rule from %s, evalute as an error : %s", e.name, args[0])
		} else {
			r = byte(v)
		}
	}
	return &RuleStubEngine{err, r}, nil
}

func TestEnsureRules(t *testing.T) {

	engines := map[string]policy.Engine{
		"good":  &StubEngine{"good", false},
		"wrong": &StubEngine{"wrong", true},
	}

	tests := []struct {
		rules []*ruleElement
		error bool
	}{
		// unknown engine
		{[]*ruleElement{{"plugin", "unknown", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true,
		},
		// invalid params
		{[]*ruleElement{{"plugin", "wrong", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true,
		},
		// all ok
		{[]*ruleElement{{"plugin", "good", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			false,
		},
	}
	for i, test := range tests {
		rl, _ := newRuleList(policy.TypeDrop, false)
		rl.ruleList = test.rules

		err := rl.ensureRules(engines)
		if err != nil {
			if !test.error {
				t.Errorf("Test %d : unexpected error at build rule : %s", i, err)
			}
			continue
		}
		if test.error {
			t.Errorf("Test %d : no error at EnsureRules returned, when one was expected", i)
		}
	}
}

func TestEvaluate(t *testing.T) {

	engines := map[string]policy.Engine{
		"good":  &StubEngine{"good", false},
		"wrong": &StubEngine{"wrong", true},
	}

	tests := []struct {
		rules []*ruleElement
		error bool
		value byte
	}{

		// error at query data
		{[]*ruleElement{{"plugin", "wrong", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// error at reply data
		{[]*ruleElement{{"plugin", "wrong", []string{}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// error returned by evaluation
		{[]*ruleElement{{"plugin", "good", []string{"Error returned"}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// invalid value returned by evaluation
		{[]*ruleElement{{"plugin", "good", []string{"123"}, nil},
			{"plugin", "good", []string{}, nil}},
			true, policy.TypeNone,
		},
		// a correct value is returned by the rulelist
		{[]*ruleElement{
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"2"}, nil}},
			false, policy.TypeAllow,
		},
		// no value is returned by the rulelist
		{[]*ruleElement{
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil},
			{"plugin", "good", []string{"0"}, nil}},
			false, policy.TypeDrop,
		},
	}
	for i, tst := range tests {
		rl, _ := newRuleList(policy.TypeDrop, false)
		rl.ruleList = tst.rules
		rl.ensureRules(engines)

		state := request.Request{W: &test.ResponseWriter{}, Req: new(dns.Msg)}
		state.Req.SetQuestion("example.org.", dns.TypeA)

		ctx := context.TODO()
		data := make(map[string]interface{})
		result, err := rl.evaluate(ctx, state, data, engines)
		if err != nil {
			if !tst.error {
				t.Errorf("Test %d : unexpected error at evaluate rulelist : %s", i, err)
			}
			continue
		}
		if tst.error {
			t.Errorf("Test %d : no error at evaluate rulelist returned, when one was expected", i)
			continue
		}
		if result != tst.value {
			t.Errorf("Test %d : value return is not the one expected - expected : %v, got : %v", i, tst.value, result)
			continue
		}

	}
}
