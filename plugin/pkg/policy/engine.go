package policy

import (
	"context"

	"github.com/coredns/coredns/request"
)

const (
	// TypeNone a no value
	TypeNone = byte(iota)
	// TypeRefuse policy action is REFUSE (do not resolve a query and return rcode REFUSED)
	TypeRefuse
	// TypeAllow policy action is ALLOW (continue to resolve query)
	TypeAllow
	// TypeBlock policy action is BLOCK (do not resolve a query and return rcode NXDOMAIN)
	TypeBlock
	// TypeDrop policy action is DROP (do not resolve a query and simulate a lost query)
	TypeDrop

	// TypeCount total number of actions allowed
	TypeCount
)

const (
	nameTypeNone   = "none"
	nameTypeAllow  = "allow"
	nameTypeRefuse = "refuse"
	nameTypeBlock  = "block"
	nameTypeDrop   = "drop"
)

// NameTypes keep a mapping of the byte constant to the corresponding name
var NameTypes [TypeCount]string

func initNameTypes() {
	NameTypes[TypeNone] = nameTypeNone
	NameTypes[TypeRefuse] = nameTypeRefuse
	NameTypes[TypeAllow] = nameTypeAllow
	NameTypes[TypeBlock] = nameTypeBlock
	NameTypes[TypeDrop] = nameTypeDrop
}

func init() {
	initNameTypes()
}

// Rule defines a policy for continuing DNS query processing.
// data is provided by BuildQueryData or BuildReplyData - content or organization of the data is up to the Engine
// Evaluate must return:
//   - an error if the evaluation is invalid
//   - nameTypeNone if this Rule cannot make a decision
//   - one of the other TypeAllow/TypeRefuse/TypeDrop/TypeBlock otherwise
type Rule interface {
	Evaluate(data interface{}) (byte, error)
}

// Engine for Firewall plugin.
// each Engine must be able to build rules (at setup time) base on one line of the corefile configuration
// build at execution time some data extracted from context or query itself, needed to evaluate the rules builts.
type Engine interface {
	// BuildRules - create a Rule based on args or throw an error, This Rule will be evaluated during processing of DNS Queries
	BuildRule(args []string) (Rule, error) // create a rule based on parameters

	//Generate the data needed for the evaluation of ALL the rules of this Engine for a QueryData
	//the function is called only once whatever the number of Rule that will be evaluated.
	BuildQueryData(ctx context.Context, state request.Request) (interface{}, error) // create the right set of data needed for policy interpretation

	//Generate the data needed for the evaluation of ALL the rules of this Engine for a ReplyData
	BuildReplyData(ctx context.Context, state request.Request, queryData interface{}) (interface{}, error)
}
