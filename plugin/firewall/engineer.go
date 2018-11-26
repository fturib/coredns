package firewall

import "github.com/coredns/coredns/plugin/pkg/policy"

// Engineer allow registration of Engines for Policy. On plugin can declare several Engines, each of these are defined by a name.
// any duplication of name will raise an ERROR info and the corresponding Engine will be skipped
type Engineer interface {
	GetEngine(name string) policy.Engine
}
