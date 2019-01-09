package firewall

import "github.com/coredns/coredns/plugin/firewall/policy"

// Engineer allow registration of Policy Engines. One plugin can declare several Engines.
type Engineer interface {
	Engine(name string) policy.Engine
}
