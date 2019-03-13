package throttle

import (
	"strconv"

	"github.com/coredns/coredns/core/dnsserver"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/mholt/caddy"
)

var log = clog.NewWithPlugin(throttle)

func init() {
	caddy.RegisterPlugin(throttle, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

const throttle = "throttle"

func setup(c *caddy.Controller) error {
	ql, err := parse(c)
	if err != nil {
		return err
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ql.Next = next
		return ql
	})

	c.OnStartup(func() error {
		metrics.MustRegister(c, throttleCount, flightCount)
		return nil
	})

	return nil
}

func parse(c *caddy.Controller) (*Throttle, error) {
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 {
			return nil, plugin.Error(throttle, c.ArgErr())
		}

		l, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			return nil, plugin.Error(throttle, err)
		}

		return &Throttle{workerLimit: l}, nil

	}
	return nil, c.ArgErr()
}
