package pprof

import (
	"net"
	"strconv"
	"sync"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/mholt/caddy"
)

var log = clog.NewWithPlugin("pprof")

const defaultAddr = "localhost:6053"

func init() {
	caddy.RegisterPlugin("pprof", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	h := &handler{addr: defaultAddr}

	i := 0
	for c.Next() {
		if i > 0 {
			return plugin.Error("pprof", plugin.ErrOnce)
		}
		i++

		args := c.RemainingArgs()
		if len(args) >= 1 {
			h.addr = args[0]
			_, _, e := net.SplitHostPort(h.addr)
			if e != nil {
				return e
			}
		}
		if len(args) >= 2 {
			l, err := strconv.ParseInt(args[1], 10, 32)
			if err != nil {
				return plugin.Error("pprof", err)
			}
			h.rateBloc = int(l)
		}
		if len(args) > 2 {
			return plugin.Error("pprof", c.ArgErr())
		}
		if c.NextBlock() {
			return plugin.Error("pprof", c.ArgErr())
		}
	}

	pprofOnce.Do(func() {
		c.OnStartup(h.Startup)
		c.OnShutdown(h.Shutdown)
	})

	return nil
}

var pprofOnce sync.Once
