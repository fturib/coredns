package throttle

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSetupThrottle(t *testing.T) {
	c := caddy.NewTestController("dns", `throttle`)
	if err := setup(c); err == nil {
		t.Fatal("Expected errors, but got none")
	}

	c = caddy.NewTestController("dns", `throttle 10`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors, but got: %v", err)
	}

	c = caddy.NewTestController("dns", `throttle 10 whatever`)
	if err := setup(c); err == nil {
		t.Fatal("Expected errors, but got none")
	}

	c = caddy.NewTestController("dns", `throttle whatever`)
	if err := setup(c); err == nil {
		t.Fatal("Expected errors, but got none")
	}

}
