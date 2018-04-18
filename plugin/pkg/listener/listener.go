package listener

import (
	"fmt"
	"log"
	"net"

	"github.com/mholt/caddy"
)

// Booker - generic type providing information on the booker
type Booker interface {
	// Tag is used to verify re-usability of a Listener - listener is reusable only for Booker with the same Tag
	Tag() string
}

// booking structure use at booking, and allocation time of the listener
type booking struct {
	booker    Booker
	hostname  string
	port      string
	protocol  string
	reusable  *net.Listener
	allocated *net.Listener
}

// a way to identify same hostname
// TODO: manage properly the difference between localhost/"" and Ipv4 or Ipv6
var (
	sameIPList = [][]string{
		{"127.0.0.1", "localhost", ""},
		{"::1", "localhost", ""},
	}
)

func contains(list []string, ip string) bool {
	for _, v := range list {
		if v == ip {
			return true
		}
	}
	return false
}

func areSameIP(ip1 string, ip2 string) bool {
	for _, l := range sameIPList {
		if contains(l, ip1) && contains(l, ip2) {
			return true
		}
	}
	return false
}

func (b booking) equal(protocol string, hostname string, port string) bool {
	// Consider that port "0" means "a new port" and will never match another port
	// Consider that "localhost" or "" is matching both "127.0.01" or "[::1]"
	if protocol == b.protocol {
		if port == "0" || b.port == "0" {
			return false
		}
		if port == b.port {
			return areSameIP(hostname, b.hostname)
		}
	}
	return false
}

// AllocationToken is an interface that is able to allocated the Listener
type AllocationToken interface {
	AllocateListener() (net.Listener, error)
}

//AllocateListener will act upon configuration of the booking:
// - either reuse an existing listener
// - either spin-up a new one
// - keep track of the new Listener in order to provide for next RELOAD
func (b *booking) AllocateListener() (net.Listener, error) {
	// Cannot allocate several times
	if b.allocated != nil {
		return nil, fmt.Errorf("listener already allocated for %s, at address (%s, %s)", b.booker.Tag(), (*b.allocated).Addr().Network(), (*b.allocated).Addr().String())
	}

	var ln net.Listener
	var err error
	if b.reusable != nil {
		// we want to reuse the same address - duplicate the FD and open a listener on that FD
		// If this is a reload and s is a GracefulServer,
		// reuse the listener for a graceful restart.
		if fileLn, ok := (*b.reusable).(caddy.Listener); ok {
			file, err := fileLn.File()
			if err != nil {
				return nil, err
			}
			ln, err = net.FileListener(file)
			if err != nil {
				return nil, err
			}
			err = file.Close()
			if err != nil {
				return nil, err
			}

		}
	}
	if ln == nil {
		ln, err = net.Listen(b.protocol, net.JoinHostPort(b.hostname, b.port))
		if err != nil {
			return nil, err
		}
	}
	b.allocated = &ln
	log.Printf("[INFO] %s - listening on network %s - address %s", b.booker.Tag(), ln.Addr().Network(), ln.Addr().String())
	return ln, err
}

// Distributor provide ability to distribute and re-distribute the listeners. Ensuring bridge for gracefull continuation after a reload
type Distributor struct {
	// Distribution is done in 2 times:
	// 1- Book the listener - (expected during Setup of plugin) - we expect to be able to reuse existing listener, but raise any error during that phase
	// 2- Allocate the listener - (expected after Start of the Servers) - an error here can happen, but would be unfortunate, leaving the system in unknown status

	// need to fail at Book time if:
	//   - address is already in used by ANOTHER plugin
	//   - address is already booked (reusing or not)
	//   - NOTE: need to take care of 'similar addresses' or address always different (port 0)
	//
	reusable []*booking
	booked   []*booking
}

// NewListenerDistributor : provide an new Distributor with ability to reuse the allocated listener of a former Distributor
func NewListenerDistributor(seedDistributor *Distributor) *Distributor {
	reusable := make([]*booking, 0)
	if seedDistributor != nil {
		for _, v := range seedDistributor.booked {
			if v.allocated != nil {
				reusable = append(reusable, v)
			}
		}
	}
	return &Distributor{reusable: reusable, booked: make([]*booking, 0)}
}

// IsBooked return status of booking for this address. The Booker info is returned
// it is typically used for the booker to be able to share the same new Listener - as re-Book the same address is forbidden.
// (see metrics plugin)
func (l *Distributor) IsBooked(network string, address string) (bool, Booker) {
	hostname, port, err := net.SplitHostPort(address)
	if err != nil {
		return false, nil
	}
	for _, b := range l.booked {
		if b.equal(network, hostname, port) {
			return true, b.booker
		}
	}
	return false, nil
}

// BookListener ask for booking a new listener. Will return an allocation interface to use when need to really instanciate the listener
func (l *Distributor) BookListener(network string, address string, bookerInfo Booker, allowReuse bool) (AllocationToken, error) {
	hostname, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("listener booking for %s, (%s, %s) - address provider is invalid : %v", bookerInfo.Tag(), network, address, err)
	}
	// check if already booked - raise error
	for _, booking := range l.booked {
		if booking.equal(network, hostname, port) {
			return nil, fmt.Errorf("listener booking for %s, (%s, %s) - an overlaping listener is already booked for %s (%s, %s) - sharing is not allowed", bookerInfo.Tag(), network, address, booking.booker.Tag(), booking.protocol, net.JoinHostPort(booking.hostname, booking.port))
		}
	}
	toBook := &booking{protocol: network, hostname: hostname, port: port, reusable: nil, booker: bookerInfo}
	// check if reusable Listener
	for r, reuse := range l.reusable {
		if reuse != nil {
			ntw := (*reuse.allocated).Addr().Network()
			host, port, _ := net.SplitHostPort((*reuse.allocated).Addr().String())
			if toBook.equal(ntw, host, port) {
				if reuse.equal(network, hostname, port) && reuse.allocated != nil {
					// check that we reuse for the same family of Booker (same Tag)
					if reuse.booker.Tag() != bookerInfo.Tag() {
						return nil, fmt.Errorf("listener booking for %s, (%s, %s) - an overlaping listener is already in use for %s (%s, %s)", bookerInfo.Tag(), network, address, reuse.booker.Tag(), reuse.protocol, net.JoinHostPort(reuse.hostname, reuse.port))
					}
					if !allowReuse {
						return nil, fmt.Errorf("listener booking for %s, (%s, %s) - this listener is already in use, and re-use is not allowed", bookerInfo.Tag(), network, address)
					}
					toBook.reusable = reuse.allocated
					// We prevent to reuse a second time - although the test on booking should also prevent it
					l.reusable[r] = nil
					break
				}
			}
		}
	}
	// book it anyway, whatever reuse status
	l.booked = append(l.booked, toBook)
	return toBook, nil
}

//Bookings return all listeners that match the provide tag
func (l *Distributor) Bookings(tag string) []*net.Listener {
	match := make([]*net.Listener, 0)
	for _, b := range l.booked {
		if b.booker.Tag() == tag {
			match = append(match, b.allocated)
		}
	}
	return match
}
