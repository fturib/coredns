# throttle

## Name

*throttle* - limits the maximum number of inflight queries.

## Description

This plugin limit the max inflight simultaneous queries.
While the limit is reached, any new queries received are dropped.


The _throttle_ plugin prevents CoreDNS from consuming an unbound amount of memory
when it receives a burst of incoming queries.

One will need to tune the **MAX-INFLIGHT** with the memory allowed for this pod or process

NOTE: `throttle` acts only on the server block is which it is defined.
To be most effective, it should be enabled on all DNS server blocks.

## Syntax

~~~ txt
throttle [MAX-INFLIGHT]
~~~

* The plugin check the number of in-process queries for each new incoming query.
it it that number is > **MAX-INFLIGHT** then the query is immediatly dropped.
* When **TIMEOUT** is defined (and non nul) this plugin verify i

## Examples

Check with the default intervals:

~~~ corefile
. {
    throttle 1000
}
~~~

Check that no more than 1000 queries are served in same time


## Metrics

If monitoring is enabled (via the *prometheus* directive) then the following metrics are exported:

* `coredns_throttle_seen_queries{server, kind}` - Total queries seen by the throttle, per `server`.

   Query `kind` can be either:
   - `incoming` : total queries getting into this plugin chain
   - `dropped`: total queries dropped because hit the limit **MAX-INFLIGHT**
   - `served`: total queries served by throttle


* `coredns_throttle_flight_queries{server}` - Total simultaneous queries currently processed by the throttle, per `server`.

