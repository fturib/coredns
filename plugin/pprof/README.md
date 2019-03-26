# pprof

## Name

*pprof* - publishes runtime profiling data at endpoints under `/debug/pprof`.

## Description

You can visit `/debug/pprof` on your site for an index of the available endpoints. By default it
will listen on localhost:6053.

This is a debugging tool. Certain requests (such as collecting execution traces) can be slow. If
you use pprof on a live server, consider restricting access or enabling it only temporarily.

This plugin can only be used once per Server Block.

## Syntax

~~~
pprof [ADDRESS] [BLOCKRATE]
~~~

- If not specified, **ADDRESS** defaults to localhost:6053.

- **BLOCKRATE** allow to enable `block` profiling. see [Diagnostics, chapter profiling](https://golang.org/doc/diagnostics.html).
if you need to use `block` profile, set a positive value to **BLOCKRATE**. See [runtime.SetBlockProfileRate](https://golang.org/pkg/runtime/#SetBlockProfileRate).
 if not specified, **BLOCKRATE** default's to 0, which means block profiling disabled.

## Examples

Enable pprof endpoints:

~~~
. {
    pprof
}
~~~

And use the pprof tool to get statistics: `go tool pprof http://localhost:6053`.

Listen on an alternate address:

~~~ txt
. {
    pprof 10.9.8.7:6060
}
~~~

Listen on an all addresses on port 6060: and enable block profiling

~~~ txt
. {
    pprof :6060 1
}
~~~

## Also See

See [Go's pprof documentation](https://golang.org/pkg/net/http/pprof/) and [Profiling Go
Programs](https://blog.golang.org/profiling-go-programs).
