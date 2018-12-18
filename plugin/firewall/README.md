# firewall

## Name

*firewall* - enables filtering on query and response using direct expression as policy.

## Description

The firewall plugin defines a rule list of expressions that triggers workflow action on the DNS query or its response.
A rule list is an ordered set of rules that are evaluated in sequence.
Each rule has two parts: an action and an expression. When the rule is evaluated,
first the expression get evaluated using Metadata and a go-like language.
- If the expression evaluates to `true` the action is performed on the query and the rule list evaluation is considered over.
- If the expression does not evaluates to `true` then next rule in sequence get evaluated


## Syntax

~~~ txt
firewall APPLICATION {
    ACTION EXPRESSION
    ACTION EXPRESSION
    ...
}
~~~~

* **APPLICATION** defines where is applied the firewall rulelist. It can be `query` or `response`

* **ACTION** defines the workflow action to apply to the DNS operation if the **EXPRESSION** evaluates to the boolean `true`
action is one of:
  - `allow` : continue the DNS resolution process
  - `refuse` : interrupt the DNS resolution, just return the REFUSE result
  - `block` : interrupt the DNS resolution, just return the NXDOMAIN result
  - `drop` : interrupt the DNS resolution, just return the NODATA result

* **EXPRESSION** defines the expression to evaluate in order to validate the action and interrupt the sequence of rules.
Expression is a [go-like language](https://github.com/Knetic/govaluate/blob/master/MANUAL.md)
where the variables are either the `metadata` of CoreDNS either a list of names associated with the DNS query/response information.
Usual operators applies.

Exemples of expression using the usual metadata:
* `client_ip == '10.0.0.20'`
* `type == 'AAAA'`
* `type IN ('AAAA', 'A', 'TXT')`
* `type IN ('AAAA', 'A') && name =~ 'google.com'`
* `[mac/address] =~ '.*:FF:.*'`

NOTE: because of the `/` separator included in a label of metadata, those labels must be enclosed on bracket [...] for a correct evaluation by the expression engine

The following names are supported for querying information

* `type`: type of the request (A, AAAA, TXT, ..)
* `name`: name of the request (the domain requested)
* `class`: class of the request (IN, CS, CH, ...)
* `proto`: protocol used (tcp or udp)
* `remote`: client's IP address, for IPv6 addresses these are enclosed in brackets: `[::1]`
* `size`: request size in bytes
* `port`: client's port
* `duration`: response duration
* `rcode`: response CODE (NOERROR, NXDOMAIN, SERVFAIL, ...)
* `rsize`: raw (uncompressed), response size (a client may receive a smaller response)
* `>rflags`: response flags, each set flag will be displayed, e.g. "aa, tc". This includes the qr
  bit as well
* `>bufsize`: the EDNS0 buffer size advertised in the query
* `>do`: is the EDNS0 DO (DNSSEC OK) bit set in the query
* `>id`: query ID
* `>opcode`: query OPCODE
* `server_ip`: server's IP address, for IPv6 addresses these are enclosed in brackets: `[::1]`
* `server_port` : client's port
* `response_ip` : the IP returned in the first A or AAAA record of the Answer section


## Examples

Allow queries for exemple.com.
Allow also the queries for google.com if those are A or AAAA type of queries
NXDOMAIN every other queries

~~~ corefile
example.org {
   firewall query {
      allow name =~ 'exemple.com'
      allow name =~ 'google.com' && (type == 'A' || type == 'AAAA')
      block true
   }
}
~~~


Define the metadata labels `group_id` and `client_id` based on the content of OPT records (EDNS0)
and use those values to filter the DNS queries: any query that have not the group_id 123456789 AND that has not the client_id matching ABCDEF will be returned REFUSED
Also filter the reply with disallowing IP returned within a specific regular expression.


~~~ txt
example.org {
   metadata {
      group_id edns0 0xffed bytes
      client_id edns0 0xffee bytes
   }
   firewall query {
      refuse [metadata/client_id] != 'ABCDEF'
      refuse [metadata/group_id] != '123456789'
      block true
   }
   firewall response {
      refuse  response_ip =~ '172.217.*'   # refuse any IP that is in 172.217.0.0/16
      allow true
   }
}
~~~

