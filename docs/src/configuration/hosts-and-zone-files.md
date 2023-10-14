Hosts and zone files
====================

`resolved` supports two venerable formats for specifying DNS information: hosts
files and zone files.

Hosts files can specify `A` and `AAAA` records, zone files can specify any types
of record.  Additionally, zone files can be "authoritative" (treated as fully
defining all the records under a given domain) or "non-authoritative" (treated
as providing a kind of permanent cache).

Non-authoritative zone files are also called "hints" files.


Hosts files
-----------

Hosts files follow a simple format, given in the [hosts(5) manual page][].  It
is a line-based format where each entry is of the form:

- `<ip-address> <hostname> [<hostname>...]`

The IP address can be an IPv4 address (in which case the entry defines one or
more `A` records) or an IPv6 address (in which case the entry defines one or
more `AAAA` records).

For example, the following hosts file assigns `A` records to `example.com` and
`example.net`, and `AAAA` records to `example.com`, `example.net`, and
`example.org`:

```text
127.0.0.1 example.com example.net
::1       example.com example.net example.org
```

Hostnames in hosts files do not need the trailing `.`, they're interpreted
relative to the root domain.

[hosts(5) manual page]: https://man7.org/linux/man-pages/man5/hosts.5.html


Zone files
----------

Zone files follow a complicated format, given in [section 5 of RFC 1035][].  It
is mostly a line-based format (other than parentheses, see below) where each
entry is one of:

- `$ORIGIN <domain-name>`
- `$INCLUDE <file-name> [<domain-name>]`
- `[<domain-name>] [<ttl>] [<class>] <type> <rdata>`
- `[<domain-name>] [<class>] [<ttl>] <type> <rdata>`

Where,

- `$ORIGIN` sets the base domain for relative domains (*i.e.* domains without
  the trailing `.`)
- `$INCLUDE` includes another file, optionally setting its `$ORIGIN` to a given
  domain name.
- The last two lines define resource records: if the domain name, TTL, or class
  are omitted the corresponding value from the previous resource record is used.

`resolved` doesn't support `$INCLUDE` directives, and only supports the `IN`
record class.

The format of the `<rdata>` depends on the `<type>`:

- `A`: an IPv4 address in standard form
- `AAAA`: an IPv6 address in standard form
- `CNAME`: a domain name
- `HINFO`: a sequence of escaped octets
- `MB`: a domain name
- `MD`: a domain name
- `MF`: a domain name
- `MG`: a domain name
- `MR`: a domain name
- `MX`: a decimal integer (the preference) and a domain name (the exchange)
- `MINFO`: two domain names (the rmailbx and emailbx)
- `NS`: a domain name
- `NULL`: a sequence of escaped octets
- `PTR`: a domain name
- `SOA`: two domain names (the mname and rname) and four decimal integers (the serial, refresh, retry, expire, and minimum)
- `SRV`: three decimal integers (the priority, weight, and port) and a domain name (the target)
- `TXT`: a sequence of escaped octets
- `WKS`: a sequence of escaped octets

There are some special characters:

- `@` by itself denotes the current `$ORIGIN`
- `\X` where `X` is some non-digit character escapes `X`
- `\DDD` where `DDD` is a decimal number is the octet corresponding to that number
- `(` ...  `)` group data that crosses a line boundary
- `"` ... `"` quote a sequence of octets, allowing spaces within

For example, the following zone file assigns `A`, `MX`, and `SOA` records to
`example.com` and `CNAME` records to `www.example.com` and `blog.example.com`:

```text
$ORIGIN example.com.

@ 300 IN SOA @ @ 1 300 300 300 300

@ 300 IN A  127.0.0.1
@ 300 IN MX 10 mail.example.net

www  300 IN CNAME @
blog 300 IN CNAME @
```

[section 5 of RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035#section-5


Behaviour
---------

`resolved` prefers using records from hosts and zone files to answer queries, so
it is possible to block a domain (or point it elsewhere) with a hosts file and
to arbitrarily override records with zone files.

Internally, hosts files are converted into non-authoritative zones (*i.e.* a
zone without a `SOA` record).

When deciding which zone to use to answer a query, `resolved` uses the `SOA`
records to decide which zones are relevant.  This has some consequences:

### More specific authoritative zones override less specific ones

`resolved` uses the most specific zone it can to answer a query about a domain,
which means if there are records for the same domain across multiple zones, only
one of the zones will be used.

For example, if we have these two zone files:

```text
; authoritative for example.com, defines A record for foo.www.example.com
$ORIGIN example.com.

@ 300 IN SOA @ @ 1 300 300 300 300

foo.www.example.com. 300 IN A 127.0.0.1
```

and

```text
; authoritative for www.example.com, defines no other records
$ORIGIN www.example.com.

@ 300 IN SOA @ @ 1 300 300 300 300
```

Then a query for `foo.www.example.com` will be routed to the authoritative zone
for `www.example.com` and return no result, even though there is a result in the
zone for `example.com`.

### Authoritative zones override non-authoritative zones

Perhaps a non-obvious consequence of more specific zones overriding less
specific ones is that authoritative zones override non-authoritative ones.  This
is because non-authoritative zones are merged into the root zone, which is the
least specific zones.

For example, if we have this zone file:

```text
; authoritative for example.com
$ORIGIN example.com.

@ 300 IN SOA @ @ 1 300 300 300 300
```

And then either a non-authoritative zone file or a hosts file overriding a
domain in that zone:

```text
; a different zone file, with no SOA record
www.example.com. 300 IN A 127.0.0.1
```

or

```text
# a hosts file
127.0.0.1 www.example.com
```

Then the override for `www.example.com` is ignored, and it will in fact resolve
to nothing, since there is no record for `www.example.com` in its authoritative
zone.

### The same authoritative zone can be defined across multiple files

If two or more zone files define the same authoritative zone, they are merged,
with records from the second file overriding records from the first file where
there is a clash.

Both zone files need to specify the `SOA` record.

For example, if we have these two zone files:

```text
; authoritative for example.com
$ORIGIN example.com.

@ 300 IN SOA @ @ 1 300 300 300 300

www  300 IN A     127.0.0.1
blog 300 IN CNAME www
```

and

```text
; authoritative for example.com
$ORIGIN example.com.

@ 300 IN SOA @ @ 2 300 300 300 300

@    300 IN MX mail

www  300 IN A 127.0.0.2
mail 300 IN A 127.0.0.3
```

Then `resolved -z file1 -z file2` would use the zone:

```text
; authoritative for example.com
$ORIGIN example.com.

@ 300 IN SOA @ @ 2 300 300 300 300

@    300 IN MX mail

www  300 IN A     127.0.0.1
www  300 IN A     127.0.0.2
blog 300 IN CNAME www
mail 300 IN A     127.0.0.3
```

This is potentially confusing if misused, but allows adding records to the
[standard zones][] without editing those files.

[standard zones]: ./standard-zones.md
