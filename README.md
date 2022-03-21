resolved
========

`resolved` (pronounced "resolved", not "resolved") is a simple DNS
server for home networks.  To that end, it supports:

- Recursive and non-recursive resolution
- Caching
- Hosts files
- Zone files

It does not support querying upstream nameservers over IPv6: I don't
have IPv6 at home, so this code doesn't support it yet.


Usage
-----

**While `resolved` does work, you probably don't want to use it yet.
Much of the code is untested and prototype quality.  You *definitely*
don't want to expose this to the internet.  There will be bugs and
maybe even exploits.**

```
cargo build --release
sudo ./target/release/resolved -Z config/zones
```

Since `resolved` binds to port 53 (both UDP and TCP), it needs to be
run as root or to have the `CAP_NET_BIND_SERVICE` capability.

There are also four utility programs---`htoh`, `htoz`, `ztoh`, and
`ztoz`---to convert between hosts files and zone files.  They accept
any syntactically valid file as input, and output it in a consistent
format regardless of how the input is structured.  So `htoh` and
`ztoz` can be used to normalise existing files.

**Signals:**

- `SIGUSR1` - reload the configuration


Development
-----------

The project structure should hopefully be fairly straightforward.  The
modules are:

- `lib-dns-types` - basic types used in other packages
  - `hosts`       - hosts files
  - `protocol`    - the DNS message types and serialisation / deserialisation logic
  - `zones`       - authoritative and non-authoritative zones

- `bin-resolved` - the DNS server

- `bin-htoh` - utility to normalise hosts files

- `bin-htoz` - utility to convert hosts files to zone files

- `bin-ztoh` - utility to convert zone files to hosts files

- `bin-ztoz` - utility to normalise zone files

### Testing

Run the unit and integration tests with:

```
cargo test
```

There are also fuzz tests in the `fuzz/` directory, using
[`cargo-fuzz`][]:

```
cargo install cargo-fuzz

# list targets
cargo fuzz list

# run a target until it panics or is killed with ctrl-c
cargo fuzz run <target>
```

[`cargo-fuzz`]: https://github.com/rust-fuzz/cargo-fuzz


Supported standards
-------------------

- [RFC 1034: Domain Names - Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1034)

  Gives the basic semantics of DNS and the algorithms for recursive
  and non-recursive resolution.

- [RFC 1035: Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)

  Defines the wire format and discusses implementation concerns of the
  algorithms from RFC 1034.

- [RFC 2782: A DNS RR for specifying the location of services (DNS SRV)](https://datatracker.ietf.org/doc/html/rfc2782)

  Defines the `SRV` record and query types.

- [RFC 3596: DNS Extensions to Support IP Version 6](https://datatracker.ietf.org/doc/html/rfc3596)

  Defines the `AAAA` record and query types.

- [RFC 4343: Domain Name System (DNS) Case Insensitivity Clarification](https://datatracker.ietf.org/doc/html/rfc4343)

  Clarifies that domain names are not ASCII, and yet for case
  insensitivity purposes are case-folded as ASCII is.  And also that
  "case preservation", as required by other RFCs, is more or less
  meaningless.

- [RFC 6761: Special-Use Domain Names](https://datatracker.ietf.org/doc/html/rfc6761)

  Defines several zones with special behaviour.  This is RFC
  implemented as configuration distributed with the DNS server (in
  `config/zones`) not code.

- [hosts(5)](https://man7.org/linux/man-pages/man5/hosts.5.html)

  Defines the Linux hosts file format.
