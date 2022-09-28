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

Install `rustup`, `clang`, and `binutils`, and then install the
nightly toolchain:

```
rustup toolchain install nightly
```

Then, compile in release mode;

```
cargo build --release
```

### The DNS Server

**I use `resolved` for my home network with no problems, but it may
not work for you.  You also probably don't want to expose this to the
internet!**

Since `resolved` binds to port 53 (both UDP and TCP), it needs to be
run as root or to have the `CAP_NET_BIND_SERVICE` capability.

```
$ sudo ./target/release/resolved -Z config/zones
```

If run as a systemd unit, set the `AmbientCapabilities=CAP_NET_BIND_SERVICE`
option and run as a non-root user.

See the `--help` text for options.

**Signals:**

- `SIGUSR1` - reload the configuration

**Monitoring:**

- Prometheus metrics are exposed at `http://127.0.0.1:9420/metrics`
- Log level can be controlled with the `RUST_LOG` environment variable:
  - `RUST_LOG=trace` - verbose messages useful for development, like
    "entered function X"
  - `RUST_LOG=debug` - warns about strange but recoverable situations,
    like "socket read error"
  - `RUST_LOG=info` - gives top-level information, like "new
    connection" or "reloading configuration"
  - `RUST_LOG=warn` - warns about recoverable internal errors and
    invalid configuration, like "could not serialise message" or
    "invalid record in cache"
  - `RUST_LOG=error` - warns about fatal errors and then terminates
    the process, like "could not bind socket"
- Log format can be controlled with the `RUST_LOG_FORMAT` environment
  variable, which is a sequence of comma-separated values:
  - One of `full` (default), `compact`, `pretty`, or `json` - see [the
    tracing_subscriber crate][]
  - One of `ansi` (default), `no-ansi`
  - One of `time` (default), `no-time`

[the tracing_subscriber crate]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/index.html#formatters

### The DNS Client

There is also a `dnsq` utility to resolve names based on the server
configuration directly.  The main purpose of it is to test configuration
changes.

```
$ ./target/release/dnsq www.barrucadu.co.uk. AAAA -Z config/zones
;; QUESTION
www.barrucadu.co.uk.    IN      AAAA

;; ANSWER
www.barrucadu.co.uk.    300     IN      CNAME   barrucadu.co.uk.
barrucadu.co.uk.        300     IN      AAAA    2a01:4f8:c0c:bfc1::
```

See the `--help` text for options, which are a subset of the `resolved` options.

It also uses the same logging environment variables as `resolved`

### Other Tools

There are also four utility programs---`htoh`, `htoz`, `ztoh`, and
`ztoz`---to convert between hosts files and zone files.  They accept
any syntactically valid file as input, and output it in a consistent
format regardless of how the input is structured.  So `htoh` and
`ztoz` can be used to normalise existing files.


Development
-----------

The project structure should hopefully be fairly straightforward.  The
modules are:

- `lib-dns-types` - basic types used in other packages
  - `hosts`       - hosts files
  - `protocol`    - the DNS message types and serialisation / deserialisation logic
  - `zones`       - authoritative and non-authoritative zones

- `lib-dns-resolver` - the DNS resolvers
  - `cache`        - the cache
  - `forwarding`   - the forwarding resolver
  - `metrics`      - resolver-specific metrics
  - `local`        - the local resolver (using configuration & cache)
  - `recursive`    - the recursive resolver
  - `util`         - shared types and functions

- `bin-dnsq` - utility to resolve DNS queries

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
