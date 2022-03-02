resolved
========

`resolved` (pronounced "resolved", not "resolved") is a simple DNS
server for home networks.  To that end, it supports:

- Recursive and non-recursive resolution
- Caching
- Custom records
- Domain blocking (by spoofing A records)

It does *not* support:

- Serving authoritative zones: this isn't intended to a full-blown
  nameserver, the custom record support is just enough to get nice
  hostnames for things on your LAN.

- Querying upstream nameservers over IPv6: I don't have IPv6 at home,
  so this code doesn't support it yet.


Usage
-----

**While `resolved` does work, you probably don't want to use it yet.
Much of the code is untested and prototype quality.  You *definitely*
don't want to expose this to the internet.  There will be bugs and
maybe even exploits.**

```
cargo build --release
sudo ./target/release/resolved ./example-config.yaml
```

Since `resolved` binds to port 53 (both UDP and TCP), it needs to be
run as root or to have the `CAP_NET_BIND_SERVICE` capability.


Development
-----------

The project structure should hopefully be fairly straightforward.  The
modules are:

- `net_util` - shared utilities used by both the `main.rs` file and
  the `resolver` module
- `protocol` - the DNS message types and serialisation /
  deserialisation logic
- `resolver` - the resolution and caching logic
- `settings` - the configuration data type & parser

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
