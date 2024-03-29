resolved
========

`resolved` (pronounced "resolved", not "resolved") is a simple DNS server, and
associated tools, for home networks.  To that end, it supports:

- Three modes of operation: as a recursive or forwarding nameserver (with
  caching) or as an authoritative nameserver for your specified domains only.
- Defining custom records in hosts files (to make existing DNS blacklists each
  to use) and in zone files.
- Listening on either IPv4 or IPv6, and communicating with upstream nameservers
  over both.

See [the documentation](https://resolved.docs.barrucadu.co.uk).


Usage
-----

Install `rustup`, and then install the default toolchain:

```bash
rustup show
```

Then, compile in release mode;

```bash
cargo build --release
```

### The DNS Server

**`resolved` hasn't had any sort of security review, so be wary of exposing it on a public network.**

Since `resolved` binds to port 53 (both UDP and TCP), it needs to be
run as root or to have the `CAP_NET_BIND_SERVICE` capability.

```bash
sudo ./target/release/resolved -Z config/zones
```

The `config/zones` directory contains standard configuration which you'll
usually want to have (such as the ["root hints" file][]), so you would typically
either put your zone files in `config/zones`, or put them somewhere else and
pass a second `-Z` option like so:

``` bash
sudo ./target/release/resolved -Z config/zones -Z /path/to/your/zone/files
```

See [the CLI documentation](https://resolved.docs.barrucadu.co.uk/cli/resolved.html) for more.

["root hints" file]: https://www.iana.org/domains/root/files

### The DNS Client

There is also a `dnsq` utility to resolve names based on the server
configuration directly.  The main purpose of it is to test configuration
changes.

```text
$ ./target/release/dnsq www.barrucadu.co.uk. AAAA -Z config/zones
;; QUESTION
www.barrucadu.co.uk.    IN      AAAA

;; ANSWER
www.barrucadu.co.uk.    300     IN      CNAME   barrucadu.co.uk.
barrucadu.co.uk.        300     IN      AAAA    2a01:4f8:c0c:bfc1::
```

See the `--help` text for all options.

### Other Tools

There are also four utility programs (`htoh`, `htoz`, `ztoh`, and `ztoz`) to
convert between hosts files and zone files.

They accept any syntactically valid file as input, and output it in a consistent
format regardless of how the input is structured, so `htoh` and `ztoz` can be
used to normalise existing files.


Development
-----------

Rust sources are in the `crates/` directory.  There are two shared libraries:

- `dns-types` - basic types used in other packages ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/dns_types/))
- `dns-resolver` - the DNS resolvers ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/dns_resolver/))

And six binaries:

- `dnsq` - utility to resolve DNS queries ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/dnsq/))
- `resolved` - the DNS server ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/resolved/))
- `htoh` - utility to normalise hosts files ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/htoh/))
- `htoz` - utility to convert hosts files to zone files ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/htoz/))
- `ztoh` - utility to convert zone files to hosts files ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/ztoh/))
- `ztoz` - utility to normalise zone files ([crate documentation](https://resolved.docs.barrucadu.co.uk/packages/ztoz/))

### Developing with nix

Open a development shell:

```bash
nix develop
```

And run cargo commands in there.

### Testing

Run the unit tests with:

```bash
cargo test
```

There are also fuzz tests in the `fuzz/` directory, using
[`cargo-fuzz`][]:

```bash
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
