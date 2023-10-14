Command line interface
======================

`resolved` consists of a DNS nameserver and client, and some conversion
utilities for [hosts and zone files][]:

- **[resolved - DNS server.](./cli/resolved.md)** Listens on port 53 to respond
  to DNS queries.  Read this in conjunction with the [configuration
  documentation][] and [guides][].

- **[dnsq - DNS client.](./cli/dnsq.md)** Command-line tool to resolve a single
  query in the same way as `resolved` does, useful for testing configuration
  changes.

- **[Conversion utilities.](./cli/conversion-utilities.md)** Convert between
  hosts files and zone files, validating the contents and normalising the
  formatting.

[hosts and zone files]: ./hosts-and-zone-files.md
[configuration documentation]: ./configuration.md
[guides]: ./guides.md
