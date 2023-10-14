Standard zones
==============

`resolved` comes with the ["root hints" file][], from IANA, and authoritative
zones for the [RFC 6761: Special-Use Domain Names][].  These zone files are
stored in the `config/zones` directory.

["root hints" file]: https://www.iana.org/domains/root/files
[RFC 6761: Special-Use Domain Names]: https://datatracker.ietf.org/doc/html/rfc6761


Root hints
----------

- **[root.hints](https://github.com/barrucadu/resolved/blob/master/config/zones/root.hints)**

This is a non-authoritative zone file (a "hints" file) giving the `NS` records
for `.` (the root domain) and the `A` and `AAAA` records for those nameservers.

This file (or an equivalent if you want to use an alternative DNS root) is
required when operating `resolved` as a recursive resolver.


RFC 6761 Private address reverse-mapping domains
------------------------------------------------

- **[10.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/10.in-addr.arpa.zone)**
- **[16.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/16.172.in-addr.arpa.zone)**
- **[168.192.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/168.192.in-addr.arpa.zone)**
- **[17.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/17.172.in-addr.arpa.zone)**
- **[18.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/18.172.in-addr.arpa.zone)**
- **[19.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/19.172.in-addr.arpa.zone)**
- **[20.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/20.172.in-addr.arpa.zone)**
- **[21.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/21.172.in-addr.arpa.zone)**
- **[22.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/22.172.in-addr.arpa.zone)**
- **[23.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/23.172.in-addr.arpa.zone)**
- **[24.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/24.172.in-addr.arpa.zone)**
- **[25.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/25.172.in-addr.arpa.zone)**
- **[26.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/26.172.in-addr.arpa.zone)**
- **[27.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/27.172.in-addr.arpa.zone)**
- **[28.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/28.172.in-addr.arpa.zone)**
- **[29.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/29.172.in-addr.arpa.zone)**
- **[30.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/30.172.in-addr.arpa.zone)**
- **[31.172.in-addr.arpa.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/31.172.in-addr.arpa.zone)**

These are authoritative zone files, defining no records by default, for
implementing reverse lookups in the private address ranges.

For example, if the name of the host `10.0.0.1` is `example.lan`, to support
reverse lookups you should add the following record to `10.in-addr.arpa.zone`:

```text
1.0.0 IN PTR example.lan.
```


RFC 6761 "invalid." domain
--------------------------

- **[invalid.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/invalid.zone)**

This is an authoritative zone file defining no records, so that all queries for
domains in this zone fail.

No records should be added to it.


RFC 6761 "localhost." domain
----------------------------

- **[localhost.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/localhost.zone)**

This is an authoritative zone file defining `A` and `AAAA` records for
`localhost.` and `*.localhost.` such that all queries respond positively with
the loopback address.

No other records should be added to it.


RFC 6761 "test." domain
-----------------------

- **[test.zone](https://github.com/barrucadu/resolved/blob/master/config/zones/test.zone)**

This is an authoritative zone file, defining no records by default.  You may add
any records you like to this zone.
