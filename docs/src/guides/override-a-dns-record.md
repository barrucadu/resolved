Override a DNS record
=====================

If `resolved` can resolve a record locally it won't query an upstream
nameserver, even if it's not authoritative for that domain.

This means you can use [hosts and zone files][hz] to override any DNS records
you want.


Override an A or AAAA record
--------------------------------

A [hosts file][hz] allows you to override the `A` or `AAAA` records for a
domain.

For example, a hosts file containing the following two lines would make
`example.com` resolve to your local machine, over both IPv4 and IPv6:

```text
127.0.0.1 example.com
::1 example.com
```

Once you have your hosts file, configure `resolved` to use it with the `-a` or
`-A` options:

- `resolved -a /path/to/directory/file`
- `resolved -A /path/to/directory`

I recommend the `-A` form, as you can then add or remove hosts files to the
directory and send `SIGUSR1` to `resolved` to reload the hosts files without
restarting the process.

Hosts files have some limitations: you can only override `A` and `AAAA` records,
and you can't define wildcard records.  For those, you need to use a zone file.


Override any type of record
---------------------------

```admonish info
This is how the ["root hints" file][] works: it overrides the `NS` records for the root domain, which `resolved` would otherwise have no way to figure out.
```

A [zone file][hz] allows you to override any type of record, including wildcard
records.

For example, a zone file containing the following three lines would make
`*.example.com` resolve to `example.com`, and `example.com` to your local
machine, over both IPv4 and IPv6.

```text
*.example.com. 300 IN CNAME example.com.
example.com.   300 IN A     127.0.0.1
example.com.   300 IN AAAA  ::1
```

If you want to totally override *all* records for a domain, rather than just
some of them, make your zone file authoritative for that domain by adding a
`SOA` record.

For example, `example.com` has an MX record, which `resolved` will fetch from
the upstream nameservers if all you do is override `CNAME`, `A`, and `AAAA`
records.  You can "delete" the `MX` record by making your zone authoritative for
`example.com`:

```text
example.com. 300 IN SOA example.com. example.com. 6 300 300 300 300

*.example.com. 300 IN CNAME example.com.
example.com.   300 IN A     127.0.0.1
example.com.   300 IN AAAA  ::1
```

Once you have your zone file, configure `resolved` to use it with the `-z` or
`-Z` options:

- `resolved -z /path/to/directory/file`
- `resolved -Z /path/to/directory`

I recommend the `-Z` form, as you can then add or remove zone files to the
directory and send `SIGUSR1` to `resolved` to reload the zone files without
restarting the process.

[hz]: ../configuration/hosts-and-zone-files.md
["root hints" file]: https://github.com/barrucadu/resolved/blob/master/config/zones/root.hints
