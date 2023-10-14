Use a DNS blocklist
===================

```admonish tip
This is a special case of [overriding DNS records][].
```

A DNS blocklist is a [hosts file][] mapping domains you want to block to
`0.0.0.0` (to block it over IPv4), `::0` (to block it over IPv6), or both.

For example, a hosts file containing the following two lines would block
`example.com` over both IPv4 and IPv6:

```text
0.0.0.0 example.com
::0 example.com
```

For a much larger example, see [Steven Black's hosts file][] which begins with:

```text
#=====================================
# Title: Hosts contributed by Steven Black
# http://stevenblack.com

0.0.0.0 ck.getcookiestxt.com
0.0.0.0 eu1.clevertap-prod.com
0.0.0.0 wizhumpgyros.com
0.0.0.0 coccyxwickimp.com
0.0.0.0 webmail-who-int.000webhostapp.com
```

And then has *many* more entries.

If you have a DNS blocklist in some other format (for example, just a list of
domains to block) you'll need to convert it into a hosts file (or a zone file)
first.

Once you have your hosts file, configure `resolved` to use it with the `-a` or
`-A` options:

- `resolved -a /path/to/directory/file`
- `resolved -A /path/to/directory`

I recommend the `-A` form, as you can then add or remove hosts files to the
directory and send `SIGUSR1` to `resolved` to reload the hosts files without
restarting the process.

[overriding DNS records]: ./override-a-dns-record.md
[hosts file]: ../configuration/hosts-and-zone-files.md
[Steven Black's hosts file]: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
