Set up LAN DNS
==============

```admonish tip
If you use NixOS, you may find it useful to look at how I run `resolved` on my home server: [package][nixfiles-package], [module][nixfiles-module], [configuration][nixfiles-config].
```

```admonish warning
You will need to keep your computer switched on all the time, otherwise other machines on your network will no longer be able to resolve DNS.
```

This guide will walk you through:

1. Installing `resolved`
2. Configuring it with the records that you want for your LAN
3. Writing a systemd unit to run it
4. Getting other hosts on your network to use it

At the end, you will be able to assign names to machines on your LAN (and any
other records you want), and have everything on your LAN use them.


Installing `resolved`
---------------------

First, install `rustup`, `clang`, and `binutils` through your package manager.

Build `resolved` in release mode:

```bash
rustup toolchain install nightly
cargo build --release
```

Copy over `resolved` to `/opt`:

```bash
sudo mkdir -p /opt/resolved/bin
sudo cp target/release/resolved /opt/resolved/bin
sudo cp -r config /opt/resolved
sudo mkdir /opt/resolved/config/hosts
```

We now have the following locations:

- `/opt/resolved/bin/resolved` - the DNS server executable
- `/opt/resolved/config/hosts` - directory to store your custom hosts files
  (e.g. DNS blocklists)
- `/opt/resolved/config/zones` - directory to store `resolved`'s standard zone
  files and your custom zone files (e.g. records for LAN hosts)

As everything is under `/opt/resolved`, you can just make a copy of that
directory to fully back up your configuration.


Writing your configuration
--------------------------

Now set up whatever configuration you want in `/opt/resolved/config/`.

- Want [a DNS blocklist][] or to [override a domain's `A` or `AAAA` records][]?
  Put the hosts files in `/opt/resolved/config/hosts`.

- Want to [override some other DNS records][]?  Put the zone files in
  `/opt/resolved/config/zones`.

- Want to set up custom records for your local machines?  Decide on a zone to
  put them in (such as `lan.`) and put an authoritative zone file for it in
  `/opt/resolved/config/zones`.

For example, here is the authoritative zone file I use for my LAN:

```text
$ORIGIN lan.

@ 300 IN SOA @ @ 6 300 300 300 300

router            300 IN A     10.0.0.1

nyarlathotep      300 IN A     10.0.0.3
*.nyarlathotep    300 IN CNAME nyarlathotep

help              300 IN CNAME nyarlathotep
*.help            300 IN CNAME help

nas               300 IN CNAME nyarlathotep

bedroom.awair     300 IN A     10.0.20.187
living-room.awair 300 IN A     10.0.20.117
```

Let's break that down:

- My router is at `10.0.0.1`, and can be reached at the name `router.lan`.
- I have a home server called `nyarlathotep` at `10.0.0.3` which is reachable by
  a few different hostnames: `nyarlathotep.lan`, `*.nyarlathotep.lan`,
  `help.lan`, `*.help.lan`, and `nas.lan`.
- I have a couple of air quality monitoring devices, with the names
  `bedroom.awair.lan` and `living-room.awair.lan`.

If you also want reverse DNS to work (going from an IP address to a hostname),
then add `PTR` records to the appropriate standard zone file.

For example, for my LAN I modify the `10.in-addr.arpa.zone` file:

```text
$ORIGIN 10.in-addr.arpa.

@ IN SOA . . 3 3600 3600 3600 3600

1.0.0    IN PTR router.lan.
3.0.0    IN PTR nyarlathotep.lan.
187.20.0 IN PTR bedroom.awair.lan.
117.20.0 IN PTR living-room.awair.lan.
```


Running it with systemd
-----------------------

Here's a simplified version of the systemd unit file that I use:

```text
[Unit]
After=network-online.target
Description=barrucadu/resolved nameserver

[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=true
Environment="RUST_LOG=dns_resolver=info,resolved=info"
Environment="RUST_LOG_FORMAT=json,no-time"
ExecReload=/bin/kill -USR1 $MAINPID
ExecStart=/opt/resolved/bin/resolved --cache-size 1000000 -A /opt/resolved/config/hosts -Z /opt/resolved/config/zones
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

This will run `resolved` under a non-root user, as a recursive resolver with a
maximum cache size of 1 million records (though in practice it'll be much
smaller than that, as records will expire - my cache hovers at around 4000
records).

See `/opt/resolved/bin/resolved --help` for other options you can set.

Save this to `/etc/systemd/system/resolved.service` and then enable it:

```bash
sudo systemctl enable --now resolved.service
```

Here are some helpful commands:

- `sudo systemctl stop resolved.service` - stop the server
- `sudo systemctl reload resolved.service` - reload the hosts and zones
- `journalctl -fu resolved.service` - follow the logs


Configuring other machines on your LAN
--------------------------------------

Open your router's control panel and:

1. Give the machine which will be running `resolved` a static IP address
2. Change the DNS server assigned by DHCP to that IP address

The other machines on your LAN will gradually switch over to resolving DNS via
`resolved` on your server.  You can force this by reconnecting a machine to the
network.

Now you're running DNS for your LAN!

[nixfiles-package]: https://github.com/barrucadu/nixfiles/blob/master/packages/resolved/default.nix
[nixfiles-module]: https://github.com/barrucadu/nixfiles/blob/master/shared/resolved/default.nix
[nixfiles-config]: https://github.com/barrucadu/nixfiles/blob/613a1f75041f837361fcdcce8a5d46f42df1df92/hosts/nyarlathotep/configuration.nix#L59
[a DNS blocklist]: ./use-a-dns-blocklist.md
[override a domain's `A` or `AAAA` records]: ./override-a-dns-record.md#override-an-a-or-aaaa-record
[override some other DNS records]: ./override-a-dns-record.md#override-any-type-of-record
