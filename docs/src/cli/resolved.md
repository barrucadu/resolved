resolved - DNS server
=====================

```admonish danger
`resolved` hasn't had any sort of security review, so be wary of exposing it on a public network.
```

A typical usage of `resolved` will look like:

```bash
sudo /path/to/resolved --cache-size 1000000     \
                       -Z /path/to/config/zones \
                       -A /path/to/your/hosts   \
                       -Z /path/to/your/zones
```

See `--help` for a full listing of command-line options (most of which can also
be specified via environment variables), and also the [configuration
documentation][] and [guides][].

[configuration documentation]: ../configuration.md
[guides]: ../guides.md


Monitoring
----------

Prometheus metrics are exposed at `http://127.0.0.1:9420/metrics` by default.

Logs are emitted to stdout.  Control the log level with the `RUST_LOG`
environment variable:

- `RUST_LOG=trace` - verbose messages useful for development, like "entered
  function X"
- `RUST_LOG=debug` - warns about strange but recoverable situations, like
  "socket read error"
- `RUST_LOG=info` - gives top-level information, like "new connection" or
  "reloading configuration"
- `RUST_LOG=warn` - warns about recoverable internal errors and invalid
  configuration, like "could not serialise message" or "invalid record in cache"
- `RUST_LOG=error` - warns about fatal errors and then terminates the process,
  like "could not bind socket"

You can also set the log level per component.  A good default `RUST_LOG`
definition is `dns_resolver=info,resolved=info`.

Set the log format with the `RUST_LOG_FORMAT` environment variable, which is a
sequence of comma-separated values:

- One of `full` (default), `compact`, `pretty`, or `json` - see [the
  tracing_subscriber crate][]
- One of `ansi` (default), `no-ansi`
- One of `time` (default), `no-time`

If running under systemd (or some other processor supervisor which automatically
adds timestamps), a good default `RUST_LOG_FORMAT` definition is `json,no-time`.

[the tracing_subscriber crate]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/format/index.html#formatters


Permissions
-----------

DNS uses port 53 (both UDP and TCP).  So `resolved` must be run as root or with
the `CAP_NET_BIND_SERVICE` capability.


Signals
-------

`SIGUSR1` - reload the configuration
