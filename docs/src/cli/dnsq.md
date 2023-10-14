dnsq - DNS client
=================

Answers questions in exactly the same way as `resolved`, providing a way to test
configuration changes before deploying them.

For example:

```text
$ /path/to/dnsq www.barrucadu.co.uk. AAAA -Z /path/to/config/zones
;; QUESTION
www.barrucadu.co.uk.    IN      AAAA

;; ANSWER
www.barrucadu.co.uk.    300     IN      CNAME   barrucadu.co.uk.
barrucadu.co.uk.        300     IN      AAAA    2a01:4f8:c0c:bfc1::
```

See `--help` for a full listing of command-line options (which are a subset of
the `resolved` options), and also the [configuration documentation][] and
[guides][].

[configuration documentation]: ../configuration.md
[guides]: ../guides.md
