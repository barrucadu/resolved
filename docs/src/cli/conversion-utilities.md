Conversion utilities
====================

This is a collection of four programs for converting between hosts files and
zones files:

- `htoh` - Read a hosts file from stdin, output it in a normalised form to stdout.
- `htoz` - Read a hosts file from stdin, convert it to a zone file, and output it in a normalised form to stdout.
- `ztoh` - Read a zone file from stdin, convert it to a hosts file, and output it in a normalised form to stdout.
- `ztoz` - Read a zone file from stdin, output it in a normalised form to stdout.


ztoh
----

Hosts files can only contain non-wildcard A and AAAA records, so this conversion
is lossy.

- `--strict` - Return an error if the zone file contains any records which cannot be represented in a hosts file
