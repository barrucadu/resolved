Introduction to DNS
===================

The Domain Name System is a huge distributed eventually-consistent database
mapping names, like `www.barrucadu.co.uk`, to numbers, like `116.203.34.201`.
It's federated, with trusted entities delegating control of segments of the DNS
namespace to others.  It holds hundreds of millions of records, and updates to
this database are typically visible in minutes to hours.

And the protocol behind it is not massively different to when it was
standardised in the 1980s in [RFC 1034: Domain Names - Concepts and
Facilities][RFC 1034] and [RFC 1035: Domain Names - Implementation and
Specification][RFC 1035].

This page gives an overview of how all this works, covering:

1. The DNS protocol
2. How your browser gets from `www.barrucadu.co.uk` to an IP address
3. What a "zone" is
4. The difference between authoritative, recursive, and forwarding nameservers
5. What happens when you update a DNS record (there's no such thing as "propagation")


The DNS protocol
----------------

Let's start with an example (the `+noedns` flag turns off some extensions to the
basic DNS protocol):

```text
$ dig +noedns www.barrucadu.co.uk

; <<>> DiG 9.18.19 <<>> +noedns www.barrucadu.co.uk
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42090
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.barrucadu.co.uk.           IN      A

;; ANSWER SECTION:
www.barrucadu.co.uk.    300     IN      CNAME   barrucadu.co.uk.
barrucadu.co.uk.        300     IN      A       116.203.34.201

;; Query time: 28 msec
;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)
;; WHEN: Sat Oct 14 15:22:49 BST 2023
;; MSG SIZE  rcvd: 67
```

I've used `dig` a lot so I'm fairly used to reading this output, but I've since
realised I wasn't *really* reading it.

What does `flags: qr rd ra` mean?  What about `AUTHORITY` and `ADDITIONAL`?

Also, all the domain names there have a trailing dot.  What's that about?

Time to dig into the protocol.  [RFC 1035][] is our guide here.

### Format of a DNS Message

DNS has two types of messages, queries and responses, and uses port 53.  It
prefers UDP but, if a message is too long to send in a single UDP datagram, it
falls back to TCP.

A DNS message has five parts.  These are:

1. A header, which specifies what sort of message this is and how many entries
   are in the other parts. This also has those flags we saw in the `dig` output.

2. The "question section", which specifies what sort of records the client is
   interested in.  In principle you can ask multiple questions in a single
   query, but in practice this isn't widely supported.

3. The "answer section", a collection of records directly answering the
   questions.

4. The "authority section", a series of `NS` records pointing to an
   authoritative source which can answer the questions.

5. The "additional section", a series of records which may be useful when using
   records from the answer and authority sections.  For example, the `A` records
   for any nameservers given in the authority section.  This is often omitted to
   save space.

The answer, authority, and additional sections won't be present in a query.  But
the question section *will* be present in a response: it's copied over from the
query.

### The Header

The header is 12 bytes long and has a few different fields packed in there.
[RFC 1035][] has some nice ASCII art illustrations:

```text
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Where,

- `ID` is a 16-bit random identifier set by the client and copied into the
  response by the server.  Since UDP is connectionless, the ID is essential for
  the client to know which response goes with which query.

- `QR` indicates whether this is a query (0) or a response (1).

- `OPCODE` is a four-bit field, set by the client and copied into the response
  by the server, indicating what type of query this message is.  The most common
  opcode is 0, which is a "standard query".

- `AA` ("Authoritative Answer") is set by the server and means that this
  response is *authoritative*.

  More on authority in [zones](#zones).

- `TC` ("Truncation") is set by the server and means that the full response
  couldn't fit in a single UDP datagram, and so the client should try again
  using TCP.

- `RD` ("Recursion Desired") is set by the client, and copied into the response
  by the server, and means that they would like the server to answer the
  question recursively, if they can.

  More on recursive and non-recursive resolution in [how resolution
  happens](#how-resolution-happens).

- `RA` ("Recursion Available") is set by the server and means that it can
  perform recursive resolution, if requested.

- `Z` is reserved for future use, and so should be set to zero if you don't
  implement those future standards.

- `RCODE` is a four-bit field, set by the server, indicating what type of
  response this message is.  There are a few common ones:

  - 0 means no error
  - 1 means the server couldn't understand the query
  - 2 means the server encountered an error processing the query
  - 3 means the domain name in the query doesn't exist
  - 4 means the server doesn't support this sort of query
  - 5 means the server refused to answer the query

- `QDCOUNT`, `ANCOUNT`, `NSCOUNT`, and `ARCOUNT` are 16-bit integers specifying
  the number of entries in the question, answer, authority, and additional
  sections (respectively) of the message.

All the multi-byte fields in a DNS message are unsigned and big endian.

### Domain Names

Before diving into the other sections, let's have a look at how domain names are
encoded.  They show up a lot, after all.

Let's take the domain name `www.barrucadu.co.uk.`, and separate it by dots.
This gives us a sequence of *labels*:

1. `www`
2. `barrucadu`
3. `co`
4. `uk`
5. (the empty label)

How you actually interpret those labels is a bit confused, unfortunately.

[RFC 1035][] says that they are sequences of arbitrary octets and that you can't
assume any particular character encoding, but it *also* says that labels are to
be compared case-insensitively.

[RFC 4343][] clarifies that that means octets in the range `0x41` to `0x5a` (the
upper case ASCII letters) are considered equal to corresponding octets in the
range `0x61` to `0x7a` (the lower case ASCII letters), and vice versa, but that
that *still* doesn't mean that labels are ASCII, as they can also contain
arbitrary non-ASCII octets.

But there's also [RFC 3492][], which defines the punycode standard for encoding
internationalised, *i.e.* unicode, domain names into ASCII.  So maybe domain
names *are* ASCII after all?

There may well be a later RFC which resolves this ambiguity and says that labels
are definitely ASCII, but I haven't seen it yet.

Anyway, back to the topic of encoding.

A label is encoded as a one-octet length field followed by the octets of the
label.  And an encoded domain name is a sequence of encoded labels.  This means
that a domain name ends with `0x00`, the length of the empty label (and also
makes encoded domain names work as null-terinated C strings, what a handy
coincidence).

So `www.barrucadu.co.uk` is encoded as:

```text
0x03 w w w 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00
```

There are two restrictions on domain names:

- A single label may be no more than 63 octets long (not including the length
  octet)

- An entire encoded domain name may be no more than 255 octets long (including
  the label length octets)

#### Compression

Domain names get repeated a lot in DNS messages, and the 512 bytes of a UDP
datagram can start to feel pretty limiting.  So DNS also has a compression
mechanism, where some suffix of a domain name can be replaced with a pointer to
an earlier occurrence of that name.

So if the name `www.barrucadu.co.uk.` appears in a message twice, the
second occurrence could be represented as:

- `www.barrucadu.co.uk.`
- `www.barrucadu.co.[pointer to 'uk.']`
- `www.barrucadu.[pointer to 'co.uk.']`
- `www.[pointer to 'barrucadu.co.uk.']`
- `[pointer to 'www.barrucadu.co.uk.']`

But how do you distinguish between a regular label and a pointer?  Well,
remember that a label can't be longer than 63 octets.  And what's 63 as an 8-bit
binary number?

It's `00111111`.

There's two whole bits there at the front which are completely wasted!

So pointers are encoded as the two-octet sequence `11[14-bit index into
message]`.

Pretty clever.

### Questions

```text
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Where,

- `QNAME` is the domain name, which can be any length (so long as it's properly
  encoded), it's not padded to any specific size.

- `QTYPE` is a 16-bit integer specifying the type of records the client is
  interested in.  Which will usually be a record type (see the next subsection)
  or 255, meaning "all records".  There are a few other `QTYPE`s but those are
  less common.

- `QCLASS` is a 16-bit integer specifying which *network class* the client is
  interested in.  These days this will always be 1, or `IN`, for
  "internet".

As an aside, it feels kind of wasteful that we effectively throw away 16 whole
bits for each question and record on the historical "class" artefact.  UDP
messages are short, so we compress domain names to squeeze out a little extra
space, but then we waste a bunch like this!  Even worse, there never were very
many network classes: [RFC 1035][] only defines *four*.  Did the IETF really
expect there to be so many non-internet networks in the future?

We can now understand the question section of our `dig` example!

```
;; QUESTION SECTION:
;www.barrucadu.co.uk.           IN      A
```

Means that it's looking for an internet address record for
`www.barrucadu.co.uk.` (yes, it shows the type and class the other
way around).  That question is encoded as:

```
0x03 w w w 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00  ; qname:  www.barrucadu.co.uk.
0x00 0x01                                                 ; qtype:  A
0x00 0x01                                                 ; qclass: IN
```

### Resource Records

The answer, authority, and additional sections are all a sequence of
*resource records*:

```asciiart
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Where,

- `NAME` is the domain name, which is variable-length like the `QNAME` of a
  question.

- `TYPE` is a 16-bit integer specifying what sort of record this is.  There are
  a fair few of these, but some common ones are:

  - 1, an `A` record
  - 2, a `NS` record
  - 5, a `CNAME` record
  - 28, a `AAAA` record (from [RFC 3596][])
  - and plenty others

- `CLASS` is a 16-bit integer specifying what network class this record applies
  to.  Like the `QCLASS`, these days this will always be 1.  Unless you're
  specifically running some sort of old non-IP-based network for fun.

- `TTL` is a 32-bit integer specifying the number of seconds that this record is
  valid for.  This is important for caching purposes.  Zero has a special
  meaning: it means that you can use the record to do whatever it is you're
  doing *right now*, but that you can't cache it at all.

- `RDLENGTH` is a 16-bit integer specifying the length of the `RDATA` section.

- `RDATA` is the record data, which is type- and class-specific.  For example:

  - `IN A` records hold an IPv4 address, as a 32-bit number
  - `IN NS` and `IN CNAME` records hold a domain name
  - `IN AAAA` records hold an IPv6 address, as a 128-bit number

Returning to our `dig` example, we had two different resource records in the
response:

```
;; ANSWER SECTION:
www.barrucadu.co.uk.    300     IN      CNAME   barrucadu.co.uk.
barrucadu.co.uk.        300     IN      A       116.203.34.201
```

We have one `IN CNAME` record for `www.barrucadu.co.uk.` and one `IN A` record
for `barrucadu.co.uk.`.  This is because, upon encountering a `CNAME`,
resolution starts again with whatever name the `CNAME` refers to (unless the
query was for, say `IN CNAME www.barrucadu.co.uk` - more on this in [how
resolution happens](#how-resolution-happens)).

Leaving out the name compression for simplicity, those records are encoded as:

```
0x03 w w w 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00  ; name:     www.barrucadu.co.uk.
0x00 0x05                                                 ; type:     CNAME
0x00 0x01                                                 ; class:    IN
0x00 0x00 0x01 0x2c                                       ; ttl:      300
0x00 0x11                                                 ; rdlength: 17
0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00             ; rdata:    barrucadu.co.uk.

0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00             ; name:     barrucadu.co.uk.
0x00 0x01                                                 ; type:     A
0x00 0x01                                                 ; class:    IN
0x00 0x00 0x01 0x2c                                       ; ttl:      300
0x00 0x04                                                 ; rdlength: 4
0x74 0xcb 0x22 0xc9                                       ; rdata:    116.203.34.201
```

### Example DNS query & response

Returning to our `dig +noedns www.barrucadu.co.uk` example from the beginning,
we can now see the whole encoded query and response.  I've included comments and
linebreaks to make it clear what's what.

Here's the query:

```
;; header
0xa4 0x6a ; ID: 46676
0x01 0x00 ; flags: RD
0x00 0x01 ; QDCOUNT: 1
0x00 0x00 ; ANCOUNT: 0
0x00 0x00 ; NSCOUNT: 0
0x00 0x00 ; ARCOUNT: 0

;; question section
; www.barrucadu.co.uk. A IN
0x03 w w w 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00 0x00 0x01 0x00 0x01
```

And here's the response (omitting compression):

```
;; header
0xa4 0x6a ; ID: 46676
0x81 0x80 ; flags: QR, RD, RA
0x00 0x01 ; QDCOUNT: 1
0x00 0x02 ; ANCOUNT: 2
0x00 0x00 ; NSCOUNT: 0
0x00 0x00 ; ARCOUNT: 0

;; question section
; www.barrucadu.co.uk. A IN
0x03 w w w 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00 0x00 0x01 0x00 0x01

;; answer section
; www.barrucadu.co.uk. CNAME IN 300 barrucadu.co.uk.
0x03 w w w 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00 0x00 0x05 0x00 0x01 0x00 0x00 0x01 0x2c 0x00 0x11 0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00
; barrucadu.co.uk. A IN 300 116.203.34.201
0x09 b a r r u c a d u 0x02 c o 0x02 u k 0x00 0x00 0x01 0x00 0x01 0x00 0x00 0x01 0x2c 0x00 0x04 0x74 0xcb 0x22 0xc9
```

And that's that!

The DNS protocol isn't very complicated.  But it *is* somewhat fiddly, what with
each record type having its own `RDATA` format, and the domain name compression.


How resolution happens
----------------------

When we ran `dig +noedns www.barrucadu.co.uk` in the previous section, we got an
answer.  We found the IP address which `www.barrucadu.co.uk.` refers to.

But *how?*

Well, `dig` tells us that it talked to some server at 1.1.1.1.  But how did
*that* server know?  Does it have a copy of the entire DNS?  Unlikely, since
there are hundreds of millions of records in use.

The answer is that the server followed a process called *recursive resolution*.
This is described in section 5.3.3 of [RFC 1034][]:

1. See if we already know the answer (*e.g.* the relevant records are already
   cached), and return it to the client if so
2. Figure out the best nameservers to ask
3. Send them queries until one responds
4. Analyse the response:
   - If the response answers the question, cache it and return it to the client
   - If the response gives some better nameservers to use, cache them and go
     back to step 2
   - If the response gives a CNAME, and this is not the answer, cache the CNAME
     record and start again with the new name
   - If the response is an error or doesn't make sense, go back to step 3

On the face of it this looks pretty straightforward, but on closer inspection
that step 2 is doing a lot of work: how exactly do we "figure out the best
nameservers to ask"? (That step 1 is also doing a surprising amount of work if
your nameserver supports authoritative zones (see next section) - for the full
details, see section 4.3.2 of [RFC 1034][]).

Well, step 4.b gives us a clue here: *if the response gives some better
nameservers to use, cache them and go back to step 2.*  So we don't need to pick
the correct nameservers at the very beginning.  We only need to know about a
nameserver which will be able to point us to a nameserver which knows that (or
is closer to knowing that).

There are thirteen nameservers which, transitively, know about *every* domain
name.  These are the root nameservers, and they're where recursive resolution
starts.

You can find them at `a.root-servers.net.` through `m.root-servers.net.`

So you just point your recursive resolver at, say, `j.root-servers.net.`
and... oh wait, we have a chicken-and-egg problem.  Ultimately, you need to know
their IP addresses.  IANA, the Internet Assigned Numbers Authority, provides the
["root hints" file][], which has the IPv4 and IPv6 addresses of these root
nameservers.

How do you download that file if you don't have DNS working to resolve
`www.iana.org.`?  Look, you just need IP addresses to get DNS and DNS to get IP
addresses.  Use 1.1.1.1 or something while you get your fancy recursive resolver
working.

Alright, let's resolve `www.barrucadu.co.uk.` recursively!  Starting with:

```text
$ dig www.barrucadu.co.uk @j.root-servers.net

; <<>> DiG 9.18.19 <<>> www.barrucadu.co.uk @j.root-servers.net
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52538
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 17
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1472
;; QUESTION SECTION:
;www.barrucadu.co.uk.           IN      A

;; AUTHORITY SECTION:
uk.                     172800  IN      NS      nsa.nic.uk.
uk.                     172800  IN      NS      nsb.nic.uk.
uk.                     172800  IN      NS      nsc.nic.uk.
uk.                     172800  IN      NS      nsd.nic.uk.
uk.                     172800  IN      NS      dns1.nic.uk.
uk.                     172800  IN      NS      dns2.nic.uk.
uk.                     172800  IN      NS      dns3.nic.uk.
uk.                     172800  IN      NS      dns4.nic.uk.

;; ADDITIONAL SECTION:
nsa.nic.uk.             172800  IN      A       156.154.100.3
nsb.nic.uk.             172800  IN      A       156.154.101.3
nsc.nic.uk.             172800  IN      A       156.154.102.3
nsd.nic.uk.             172800  IN      A       156.154.103.3
dns1.nic.uk.            172800  IN      A       213.248.216.1
dns2.nic.uk.            172800  IN      A       103.49.80.1
dns3.nic.uk.            172800  IN      A       213.248.220.1
dns4.nic.uk.            172800  IN      A       43.230.48.1
nsa.nic.uk.             172800  IN      AAAA    2001:502:ad09::3
nsb.nic.uk.             172800  IN      AAAA    2001:502:2eda::3
nsc.nic.uk.             172800  IN      AAAA    2610:a1:1009::3
nsd.nic.uk.             172800  IN      AAAA    2610:a1:1010::3
dns1.nic.uk.            172800  IN      AAAA    2a01:618:400::1
dns2.nic.uk.            172800  IN      AAAA    2401:fd80:400::1
dns3.nic.uk.            172800  IN      AAAA    2a01:618:404::1
dns4.nic.uk.            172800  IN      AAAA    2401:fd80:404::1

;; Query time: 12 msec
;; SERVER: 192.58.128.30#53(j.root-servers.net) (UDP)
;; WHEN: Sat Oct 14 15:26:42 BST 2023
;; MSG SIZE  rcvd: 552
```

Alright, we now know the names and IP addresses of the `uk.`  nameservers.
Thanks, additional section!

On we go:

```text
$ dig www.barrucadu.co.uk @156.154.100.3

; <<>> DiG 9.18.19 <<>> www.barrucadu.co.uk @156.154.100.3
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32107
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: e393a7276308963401000000652aa5442e48e9fbe6ee0c99 (good)
;; QUESTION SECTION:
;www.barrucadu.co.uk.           IN      A

;; AUTHORITY SECTION:
barrucadu.co.uk.        172800  IN      NS      ns-1828.awsdns-36.co.uk.
barrucadu.co.uk.        172800  IN      NS      ns-1520.awsdns-62.org.
barrucadu.co.uk.        172800  IN      NS      ns-98.awsdns-12.com.
barrucadu.co.uk.        172800  IN      NS      ns-763.awsdns-31.net.

;; Query time: 12 msec
;; SERVER: 156.154.100.3#53(156.154.100.3) (UDP)
;; WHEN: Sat Oct 14 15:27:16 BST 2023
;; MSG SIZE  rcvd: 215
```

No additional section here, so we'll need to resolve one of those nameservers.
However, if we pick `ns-1828.awsdns-36.co.uk.` we can just ask the `uk.`
nameservers again rather than going back to the root:

```text
$ dig ns-1828.awsdns-36.co.uk. @156.154.101.3

; <<>> DiG 9.18.19 <<>> ns-1828.awsdns-36.co.uk. @156.154.101.3
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1223
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 9
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 3976ec588720dc3001000000652aa5b0bad98873c996aaa1 (good)
;; QUESTION SECTION:
;ns-1828.awsdns-36.co.uk.       IN      A

;; AUTHORITY SECTION:
awsdns-36.co.uk.        172800  IN      NS      g-ns-356.awsdns-36.co.uk.
awsdns-36.co.uk.        172800  IN      NS      g-ns-1511.awsdns-36.co.uk.
awsdns-36.co.uk.        172800  IN      NS      g-ns-932.awsdns-36.co.uk.
awsdns-36.co.uk.        172800  IN      NS      g-ns-1832.awsdns-36.co.uk.

;; ADDITIONAL SECTION:
g-ns-1832.awsdns-36.co.uk. 172800 IN    A       205.251.199.40
g-ns-1511.awsdns-36.co.uk. 172800 IN    A       205.251.197.231
g-ns-932.awsdns-36.co.uk. 172800 IN     A       205.251.195.164
g-ns-356.awsdns-36.co.uk. 172800 IN     A       205.251.193.100
g-ns-1832.awsdns-36.co.uk. 172800 IN    AAAA    2600:9000:5307:2800::1
g-ns-1511.awsdns-36.co.uk. 172800 IN    AAAA    2600:9000:5305:e700::1
g-ns-932.awsdns-36.co.uk. 172800 IN     AAAA    2600:9000:5303:a400::1
g-ns-356.awsdns-36.co.uk. 172800 IN     AAAA    2600:9000:5301:6400::1

;; Query time: 10 msec
;; SERVER: 156.154.101.3#53(156.154.101.3) (UDP)
;; WHEN: Sat Oct 14 15:29:04 BST 2023
;; MSG SIZE  rcvd: 350
```

Getting there, we've now got down to the AWS DNS nameservers.  Next!

```text
$ dig ns-1828.awsdns-36.co.uk. @205.251.199.40

; <<>> DiG 9.18.19 <<>> ns-1828.awsdns-36.co.uk. @205.251.199.40
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8253
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;ns-1828.awsdns-36.co.uk.       IN      A

;; ANSWER SECTION:
ns-1828.awsdns-36.co.uk. 172800 IN      A       205.251.199.36

;; AUTHORITY SECTION:
awsdns-36.co.uk.        172800  IN      NS      g-ns-1511.awsdns-36.co.uk.
awsdns-36.co.uk.        172800  IN      NS      g-ns-1832.awsdns-36.co.uk.
awsdns-36.co.uk.        172800  IN      NS      g-ns-356.awsdns-36.co.uk.
awsdns-36.co.uk.        172800  IN      NS      g-ns-932.awsdns-36.co.uk.

;; ADDITIONAL SECTION:
g-ns-1511.awsdns-36.co.uk. 172800 IN    A       205.251.197.231
g-ns-1511.awsdns-36.co.uk. 172800 IN    AAAA    2600:9000:5305:e700::1
g-ns-1832.awsdns-36.co.uk. 172800 IN    A       205.251.199.40
g-ns-1832.awsdns-36.co.uk. 172800 IN    AAAA    2600:9000:5307:2800::1
g-ns-356.awsdns-36.co.uk. 172800 IN     A       205.251.193.100
g-ns-356.awsdns-36.co.uk. 172800 IN     AAAA    2600:9000:5301:6400::1
g-ns-932.awsdns-36.co.uk. 172800 IN     A       205.251.195.164
g-ns-932.awsdns-36.co.uk. 172800 IN     AAAA    2600:9000:5303:a400::1

;; Query time: 12 msec
;; SERVER: 205.251.199.40#53(205.251.199.40) (UDP)
;; WHEN: Sat Oct 14 15:30:26 BST 2023
;; MSG SIZE  rcvd: 338
```

We've got an IP address for `ns-1828.awsdns-36.co.uk.`!  Now we can answer our
original question:

```
$ dig www.barrucadu.co.uk @205.251.199.36

; <<>> DiG 9.18.19 <<>> www.barrucadu.co.uk @205.251.199.36
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62416
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.barrucadu.co.uk.           IN      A

;; ANSWER SECTION:
www.barrucadu.co.uk.    300     IN      CNAME   barrucadu.co.uk.
barrucadu.co.uk.        300     IN      A       116.203.34.201

;; AUTHORITY SECTION:
barrucadu.co.uk.        172800  IN      NS      ns-1520.awsdns-62.org.
barrucadu.co.uk.        172800  IN      NS      ns-1828.awsdns-36.co.uk.
barrucadu.co.uk.        172800  IN      NS      ns-763.awsdns-31.net.
barrucadu.co.uk.        172800  IN      NS      ns-98.awsdns-12.com.

;; Query time: 12 msec
;; SERVER: 205.251.199.36#53(205.251.199.36) (UDP)
;; WHEN: Sat Oct 14 15:31:20 BST 2023
;; MSG SIZE  rcvd: 212
```

And we're done, after 5 requests to other nameservers.  But in practice, a
recursive resolver would likely have some of those already cached and wouldn't
need to fetch them again.

["root hints" file]: https://www.iana.org/domains/root/files


Zones
-----

In the previous section, it looked very much like the DNS was broken up into
subtrees (or "zones", if you will) based on the label structure: the `.`
nameservers knew about the `uk.` nameservers, but couldn't answer queries about
subdomains of those directly; and similarly, the `uk.` nameservers knew about
the nameservers for `barrucadu.co.uk.`, but not any of its other records.

This makes sense.  Imagine if the root nameservers knew every DNS record!  Their
databases would be *huge!*  It would be infeasible to run a handful of servers
which know hundreds of millions of records and which the whole world uses.

So `.` is a zone.  And `uk.` is a zone.  And `barrucadu.co.uk.` is a zone.  All
of the TLDs are zones, and every domain you can buy creates a new zone.  A zone
can be bigger than a single label, *e.g.*  `foo.bar.baz.barrucadu.co.uk.` is in
the `barrucadu.co.uk.` zone unless I *delegate* it to someone else, by creating
some `NS` records for, say, `baz.barrucadu.co.uk.`

That's exactly how registering a domain name works, by the way.  The registrars
have privileged access to the TLD nameservers, and you pay them some money for
them to send a message to the nameservers saying "please delegate `barrucadu` to
these other nameservers".

Zones are traditionally represented in a textual format defined in [RFC 1035][].
You've seen this format before: it's the format `dig` gives its responses in and
it's the format of the root hints file.

Here's the zone file I use for my LAN DNS (which is served by `resolved`):

```
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

It's a list of records, but note that they all use relative domain names (no dot
at the end).  I could write them as absolute domain names, but that would be
repetitive, and who doesn't want to golf their zone files?  The `$ORIGIN` line
at the top is used to complete any relative names, and the `@` is an alias for
the origin, so this zone file could also be written as:

```
lan. 300 IN SOA lan. lan. 6 300 300 300 300

router.lan.            300 IN A     10.0.0.1

nyarlathotep.lan.      300 IN A     10.0.0.3
*.nyarlathotep.lan.    300 IN CNAME nyarlathotep.lan.

help.lan.              300 IN CNAME nyarlathotep.lan.
*.help.lan.            300 IN CNAME help.lan.

nas.lan.               300 IN CNAME nyarlathotep.lan.

bedroom.awair.lan.     300 IN A     10.0.20.187
living-room.awair.lan. 300 IN A     10.0.20.117
```

Zones come in two types: *authoritative* (also just called a zone, or a master
zone) and *non-authoritative* (also called hints).  An authoritative zone has a
SOA record, and causes the nameserver to give authoritative responses to
questions which fall into that zone (see the next section).

Non-authoritative zones are primarily useful as a sort of permanent cache.  Take
the root hints file for example: all recursive resolvers need to know the `NS`
records for `.`.  But they should *not* act as if they're authoritative for `.`,
they just know a little bit about it.

Since any nameserver could claim to be authoritative for any zone it wants, and
I'm sure malicious nameservers often do try to claim ownership of big sites like
`google.com.`, how does the DNS work?

It works on trust.

You trust that the root nameservers will give you the correct nameservers for
all the TLDs.  You then, in turn, trust that the TLD nameservers will give the
correct nameservers for the domains registered under those TLDs.  And so on, all
the way down to the domain you actually want to resolve.

Not every nameserver operator will be equally trustworthy or competent, so that
trust does erode somewhat as you move further and further away from the root,
but if you do some basic validation of DNS responses (*e.g.* validating that the
answers you get are for domains you know to be delegated to this nameserver),
you can do pretty well.


DNS doesn't "propagate"
-----------------------

When I first got into web development, the common wisdom was that DNS changes
took 24 to 48 hours to "propagate".  But having seen some details of the DNS
protocol and how recursive resolution works, does that really make sense?
Shouldn't changes be visible as soon as the TTL of the old record expires?  And
shouldn't new records be visible immediately?  Why do changes need to propagate?
Where do they propagate to?

Propagation implies a push model, where you make your changes and then they get
sent to the resolvers which need them.  But that's not what happens at all:
instead, caches expire.

Ok, there *are* two cases in which DNS does propagate:

1. If you update your domain's NS records, your registrar needs to push those
   changes to the TLD nameservers.  Apparently this used to be kind of slow,
   like, 20+ years ago.  These days it's very fast.
2. If you run a very high traffic authoritative nameserver, you'll operate
   multiple instances of it around the world to improve reliability and latency.
   So if you change a record, that change needs to be pushed out to all your
   servers.  But this should take under a minute unless something is very wrong.

My hunch is that this 24 to 48 hour window came from:

- Registrars being slow to update the TLD nameservers once upon a time
- ISPs running notoriously poorly-behaving nameservers

Ah, ISP DNS.  Almost the first thing any self-respecting nerd changes when
setting up a new home network.  They often do nefarious things like redirect
misspelled domain names to ad-covered search pages, trying to profit off your
typos.  And, as it turns out, a lot of them ignore TTLs, and will cache
something for a long period if they feel like it.

How long?  Well, I've seen reports of 24 hours...

Well, no matter what the cause of the occasional slow DNS update is (though I
can't say I've experienced slow DNS updates in a very long time, and updates are
evidently fast enough for changing an A record to be considered a viable
failover mechanism for big sites) "propagation" is the wrong mental model.

DNS is pull, not push.


[RFC 1034]: https://datatracker.ietf.org/doc/html/rfc1034
[RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
[RFC 3492]: https://datatracker.ietf.org/doc/html/rfc3492
[RFC 3596]: https://datatracker.ietf.org/doc/html/rfc3596
[RFC 4343]: https://datatracker.ietf.org/doc/html/rfc4343
