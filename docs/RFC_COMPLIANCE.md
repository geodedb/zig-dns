# RFC Compliance Status

This document tracks zigdns implementation status for relevant DNS RFCs.

## Legend

| Status | Description |
|--------|-------------|
| Complete | Fully implemented and tested |
| Partial | Core functionality implemented, some features missing |
| Stub | Module exists but implementation is placeholder |
| Planned | Not yet started, tracked in GitLab issues |
| N/A | Not applicable to this library |

---

## Core DNS Protocol

### RFC 1034 - Domain Names: Concepts and Facilities

**Status: Complete**

| Section | Feature | Status | Notes |
|---------|---------|--------|-------|
| 3.1 | Name space | Complete | Full label/name handling |
| 3.6 | Resource Records | Complete | Common types supported |
| 4.1 | Name servers | Complete | Full iterative resolution |
| 4.2 | Zones | Complete | AXFR/IXFR zone transfer (RFC 5936/1995) |
| 5.2 | Stub resolver | Complete | UDP/TCP with fallback |
| 5.3 | Recursive resolver | Complete | QNAME minimization, 0x20 |

### RFC 1035 - Domain Names: Implementation and Specification

**Status: Complete**

| Section | Feature | Status | Notes |
|---------|---------|--------|-------|
| 2.3.1 | Preferred name syntax | Complete | Validation in name.zig |
| 2.3.4 | Size limits | Complete | 63 byte labels, 255 byte names |
| 3.1 | Name representation | Complete | Wire format encoding |
| 3.2 | RR definitions | Complete | A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, DNAME, SRV, CAA, TLSA, SVCB, HTTPS, DNSSEC types |
| 3.3 | Standard RRs | Complete | All common RR types implemented including SRV, CAA, TLSA, SVCB/HTTPS |
| 4.1.1 | Header format | Complete | Full header parsing |
| 4.1.2 | Question format | Complete | QNAME/QTYPE/QCLASS |
| 4.1.3 | RR format | Complete | NAME/TYPE/CLASS/TTL/RDATA |
| 4.1.4 | Message compression | Complete | Pointer handling |
| 4.2.1 | UDP usage | Complete | Full implementation |
| 4.2.2 | TCP usage | Complete | 2-byte length prefix |
| 7.4 | Caching | Complete | TTL-aware with SOA minimum negative caching (RFC 2308) |

---

## DNSSEC

### RFC 4033 - DNS Security Introduction and Requirements

**Status: Primitives only — NOT wired into resolution (Ed25519/ECDSA implemented; RSA 5/8/10 not implemented)**

DNSSEC validation primitives exist in `src/resolver/dnssec.zig`, but the
validator is not invoked by the resolution pipeline and outgoing queries do not
set the EDNS DO bit, so resolved answers are not validated. No integrity
guarantee is provided. Tracked by issues #207 / #255.

### RFC 4034 - Resource Records for DNSSEC

**Status: Partial (Ed25519/ECDSA complete; RSA algorithms 5/8/10 not implemented)**

| Record Type | Status | Issue | Notes |
|-------------|--------|-------|-------|
| DNSKEY | Complete | [#13](https://gitlab.com/devnw/zig/dns/-/issues/13) | parseDNSKEY() with KSK/ZSK detection |
| RRSIG | Complete | [#13](https://gitlab.com/devnw/zig/dns/-/issues/13) | parseRRSIG() with validity checking |
| NSEC | Complete | [#15](https://gitlab.com/devnw/zig/dns/-/issues/15) | parseNSEC() with type bitmap |
| DS | Complete | [#14](https://gitlab.com/devnw/zig/dns/-/issues/14) | parseDS() with digest verification |
| NSEC3 | Complete | [#15](https://gitlab.com/devnw/zig/dns/-/issues/15) | parseNSEC3() with opt-out support |
| NSEC3PARAM | Complete | [#15](https://gitlab.com/devnw/zig/dns/-/issues/15) | parseNSEC3PARAM() |

### RFC 4035 - Protocol Modifications for DNSSEC

**Status: Complete (Ed25519/ECDSA, RSA requires external lib)**

| Feature | Status | Issue | Notes |
|---------|--------|-------|-------|
| Signature validation | Complete | [#16](https://gitlab.com/devnw/zig/dns/-/issues/16) | Ed25519, ECDSA P-256/P-384 via std.crypto |
| Chain of trust | Complete | [#17](https://gitlab.com/devnw/zig/dns/-/issues/17) | Trust anchor to leaf validation |
| Authenticated denial | Complete | [#15](https://gitlab.com/devnw/zig/dns/-/issues/15) | NSEC/NSEC3 NXDOMAIN/NODATA proofs |

Note: RSA signature verification (algorithms 5, 8, 10) requires external crypto library.

### RFC 5155 - NSEC3 Hashed Authenticated Denial

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| NSEC3 parsing | Complete | Full record parsing with type bitmaps |
| NSEC3PARAM parsing | Complete | Zone parameters extraction |
| Hash computation | Complete | SHA-1 iterated hashing |
| Opt-out support | Complete | Unsigned delegation detection |
| NXDOMAIN proof | Complete | Hash range coverage |
| NODATA proof | Complete | Type bitmap absence |

---

## EDNS and Extensions

### RFC 6891 - Extension Mechanisms for DNS (EDNS0)

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| OPT pseudo-RR | Complete | Parsing and encoding |
| UDP payload size | Complete | Default 4096, negotiable |
| Extended RCODE | Complete | 12-bit RCODE support |
| DNSSEC OK (DO) | Not wired | OPT-record machinery exists, but resolver queries do not set the DO bit (#207) |
| Option iteration | Complete | Generic option parsing |

### RFC 7871 - Client Subnet in DNS Queries

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| ClientSubnet struct | Complete | Full parsing and encoding |
| IPv4/IPv6 support | Complete | Address family detection |
| Prefix handling | Complete | Truncated address encoding |
| Option builder | Complete | buildOption() helper |

See [#20](https://gitlab.com/devnw/zig/dns/-/issues/20).

### RFC 7873 - DNS Cookies

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| Cookie struct | Complete | Full parsing and encoding |
| Client cookie | Complete | 8-byte generation |
| Server cookie | Complete | 8-32 byte handling |
| SipHash computation | Complete | computeClientCookie() |
| Option builder | Complete | buildOption() helper |

See [#21](https://gitlab.com/devnw/zig/dns/-/issues/21).

---

## Negative Caching

### RFC 2308 - Negative Caching of DNS Queries

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| NXDOMAIN caching | Complete | SOA minimum extraction implemented |
| NODATA caching | Complete | Full support with SOA minimum |
| Negative TTL | Complete | min(SOA TTL, SOA MINIMUM) per RFC |
| Zone-level NXDOMAIN | Complete | Optional optimization |
| TTL clamping | Complete | Configurable max negative TTL |

---

## Transport Protocols

### RFC 7858 - DNS over TLS (DoT)

**Status: Complete (TLS backend required)**

| Feature | Status | Notes |
|---------|--------|-------|
| TLS backend interface | Complete | Pluggable TlsBackend abstraction |
| ALPN ("dot") | Complete | Validation enforced |
| Certificate validation | Complete | Via TLS backend |
| Port 853 | Complete | Default configured |
| Connection pooling | Complete | Keepalive with idle timeout |
| RFC 7858 Strict Profile | Complete | SNI, ALPN, cert validation |

Note: Requires external TLS library implementation of TlsBackend interface.

### RFC 8484 - DNS over HTTPS (DoH)

**Status: Complete (HTTP backend required)**

| Feature | Status | Notes |
|---------|--------|-------|
| HTTP backend interface | Complete | Pluggable HttpBackend abstraction |
| GET with ?dns= | Complete | base64url encoding |
| POST method | Complete | application/dns-message body |
| application/dns-message | Complete | Content type handling |
| Accept header | Complete | Proper content negotiation |
| Connection management | Complete | Configurable timeout |

Note: Requires external HTTP/2 library implementation of HttpBackend interface.

See [#18](https://gitlab.com/devnw/zig/dns/-/issues/18).

### RFC 9250 - DNS over QUIC (DoQ)

**Status: Complete (QUIC backend required)**

| Feature | Status | Notes |
|---------|--------|-------|
| QUIC backend interface | Complete | Pluggable QuicBackend abstraction |
| ALPN ("doq") | Complete | Validation enforced |
| 2-byte length prefix | Complete | prepareDoQMessage() |
| Message ID = 0 | Complete | Enforced per RFC |
| Stream management | Complete | Open/read/close operations |
| Connection pooling | Complete | Reusable connections |

Note: Requires external QUIC library implementation of QuicBackend interface.

See [#19](https://gitlab.com/devnw/zig/dns/-/issues/19).

---

## Resolver Behavior

### RFC 7816 - QNAME Minimization

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| Minimized queries | Complete | zoneAtDepth(), minimizedName() |
| Privacy protection | Complete | Only needed labels sent |
| Integration | Complete | Enabled by default in resolver |

### RFC 5936 - DNS Zone Transfer (AXFR)

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| TCP transport | Complete | 2-byte length prefix |
| Multi-message support | Complete | Handles large zones |
| SOA boundary detection | Complete | Transfer start/end markers |
| Zone record parsing | Complete | All common record types |
| Serial verification | Complete | Configurable option |

### RFC 1995 - Incremental Zone Transfer (IXFR)

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| Incremental changes | Complete | Deletion/addition sets |
| SOA serial tracking | Complete | Old/new serial detection |
| AXFR fallback | Complete | Detects full zone response |
| Changeset parsing | Complete | IxfrChangeset structure |

### RFC 5452 - Measures for Making DNS More Resilient

**Status: Complete**

| Feature | Status | Notes |
|---------|--------|-------|
| Bailiwick checking | Complete | In-bailiwick record filtering |
| TTL capping | Complete | Configurable max TTL |
| Source validation | Complete | Address verification |
| Transaction ID check | Complete | ID matching in resolver |
| 0x20 randomization | Complete | In name.zig |

---

## Record Types

### Core Records (RFC 1035)

| Type | ID | Status | Notes |
|------|-----|--------|-------|
| A | 1 | Complete | parseA() |
| NS | 2 | Complete | parseName() |
| CNAME | 5 | Complete | parseName() |
| SOA | 6 | Complete | parseSOA() |
| PTR | 12 | Complete | parseName() |
| MX | 15 | Complete | parseMX() |
| TXT | 16 | Complete | parseTXT() |

### IPv6 (RFC 3596)

| Type | ID | Status | Notes |
|------|-----|--------|-------|
| AAAA | 28 | Complete | parseAAAA() |

### Service Discovery

| Type | ID | Status | Notes |
|------|-----|--------|-------|
| SRV | 33 | Complete | parseSRV() |
| SVCB | 64 | Complete | parseSVCB() with params |
| HTTPS | 65 | Complete | parseSVCB() with params |

### Security

| Type | ID | Status | Notes |
|------|-----|--------|-------|
| CAA | 257 | Complete | parseCAA() |
| TLSA | 52 | Complete | parseTLSA() |
| DNSKEY | 48 | Complete | parseDNSKEY() |
| DS | 43 | Complete | parseDS() |
| RRSIG | 46 | Complete | parseRRSIG() |
| NSEC | 47 | Complete | parseNSEC() |
| NSEC3 | 50 | Complete | parseNSEC3() |
| NSEC3PARAM | 51 | Complete | parseNSEC3PARAM() |

### Other

| Type | ID | Status | Notes |
|------|-----|--------|-------|
| DNAME | 39 | Complete | parseName() |
| OPT | 41 | Complete | EDNS pseudo-RR |
| AXFR | 252 | Complete | Full zone transfer (RFC 5936) |
| IXFR | 251 | Complete | Incremental zone transfer (RFC 1995) |

---

## Compliance Testing

Run RFC-specific test suites:

```bash
zig build test-rfc1035     # RFC 1035 core protocol
zig build test-rfc3596     # RFC 3596 IPv6 (AAAA)
zig build test-rfc6891     # RFC 6891 EDNS(0)
zig build test-vectors     # RFC test vectors
zig build test-accept      # Acceptance tests
```

---

## References

- [IANA DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [DNS RFC Index](https://www.isc.org/docs/dns-rfcs/)
- [DNSSEC Algorithm Numbers](https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml)
