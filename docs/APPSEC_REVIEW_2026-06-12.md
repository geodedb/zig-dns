# Application Security Review — Zig DNS Library

- **Target:** `gitlab.com/devnw/zig/dns` @ branch `main` (commit `86ee75f`), version `0.1.8`
- **Date:** 2026-06-12
- **Reviewer role:** Defensive application-security code review (read-only)
- **Frameworks:** OWASP Top 10:2025, CIS Controls v8.1.2
- **Scope:** Full first-party codebase (`src/`, `cmd/`, `build.zig`, `build.zig.zon`, `scripts/`, CI config). Vendored deps under `zig-pkg/` and the external dependency packages (`cli`, `config`, `thread_pool`, `otel`, `tls`) were **out of scope**.

---

## 1. Scope and Assumptions

**Reviewed (read directly, with line citations throughout):**

- Wire parsers: `src/name.zig` (full), `src/message.zig` (parse path), `src/record.zig` (data structures), `src/edns.zig` (headers).
- Randomness / anti-spoofing: `src/util/random.zig`, `src/recursive.zig` (TXID/CSPRNG), `src/stub.zig` (query path), `src/resolver/cache_protection.zig`, `src/resolver/zone_transfer.zig` (TXID).
- Transaction security: `src/security/tsig.zig` (full), `src/security/sig0.zig` (full).
- DNSSEC: `src/resolver/dnssec.zig` (full, 2019 lines).
- Encrypted transports: `src/transports/{dot,doh,doq,tcp,udp,connection_pool,happy_eyeballs}.zig`, `src/resolver/{failover,split_dns}.zig`, `src/resolver/channel.zig`.
- Recursive resolution path: `src/recursive.zig` (referral/glue/cache logic).
- Supply chain / CI: `.gitlab-ci.yml`, `build.zig.zon`, `SECURITY.md`.

**Assumptions:**

1. This is a **library + CLI** (`zdig`). It does not run as a network-exposed daemon, so the primary trust boundary is **untrusted DNS wire input and zone-file input parsed by library consumers**. There is no user authentication surface; "auth" here means DNS-protocol primitives (TSIG/SIG(0)/DNSSEC).
2. TLS/QUIC/HTTP for DoT/DoH/DoQ are **delegated to caller-supplied backends via vtable interfaces** (`dot.zig:85`, `doh.zig:65`, `doq.zig:28`). The cryptographic correctness of those backends is out of scope; the **library's responsibility to give backends the inputs needed to verify** is in scope.
3. Findings about the DNSSEC validator are weighed against the dispositive fact (Finding A1) that the validator is **not wired into the resolution path**.
4. Severity reflects the library's threat model (`docs/SECURITY.md` claims memory safety, fuzzing, no C deps). No `docs/THREAT_MODEL.md` exists; standard resolver threat model (RFC 5452, RFC 9520, RFC 4035) applied.

**Not reviewed / could not be verified:** runtime behavior (no execution), the external `tls` package internals, the full `record.zig` RDATA parser for every record type, observability sinks (`otel`), and whether any production consumer wires `dnssec.Validator` itself.

---

## 2. Executive Summary

- **The wire-format parsers are robust.** Name decompression enforces hop limits, **rejects forward pointers on every hop including the first** (`name.zig:98-125`), and caps decompressed length at 255 bytes. Message parsing caps section counts at 4096 to prevent parse-loop DoS (`message.zig:37,72-78`). I found **no confirmed memory-safety, OOB, or decompression-bomb vulnerability** in the reviewed parsers (Q1 answered: parsers are sound).
- **TXID + source-port randomization is cryptographically sound on the live query paths.** The stub and recursive resolvers draw each transaction ID directly from the OS CSPRNG per query (`stub.zig:155-159`, `recursive.zig:34-39,172-181`) and fail closed when entropy is unavailable. 0x20 case randomization and full response-matching (TXID+QNAME+QTYPE+QCLASS+source-IP) are implemented (Q2 answered).
- **TSIG and SIG(0) are well-built.** Constant-time MAC comparison, MAC-verified-before-time-check, key/HMAC-state zeroization, and checked integer arithmetic are all present (`tsig.zig:398-435`, `sig0.zig:132-152`) (Q3 answered: comparisons are constant-time and key material is zeroized).
- **Highest-risk issue — DNSSEC is "security theater":** The recursive resolver's `dnssec=true` flag only sets the DO bit to *request* records; **no validation is ever performed** (the `dnssec.Validator` is never called from any resolver — A1). Independently, the validator itself, if a consumer used it directly, contains **fail-open flaws**: denial-of-existence (NSEC/NSEC3) and the DS chain are accepted **without verifying any RRSIG over those records** (A2, A3). A caller relying on this for DNSSEC gets no protection (Q4 answered: yes, downgrade/bypass issues exist).
- **Encrypted transports cannot guarantee cert verification:** DoH and DoQ **never pass a verification hostname (and DoQ never passes the CA bundle) to their backends** (A4, A5), and the library never confirms a cert was verified or a minimum TLS version negotiated. There is **no silent fallback to plaintext** on encrypted-transport failure (they fail closed), which is good (Q5 answered: no silent plaintext downgrade, but unverifiable cert posture is the real risk).
- **Supply chain and CI are strong:** dependencies are pinned by git ref **and** content hash (Zig-enforced), the toolchain is SHA-256-verified, and SAST/secret-scan/SBOM run in CI (Q6 answered: hashes enforced; CI follows good practice).

**Overall confidence: High** for parser, randomness, TSIG/SIG(0), and DNSSEC-wiring findings (all read directly). **Medium** for the transport-backend findings (correctness depends on out-of-scope backend implementations) and the referral-hierarchy finding (exploitability requires an authoritative/on-path attacker).

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP 2025 | Status |
|----|----------|-----------|-------|----------|-----------|--------|
| A1 | High | High | `dnssec=true` requests but never validates DNSSEC (security theater) | `recursive.zig:110,594`; `dnssec.zig` (unreferenced) | A04 / A08 | Open |
| A2 | High | High | NSEC/NSEC3 denial-of-existence accepted without RRSIG verification | `dnssec.zig:220-354` | A08 | Open |
| A3 | High | High | DS chain trusts unauthenticated DS records; `.secure` returned on key-presence | `dnssec.zig:559-580` | A08 | Open |
| A4 | High | Medium | DoH backend never receives verification hostname (SNI) | `doh.zig:102-105,203-206` | A02 / A04 | Open |
| A5 | High | Medium | DoQ transport discards `ca_pem` and passes no server name to backend | `doq.zig:36-42,179-186`; `channel.zig:91-96` | A02 / A04 | Open |
| A6 | Medium | High | Library cannot enforce cert-verified / min-TLS-version; CA guard only on DoT | `dot.zig:211-215,279-287`; `doh.zig:172-175`; `doq.zig` | A02 | Open |
| A7 | Medium | Medium | Recursive resolver accepts upward/lateral referrals (no zone-descent check) | `recursive.zig:705-719,405-457` | A06 | Open |
| A8 | Medium | High | RRSIG verification omits key-tag and signer-bailiwick checks | `dnssec.zig:361-394` | A08 | Open |
| A9 | Low | Medium | SHA-1 DS digest and deprecated algorithms accepted without downgrade policy | `dnssec.zig:594-616,785-831` | A04 | Open |
| A10 | Low | High | `SystemRandom` seeds a non-CSPRNG once (latent footgun, currently unused on hot path) | `util/random.zig:43-70` | A04 | Open |
| A11 | Low | Low | Connection-pool key compares host by 64-bit hash and omits TLS identity | `connection_pool.zig:213-223` | A01 | Open |
| A12 | Low | High | DoH accepts response when `Content-Type` header absent | `doh.zig:234-239,255-260` | A10 | Open |

---

## 4. Finding Details

### A1 — `dnssec=true` requests DNSSEC records but never validates them (security theater)

**Severity: High · Confidence: High · OWASP A04 (Cryptographic Failures) / A08 (Software & Data Integrity) · CWE-325 (Missing Required Cryptographic Step)**

**Evidence.** The recursive resolver exposes `dnssec: bool = false` (`recursive.zig:109-110`). The only place that flag is consumed is building the query:

```zig
// recursive.zig:594
const query = try message_mod.buildQueryBuf(&query_buf, id, query_name, qtype, .in, self.config.dnssec);
```

That sets the EDNS DO bit so the upstream *returns* RRSIG/DNSKEY/NSEC records. A repository-wide search shows the DNSSEC validator (`validateChainOfTrust`, `verifyRrsig`, `validateNxdomainWithNsec`) is **never called from `recursive.zig`, `client.zig`, or `stub.zig`** — only from its own tests. `dnssec.zig` is re-exported as a public API (`lib.zig:99`) but no internal resolution path invokes it. The recursive resolver returns the response as `.success` based solely on record type matching (`recursive.zig:382-394`) with no signature check.

**Attack scenario.** An operator enables `dnssec=true`, believing responses are validated. An on-path or malicious-upstream attacker returns a forged A record (with or without bogus RRSIGs). The resolver accepts and caches it; no `.bogus` is ever produced. The "DNSSEC" setting provides zero integrity guarantee.

**Impact.** False sense of security. Any consumer trusting `dnssec=true` for integrity is fully exposed to cache poisoning / answer forgery from the upstream or an on-path attacker, despite an explicit security control being enabled.

**Root cause.** The validation engine was implemented as a standalone module but never integrated into the resolution state machine.

**Remediation.**

- Until validation is wired in and correct (see A2, A3, A8), **rename the flag or fail loudly**: e.g. `request_dnssec_records` for the DO-bit behavior, and make any `validate_dnssec=true` return an explicit `error.DnssecValidationUnavailable` rather than silently resolving.
- When integrating, the resolver must collect the DNSKEY/DS/RRSIG/NSEC RRsets per zone, call the validator, and **refuse to return/cache `.bogus` results** (return SERVFAIL-equivalent), per RFC 4035 §5.
- Document the current behavior prominently in `docs/SECURITY.md` (which currently does not mention the gap).

**Regression tests.** Add an integration test: feed the resolver a response with a deliberately invalid RRSIG and assert the result is an error/`.bogus`, not `.success`.

---

### A2 — NSEC/NSEC3 denial-of-existence accepted without verifying RRSIG over the NSEC records

**Severity: High · Confidence: High · OWASP A08 · CWE-347 (Improper Verification of Cryptographic Signature)**

**Evidence.** All four denial-of-existence validators check range/bitmap coverage of attacker-supplied records but **never verify a signature over them**:

```zig
// dnssec.zig:220-241  validateNxdomainWithNsec
for (nsec_records) |nsec_rr| {
    if (nsec_rr.rtype != .nsec) continue;
    const nsec = nsec_rr.parseNSEC(full_message) catch continue;
    if (nameInNsecRange(qname_wire.slice(), nsec_rr.name.labels, nsec.next_domain.labels)) {
        return true;            // <-- "proven" with no RRSIG check
    }
}
```

The same pattern holds for `validateNodataWithNsec` (`dnssec.zig:245-270`), `validateNxdomainWithNsec3` (`dnssec.zig:277-311`), and `validateNodataWithNsec3` (`dnssec.zig:314-354`). None calls `verifyRrsig` on the NSEC/NSEC3 RRset before trusting it.

**Attack scenario.** An attacker who can inject records (on-path, or a malicious upstream) supplies unsigned NSEC/NSEC3 records whose range covers the queried name. The validator returns `true` ("authenticated denial"), letting the attacker forge an NXDOMAIN/NODATA for a name that actually exists — e.g., suppressing a CAA record or an MX record to weaken a downstream security decision.

**Impact.** Spoofed authenticated denial-of-existence. Defeats the core DNSSEC guarantee for negative answers.

**Root cause.** These functions validate *structure* (ranges, bitmaps, NSEC3 hashing/iteration caps — which are correctly implemented) but skip the *cryptographic* step.

**Remediation.** Require the NSEC/NSEC3 RRset to be validated via `verifyRrsig` against the zone's already-validated DNSKEY before any range/bitmap logic runs, and enforce that the NSEC owner/signer is in-bailiwick. Implement the full RFC 5155 closest-encloser proof for NSEC3 NXDOMAIN (current single-cover check at `dnssec.zig:299-308` is insufficient).

**Regression tests.** Add tests passing unsigned (and wrong-signer) NSEC/NSEC3 records and assert the validators return `false`/error.

---

### A3 — DS chain trusts unauthenticated DS records; `.secure` returned merely because a key is present

**Severity: High · Confidence: High · OWASP A08 · CWE-345 (Insufficient Verification of Data Authenticity)**

**Evidence.** `validateChainOfTrust` takes a flat `ds_records: []const ResourceRecord` and, for any DS whose digest matches any key, sets `trusted_key` (`dnssec.zig:559-577`). The DS RRset is **never RRSIG-verified** and is not tied to an already-validated parent zone. The final verdict is:

```zig
// dnssec.zig:580
return if (trusted_key != null) .secure else .bogus;
```

So `.secure` is returned whenever *some* key was matched to *some* (unauthenticated) DS — not because the **target RRset's signature** was verified. DS records are public digests and trivially forgeable.

**Attack scenario.** An attacker supplies a DS record they computed over a DNSKEY they control plus that DNSKEY. The digest matches, `trusted_key` is set, and `validateChainOfTrust` returns `.secure` — a full chain-of-trust forgery.

**Impact.** Complete DNSSEC bypass for any consumer that calls `validateChainOfTrust` directly.

**Root cause.** The orchestration conflates "a key digest-matched a DS" with "the chain of trust is established and the data is signed." It also self-signs the apex by raw byte comparison only (`verifyTrustAnchor`, `dnssec.zig:584-620`) without verifying the apex DNSKEY RRSIG, so injected extra keys in the apex RRset can become the trusted KSK (`dnssec.zig:551-557`).

**Remediation.** Rewrite as a proper top-down validator: validate apex DNSKEY RRSIG against the anchor → validate the **DS RRset's RRSIG** against the validated parent key → match DS to child DNSKEY → validate child DNSKEY RRSIG → … → **validate the target data RRset's RRSIG**. `.secure` must require the *target data* signature verified, never mere key presence. Until then, treat `validateChainOfTrust` as unsafe and gate it behind a clear "experimental/incomplete" warning.

**Regression tests.** Feed a forged DS+DNSKEY pair with no valid RRSIG over the target RRset; assert `.bogus`.

---

### A4 — DoH backend never receives the certificate-verification hostname (SNI)

**Severity: High · Confidence: Medium · OWASP A02 / A04 · CWE-295 (Improper Certificate Validation)**

**Evidence.** The DoH `TlsConfig` handed to the HTTP backend contains only the CA bundle and an optional bootstrap IP — **no `server_name`/hostname field**:

```zig
// doh.zig:102-105
pub const TlsConfig = struct {
    ca_pem: []const u8,
    bootstrap_ip: ?channel.SocketAddress,
};
// doh.zig:203-206 — populated with only ca_pem + bootstrap_ip
```

The hostname exists only inside `options.uri` and is used as the request URL (`doh.zig:220-224`). When `bootstrap_ip` is set, the backend dials an IP; the library never tells it which hostname the certificate must match. A backend that derives the verification name from the connect target (the IP) would verify against the IP or nothing.

**Attack scenario.** DoH configured with a `bootstrap_ip`. A backend that verifies against the dial target accepts any CA-trusted certificate for the bootstrap IP (or skips name checking), allowing an on-path attacker to MITM DoH queries.

**Impact.** Defeats DoH confidentiality/integrity for backends that don't independently re-parse the URL authority.

**Root cause.** Interface under-specification: the verification name is not a first-class input to the backend.

**Remediation.** Add `server_name: []const u8` to `HttpBackend.TlsConfig`, populate it from the URL authority, and document that backends MUST use it as the verification name regardless of `bootstrap_ip`.

**Verification.** Add an interface conformance test/fake backend asserting `server_name` is non-empty and matches the URI host.

---

### A5 — DoQ transport discards `ca_pem` and passes no verification name to the backend

**Severity: High · Confidence: Medium · OWASP A02 / A04 · CWE-295**

**Evidence.** The DoQ `connect` vtable takes only `host, port, alpn, timeout_ms` — no `server_name`, no `ca_pem`:

```zig
// doq.zig:36-42
connect: *const fn (ctx, host: []const u8, port: u16, alpn: []const u8, timeout_ms: u32) anyerror!void,
// doq.zig:179-186 — passes options.server_name as `host`; ca_pem never passed
```

`DoQOptions` *has* a `ca_pem` field (`channel.zig:91-96`) but the DoQ transport never reads it. The QUIC/TLS backend therefore receives no configured trust store and no explicit verification hostname from the library.

**Attack scenario / Impact.** Same MITM exposure as A4: certificate verification is entirely at the backend's discretion with no trust material supplied by the configured `ca_pem`.

**Remediation.** Extend `QuicBackend.connect` to accept `server_name` and `ca_pem` (and `use_system_ca`), mirroring DoT (`dot.zig:268-269`), and wire `options.ca_pem` through.

---

### A6 — Library cannot enforce that a cert was verified or a minimum TLS version negotiated; CA-trust guard exists only for DoT

**Severity: Medium · Confidence: High · OWASP A02 · CWE-1188 / CWE-295**

**Evidence.** DoT correctly fails closed when no trust is configured:

```zig
// dot.zig:211-215
if (options.ca_pem.len == 0 and !options.use_system_ca) {
    return error.NoCaTrustConfigured;
}
```

But: (a) **DoH** only checks the URI starts with `https://` (`doh.zig:172-175`) and accepts `ca_pem=""` with no `use_system_ca` opt-in; (b) **DoQ** has no such guard (A5). After connect, DoT verifies ALPN (`dot.zig:279-287`) but **never calls `getTlsVersion()`** to enforce a floor, and there is no `peerVerified()` predicate in the vtable — `tls_version` is a preference hint, not a minimum (`dot.zig:117-118`). A backend negotiating TLS 1.0 or skipping verification is invisible to the library.

**Impact.** Inconsistent, unenforceable transport security posture; silent downgrade/non-verification is undetectable at the library layer.

**Remediation.** Replicate the `dot.zig:211-215` fail-closed guard in `DoHTransport.init` and `DoQTransport.init`; add `use_system_ca` to `DoHOptions`/`DoQOptions`; add `min_tls_version` and a `peerVerified()` predicate to the connection vtables and assert both before sending the first query.

---

### A7 — Recursive resolver accepts upward/lateral referrals (no zone-descent check)

**Severity: Medium · Confidence: Medium · OWASP A06 (Insecure Design) · CWE-345**

**Evidence.** `extractReferral` derives the delegated zone from the **NS owner name in the response itself** (`recursive.zig:708-710`) and only checks that *glue* is in-bailiwick of that claimed zone (`recursive.zig:749-754`). At the call site, the resolver switches `current_zone` to `ref.zone` (`recursive.zig:442-443`) and only enforces a *depth* limit (`recursive.zig:448-450`) — there is **no check that `ref.zone` is at or below the current zone** in the hierarchy.

**Attack scenario.** When the resolver queries an authoritative server it controls (e.g. for `evil.example`), that server returns NS records whose owner name is `bank.com`. The resolver accepts the referral, queries the attacker's listed nameservers for `bank.com`, and caches the resulting (in-bailiwick-to-`bank.com`) answers as authoritative. The glue bailiwick check does not prevent this because it validates glue *against the attacker-claimed zone*, not the claimed zone against the legitimate hierarchy.

**Impact.** Off-path delegation hijack / cache poisoning for unrelated zones. Requires the attacker to be (or control) an authoritative server in the resolution path, or be on-path; not a remote-unauthenticated bug, hence Medium.

**Root cause.** The referral is trusted to define its own zone with no ancestry constraint relative to the query's current delegation point.

**Remediation.** Before accepting a referral, require `isSubdomainOf(ref.zone, current_zone)` (the delegation must descend) and that `ref.zone` is an ancestor-or-equal of the QNAME being resolved. Reject referrals that move sideways or upward. (`isSubdomainOf` at `recursive.zig:879` already exists and can be reused.)

**Regression tests.** Construct a referral whose authority NS owner is a sibling/parent zone of `current_zone`; assert it is rejected.

---

### A8 — RRSIG verification omits key-tag match and signer-bailiwick check

**Severity: Medium · Confidence: High · OWASP A08 · CWE-347**

**Evidence.** `verifyRrsig` (`dnssec.zig:361-394`) checks the validity window and `rrsig.algorithm == dnskey.algorithm`, then verifies the signature — but never checks `rrsig.key_tag` against the DNSKEY's computed key tag, and never validates `rrsig.signer` is in-bailiwick (equal-to-or-parent-of) the RRset owner names. `findRrsig` locates the RRSIG by `type_covered` only (`dnssec.zig:1190-1199`).

**Attack scenario.** An RRSIG whose `signer` is an out-of-bailiwick zone (`evil.com`) over records owned by `victim.com` is accepted as long as `evil.com`'s key is in the validation set — enabling a zone with any validated key to sign records for zones it does not control. The missing `labels`/wildcard validation (no reconstruction of `*.<closest-encloser>` per RFC 4035 §5.3.2) compounds this.

**Impact.** Out-of-bailiwick signer forgery and wildcard-expansion replay. (Contained today by A1 — the validator is unreachable — but a latent High if `dnssec.Validator` is wired in or used by a consumer.)

**Remediation.** In `verifyRrsig`, require `rrsig.key_tag == calculateKeyTag(dnskey_rdata)`, `rrsig.signer` equal to the key's zone, `rrsig.signer` in-bailiwick of every RR owner, and validate `rrsig.labels` against owner label counts (synthesizing the wildcard owner name when fewer, plus requiring the accompanying NSEC/NSEC3 proof).

---

### A9 — SHA-1 DS digests and deprecated algorithms accepted without a downgrade policy

**Severity: Low · Confidence: Medium · OWASP A04 · CWE-327 (Use of a Broken/Risky Cryptographic Algorithm)**

**Evidence.** `verifyTrustAnchor`/`verifyDsMatch` accept SHA-1 DS digests (`dnssec.zig:594-616`, `dsDigestLength`/`computeDsDigest` at `785-831`) with no preference for SHA-256 when both are present (RFC 8624 discourages SHA-1). RSA-SHA1 is reported `isSupported()` in `record.zig` while `verifySignature` returns `error.UnsupportedAlgorithm` for RSA generally — a misleading status. There is no explicit "refuse insecure algorithm" classification distinct from "unsupported."

**Impact.** Downgrade exposure if an attacker can present a SHA-1 DS chain; misleading capability reporting. Low because the digest compare itself is constant-time and length-checked (`dnssec.zig:601-613`), and RSA verification fails closed.

**Remediation.** Prefer/require SHA-256+ DS digests; add an explicit insecure-algorithm rejection list (RSAMD5=1, DSA=3, GOST); correct `isSupported()` for RSA-SHA1.

---

### A10 — `SystemRandom` seeds a non-cryptographic PRNG once (latent footgun)

**Severity: Low · Confidence: High · OWASP A04 · CWE-338 (Use of Cryptographically Weak PRNG)**

**Evidence.** `SystemRandom` seeds `std.Random.DefaultPrng` (xoshiro256++, non-CSPRNG) once from 64 bits of OS entropy, then serves all subsequent values from that stream (`util/random.zig:43-70`). Xoshiro's internal state is recoverable from observed outputs, so if this were used to generate TXIDs/source ports, an attacker could predict future values (RFC 5452, CWE-330).

**Mitigating fact.** A repository search shows `SystemRandom` is referenced **only in its own tests** — the live stub and recursive query paths instead draw each TXID directly from the OS CSPRNG (`stub.zig:155-159`, `recursive.zig:34-39`). The `zone_transfer.zig` TXID path also reseeds a fresh `DefaultPrng` from `getrandom` per call (`zone_transfer.zig:438-443,470-475`) and reads only one `u16`, so it does not expose a predictable stream. So this is a **latent** hazard, not an active vulnerability.

**Remediation.** Either delete `SystemRandom` or make it draw each value directly from `std.Io.randomSecure` (matching the pattern already used elsewhere) so it cannot become a predictable source if a future caller adopts it for security-sensitive values. Add a doc-comment warning against using a seeded `DefaultPrng` for TXIDs/ports.

---

### A11 — Connection-pool key compares host by 64-bit hash and omits TLS identity

**Severity: Low · Confidence: Low · OWASP A01 (Broken Access Control / confused deputy) · CWE-345**

**Evidence.** `ServerKey.eql` compares `host_hash` (constant-seed `Wyhash`) rather than the host string, and the key omits SNI/CA identity (`connection_pool.zig:213-223`). A Wyhash collision between two configured hostnames at the same port+transport could cause connection reuse across servers; TLS-bearing transports sharing host+port but differing in expected cert/SNI would share a pooled connection.

**Impact / caveat.** Low/Low because the pool currently manages raw TCP fds wired only for `.tcp` (`connection_pool.zig:667-673`); DoT/DoH pooling is not exercised in scope, and exploitation requires attacker-chosen colliding hostnames. It is a correctness/abstraction weakness worth fixing before TLS pooling is enabled.

**Remediation.** Store and compare the full host string (keep the hash as a bucket hint only) and include SNI + CA-bundle identity + `use_system_ca` in the key for TLS transports.

---

### A12 — DoH accepts response body when `Content-Type` header is absent

**Severity: Low · Confidence: High · OWASP A10 (Mishandling of Exceptional Conditions) · CWE-755**

**Evidence.** `content_type` is optional; the equality check is skipped when it is `null` (`doh.zig:234-239` GET, `255-260` POST), so a response with no `Content-Type` is accepted and parsed as a DNS message.

**Impact.** Low — downstream `Message.parse` rejects non-DNS bytes — but a misconfigured/hostile endpoint can omit the header to bypass the content-type gate, and the exact-match comparison also rejects valid `application/dns-message; charset=...` variants (a correctness nit).

**Remediation.** Treat a missing `Content-Type` as `error.InvalidContentType` (fail closed); compare case-insensitively on the media-type prefix.

---

## 5. Secure Design Notes (positive controls observed)

- **Name decompression is hardened (CWE-835 / CWE-130).** `LabelIterator.followPointer` enforces a 16-hop cap and **rejects forward pointers on every hop, including the first** (the `SEC-AUDIT-01` regression at `name.zig:880-910` proves the first-hop case). `parse` caps decompressed length at 255 bytes (`name.zig:332-336`) and label length at 63. Extensive security tests cover loops, self-references, and forward chains (`name.zig:1029-1096,1570-1748`).
- **Message parsing bounds resources.** Section counts are capped at 4096 to prevent CPU-bound parse loops (`message.zig:37,72-78`); `Message` borrows the caller's buffer (no copy) with clear ownership docs.
- **TXID/anti-spoofing is correct on live paths.** Per-query OS-CSPRNG TXIDs (`stub.zig:155-159`, `recursive.zig:172-181`), fail-closed entropy probing (`stub.zig:117-123`), UDP source-address validation with a flood-discard cap (`stub.zig:285-306`, `udp.zig:87-90`), full response matching including QR/opcode/QDCOUNT/QNAME/QTYPE/QCLASS (`stub.zig:161-180`), TCP-fallback re-validation (`stub.zig:230-243`), and 0x20 case randomization (`name.zig:691-723`).
- **TSIG is well-implemented.** Constant-time MAC comparison via `std.crypto.timing_safe.eql` per algorithm (`tsig.zig:398-412`), **MAC verified before the time/fudge check** to avoid a timing oracle (`tsig.zig:377-435`), error/other_data correctly included in the MAC input (`tsig.zig:451-492`), HMAC state and secret material securely zeroed (`tsig.zig:160-179,732-735`), and checked arithmetic on ARCOUNT/RDLENGTH/fudge (`tsig.zig:597-599,617,422`).
- **SIG(0) is well-implemented.** Ed25519/ECDSA via `std.crypto`, private-key zeroization on deinit (`sig0.zig:132-152`), checked timestamp arithmetic (`sig0.zig:315-317`), unknown-algorithm enums handled without panic (`sig0.zig:26-61,748-786`).
- **DNSSEC primitives that *are* sound:** constant-time DS digest compare with exact-length enforcement (`dnssec.zig:601-616,837-844`), NSEC3 iteration cap of 150 to prevent CPU-DoS (`dnssec.zig:636-643`), compression-pointer/OOB rejection in canonical-name extraction (`dnssec.zig:1008-1030`), and strict base32hex canonicalization (`dnssec.zig:1128-1155`).
- **Cache-poisoning protections exist and are used.** Bailiwick checks, glue validation (type + NS-target + depth), and TTL clamping (`cache_protection.zig`), enforced on glue (`recursive.zig:749-754`) and on cache insertion via `putRecordWithBailiwick` (`recursive.zig:862`, `dns_cache.zig:497-507`).
- **Supply chain & CI.** Dependencies pinned by git ref **and** Zig-enforced content hash (`build.zig.zon:23-46`); toolchain SHA-256-verified against the official index (`.gitlab-ci.yml:43-82`); SAST, dependency scanning, secret detection, gitleaks, and SBOM generation in CI; coverage-guided fuzzing of parsers (`.gitlab-ci.yml:165-185`, `tests/fuzz_parsers.zig`). Encrypted transports **fail closed** (return errors) rather than silently downgrading to plaintext UDP/53 on failure.

---

## 6. Coverage Gaps and Questions

1. **DNSSEC validator integration is unknown for external consumers.** I confirmed no *internal* resolver calls it (A1). Whether any production consumer wires `dnssec.Validator` directly — and is thus exposed to A2/A3/A8 — is outside this repo. **Question for the team:** is `dnssec.Validator` advertised as production-ready? If so, A2/A3/A8 are effectively High.
2. **TLS/QUIC/HTTP backends are out of scope.** A4/A5/A6 describe the *library's* under-provisioning of verification inputs; actual cert verification correctness depends on the (unreviewed) backend each consumer supplies. Confirm what backend is recommended/shipped.
3. **`record.zig` RDATA parsers** for every record type were not exhaustively reviewed for bounds; the message/name layer caps and the bailiwick layer mitigate, but per-type RDATA parsing (e.g., SVCB/HTTPS, NAPTR) deserves a dedicated pass.
4. **`zone_file.zig`** (929 lines) parsing of untrusted zone files was not fully read; recommend a focused review for resource limits and `$INCLUDE`/`$GENERATE` handling if those are supported.
5. **Diamond-dependency version skew** (e.g., `config` URL `v0.1.5` vs hash `config-0.1.4-…` in `build.zig.zon:28-31`) is a hygiene/SBOM-accuracy concern, not an injection vector (Zig enforces the content hash). Reconcile the pins.
6. **No runtime/dynamic testing** was performed (read-only review). The fuzz harness exists but results were not executed here.

---

## 7. Prioritized Next Actions

1. **(A1) Stop the DNSSEC security-theater immediately.** Either wire validation into the resolver correctly or rename/guard the flag so `dnssec=true` cannot be mistaken for "responses are validated." Document the current state in `docs/SECURITY.md`. *(High, low effort to make safe.)*
2. **(A2, A3, A8) Make the DNSSEC validator fail-closed before advertising it.** Require RRSIG verification of NSEC/NSEC3 and DS RRsets; make `.secure` depend on the target data's verified signature; add key-tag, signer-bailiwick, and labels/wildcard checks. If a correct rewrite is not imminent, mark `dnssec.Validator` experimental in `lib.zig`/docs. *(High.)*
3. **(A4, A5, A6) Thread verification material through the DoH/DoQ backend interfaces.** Add `server_name` to DoH `TlsConfig`; add `server_name` + `ca_pem` (+`use_system_ca`) to DoQ `connect`; add the fail-closed CA guard to DoH/DoQ init; add `min_tls_version` + a `peerVerified()` assertion to all TLS connection vtables. *(High for MITM resistance.)*
4. **(A7) Enforce zone descent on referrals.** Reject referrals whose claimed zone is not a descendant of the current delegation point and an ancestor-or-equal of the QNAME. *(Medium.)*
5. **(A9, A12) Tighten policy gates.** Prefer SHA-256+ DS digests and reject deprecated algorithms explicitly; fail closed on missing DoH `Content-Type`. *(Low.)*
6. **(A10, A11) Remove latent footguns.** Make `SystemRandom` draw directly from the CSPRNG or delete it; key the connection pool by full host string + TLS identity before enabling TLS pooling. *(Low.)*
7. **Follow-up reviews:** dedicated passes on `record.zig` RDATA parsers and `zone_file.zig`; reconcile dependency pin skew in `build.zig.zon`.

---

*No secrets were found or disclosed in the reviewed scope. No code was executed or modified. "No confirmed vulnerabilities" is asserted only for the specific parser memory-safety and live-path randomness questions; all other areas carry the findings above.*
