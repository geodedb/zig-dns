# AppSec Review — devnw/zig/dns (DNS library + zdig CLI)

**Review date:** 2026-06-12 · **Commit:** `86ee75f` (branch `main`, clean tree) · **Reviewer role:** defensive appsec · **Standard:** OWASP Top 10:2025 + CIS Controls v8.1.2

---

## 1. Scope and Assumptions

**Reviewed (read directly from disk):**

- Wire parsing: `src/message.zig`, `src/name.zig`, `src/record.zig`, `src/header.zig` (via callers), `src/question.zig` (via callers), `src/edns.zig` (via callers)
- Anti-spoofing: `src/util/random.zig`, `src/recursive.zig`, `src/stub.zig`, `src/parallel.zig`, `src/resolver/cache_protection.zig`, `cmd/zdig.zig` (entry)
- Crypto: `src/security/tsig.zig`, `src/resolver/dnssec.zig` (full), `src/security/sig0.zig` (sized), `src/security/dns_name.zig` (via callers)
- Transports: `src/transports/dot.zig`, `src/transports/doh.zig`
- Cache: `src/resolver/dns_cache.zig`, `src/resolver/cache_protection.zig`
- Other inputs: `src/zone_file.zig`, `src/resolver/rpz.zig`
- Supply chain: `build.zig.zon`, `.gitlab-ci.yml`, `scripts/sync_diamond_deps.py`, `scripts/sync_diamond_deps.sh`
- Context: `docs/SECURITY.md`, `SECURITY.md`, `docs/GAP_ANALYSIS.md` (+ resolved index)

**Not fully reviewed (time/scope):** `src/transports/doq.zig`, `src/security/sig0.zig` body, `src/resolver/{split_dns,zone_transfer (partial),edns,channel,config,logging,failover}.zig`, `src/edns.zig`/`question.zig`/`header.zig` bodies, `src/util/lru.zig`, `tests/`. These are flagged in §6.

**Assumptions:** Library is built `ReleaseSafe` in production (per `docs/SECURITY.md`) so Zig bounds/overflow checks are active. TLS/HTTP backends for DoT/DoH are caller-supplied. The repo has a mature, well-tracked security history (`docs/GAP_ANALYSIS.md`): the great majority of classic DNS parser/crypto findings (SEC-C05 CSPRNG, SEC-C23/C100/C101 TSIG, SEC-AUDIT-01 forward pointers, SEC-SCAN-08/09 constant-time digests, NSEC3 iteration cap, etc.) are already resolved. This review focuses on **NEW** issues and marks anything already tracked as *previously tracked*.

**Conventions honored:** No files modified. No secrets disclosed. Findings are evidence-bounded; where I could not confirm exploitability I say so.

---

## 2. Executive Summary

- **The recursive resolver requests DNSSEC (sets the DO bit) but never validates the returned signatures.** The `dnssec.Validator` is fully implemented and unit-tested, yet it is **not invoked from any resolution path** (`recursive.zig`, `client.zig`, `convenience.zig`, `parallel.zig`). With `dnssec = true`, responses are accepted as-is — a fail-open posture that does not match the security promise advertised in docs. **Highest-risk finding (ASR-001).**
- **Wire-format parsing is robust.** Compression-pointer loops, forward pointers, decompression/allocation bombs, OOB reads, and integer overflow are systematically guarded with bounds checks and tests across `name.zig`, `message.zig`, `record.zig`. No new memory-safety defects found in the reviewed parsers.
- **Anti-spoofing core is strong.** TXIDs use the OS CSPRNG per query (`std.Io.randomSecure`), responses are validated on TXID + question (case-insensitive 0x20 via `Name.eql`) + source address, with a spurious-packet discard cap and TCP-fallback re-validation.
- **TSIG is well-hardened** (MAC-before-time ordering, constant-time MAC compare, RFC 2104 key sizing, fudge clamp, secret zeroization). The truncated-MAC (BADTRUNC / CVE-2017-3142 class) attack is *not* present — only full-length MACs are accepted.
- **DNSSEC RRSIG validation omits the `labels` check** (RFC 4035 §5.3.2), permitting wildcard-expansion signature replay *if* validation were wired in (ASR-002).
- **Defense-in-depth divergences:** DoH does not require a CA-trust configuration the way DoT does, and its Content-Type check is skipped when the backend returns no header (ASR-003); RPZ `matchPattern` does not normalize trailing-dot FQDNs, enabling a filter bypass depending on caller input (ASR-004).
- **Supply chain is sound:** dependencies pinned by hash, Zig toolchain SHA-256-verified in CI, Python tooling uses list-form `subprocess` (no shell injection).

**Overall confidence:** High for the parsing/anti-spoofing/TSIG conclusions (full reads). Medium for the DNSSEC-enforcement conclusion (confirmed by exhaustive grep of resolution modules, but DoQ and a few resolver modules were not read).

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP 2025 | Status |
|----|----------|-----------|-------|----------|-----------|--------|
| ASR-001 | High | High | DNSSEC requested (DO bit) but never validated in resolution path (fail-open) | `recursive.zig:594`; `dnssec.zig` (unused) | A06 Insecure Design | New |
| ASR-002 | Medium | High | RRSIG `labels` field not validated → wildcard-expansion signature replay | `dnssec.zig:361-394, 867` | A04 Cryptographic Failures | New |
| ASR-003 | Low | High | DoH lacks CA-trust gate; Content-Type check skipped when header absent | `doh.zig:171-182, 235-239, 256-260` | A02 Security Misconfiguration | New |
| ASR-004 | Low | Medium | RPZ `matchPattern` does not normalize trailing-dot FQDN → filter bypass | `rpz.zig:302-332` | A01 Broken Access Control | New |
| ASR-005 | Info | High | `DnssecAlgorithm.isSupported()` claims RSA/P-384 support that `verifySignature` rejects | `record.zig:714-720`; `dnssec.zig:481-495` | A06 Insecure Design | New |
| ASR-006 | Info | High | `build.zig.zon` version `0.1.8` lags tagged releases (`v0.1.9`) | `build.zig.zon:8` | A08 Software/Data Integrity | New |

No Critical findings. No secrets found in source or CI.

---

## 4. Finding Details

### ASR-001 — DNSSEC is requested but never validated (fail-open) · High · A06 (CWE-1325/CWE-345/CWE-754)

**Evidence.**

- `recursive.zig:594` builds the query with the DNSSEC OK bit derived from config:
  `const query = try message_mod.buildQueryBuf(&query_buf, id, query_name, qtype, .in, self.config.dnssec);`
- A full grep of all resolution modules (`recursive.zig`, `client.zig`, `resolver/convenience.zig`, `resolver/failover.zig`, `parallel.zig`) for `Validator`, `verifyRrsig`, `validateChainOfTrust`, `validateNxdomain*`, `ValidationResult`, `.secure` returns **no call sites** — only a comment in `parallel.zig:350` stating cryptographic verification "is deferred to the `dnssec.Validator`."
- The `dnssec.zig` `Validator` (lines 109-662) is complete and unit-tested but is reachable only as a standalone API; nothing in the resolver constructs one or feeds responses to it.
- `docs/SECURITY.md` (DNSSEC Considerations) and `dnssec.zig` module docs prominently describe DNSSEC validation support, implying responses are validated.

**Attack scenario (non-destructive).** A resolver configured with `dnssec = true` queries a name. An on-path or spoofing attacker (the exact threat DNSSEC defends against) returns forged A/AAAA records without valid RRSIGs, or with expired/forged signatures. Because no RRSIG/chain validation occurs, the forged answer is accepted and (subject to bailiwick/TTL filtering) cached and returned to the caller as though authentic. The `dnssec` flag gives a false sense of integrity protection.

**Impact.** Defeats the integrity guarantee DNSSEC exists to provide. Callers who enable `dnssec` reasonably believe answers are cryptographically validated; they are not. This is a security-design gap (fail-open), not a memory-safety bug.

**Root cause.** Validation logic was built as an independent module but never integrated into the response-processing pipeline; the config flag only toggles the outgoing DO bit.

**Remediation.**

- In the recursive resolution path, when `config.dnssec` is set: collect the answer/authority RRsets plus their RRSIG/DNSKEY/DS records, instantiate `dnssec.Validator` with configured trust anchors, and call `verifyRrsig`/`validateChainOfTrust`. Treat `ValidationResult.bogus` as a hard failure (drop response, do not cache); surface `insecure`/`indeterminate` per a documented policy.
- Until integration lands, change the API/docs so that requesting `dnssec = true` either (a) performs validation, or (b) returns an explicit "DNSSEC requested but not validated" signal and the docs/`SECURITY.md` state plainly that the library does not validate in-path. Do not let the flag imply validation it does not perform.
- Given the existing RSA limitation (`dnssec.zig:19-45`), document that zones signed with RSA (root, most TLDs) cannot be validated and choose a fail policy (fail-closed vs. explicit insecure) deliberately.

**Regression tests.** Add resolver-level tests: (1) forged answer with no RRSIG under `dnssec = true` is rejected/flagged; (2) answer with expired RRSIG is rejected; (3) answer with valid Ed25519/ECDSA chain to a configured trust anchor is accepted. Assert the `Validator` is actually invoked (e.g., via a counting trust-anchor or seam).

**References.** RFC 4035 §5; OWASP A06:2025 Insecure Design; CWE-345 (Insufficient Verification of Data Authenticity), CWE-754 (Improper Check for Unusual Conditions). CIS v8.1.2: secure design principles, application testing.

---

### ASR-002 — RRSIG `labels` field not validated (wildcard-expansion replay) · Medium · A04 (CWE-347)

**Evidence.** `dnssec.zig:361-394` `verifyRrsig` checks the validity window (`rrsig.isValid`) and `rrsig.algorithm != dnskey.algorithm`, then builds the signed data and verifies the signature. The `labels` field is parsed (`record.zig:867`, `RrsigData.labels`) and serialized into the signed data (`dnssec.zig:407`), but **`verifyRrsig` never compares `rrsig.labels` against the actual label count of the RRset owner name**, and never reconstructs the wildcard owner (`*.zone`) when `labels` is less than the owner's label count. RFC 4035 §5.3.1/§5.3.2 requires both.

**Attack scenario.** An attacker holding a legitimately signed RRSIG for a wildcard record `*.example.com` (where `labels` = 2) replays it to authenticate a synthesized name such as `victim.example.com`. Without the `labels`/wildcard reconstruction check, the canonical signed data the verifier builds can be made to match, so a wildcard signature is accepted for names it should not cover.

**Impact.** Within DNSSEC validation, allows a valid wildcard signature to authenticate names outside the wildcard's intended coverage. **Practical impact is currently latent** because ASR-001 means `verifyRrsig` is not invoked during resolution; it becomes exploitable the moment validation is wired in.

**Root cause.** Incomplete implementation of RFC 4035 §5.3.2 canonical-RRset construction (wildcard handling and label-count enforcement).

**Remediation.** In `verifyRrsig`, before building signed data: reject if `rrsig.labels` exceeds the owner's label count; if `rrsig.labels` is less, reconstruct the owner as `*` + the rightmost `labels` labels per RFC 4035 §5.3.2 and use that canonical owner in `appendCanonicalRrset`. Add the count comparison as a fast-fail.

**Regression tests.** (1) RRSIG with `labels` greater than owner label count → reject; (2) valid wildcard RRSIG correctly authenticates a direct subdomain match but is rejected for a name at a different depth; (3) non-wildcard RRSIG with matching `labels` still validates.

**References.** RFC 4035 §5.3.1–5.3.2; OWASP A04:2025; CWE-347 (Improper Verification of Cryptographic Signature).

---

### ASR-003 — DoH: no CA-trust gate; Content-Type check bypassable when header absent · Low · A02 (CWE-295/CWE-319)

**Evidence.**

- DoT enforces a trust gate at construction: `dot.zig:213-215` returns `error.NoCaTrustConfigured` when `ca_pem.len == 0 and !use_system_ca`.
- DoH (`doh.zig:171-182`) validates only the `https://` scheme; it accepts `ca_pem = ""` with no equivalent `use_system_ca` gate. There is no defense-in-depth check that *some* trust source is configured before delegating to the backend.
- The Content-Type validation runs only when the backend reports one: `doh.zig:235-239` and `256-260` are guarded by `if (response.content_type) |ct|`. A backend that returns `null` content_type skips the `application/dns-message` check entirely.

**Attack scenario.** A misconfigured or weak HTTP backend that does not itself enforce certificate validation, combined with the absent library-level gate, yields silent acceptance of an unauthenticated TLS peer — undermining DoH's MITM protection. Separately, a backend returning a `200` with no Content-Type lets non-DNS bodies through the transport's own validation.

**Impact.** Low: actual TLS verification is the backend's documented responsibility, and a competent backend mitigates both issues. This is a missing defense-in-depth parity with DoT rather than a direct bypass.

**Root cause.** DoH transport applies fewer constructor-time invariants than DoT; Content-Type enforcement is opt-in on backend behavior.

**Remediation.** Mirror DoT's gate in `DoHTransport.init`: require `ca_pem` non-empty or an explicit `use_system_ca`/equivalent flag. Make the Content-Type check fail-closed: if the backend reports no Content-Type, reject (or require backends to populate it). Document that DoH backends MUST verify certificates and hostnames.

**Regression tests.** (1) `DoHTransport.init` with empty `ca_pem` and no system-CA opt-in → error; (2) response with `content_type = null` → `error.InvalidContentType` (or documented reject).

**References.** RFC 8484; OWASP A02:2025; CWE-295 (Improper Certificate Validation), CWE-319 (Cleartext Transmission). CIS v8.1.2: data-in-transit protection, hardening templates.

---

### ASR-004 — RPZ `matchPattern` does not normalize trailing-dot FQDNs · Low · A01 (CWE-863)

**Evidence.** `rpz.zig:302-332` `matchPattern` performs case-insensitive exact match (`std.ascii.eqlIgnoreCase(domain, pattern)`) and wildcard-suffix match with boundary validation, but it does **not** strip a trailing `.` from either `domain` or `pattern`. `cache_protection.zig` has a `normalizeZone` helper for exactly this, but `rpz.zig` does not use it. A blocklist rule `"malware.com"` will not match a query presented as `"malware.com."` (the standard FQDN root form), and `"*.example.com"` will not match `"x.example.com."`.

**Attack scenario.** Where the RPZ check receives the qname in absolute/FQDN form (trailing dot) — common in DNS pipelines — an attacker (or ordinary client) reaches a domain intended to be blocked by appending the canonical root dot, bypassing nxdomain/drop/redirect policy. The reverse (rule written with a trailing dot, query without) also fails to match.

**Impact.** Low–Medium depending on how callers feed qnames into `RpzManager.check`/`ResponsePolicyZone.check`. As a security-policy enforcement primitive, inconsistent normalization is a filter-bypass class. The wildcard *boundary* bypass (GAP-0048) is already resolved and well-tested; this trailing-dot normalization gap is distinct and **not** previously tracked.

**Root cause.** Missing canonicalization of DNS names before policy comparison.

**Remediation.** Normalize both `domain` and `pattern` (strip a single trailing `.`, and ideally lower-case) at the top of `matchPattern`, reusing the existing `normalizeZone` logic. Document that callers should pass canonical names, but do not rely on it.

**Regression tests.** (1) rule `"malware.com"` matches query `"malware.com."`; (2) rule `"*.example.com"` matches `"x.example.com."`; (3) rule `"malware.com."` matches query `"malware.com"`.

**References.** RFC 8499 (terminology, FQDN root); OWASP A01:2025; CWE-863 (Incorrect Authorization).

---

### ASR-005 — Algorithm-support inconsistency between `isSupported()` and `verifySignature()` · Info · A06 (CWE-684)

**Evidence.** `record.zig:714-720` `DnssecAlgorithm.isSupported()` returns `true` for `rsasha256, ecdsap256sha256, ed25519, rsasha1, rsasha512, ecdsap384sha384`. But `dnssec.zig:481-495` `verifySignature` returns `error.UnsupportedAlgorithm` for all RSA variants (`rsasha1/rsasha256/rsasha512`) and only implements Ed25519/ECDSA-P256/ECDSA-P384. So `isSupported()` advertises RSA-SHA256/512 and RSA-SHA1 as supported when verification cannot validate them.

**Impact.** Informational. `verifySignature` fails closed (returns an error), so there is no validation bypass. The risk is that callers branching on `isSupported()` make incorrect decisions (e.g., treating an RSA-signed zone as validatable). Compounds the ASR-001 fail-open posture by overstating capability.

**Remediation.** Make `isSupported()` return the set actually verifiable (`ed25519, ecdsap256sha256, ecdsap384sha384`), matching `verifySignature` and the `docs/SECURITY.md` table that already lists RSA as NOT SUPPORTED. If `isSupported()` intentionally means "recognized algorithm," rename it (e.g., `isKnown`) to avoid the implication.

**References.** OWASP A06:2025; CWE-684 (Incorrect Behavior Order / inconsistent capability reporting).

---

### ASR-006 — Manifest version lags tagged releases · Info · A08 (CWE-1395)

**Evidence.** `build.zig.zon:8` declares `.version = "0.1.8"`, while recent commits (`159f406 chore(release): bump to v0.1.8`, plus `dc2329d`/`86ee75f` referencing `v0.1.9` / tls v0.1.9 convergence) indicate the working tree is ahead of the declared package version. Dependencies themselves are correctly pinned by both git ref and `hash` (`build.zig.zon:23-46`), and the `otel` dep is `lazy`.

**Impact.** Informational/integrity hygiene. Version drift between the manifest and the release tag can confuse downstream pinning, SBOM accuracy, and provenance auditing. No exploitability.

**Remediation.** Ensure `build.zig.zon` `.version` is bumped in the same commit as the release tag (the semantic-release CI component should own this). Verify the SBOM-generate job reflects the intended version.

**References.** OWASP A08:2025 Software/Data Integrity; CWE-1395 (Dependency on Vulnerable/Stale Component metadata). CIS v8.1.2: SBOM + third-party inventory.

---

## 5. Secure Design Notes (positive controls observed)

- **CSPRNG TXIDs everywhere they matter.** `recursive.zig:34-39, 565` (`csprngInt(u16)`), `stub.zig:31-36, 155-159`, `parallel.zig:80-83`, and `zone_transfer.zig:438-443, 470-475` all draw transaction IDs from `std.Io.randomSecure`/`std.posix.getrandom` per call (not a long-lived seeded PRNG), and **fail-closed** on entropy unavailability (`util/random.zig:53-65`, `stub.zig:117-123`). Matches RFC 5452 and resolves SEC-C05/C24 (*previously tracked*).
- **Strong response validation.** `stub.zig:161-180` and `recursive.zig:601-613` match responses on TXID + question (qname/qtype/qclass) using zero-allocation case-insensitive `Name.eql`, validate source address (`stub.zig:303`), cap spurious-packet discards (`stub.zig:304`, SEC-AUDIT-02), and re-validate TCP-fallback responses (`stub.zig:230-244`, SEC-AUDIT-10).
- **Hardened compression-pointer handling.** `name.zig` `LabelIterator` enforces hop limits (`max_compression_hops = 16`), rejects forward pointers on every hop including the first (`name.zig:98-125`, SEC-AUDIT-01), and bounds every label read. `Name.parse` enforces the 255-byte name cap (`name.zig:332-336`).
- **Section-count and RDLENGTH bounds.** `message.zig:72-78` caps each section at `max_section_count = 4096`; `record.zig:94-128` bounds-checks the 10-byte fixed header and RDLENGTH against the buffer; every typed RDATA parser (TXT, SVCB, NSEC3, CAA, RRSIG, etc.) validates lengths before slicing.
- **TSIG done right.** `tsig.zig`: MAC verified before time/fudge (SEC-C101); constant-time MAC compare via `std.crypto.timing_safe.eql` with exact-length gating (only full-length MACs accepted — the CVE-2017-3142 truncation class is *not* present); RFC 2104 key sizing delegated to `std.crypto` (SEC-C23); fudge clamped post-MAC with u32 widening (SEC-C100/AUDIT-08); secret and HMAC state zeroized (`secureZero`, SEC-SCAN-01/C25); ARCOUNT/RDLENGTH overflow guards. (Many *previously tracked* and resolved.)
- **DNSSEC primitives that are present are careful.** Constant-time DS/trust-anchor digest comparison with exact-length match (`dnssec.zig:204-211, 600-616`, SEC-SCAN-08/09); NSEC3 iteration cap of 150 to prevent CPU DoS (`dnssec.zig:636-643`); base32hex decode rejects non-zero trailing bits (`dnssec.zig:1148-1154`, SEC-AUDIT-13); `extractWireLabels` rejects compression pointers and OOB in canonical names (`dnssec.zig:1008-1030`, SEC-AUDIT-12).
- **Cache poisoning resistance primitives.** `cache_protection.zig` implements bailiwick checks with proper boundary handling (`isSubdomainOrEqual`), TTL clamping (positive/negative/min), glue validation, and source/TXID validation. `dns_cache.zig` keys on (name, qtype, **qclass**) avoiding class confusion, clamps TTLs on insert, and frees entries via an LRU `on_evict` callback.
- **Transport trust posture (DoT).** `dot.zig:213-215` refuses to construct without a CA trust source; ALPN is validated post-handshake (`dot.zig:278-287`); length-prefixed framing with full read/write loops and a 64 KB cap.
- **Supply chain.** All deps pinned by git ref + content `hash`; CI verifies the Zig toolchain tarball against the official `index.json` SHA-256 (`.gitlab-ci.yml:43-82`); SAST/secrets/gitleaks/dependency-scan/SBOM components included; Python tooling uses list-form `subprocess.run` (no `shell=True`, no string interpolation) — no command injection.

---

## 6. Coverage Gaps and Questions

- **Not read in full:** `src/transports/doq.zig` (QUIC cert verification / 0-RTT replay posture unverified — recommend a follow-up specifically on DoQ), `src/security/sig0.zig` (SIG(0) inception/expiration and replay handling — only sized, not analyzed), `src/edns.zig`, `src/question.zig`, `src/header.zig` bodies (relied on their callers' bounds checks and existing tests), `src/util/lru.zig` (eviction correctness/integer handling), `src/resolver/{split_dns,edns,channel,config,zone_transfer (body),failover}.zig`.
- **DNSSEC fail policy is undefined.** Once ASR-001 is addressed, the intended behavior for `bogus`/`insecure`/`indeterminate` and for RSA-signed zones (unverifiable) must be specified. Question for maintainers: should `dnssec = true` fail-closed for unvalidatable algorithms, or return an explicit insecure status?
- **RPZ qname provenance.** ASR-004's severity depends on whether callers pass FQDN-form (trailing-dot) names to `RpzManager.check`. Question: what is the canonical form guaranteed at that boundary?
- **TSIG/SIG(0) replay.** `docs/GAP_ANALYSIS.md` records ADV-02 (TSIG replay within fudge window) and SIG(0) replay as *Won't Do* (accepted risk). Noted, not re-raised.
- **Dynamic analysis not performed.** No code executed; conclusions are from static review plus the project's existing fuzz harness (`tests/fuzz_parsers.zig`, CI `fuzz` job) which I did not run.

---

## 7. Prioritized Next Actions

1. **ASR-001 (High):** Either wire `dnssec.Validator` into the resolution path with a deliberate fail policy, or change the API/docs so `dnssec = true` cannot be mistaken for in-path validation. This is the single most material gap relative to the library's stated security posture.
2. **ASR-002 (Medium):** Implement RFC 4035 §5.3.2 `labels`/wildcard handling in `verifyRrsig` before (or as part of) the ASR-001 integration, so validation is correct when enabled.
3. **ASR-005 (Info, quick win):** Align `DnssecAlgorithm.isSupported()` with `verifySignature` to stop overstating RSA/P-384 support. Pairs naturally with ASR-001/002.
4. **ASR-003 (Low):** Add a DoH CA-trust gate mirroring DoT and make the Content-Type check fail-closed.
5. **ASR-004 (Low):** Normalize trailing-dot/case in `rpz.matchPattern` (reuse `normalizeZone`); add FQDN-form tests.
6. **ASR-006 (Info):** Keep `build.zig.zon` `.version` in lockstep with release tags; verify SBOM output.
7. **Follow-up review:** Schedule a focused pass on `doq.zig` (QUIC TLS/cert verification, 0-RTT replay) and `sig0.zig` (signature time-window and replay), which were out of depth this round.

No Critical issues and no exposed secrets were found in the reviewed scope. The parser, anti-spoofing, and TSIG subsystems are in strong shape; the primary residual risk is the **DNSSEC fail-open posture (ASR-001)**.
