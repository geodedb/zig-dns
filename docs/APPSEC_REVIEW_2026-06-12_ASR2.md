# AppSec Review (Round 2 — Convergence Check) — devnw/zig/dns

**Review date:** 2026-06-12 · **Commit:** `967c18b` (branch `main`, clean tree) · **Reviewer role:** defensive appsec · **Standard:** OWASP Top 10:2025 + CIS Controls v8.1.2 · **Prior baselines:** `APPSEC_REVIEW_2026-06-12_ASR.md` (ASR-001..006), `APPSEC_REVIEW_2026-06-12.md` (A1..A12), `GAP_ANALYSIS.md` (GAP-0839..0890, SEC-*)

---

## 1. Scope and Assumptions

**Mandate:** This is the convergence check after the GAP-0839..0890 remediation campaign (~90 commits, `86ee75f..967c18b`). The job is to (a) adversarially review the *substantial new security-critical code* the remediation introduced, (b) cover round-1 §6 gaps, and (c) spot-check previously-clean areas for churn regressions. Anything already tracked/accepted in `GAP_ANALYSIS*.md` is **not** re-raised.

**Reviewed (read directly from disk at HEAD `967c18b`):**

- **New DNSSEC resolution wiring (priority 1):** `src/recursive.zig` — `enforceDnssecPolicy` (947-965), `validateDnssecResponse` (1010-1138), `buildDnssecTrustSet` (1148-1212), `verifyAnswerRrset` (1221-1280), `dnskeyUsable`/`ownerWithinAnyAnchorZone`/`dnsNamesEqual`/`isSubdomainOf` (1286-1338), config (105-126), answer/CNAME handling (388-426).
- **DNSSEC crypto:** `src/resolver/dnssec.zig` — `verifyRrsig` + wildcard `labels` handling (361-428), `appendCanonicalRrset`/`appendCanonicalName` (473-522, 1066-1093), `verifySignature` dispatch (524-550), `verifyRsa` RFC-3110 parser (1016-1064), Ed25519/ECDSA verifiers (947-1007), `verifyDsMatch` (173-212), `extractWireLabels`/`compareDnsNames`/wildcard helpers (808-1187), `validateChainOfTrust` (557-620, confirmed *unused by resolver*).
- **TSIG chained API:** `src/security/tsig.zig` — `verifyWithPrior` (427-545), `verifyResponse`/`verifySubsequent` (414-424), `signWithPrior`/`signWithMac` (338-405), `computeMacParts`/`hmacParts` (615+, 855-862), `stripTsig` (783-807), `extractTsig` (709-783), `VerifyResult`/`SignOutput` (815-841).
- **AXFR MAC chain:** `src/resolver/zone_transfer.zig` — `runAxfrTransfer` (349-478), `makeTsigContext`/`signQuery`/`SignedQuery` (625-647, 615-622), IXFR verify (544-551).
- **Other priority-1 new code:** `src/util/lru.zig` (full, heap-node redesign), `src/resolver/failover.zig` (ServerHandle/generation scheme, 162-339, 446-474), `src/message.zig` (`buildQueryBuf` OPT/DO-bit, 309-353), `src/edns.zig` (`validatePrefixLength`/ECS parse+encode, 284-360), `src/transports/io.zig` (`writeFramedWithTimeout`, 87-108), `src/parallel.zig` (`task_allocator = smp_allocator`, 86-92, alloc/free sites).
- **Churn regression spot-checks (priority 3):** `src/stub.zig` response validation (183-219), `src/resolver/split_dns.zig` FQDN normalization (50-123).

**Not re-reviewed (already covered round-1, low churn):** full `name.zig` decompression internals, `doq.zig`/`doh.zig`/`dot.zig` bodies (their round-1 findings ASR-003/A4/A5/A6/A12 are tracked as GAP-0854 *Closed* and SEC-A4/A5/A6 *Open-accepted*), `sig0.zig` body, `zone_file.zig`.

**Assumptions:** Built `ReleaseSafe` in production (Zig bounds/overflow checks active). TLS/QUIC/HTTP backends are caller-supplied. Trust anchors are operator-configured (trusted input). The `GAP_ANALYSIS.md` SEC-* table still lists SEC-A1/A2/A3/A7/A8 as "Open," but the campaign (GAP-0839 et al.) rewrote the DNSSEC resolution path; this review evaluates the *as-built* new path on `main`, not the stale table.

**Conventions honored:** No files modified. No secrets disclosed. Tree confirmed clean at `967c18b`. Findings are evidence-bounded.

---

## 2. Executive Summary

> **Headline question — Did round 2 find any NEW actionable security issues?**
> **No.** Zero new actionable security findings (0 Critical, 0 High, 0 Medium, 0 Low). Three Informational/observational notes are recorded, none of which is exploitable and none of which is a regression. **The remediation campaign converges.**

- **The new in-resolver DNSSEC validator is the right design and is built defensively.** Rather than wiring the round-1-flawed `validateChainOfTrust` (which returned `.secure` on mere DS/key presence — A3) into the pipeline, the campaign wrote a *new* path (`validateDnssecResponse`/`verifyAnswerRrset`) that verifies an actual covering RRSIG over each answer RRset against trust-anchor-rooted keys, with signer-bailiwick enforcement (`isSubdomainOf(owner, signer)`), key-tag + algorithm + signer-zone binding, and wildcard `labels` reconstruction (RFC 4035 §5.3.2). This **closes the exploitable cores of ASR-002, A3, and A8** as they would manifest in-path. Critically, it **never returns `.secure` without a verified target-data signature**, and unverifiable/forged inputs degrade to `.insecure`/`.bogus` (fail-closed in strict mode), not a false `.secure`.
- **The RSA verifier — the highest memory-safety risk in the new code (parsing untrusted RFC-3110 DNSKEY data) — is bounds-safe.** `verifyRsa` (dnssec.zig:1016-1064) guards `len<3`, the 0-byte/2-byte exponent-length form, `offset+exp_len >= len`, `signature.len == modulus.len`, and dispatches over a comptime-fixed set of modulus sizes with an `emLen >= tLen+11` (RFC 8017) floor. No OOB, no overflow (usize math). RSA/SHA-1 is deliberately rejected.
- **The TSIG chained verification API preserves every round-1 security property** under the new multi-message flow: MAC-verified-before-time (SEC-C101), constant-time exact-length compare (no truncation/CVE-2017-3142 class), record-supplied fudge digested (not local default), `prior_mac` length-prefixed with a `> maxInt(u16)` guard, and the verified MAC safely exposed (`@memcpy` bounded by `max_mac_length=64`). `stripTsig` now re-validates the record at the truncation offset is actually a TSIG RR (type 250) with an ARCOUNT-underflow guard.
- **The AXFR TSIG chain is correct and stricter than RFC 8945:** every envelope must be signed and chain-verified *before* any record is trusted; fail-closed on a configured key with no request MAC, on oversized request MAC, or on any envelope failure; `prior_mac` advanced per envelope.
- **The LRU heap-node redesign (GAP-0867 Critical UAF fix) is lifecycle-clean.** Stable heap `*Node` addresses survive map rehash; every create is paired with exactly one destroy and every key dupe with exactly one free across `put`/`remove`/`removeByHandle`/`evictLru`/`clear`/`deinit`, with correct `errdefer` on the `put` insertion path.
- **The failover ServerHandle generation scheme eliminates the round-1 UAF (A11/GAP-0876)** without introducing OOB: every handle dereference validates `generation` *and* `index < items.len`.
- **EDNS OPT/DO-bit building, ECS prefix validation, and framed-write coalescing are all bounds-safe** and correctly fix GAP-0840/0872/0888.

**Overall confidence:** High for the DNSSEC-path, RSA, TSIG, LRU, failover, and EDNS conclusions (full direct reads of the new code). Medium only for the out-of-scope TLS/QUIC backend posture (unchanged from round 1, tracked).

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP 2025 | Status |
|----|----------|-----------|-------|----------|-----------|--------|
| ASR2-001 | Info | High | Canonical RRset RDATA not lowercased/expanded for name-bearing RR types (RFC 4034 §6.2) — availability/interop, not bypass | `dnssec.zig:519-520` | A04 | New (observation) |
| ASR2-002 | Info | Medium | DNSSEC validation scope excludes CNAME-hop and denial-of-existence RRsets in-path (documented, fail-safe) | `recursive.zig:1001-1002, 388-398, 1059` | A06 | New (observation; aligns with tracked GAP-0839 scope) |
| ASR2-003 | Info | High | Stale `GAP_ANALYSIS.md` SEC-* table marks SEC-A1/A2/A3/A7/A8 "Open" though the as-built path remediates the in-path cores | `GAP_ANALYSIS.md:1230-1245` | A08 (doc integrity) | New (tracking hygiene) |

**No Critical, High, Medium, or Low findings. No secrets found. No memory-safety defects in the new code.**

---

## 4. Finding Details

### ASR2-001 — Canonical RRset construction appends RDATA verbatim (RFC 4034 §6.2 name-canonicalization omitted) · Info · A04 (CWE-347-adjacent)

**Evidence.** In `appendCanonicalRrset` (`dnssec.zig:496-521`), each RR's RDATA is appended raw: `try data.appendSlice(allocator, rr.rdata);` (line 520). RFC 4034 §6.2 requires that for RRSIG canonical form, domain names *embedded in RDATA* for a specific set of RR types (NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6, RRSIG, NSEC) must be (1) uncompressed and (2) lowercased before signing. The owner name *is* canonicalized (`appendCanonicalName`, lowercased, 1066-1093), but embedded RDATA names are not.

**Why this is not a security finding.** This can only cause a *valid* signature over a name-bearing RR type (e.g., MX, SRV, NS) to **fail** verification when the authoritative signer used canonical (lowercased) embedded names and the wire copy carries mixed case — i.e., a false `.bogus`/`.insecure`, never a false `.secure`. It cannot make a forged signature verify. With ASR2-002's fail-safe posture, the worst case is over-rejection (availability/interop), and the in-scope answer types most affected by the resolver path (A/AAAA) carry no embedded names. No bypass.

**Impact.** Latent DNSSEC interop/availability gap for name-bearing RR types once those are validated in-path. No integrity impact.

**Root cause.** Canonical-form construction omits the §6.2 per-type RDATA name rewrite.

**Remediation (when MX/SRV/NS etc. become in-scope for in-path validation).** Add a per-RR-type RDATA canonicalizer that rewrites embedded names to uncompressed lowercase before append; gate it on the `type_covered`.

**References.** RFC 4034 §6.2; OWASP A04:2025; CWE-347.

---

### ASR2-002 — In-path DNSSEC scope excludes CNAME hops and NSEC/NSEC3 denial-of-existence (documented, fail-safe) · Info · A06

**Evidence.** `validateDnssecResponse` iterates only the **answer** section (`recursive.zig:1035`) and returns `.insecure` when `answer_count == 0` (line 1059) — so a forged NXDOMAIN/NODATA is reported `insecure`, never `secure`. CNAME intermediate hops are followed (lines ~388-398) by the resolver loop *before* the per-hop CNAME RRset is RRSIG-validated; only the *final* answer RRset matching `state.qtype` reaches `enforceDnssecPolicy` (line 406). The module doc comment explicitly scopes this out: "A full iterative DS-walk ... is NOT performed here; ... as are CNAME intermediate hops and NXDOMAIN/NODATA denial-of-existence (NSEC/NSEC3) validation" (1000-1002).

**Why this is not a new actionable finding.** (1) The behavior is *fail-safe*: neither a forged denial-of-existence nor a forged CNAME can yield a `.secure` verdict; in strict mode an off-anchor / unsigned outcome resolves to `.insecure`/`.indeterminate` → `error.DnssecValidationFailed` (fail-closed). (2) It matches the **tracked, accepted scope** of GAP-0839 ("minimum spec-compliant scope") and the round-1 A2 disposition (NSEC RRSIG verification is a known validator-internal gap, tracked as SEC-A2). It is therefore neither a regression nor a *new* defect — it is the documented boundary of the shipped increment.

**Remediation (future increment, already on the roadmap).** Validate the CNAME RRset's RRSIG at each hop, and implement RFC 5155 closest-encloser-proof RRSIG verification for negative answers, before promoting those to `.secure`.

**References.** RFC 4035 §5.3.4; RFC 5155; OWASP A06:2025. Cross-ref: SEC-A2 (#291), GAP-0839.

---

### ASR2-003 — `GAP_ANALYSIS.md` SEC-* table is stale relative to the as-built remediation · Info · A08 (documentation/provenance integrity)

**Evidence.** `GAP_ANALYSIS.md:1230-1245` still lists SEC-A1, SEC-A2, SEC-A3, SEC-A7, SEC-A8 as **Open**, and line 1260 states "The validator remains unreachable from the pipeline (GAP-0070/#207)." But on `main` at `967c18b`: `recursive.zig:21` imports the DNSSEC module, `enforceDnssecPolicy` is invoked on the answer path (line 406), GAP-0070/GAP-0839 are marked **Closed** elsewhere in the same document (lines 16-22, 148-154), and the new path remediates the in-path cores of A3 (no `.secure` without verified target data) and A8 (signer-bailiwick + key-tag + signer-zone binding present in `verifyAnswerRrset`). SEC-A7 (upward/lateral referral) was also addressed (`e7a13fd fix(security): reject upward/lateral referrals`).

**Impact.** Informational. Tracking-hygiene drift between the SEC-* section (from the parallel cycle) and the campaign close-out can mislead a reader about residual DNSSEC risk and SBOM/audit provenance. No code impact. This is the same *class* as the tracked GAP-0866 reconciliation backlog but concerns the flatfile, not the issue tracker.

**Remediation.** Reconcile the SEC-* table: mark SEC-A1/A7 Closed; reclassify SEC-A2/A3/A8 as **partially remediated in-path / residual in the standalone `validateChainOfTrust` + denial-of-existence + CNAME-hop scope** (ASR2-002), pointing at the new `verifyAnswerRrset` path. Note that `dnssec.validateChainOfTrust` (dnssec.zig:557) — the A3-flawed function — **still exists as a public API** and remains a direct-API hazard for any external consumer who calls it; either fix it top-down or annotate it experimental/unsafe in `lib.zig` (this matches the round-1 A3 remediation guidance and is already a tracked Strategic item).

**References.** OWASP A08:2025; CIS v8.1.2 (vulnerability intake/tracking accuracy). Cross-ref: GAP-0866, SEC-A2/A3/A8.

---

## 5. Secure Design Notes (positive controls observed in the new code)

- **DNSSEC `.secure` requires a verified target-data signature.** `verifyAnswerRrset` returns `.secure` only when a trusted key's RRSIG verifies over the actual RRset (`dnssec.zig` `verifyRrsig` → `verifySignature`), with the key bound by key-tag (`tag != sig_data.key_tag` skip), algorithm, and signer-zone equality (`dnsNamesEqual(signer_str, zone)`). This is the precise inversion of the round-1 A3 "secure on key presence" flaw.
- **Signer-bailiwick enforced (round-1 A8 core).** `verifyAnswerRrset:1248` rejects any RRSIG whose `signer` is not an ancestor-or-equal of the owner (`isSubdomainOf(owner_str, signer_str)`); `isSubdomainOf` (recursive.zig:1317) does proper label-boundary checking (no `evilexample.com` ⊂ `example.com` confusion).
- **Wildcard `labels` validation (ASR-002/GAP-0841).** `verifyRrsig:381-397` rejects `rrsig.labels > owner_labels` and reconstructs the `*.`-prefixed canonical owner when `labels < owner_labels` (`buildWildcardOwner`), with the wildcard-`*`-excluded count in `countRrsigOwnerLabels`.
- **DS matching is downgrade-resistant.** `verifyDsMatch:182` rejects SHA-1 DS by default (`allow_sha1_ds=false`, round-1 A9), with key-tag + algorithm match and constant-time exact-length digest compare.
- **RSA parser is hostile-input-hardened.** `verifyRsa` guards every length derivation from untrusted DNSKEY data and uses comptime-sized PKCS#1 v1.5 verification with an `emLen ≥ tLen+11` floor.
- **TSIG chained API keeps all round-1 invariants.** MAC-before-time (SEC-C101), constant-time exact-length compare (no truncated-MAC acceptance), record-fudge digested, `prior_mac` length-prefixed + `>maxInt(u16)` guard, HMAC state `secureZero`'d, `stripTsig` type-250 + ARCOUNT-underflow guard.
- **AXFR auth-before-trust.** `runAxfrTransfer` verifies the TSIG chain before parsing/trusting any record; fail-closed on missing/oversized request MAC and every envelope; bounded by message cap + deadline (GAP-0869).
- **LRU lifecycle is leak-/UAF-free** with correct `errdefer` on the create+map.put path; stable heap nodes immune to rehash (GAP-0867).
- **Failover handles are generation-validated and index-bounded** on every dereference (GAP-0876).
- **EDNS OPT append, ECS prefix math, and framed writes** all bounds-check before casts (GAP-0840/0872/0888/0856 patterns), writing into size-proven buffers.
- **`smp_allocator` for parallel tasks** (GAP-0860) is the correct thread-safe general-purpose allocator; alloc/free pair on `task_allocator` consistently.
- **Stub response validation intact** post-churn: QR/opcode/qdcount/qtype/qclass + zero-alloc case-insensitive QNAME (`Name.eql`) + source-addr + spurious-discard cap.

---

## 6. Coverage Gaps and Questions

- **Not dynamically executed.** Static review only; the 688-test suite and fuzz harness were not run in this pass. Conclusions are from direct reads.
- **`validateChainOfTrust` (dnssec.zig:557) remains a public, round-1-A3-flawed API** but is confirmed *not* on the resolver path. Its risk is now solely "external consumer calls it directly" — a tracked Strategic item (SEC-A3). Recommend an `experimental`/`unsafe` annotation in `lib.zig` until rewritten (ASR2-003).
- **TLS/QUIC backend posture (SEC-A4/A5/A6) unchanged and out of scope** here; GAP-0854 (the DoH/DoQ CA-trust + Content-Type parity) is marked Closed but the deeper `server_name`-threading items (SEC-A4/A5) remain tracked. Not re-reviewed this round (no relevant churn in the priority set).
- **RFC 4034 §6.2 RDATA name canonicalization (ASR2-001)** matters only when name-bearing RR types enter in-path validation; verify before extending validated types.
- **Question for maintainers:** Is `dnssec.Validator.validateChainOfTrust` advertised as production-ready in any external doc? If yes, SEC-A3/A2/A8 remain effectively High *for that entry point* and the annotation in ASR2-003 should be prioritized.

---

## 7. Prioritized Next Actions

1. **(ASR2-003, hygiene) Reconcile the `GAP_ANALYSIS.md` SEC-* table** with the as-built path: close SEC-A1/A7, reclassify SEC-A2/A3/A8 as in-path-remediated with residual scope, and annotate the standalone `validateChainOfTrust` as experimental/unsafe in `lib.zig`. *(Doc + 1-line annotation.)*
2. **(ASR2-002, future increment) Extend in-path validation** to CNAME-hop RRSIGs and RFC 5155 denial-of-existence proofs before promoting those to `.secure` — already on the roadmap; the current fail-safe behavior is acceptable in the interim.
3. **(ASR2-001, future) Add RFC 4034 §6.2 RDATA name canonicalization** when MX/SRV/NS/etc. become in-path-validated record types.
4. **No remediation required for the campaign to land.** The new security-critical code (DNSSEC wiring, RSA, TSIG chain, AXFR, LRU, failover, EDNS) is sound.

---

**Convergence verdict:** The remediation campaign (`86ee75f..967c18b`) introduced substantial new security-critical code and did **not** introduce any new exploitable defect. No Critical/High/Medium/Low issues were found in the new code or in the spot-checked previously-clean areas. The three Info notes are observational (one interop, one documented-scope, one tracking-hygiene). **No new actionable security issues — the round-2 convergence check passes.** No secrets found; no code executed or modified.
