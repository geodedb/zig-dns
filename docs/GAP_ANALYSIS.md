# Gap Analysis

Last updated: 2026-06-12 (close-out 2026-06-12) -- two same-day audit cycles merged and closed:

1. **AppSec + Adversarial + Supply-chain review cycle:** 25 security findings (SEC-A1..A12, SEC-SR-1..SR-11, SEC-SC-1..SC-2) filed as issues #279-#303 (9 confidential), plus 8 implementation-scan gaps (GAP-0070..GAP-0077). See the Security Findings section. GAP-0070/0073/0074/0075/0077 closed this campaign; GAP-0071/0072/0076 remain open.
2. **Full /codepros:audit cycle (Phase 3/4):** 51 gaps GAP-0839..GAP-0890 filed as issues #304-#345 (2 confidential). **Campaign closed 2026-06-12**: 49 Closed, 1 Won't-Do (GAP-0864), 1 Open/Needs-Decision (GAP-0866). Resolved stubs moved to `GAP_ANALYSIS_RESOLVED.md` section "Gap-Closure Campaign 2026-06-12".

> **Campaign close-out summary (2026-06-12):**
>
> - **GAP-0839/GAP-0867/GAP-0875** (Critical) -- ALL CLOSED. LRU UAF, DNSSEC wiring, zdig double-free all fixed.
> - **49/51 gaps closed**, 1 Won't-Do (GAP-0864), 1 open needs-decision (GAP-0866).
> - Tests: 543 -> 688 passing (145 new), 0 failures. 50 commits (386eebf..0ed5ca7).

## Gaps

### GAP-0070: DNSSEC validator never invoked from the resolution pipeline (`dnssec=true` only sets the DO bit) -- **CLOSED**

- **Issue:** [#207](https://gitlab.com/devnw/zig/dns/-/issues/207) (closed)
- **Category:** Security
- **Severity:** Critical
- **Status:** **Closed** (2026-06-12). Alias of GAP-0839. `recursive.zig` now imports and invokes the DNSSEC validator; fail-closed on bogus responses.
- **Resolution:** Commits 15258de, 1f7fe2d (GAP-0839 campaign). See `GAP_ANALYSIS_RESOLVED.md` section "Gap-Closure Campaign 2026-06-12 / GAP-0839".
- **Resolved date:** 2026-06-12

---

### GAP-0071: EDNS Client Subnet (RFC 7871) type complete but never injected into outgoing queries -- **OPEN**

- **Issue:** [#208](https://gitlab.com/devnw/zig/dns/-/issues/208)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Open** (2026-06-12). `ClientSubnet` type at `src/edns.zig:272` is fully implemented (parse/encode/buildOption) and unit-tested. No call to `ClientSubnet.buildOption` exists in `src/stub.zig`, `src/recursive.zig`, or `src/client.zig`. Query builders `message.buildQuery`/`buildQueryBuf` take no EDNS-option parameter.
- **Evidence:**
  - `src/edns.zig:272` -- `pub const ClientSubnet = struct { ... }` with `parse`/`encode`/`buildOption`
  - `grep -rn ClientSubnet src/` outside `edns.zig` -- no hits
  - `src/message.zig:303,318` -- query builders, no EDNS option parameter
  - Tests at `src/edns.zig:819-880` are unit-only; no integration test injects ECS into a live query
- **Impact:** "Geo-aware queries (EDNS Client Subnet)" deliverable is non-functional at runtime. ROADMAP Phase 4 claims "Complete -- Full ECS support"; that claim is false.
- **Acceptance criteria:**
  - [ ] An optional ECS parameter in `RecursiveConfig` or `ClientOptions` causes the ECS option (code 8) to be appended to outgoing EDNS OPT RRs
  - [ ] Integration test verifies the encoded query wire bytes contain option code 8 with the configured prefix
  - [ ] When unset (default), no ECS option is added

---

### GAP-0072: DNS Cookies (RFC 7873) type complete but never wired into query building -- **OPEN**

- **Issue:** [#209](https://gitlab.com/devnw/zig/dns/-/issues/209)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Open** (2026-06-12). `Cookie` type at `src/edns.zig:366` is fully implemented (parse/encode, option code 10) and unit-tested. No call to cookie injection exists in any resolver code path.
- **Evidence:**
  - `src/edns.zig:366` -- `pub const Cookie = struct { ... }` with parse and constants
  - `grep -rni cookie src/` outside `edns.zig` -- no hits in resolver/transport stack
  - Tests at `src/edns.zig:888,896` are unit-only; no query-injection test
- **Impact:** "Replay protection (DNS Cookies)" deliverable is non-functional at runtime. ROADMAP Phase 4 claims "Complete -- SipHash cookie computation"; cookies are never sent on the wire.
- **Acceptance criteria:**
  - [ ] Outgoing queries carry an EDNS Cookie option (code 10) with an 8-byte client cookie when enabled
  - [ ] Server cookie round-trip handled per RFC 7873
  - [ ] Integration test verifies the wire query contains option code 10

---

### GAP-0073: `-Dwith_otel=true` build broken -- second `lazyDependency("otel")` omits 4 forwarded options (module dedup collision) -- **CLOSED**

- **Issue:** [#210](https://gitlab.com/devnw/zig/dns/-/issues/210) (closed 2026-06-12)
- **Category:** CI-CD
- **Severity:** High
- **Status:** **Closed** (2026-06-12). Both `lazyDependency("otel")` call sites now pass identical option sets; `-Dwith_otel=true` builds without errors.
- **Resolution:** Verified fixed during audit Phase 2 (2026-06-12). See `GAP_ANALYSIS_RESOLVED.md` section "Audit Cycle 2026-06-12 -- Verified Fixed (Phase 2) / #226".
- **Resolved date:** 2026-06-12

---

### GAP-0074: OTel seam hardcodes `enabled = false` -- observability is a no-op regardless of build flag -- **CLOSED**

- **Issue:** [#206](https://gitlab.com/devnw/zig/dns/-/issues/206), [#210](https://gitlab.com/devnw/zig/dns/-/issues/210) (both closed 2026-06-12)
- **Category:** Observability
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). `observability.enabled` now reflects `build_options.with_otel`; `-Dwith_otel=true` build works.
- **Resolution:** Verified fixed during audit Phase 2 (2026-06-12). See `GAP_ANALYSIS_RESOLVED.md` section "Audit Cycle 2026-06-12 -- Verified Fixed (Phase 2) / #210".
- **Resolved date:** 2026-06-12

---

### GAP-0075: `minimum_zig_version` and README claim 0.15.1 but 19 source files require Zig 0.16-only `std.Io.*` -- **CLOSED**

- **Issue:** [#211](https://gitlab.com/devnw/zig/dns/-/issues/211) (closed), [#70](https://gitlab.com/devnw/zig/dns/-/issues/70) (updated)
- **Category:** Docs
- **Severity:** High
- **Status:** **Closed** (2026-06-12). Alias of GAP-0848. `build.zig.zon`, README, and cross-platform docs updated to Zig 0.16.0.
- **Resolution:** Commits d7cfdf0 (docs: close GAP-0848), 10cb5b0 (docs: correct stale Zig-version claims). See `GAP_ANALYSIS_RESOLVED.md` section "Gap-Closure Campaign 2026-06-12 / GAP-0848".
- **Resolved date:** 2026-06-12

---

### GAP-0076: Zone-transfer `buildMinimalSoaRdata` emits placeholder MNAME/RNAME/timers -- **OPEN**

- **Issue:** [#12](https://gitlab.com/devnw/zig/dns/-/issues/12)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Open** (2026-06-12). `src/resolver/zone_transfer.zig:506-524` -- `buildMinimalSoaRdata` sets MNAME and RNAME both to the zone name ("use zone name as placeholder") and hardcodes Refresh=3600/Retry=600/Expire=604800/Minimum=86400 with the comment "(placeholder values)".
- **Evidence:**
  - `src/resolver/zone_transfer.zig:497` -- single call site for `buildMinimalSoaRdata`
  - `src/resolver/zone_transfer.zig:506-524` -- MNAME/RNAME use zone name; timers hardcoded with "(placeholder values)" comments
- **Impact:** Low -- affects only the synthesized/minimal SOA path; real transferred SOAs are unaffected. Incorrect RNAME (admin mailbox) and fabricated timers may cause incorrect secondary-zone timing or negative-cache TTLs where the synthesized record is used.
- **Acceptance criteria:**
  - [ ] SOA RNAME is a configurable admin mailbox, not the zone name
  - [ ] Refresh/Retry/Expire/Minimum are configuration-driven, not hardcoded constants, OR the function is restricted to non-authoritative/test use with explicit documentation

---

### GAP-0077: Benchmark harness (`bench.zig`, `compare.zig`) broken on Zig 0.16 -- regression-detection capability lost -- **CLOSED**

- **Issue:** [#216](https://gitlab.com/devnw/zig/dns/-/issues/216) (closed)
- **Category:** CI-CD
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Alias of GAP-0849/GAP-0850. Both harnesses restored on Zig 0.16: `std.time.Timer` replaced with `nowNs()` pattern (9 sites), `std.process.args()` replaced with `argsAlloc`.
- **Resolution:** Commit 675d1cf (fix(bench): restore bench and compare harnesses on Zig 0.16). See `GAP_ANALYSIS_RESOLVED.md` section "Gap-Closure Campaign 2026-06-12 / GAP-0849" and "GAP-0850".
- **Resolved date:** 2026-06-12

## Gap-Closure Campaign 2026-06-12 (GAP-0839..GAP-0890) -- CLOSED

> Campaign closed 2026-06-12. 49 Closed, 1 Won't-Do (GAP-0864), 1 Open/Needs-Decision (GAP-0866).
> Full resolved stubs with commit evidence in `GAP_ANALYSIS_RESOLVED.md` under "Gap-Closure Campaign 2026-06-12".
> Issues marked *(confidential)* were filed as confidential in the GitLab tracker.

### GAP-0867: LruCache intrusive list pointers invalidated on StringHashMap rehash -> use-after-free -- **CLOSED**

- **Issue:** [#304](https://gitlab.com/devnw/zig/dns/-/issues/304) *(confidential)* (closed)
- **Category:** Security (CWE-416)
- **Severity:** Critical
- **Status:** **Closed** (2026-06-12). LRU now uses stable heap-allocated nodes; pointer invalidation on rehash eliminated.
- **Resolution:** Commit 3185950. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0867".

---

### GAP-0875: zdig sendUdp double-free on recvfrom error / SourceAddressMismatch -- **CLOSED**

- **Issue:** [#305](https://gitlab.com/devnw/zig/dns/-/issues/305) *(confidential)* (closed)
- **Category:** Security
- **Severity:** Critical
- **Status:** **Closed** (2026-06-12). Exactly one free on every error path; double-free eliminated.
- **Resolution:** Commit 758f1f1. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0875".

---

### GAP-0839: DNSSEC validation never wired into resolution path (fail-open) + DO bit never set -- **CLOSED**

- **Issue:** [#207](https://gitlab.com/devnw/zig/dns/-/issues/207) (closed)
- **Category:** Security
- **Severity:** Critical
- **Status:** **Closed** (2026-06-12). `recursive.zig` imports and invokes the DNSSEC validator; fail-closed on bogus. Also closes GAP-0070.
- **Resolution:** Commits 15258de, 56939ea, 1f7fe2d. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0839".

---

### GAP-0840: config.dnssec passed as rd bool; EDNS OPT with DO=1 never appended -- **CLOSED**

- **Issue:** [#255](https://gitlab.com/devnw/zig/dns/-/issues/255) (closed)
- **Category:** Security
- **Severity:** High
- **Status:** **Closed** (2026-06-12). `config.dnssec` now sets the DO bit in an EDNS OPT record.
- **Resolution:** Commit 56939ea. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0840".

---

### GAP-0842: RSA DNSSEC algorithms 5/8/10 unimplemented; root+most TLDs unverifiable -- **CLOSED**

- **Issue:** [#76](https://gitlab.com/devnw/zig/dns/-/issues/76) (closed)
- **Category:** Feature
- **Severity:** High
- **Status:** **Closed** (2026-06-12). RSA/SHA-1 (5), RSA/SHA-256 (8), RSA/SHA-512 (10) implemented. GAP-0843 auto-resolved.
- **Resolution:** Commit 8e56bb9. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0842".

---

### GAP-0846: Zone-file leading-whitespace continuation detection is dead code -> owner mis-attribution -- **CLOSED**

- **Issue:** [#257](https://gitlab.com/devnw/zig/dns/-/issues/257) (closed)
- **Category:** Bug
- **Severity:** High
- **Status:** **Closed** (2026-06-12). Continuation detection now runs against the untrimmed line; owner inheritance correct.
- **Resolution:** Commit d92e657. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0846".

---

### GAP-0847: split_dns matchSuffix lacks label-boundary check -> policy bypass -- **CLOSED**

- **Issue:** [#306](https://gitlab.com/devnw/zig/dns/-/issues/306) (closed)
- **Category:** Security
- **Severity:** High
- **Status:** **Closed** (2026-06-12). `matchSuffix` now requires a label boundary; `evilcorp.local` no longer matches `corp.local`.
- **Resolution:** Commit 02fb95c. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0847".

---

### GAP-0868: Zone transfer never computes/verifies TSIG (RFC 8945) -- fail-open -- **CLOSED**

- **Issue:** [#307](https://gitlab.com/devnw/zig/dns/-/issues/307) (closed)
- **Category:** Security
- **Severity:** High
- **Status:** **Closed** (2026-06-12). TSIG signing and chained MAC verification enforced on AXFR; missing/invalid MAC aborts transfer.
- **Resolution:** Commits 9315644, 2d6f964. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0868".

---

### GAP-0876: failover selectServer returns aliasing *ServerState -> UAF on add/removeServer -- **CLOSED**

- **Issue:** [#308](https://gitlab.com/devnw/zig/dns/-/issues/308) (closed)
- **Category:** Bug
- **Severity:** High
- **Status:** **Closed** (2026-06-12). `selectServer` returns a stable index handle; UAF eliminated.
- **Resolution:** Commits c69c2d7, 80573a2. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0876".

---

### GAP-0841: RRSIG labels field not validated (RFC 4035 §5.3.2 wildcard replay) -- **CLOSED**

- **Issue:** [#309](https://gitlab.com/devnw/zig/dns/-/issues/309) (closed)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). RRSIG `labels` field validated; wildcard replay rejected.
- **Resolution:** Commit 53382d7. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0841".

---

### GAP-0844: Client.initWithConfig missing errdefer; leaks on StubResolver.init failure -- **CLOSED**

- **Issue:** [#258](https://gitlab.com/devnw/zig/dns/-/issues/258) (closed)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). `errdefer` added; no leak on init failure.
- **Resolution:** Commit 15fd180. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0844".

---

### GAP-0845: Unguarded @intCast(timeMilli()-start_time) panics on clock regression -- **CLOSED**

- **Issue:** [#310](https://gitlab.com/devnw/zig/dns/-/issues/310) (closed)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Elapsed time clamped with `@max(0, delta)`.
- **Resolution:** Commit 2217ef3. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0845".

---

### GAP-0848: Docs claim Zig 0.15.1 (needs 0.16.0); manifest version 0.1.8 lags v0.1.9 tags -- **CLOSED**

- **Issue:** [#211](https://gitlab.com/devnw/zig/dns/-/issues/211) (closed)
- **Category:** Docs
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Docs and manifest updated to 0.16.0. Also closes GAP-0075.
- **Resolution:** Commits d7cfdf0, 10cb5b0. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0848".

---

### GAP-0849: bench.zig uses removed std.time.Timer (9 sites); zig build bench fails -- **CLOSED**

- **Issue:** [#216](https://gitlab.com/devnw/zig/dns/-/issues/216) (closed). Also closes GAP-0077.
- **Category:** CI-CD
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). `std.time.Timer` replaced with `nowNs()` pattern (9 sites); `zig build bench` compiles.
- **Resolution:** Commit 675d1cf. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0849".

---

### GAP-0850: compare.zig uses removed std.process.args(); compare-bench fails; no CI coverage -- **CLOSED**

- **Issue:** [#311](https://gitlab.com/devnw/zig/dns/-/issues/311) (closed)
- **Category:** CI-CD
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). `std.process.args()` replaced with `argsAlloc`; `zig build compare-bench` compiles.
- **Resolution:** Commit 675d1cf. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0850".

---

### GAP-0851: systemRandomU16() duplicated 3x with catch unreachable; inconsistent entropy APIs -- **CLOSED**

- **Issue:** [#312](https://gitlab.com/devnw/zig/dns/-/issues/312) (closed)
- **Category:** Code Quality (maintainability)
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Single `util/random.zig` helper used everywhere; `catch unreachable` removed; consistent entropy API.
- **Resolution:** Commits 4d5abf3, c0a6ba9. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0851".

---

### GAP-0858: scale_bench 100K tier times out (DebugAllocator + legacy O(n) Cache eviction) -- **CLOSED**

- **Issue:** [#313](https://gitlab.com/devnw/zig/dns/-/issues/313) (closed)
- **Category:** Performance
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). 100K tier completes within budget.
- **Resolution:** Commit e0adc73. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0858".

---

### GAP-0859: Benches measure legacy Cache, not production DnsCache; baseline non-representative -- **CLOSED**

- **Issue:** [#314](https://gitlab.com/devnw/zig/dns/-/issues/314) (closed)
- **Category:** Performance
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Cache benchmarks now target DnsCache; baseline re-captured.
- **Resolution:** Commit 8f8592a. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0859".

---

### GAP-0860: page_allocator per thread-pool task -- **CLOSED**

- **Issue:** [#315](https://gitlab.com/devnw/zig/dns/-/issues/315) (closed)
- **Category:** Performance
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Tasks use pooled/arena allocator.
- **Resolution:** Commit a742417. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0860".

---

### GAP-0861: putRecordWithKey O(N^2) rdata copy -- **CLOSED**

- **Issue:** [#316](https://gitlab.com/devnw/zig/dns/-/issues/316) (closed)
- **Category:** Performance
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Rdata copy is now linear.
- **Resolution:** Commit 5e9c6e2. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0861".

---

### GAP-0869: AXFR receive loop unbounded: no message-count cap, no in-loop deadline -> DoS -- **CLOSED**

- **Issue:** [#317](https://gitlab.com/devnw/zig/dns/-/issues/317) (closed)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Per-loop deadline and max message/record count enforced.
- **Resolution:** Commit 6560230. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0869".

---

### GAP-0870: SIG(0) verify never checks signer_name against trusted key name (key_tag collision) -- **CLOSED**

- **Issue:** [#318](https://gitlab.com/devnw/zig/dns/-/issues/318) (closed)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). `verify` matches signer_name to trusted key name; key_tag-colliding key rejected.
- **Resolution:** Commits d44c58d, 2d6f964. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0870".

---

### GAP-0877: Inline clock shim re-implemented in 16 modules; util/clock.zig shims unused -- **CLOSED**

- **Issue:** [#319](https://gitlab.com/devnw/zig/dns/-/issues/319) (closed)
- **Category:** Code Quality (maintainability)
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). All 16 inline shims replaced with `util/clock.zig`; injectable clock available.
- **Resolution:** Commit 6264654. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0877".

---

### GAP-0878: Zig-0.16 Mutex shim copy-pasted in 3 files -- **CLOSED**

- **Issue:** [#320](https://gitlab.com/devnw/zig/dns/-/issues/320) (closed)
- **Category:** Code Quality (maintainability)
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Single shared Mutex shim in `util/sync.zig` imported by all three files.
- **Resolution:** Commit 4852ffe. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0878".

---

### GAP-0880: failover: zero test coverage for circuit recovery/weighted/least-conn/latency; no injectable Clock -- **CLOSED**

- **Issue:** [#321](https://gitlab.com/devnw/zig/dns/-/issues/321) (closed)
- **Category:** Test
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Injectable Clock and tests for all four strategies added.
- **Resolution:** Commits c19b426, 80573a2. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0880".

---

### GAP-0888: TCP length-prefix + payload sent as 2 writeAll calls under TCP_NODELAY -> 2 segments/syscalls per query -- **CLOSED**

- **Issue:** [#322](https://gitlab.com/devnw/zig/dns/-/issues/322) (closed)
- **Category:** Performance
- **Severity:** Medium
- **Status:** **Closed** (2026-06-12). Length prefix and payload coalesced into one write.
- **Resolution:** Commit 3527d69. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0888".

---

### GAP-0866: ~190 stale tracker issues open but resolved per docs (reconciliation backlog)

- **Issue:** [#345](https://gitlab.com/devnw/zig/dns/-/issues/345)
- **Category:** Other (tracker reconciliation)
- **Severity:** Medium
- **Status:** **Open** -- NEEDS-DECISION (admin). This audit intentionally does NOT mass-close these.
- **Evidence:** GitLab tracker -- ~190 issues open that docs report resolved; see #78 (GAP-0015).
- **Linked findings:** #78, GAP-0015
- **Acceptance criteria:** maintainer chooses a reconciliation approach; stale issues closed with evidence OR re-validated as genuinely open.

---

### GAP-0843: DnssecAlgorithm.isSupported() claims RSA support; verifySignature rejects -- **CLOSED**

- **Issue:** [#323](https://gitlab.com/devnw/zig/dns/-/issues/323) (closed; auto-resolved with GAP-0842)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). `isSupported()` now agrees with `verifySignature` for RSA 5/8/10.
- **Resolution:** Commit 0f64fbf. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0843".

---

### GAP-0852: $INCLUDE silently ignored; module doc claims support -- **CLOSED**

- **Issue:** [#244](https://gitlab.com/devnw/zig/dns/-/issues/244) (closed)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). `$INCLUDE` now returns an explicit error instead of silently ignoring.
- **Resolution:** Commit 35726f4. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0852".

---

### GAP-0853: UDP SO_RCVTIMEO full timeout per recvfrom -- **CLOSED**

- **Issue:** [#259](https://gitlab.com/devnw/zig/dns/-/issues/259) (closed)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Overall deadline tracked across spurious packets; total wait bounded by query timeout budget.
- **Resolution:** Commit 6258f8a. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0853".

---

### GAP-0854: DoH and DoQ lack CA-trust gate; DoH Content-Type skipped when header absent; DoQ checks only ALPN -- **CLOSED**

- **Issue:** [#324](https://gitlab.com/devnw/zig/dns/-/issues/324) (closed)
- **Category:** Security
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). DoH and DoQ enforce CA trust identically to DoT; Content-Type and ALPN validation tightened.
- **Resolution:** Commits 06353b4, bab5638, efa920a. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0854".

---

### GAP-0855: RPZ matchPattern no trailing-dot normalization -- **CLOSED**

- **Issue:** [#325](https://gitlab.com/devnw/zig/dns/-/issues/325) (closed)
- **Category:** Security
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Trailing-dot normalization applied; `example.com.` and `example.com` match the same rule.
- **Resolution:** Commit 311ce9f. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0855".

---

### GAP-0856: calculatePadding @intCast without u16 bound guard -- **CLOSED**

- **Issue:** [#326](https://gitlab.com/devnw/zig/dns/-/issues/326) (closed)
- **Category:** Security
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Padding bounded to u16 before cast.
- **Resolution:** Commit 95f6580. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0856".

---

### GAP-0857: CI fmt check excludes tests/examples/benchmarks -- **CLOSED**

- **Issue:** [#327](https://gitlab.com/devnw/zig/dns/-/issues/327) (closed)
- **Category:** CI-CD
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). fmt check now covers `tests/`, `examples/`, `benchmarks/`.
- **Resolution:** Commit db34f84. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0857".

---

### GAP-0862: Full sort on every addRule (RPZ + split_dns) -- **CLOSED**

- **Issue:** [#328](https://gitlab.com/devnw/zig/dns/-/issues/328) (closed)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Sort deferred/batched; no full re-sort per insert.
- **Resolution:** Commit 2dd64a4. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0862".

---

### GAP-0863: Naive substring search in split_dns matchContains -- **CLOSED**

- **Issue:** [#329](https://gitlab.com/devnw/zig/dns/-/issues/329) (closed)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). `std.mem.indexOf` (case-insensitive) used; behavior unchanged.
- **Resolution:** Commit 4f330a7. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0863".

---

### GAP-0864: getPool() unconditional mutex -- **WON'T DO**

- **Issue:** [#330](https://gitlab.com/devnw/zig/dns/-/issues/330) (closed as Won't-Do)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Won't Do** (2026-06-12). `Mutex` is the correct primitive; lock-free fast path adds complexity and risk for negligible gain.
- **Reason:** Pool acquisition is not on the per-query hot loop. Correctness risk outweighs the marginal performance gain. See `GAP_ANALYSIS_RESOLVED.md` "Won't Do (2026-06-12 Campaign) / GAP-0864".

---

### GAP-0871: DoQ queryImpl does not verify response Message ID == 0 on live path -- **CLOSED**

- **Issue:** [#331](https://gitlab.com/devnw/zig/dns/-/issues/331) (closed)
- **Category:** Security
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Live DoQ path rejects non-zero Message ID.
- **Resolution:** Commit 5a5c351. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0871".

---

### GAP-0872: ClientSubnet.parse (source_prefix_length+7)/8 u8 overflow panic; RFC 7871 cap unenforced -- **CLOSED**

- **Issue:** [#332](https://gitlab.com/devnw/zig/dns/-/issues/332) (closed)
- **Category:** Security
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Prefix length validated against RFC 7871 caps before byte math.
- **Resolution:** Commit bce6714. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0872".

---

### GAP-0873: SIG(0) verify accepts inverted validity windows; no inception<=expiration check -- **CLOSED**

- **Issue:** [#333](https://gitlab.com/devnw/zig/dns/-/issues/333) (closed)
- **Category:** Security
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). `verify` rejects signatures where inception > expiration.
- **Resolution:** Commit e49cf1d. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0873".

---

### GAP-0881: zdig exits 0 when no domain specified -- **CLOSED**

- **Issue:** [#334](https://gitlab.com/devnw/zig/dns/-/issues/334) (closed)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Missing domain prints usage to stderr and exits non-zero.
- **Resolution:** Commit 449be6c. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0881".

---

### GAP-0882: zdig @server parsing IPv4-only; IPv6 fails opaquely -- **CLOSED**

- **Issue:** [#335](https://gitlab.com/devnw/zig/dns/-/issues/335) (closed)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). IPv6 and bracketed-IPv6 @server parsing added; invalid server yields explicit error.
- **Resolution:** Commit d088eb9. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0882".

---

### GAP-0883: zdig silently ignores unknown +options -- **CLOSED**

- **Issue:** [#336](https://gitlab.com/devnw/zig/dns/-/issues/336) (closed)
- **Category:** Bug
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Unknown +options now emit a warning; invalid option exits with clear error message.
- **Resolution:** Commit 213a8ba. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0883".

---

### GAP-0884: Stale doc comment claims std.crypto.random (removed in 0.16) -- **CLOSED**

- **Issue:** [#337](https://gitlab.com/devnw/zig/dns/-/issues/337) (closed)
- **Category:** Docs
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Doc comment updated to reflect the actual entropy source used in Zig 0.16.
- **Resolution:** Commit f9548c2. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0884".

---

### GAP-0885: selectWeighted batchy WRR distribution -- **CLOSED**

- **Issue:** [#338](https://gitlab.com/devnw/zig/dns/-/issues/338) (closed)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Smooth WRR interleaving implemented; test asserts interleaved distribution over a full cycle.
- **Resolution:** Commits ebe6d24, 80573a2. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0885".

---

### GAP-0887: applyCase0x20 heap alloc per delegation hop; stack variant possible -- **CLOSED**

- **Issue:** [#339](https://gitlab.com/devnw/zig/dns/-/issues/339) (closed)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Stack-buffer variant implemented for in-bound names; no heap alloc on common delegation path.
- **Resolution:** Commit 53a0dcc. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0887".

---

### GAP-0889: ConnectionPool fully linear-scan; acquire scans up to 3x -- **CLOSED**

- **Issue:** [#340](https://gitlab.com/devnw/zig/dns/-/issues/340) (closed)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). Acquire rewritten as single-pass scan; behavior unchanged.
- **Resolution:** Commit d369a05. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0889".

---

### GAP-0890: dnssec signed_data ArrayList no capacity reservation -- **CLOSED**

- **Issue:** [#341](https://gitlab.com/devnw/zig/dns/-/issues/341) (closed)
- **Category:** Performance
- **Severity:** Low
- **Status:** **Closed** (2026-06-12). ensureTotalCapacity added before building signed_data; no functional change.
- **Resolution:** Commit b7bb3d5. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0890".

---

### GAP-0865: Unreachable protobuf CVEs in zig-pkg transitive dep; add SBOM exclude -- **CLOSED**

- **Issue:** [#342](https://gitlab.com/devnw/zig/dns/-/issues/342) (closed)
- **Category:** Security (supply-chain)
- **Severity:** Info
- **Status:** **Closed** (2026-06-12). SBOM updated with exclusion annotation for unreachable protobuf CVEs with justification.
- **Resolution:** Commit a05d5e2. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0865".

---

### GAP-0874: DnsConfig allows semantically invalid in-range values -- **CLOSED**

- **Issue:** [#343](https://gitlab.com/devnw/zig/dns/-/issues/343) (closed)
- **Category:** Security (hardening)
- **Severity:** Info
- **Status:** **Closed** (2026-06-12). Config validation added rejecting/normalizing timeout_ms=0, retries=255, and max_ttl overflow values.
- **Resolution:** Commit 4509ed3. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0874".

---

### GAP-0886: isAvailable redundant early-return branch -- **CLOSED**

- **Issue:** [#344](https://gitlab.com/devnw/zig/dns/-/issues/344) (closed)
- **Category:** Code Quality (cleanup)
- **Severity:** Info
- **Status:** **Closed** (2026-06-12). Redundant early-return branch removed; behavior unchanged.
- **Resolution:** Commit 5f1b681. See `GAP_ANALYSIS_RESOLVED.md` "Gap-Closure Campaign 2026-06-12 / GAP-0886".

---

## Resolved / Won't-Do (audit trail)

### GAP-0048: RPZ wildcard boundary bypass test missing -- **RESOLVED**

- **Issue:** (not yet filed)
- **Category:** Test
- **Severity:** Low
- **Status:** **Resolved** (2026-03-24). Test added verifying wildcard boundary matching for RPZ.
- **Evidence:** `src/resolver/rpz.zig` -- test asserts `*example.com` matches `sub.example.com` but NOT `fakeexample.com`
- **Resolved date:** 2026-03-24

---

### GAP-0049: DNSSEC canonical RRset sorting not implemented (RFC 4034 S6.3) -- **RESOLVED**

- **Issue:** (not yet filed)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). Canonical RRset sorting implemented in `appendCanonicalRrset` per RFC 4034 S6.3 before RRSIG wire-format construction.
- **Evidence:** `src/resolver/dnssec.zig` -- `appendCanonicalRrset` sorts RRsets in canonical order before RRSIG verification
- **Resolved date:** 2026-03-24

---

### GAP-0050: RFC_COMPLIANCE.md claims "Complete" for RFC 4033/4034 but RSA missing -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Low
- **Status:** **Resolved** (2026-03-24). RFC_COMPLIANCE.md RFC 4033 and 4034 statuses updated to "Partial (Ed25519/ECDSA complete; RSA algorithms 5/8/10 not implemented)".
- **Evidence:** `docs/RFC_COMPLIANCE.md:53-59` -- both entries now say "Partial" with RSA caveat, consistent with README.md.
- **Resolved date:** 2026-03-24

---

### GAP-0051: DoQ feature gate blocks all DoQ tests in CI -- **WON'T DO**

- **Issue:** (not yet filed)
- **Category:** CI-CD
- **Severity:** Low
- **Status:** **Won't Do** (2026-03-24). Requires QUIC dependencies that are not available in the Zig ecosystem. DoQ transport is behind a feature gate by design; enabling it in CI requires external QUIC library integration which is out of scope.
- **Reason:** QUIC dependency not available; feature gate is intentional. Cross-ref GAP-0014 (DoT/DoH/DoQ transports are interface-only by design).

---

### GAP-0015: 24 issues marked Complete in docs but Open in GitLab tracker -- **WON'T DO**

- **Issue:** [#78](https://gitlab.com/devnw/zig/dns/-/issues/78)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Won't Do** -- Docs-side is resolved. GitLab issue closure requires admin action and is outside the scope of code-level gap closure.
- **Reason:** Administrative tracker reconciliation; code and docs are accurate.

---

### GAP-0017: Functional UDP/TCP transports suppressed from public API -- **WON'T DO**

- **Issue:** [#80](https://gitlab.com/devnw/zig/dns/-/issues/80)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Won't Do** -- Transport modules are exposed in public API (GAP-0011 resolved). Wiring resolvers to use transport abstractions requires significant architectural refactoring.
- **Reason:** Architectural refactor outside scope. Inline socket code works correctly. Cross-ref GAP-0044, QC-NEW-03.

---

### GAP-0038: README "Zero Dependencies" claim is inaccurate -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). README.md updated to say "Minimal Dependencies" with distinction between runtime and test-only dependencies.
- **Evidence:** `README.md` -- dependency claim updated to match `build.zig.zon` manifest
- **Resolved date:** 2026-03-24

---

### GAP-0039: README RFC 4033/4034/4035 says "Complete" -- RSA missing, should say Partial -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). README RFC table updated to "Partial" with RSA caveat note: "Ed25519/ECDSA complete, RSA pending".
- **Evidence:** `README.md` -- RFC 4033/4034/4035 status says "Partial"; consistent with ROADMAP.md Phase 3
- **Resolved date:** 2026-03-24

---

### GAP-0040: README RFC 7858 DoT listed "Complete" without asterisk -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Docs
- **Severity:** Low
- **Status:** **Resolved** (2026-03-24). Added footnote to README RFC 7858 entry noting "Interface only -- requires external TLS backend", consistent with DoH/DoQ treatment and GAP-0014 documentation.
- **Evidence:** `README.md` -- RFC 7858 entry has interface-only annotation
- **Resolved date:** 2026-03-24

---

### GAP-0041: Convenience API stubs return error.NotImplemented -- **WON'T DO**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Won't Do** -- Functions return explicit `error.NotImplemented` (improved from silent empty returns in QH-NEW-01). `client.Client` is the documented working alternative.
- **Reason:** Feature addition outside scope. Convenience API returns explicit errors; `client.Client` provides all functionality.

---

### GAP-0042: Client API missing lookupSRV/TXT/PTR/NS/SOA methods -- **WON'T DO**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Feature
- **Severity:** Medium
- **Status:** **Won't Do** -- Feature addition outside scope. Raw query API (`resolve()`) works for all record types. Cache now correctly formats 9 record types (GAP-0043 resolved).
- **Reason:** New feature development; raw query API provides full access to all record types.

---

### GAP-0043: Cache hit only formats A/AAAA -- MX/SRV/TXT cache hits return empty -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-24). Added `formatCachedRdata` function in `client.zig` that handles 9 record types (A, AAAA, MX, SRV, TXT, PTR, NS, SOA, CNAME) on cache hit path. No record type silently returns empty on cache hit. Cross-ref QM-NEW-03 in QUALITY_GAP_ANALYSIS.md.
- **Evidence:** `src/client.zig` -- `formatCachedRdata` function covering 9 record types
- **Resolved date:** 2026-03-24

---

### GAP-0044: Transport abstraction not wired into resolvers -- **WON'T DO**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Code Quality
- **Severity:** Medium
- **Status:** **Won't Do** -- Architectural refactor requiring significant transport layer redesign. Inline socket code works correctly. Cross-ref GAP-0017 (also Won't Do), QC-NEW-03 (Won't Do).
- **Reason:** Large architectural change outside scope. Inline socket code is well-tested and functionally correct.

---

### GAP-0045: resolveIterative zero test coverage -- 219 lines, 9 nesting levels, untested -- **WON'T DO**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Test
- **Severity:** High
- **Status:** **Won't Do** -- Requires mock DNS transport infrastructure that does not exist. Remains as a production recommendation (see Production Blockers section).
- **Reason:** Test infrastructure gap. Mock transport layer needed for injection of DNS responses. Cross-ref QH-NEW-02.

---

### GAP-0046: Zero fuzz testing for wire parsers -- **WON'T DO**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Test
- **Severity:** High
- **Status:** **Won't Do** -- Requires fuzz infrastructure setup (`std.testing.fuzz` targets, CI integration). Remains as a production recommendation. Note: all 7 bounds-check bugs found by adversarial review (SEC-NEW-01 through SEC-NEW-07) have been fixed.
- **Reason:** Fuzz infrastructure investment outside scope. All known bounds-check bugs resolved.

---

### GAP-0047: spice dependency pins main branch -- **WON'T DO**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Won't Do** -- Upstream concern. Hash pinning in `build.zig.zon` provides integrity protection. Tagged release requires upstream action.
- **Reason:** Upstream dependency management. Hash pinning provides partial mitigation. Cross-ref SEC-C14/C31, QS-NEW-08.

---

### GAP-0057: DNSSEC validation module has compile-time API mismatches -- dead code -- **RESOLVED**

- **Issue:** (not yet filed)
- **Category:** Bug
- **Severity:** Critical
- **Status:** **Resolved** (2026-03-25). 11 code fixes in `dnssec.zig`: updated all `parseNSEC()`/`parseRRSIG()` call sites to pass `full_message` argument; fixed `next_name` to `next_domain`; replaced `[]const u8` with `Name` struct comparisons via `Name.toStringBuf`/`Name.eql`; replaced `std.mem.eql` on `Name` structs. 7 new integration tests added; all 479 tests pass.
- **Evidence:** `src/resolver/dnssec.zig` -- 11 call site fixes; 7 new tests; all 479 tests pass
- **Resolved date:** 2026-03-25

---

### GAP-0058: LabelIterator first compression pointer hop skips forward check -- **RESOLVED**

- **Issue:** (not yet filed -- confidential)
- **Category:** Security
- **Severity:** High
- **Status:** **Resolved** (2026-03-25). Forward pointer check added on first hop: when `last_ptr_target` is null, `ptr_offset` is now validated against the current name offset to ensure backward-only pointers. 1 new test verifying first-hop forward pointer rejection.
- **Evidence:** `src/name.zig:107-114` -- forward pointer check on first hop; 1 new test
- **CWE:** CWE-835 (Loop with Unreachable Exit Condition)
- **Resolved date:** 2026-03-25

---

### GAP-0059: UDP receive loops lack packet discard count limit -- **RESOLVED**

- **Issue:** (not yet filed -- confidential)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). Added `max_spurious_discards = 1000` counter to all three UDP receive loops. Returns `error.TooManySpuriousPackets` when exceeded. 3 new tests verifying the discard limit.
- **Evidence:** `src/stub.zig:87`, `src/recursive.zig:130`, `src/transports/udp.zig:16` -- max_spurious_discards constant; 3 new tests
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Resolved date:** 2026-03-25

---

### GAP-0060: Client.resolve silently returns NoAnswer for non-A/AAAA queries -- **RESOLVED**

- **Issue:** (not yet filed)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). Added `error.UnsupportedRecordType` guard for non-A/AAAA queries, returning an explicit error instead of silently returning NoAnswer. 1 new test verifying the guard.
- **Evidence:** `src/client.zig:169-171` -- error.UnsupportedRecordType guard; 1 new test
- **Resolved date:** 2026-03-25

---

### GAP-0061: TSIG MAC recomputation hardcodes error/other fields to zero -- **RESOLVED**

- **Issue:** (not yet filed -- confidential)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). `buildTsigVariables` parameterized with `error_code` and `other_data` parameters. `verify()` now passes wire values from the received TSIG record instead of hardcoded zeros. 1 new test verifying MAC covers actual error/other fields.
- **Evidence:** `src/security/tsig.zig` -- buildTsigVariables parameterized with error_code/other_data; verify() passes wire values; 1 new test
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
- **Resolved date:** 2026-03-25

---

### GAP-0062: SIG(0) sign() u32 expiration addition can overflow -- **RESOLVED**

- **Issue:** (not yet filed -- confidential)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). Replaced unchecked `now + self.validity_seconds` with `std.math.add(u32, now, self.validity_seconds) catch return error.TimestampOverflow`. 1 new test verifying overflow detection.
- **Evidence:** `src/security/sig0.zig:308-309` -- std.math.add with error.TimestampOverflow; 1 new test
- **CWE:** CWE-190 (Integer Overflow)
- **Resolved date:** 2026-03-25

---

### GAP-0063: NSEC NODATA validation uses case-sensitive name comparison -- **RESOLVED**

- **Issue:** (not yet filed)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). Replaced `std.mem.eql` with `std.ascii.eqlIgnoreCase` for DNS name comparison per RFC 4343. Unblocked by GAP-0057 fix. 1 new test verifying case-insensitive NSEC NODATA matching.
- **Evidence:** `src/resolver/dnssec.zig:245` -- std.ascii.eqlIgnoreCase; 1 new test
- **CWE:** CWE-178 (Improper Handling of Case Sensitivity)
- **Resolved date:** 2026-03-25

---

### GAP-0064: compareDnsNames does left-to-right byte comparison instead of RFC 4034 Section 6.1 canonical label ordering -- **RESOLVED**

- **Issue:** (not yet filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** High
- **Status:** **Resolved** (2026-03-25). `compareDnsNames` rewritten to extract labels from wire-format names into stack arrays, reverse to root-first order, and compare label-by-label with case-insensitive byte comparison per RFC 4034 Section 6.1. 9 new tests added covering canonical ordering edge cases.
- **CWE:** CWE-697 (Incorrect Comparison)
- **Evidence:** `src/resolver/dnssec.zig:821` -- `compareDnsNames` splits wire-format names into labels and compares root-first; 9 new tests
- **Resolved date:** 2026-03-25

---

### GAP-0065: extractNsec3OwnerHash returns base32hex-encoded ASCII instead of decoded raw hash bytes -- **RESOLVED**

- **Issue:** (not yet filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** High
- **Status:** **Resolved** (2026-03-25). `extractNsec3OwnerHash` replaced with `decodeNsec3OwnerHash` that decodes base32hex ASCII owner labels to raw binary bytes. Base32hex codec added to `dnssec.zig`. `hashInNsec3Range` and `validateNodataWithNsec3` now compare binary-to-binary. 6 new tests added.
- **CWE:** CWE-704 (Incorrect Type Conversion or Cast)
- **Evidence:** `src/resolver/dnssec.zig` -- `decodeNsec3OwnerHash` with base32hex codec; 6 new tests
- **Resolved date:** 2026-03-25

---

### GAP-0066: validateNodataWithNsec wire-format vs dotted-string mismatch -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** High
- **Status:** **Resolved** (2026-03-25). `dottedToWire` conversion added at entry point of `validateNodataWithNsec`. The function now converts the dotted-string `qname` to wire-format before comparison with `wireNamesEqlInsensitive`.
- **Evidence:** `src/resolver/dnssec.zig` -- `dottedToWire(qname)` called before `wireNamesEqlInsensitive` comparison. 1 new test verifying NSEC NODATA validation with dotted-string input.
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `validateNodataWithNsec` returns `true` when given a valid NSEC record whose owner name matches the query name (format-normalized)
  - [x] Test with mixed-case dotted-string qname and wire-format NSEC owner

---

### GAP-0067: validateNxdomainWithNsec wire-format vs dotted-string mismatch -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** High
- **Status:** **Resolved** (2026-03-25). `dottedToWire` conversion added at entry point of `validateNxdomainWithNsec`. The function now converts the dotted-string `qname` to wire-format before passing to `nameInNsecRange`.
- **Evidence:** `src/resolver/dnssec.zig` -- `dottedToWire(qname)` called before `nameInNsecRange`. 1 new test verifying NSEC NXDOMAIN range check with dotted-string input.
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `validateNxdomainWithNsec` returns `true` when qname falls within a valid NSEC range (format-normalized)
  - [x] Test with dotted-string qname and wire-format NSEC owner/next names

---

### GAP-0068: computeNsec3Hash receives dotted-string instead of wire-format -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). `dottedToWire` conversion added at both NSEC3 validation entry points (`validateNxdomainWithNsec3`, `validateNodataWithNsec3`). The `computeNsec3Hash` function now receives wire-format input, producing correct SHA-1 digests per RFC 5155 Section 5.
- **Evidence:** `src/resolver/dnssec.zig` -- `dottedToWire(qname)` called in both NSEC3 entry points before `computeNsec3Hash`. 1 new test verifying NSEC3 hash computation with dotted-string input produces correct wire-format digest.
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `computeNsec3Hash("example.com", ...)` produces the same digest as hashing wire-format `"\x07example\x03com\x00"`
  - [x] NSEC3 NXDOMAIN and NODATA validation return `true` for valid NSEC3 coverage of a dotted-string query name

---

### GAP-0069: TCP fallback parse failure leaks tcp_response memory -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Bug
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). `catch continue` replaced with `catch { self.allocator.free(tcp_response); continue; }` to free the TCP response buffer on parse failure. Regression test added using testing allocator to verify no leaks.
- **Evidence:** `src/stub.zig:209-212` -- `Message.parse(tcp_response) catch { self.allocator.free(tcp_response); continue; };`
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `tcp_response` is freed when `Message.parse` fails
  - [x] Test that allocator reports no leaks after a TCP fallback parse failure

---

### SEC-AUDIT-11: validateChainOfTrust ignores target_zone parameter -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Medium
- **Status:** **Resolved** (2026-03-25). `target_zone` parameter is now used via `isNameInZone` to verify that DNSKEY/DS records belong to the expected zone during chain-of-trust validation. Cross-zone records are rejected.
- **Evidence:** `src/resolver/dnssec.zig` -- `isNameInZone(target_zone, ...)` check added in `validateChainOfTrust`. 1 new test verifying cross-zone DNSKEY rejection.
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `validateChainOfTrust` rejects DNSKEY/DS records whose owner name does not match the expected zone
  - [x] Test with cross-zone DNSKEY injection returns `indeterminate` or `bogus`

---

### SEC-AUDIT-12: extractWireLabels silently truncates malformed names -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Low
- **Status:** **Resolved** (2026-03-25). `extractWireLabels` now returns an error union. Compression pointers in canonical wire-format and out-of-bounds label lengths return `error.MalformedName`. `compareDnsNames` propagates the error to callers.
- **Evidence:** `src/resolver/dnssec.zig` -- `extractWireLabels` returns `!LabelList`; 4 new tests for compression pointer rejection, OOB label length, empty input, and valid wire names.
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `extractWireLabels` returns an error for truncated label lengths
  - [x] `compareDnsNames` propagates the error to callers

---

### SEC-AUDIT-13: base32hexDecode does not reject non-zero trailing bits -- **RESOLVED**

- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security
- **Severity:** Low
- **Status:** **Resolved** (2026-03-25). After the decode loop, `base32hexDecode` now checks remaining bits in `bit_buffer` and returns `error.InvalidData` when trailing bits are non-zero, per RFC 4648 Section 3.5.
- **Evidence:** `src/resolver/dnssec.zig` -- trailing-bit check added after decode loop. 2 new tests: canonical encoding accepted, non-zero trailing bits rejected with `error.InvalidData`.
- **Resolved date:** 2026-03-25
- **Acceptance criteria:**
  - [x] `base32hexDecode` rejects input with non-zero trailing bits
  - [x] Test that canonical encoding is accepted and non-canonical is rejected

---

## Security Findings (Phase 3 + Adversarial Review + Full Audit)

The following security findings were identified across all review phases. Findings that duplicate existing GAP entries are cross-referenced. All new issues are created as **confidential** on GitLab.

### Stack-Ranked Security Findings (All Phases, Unified)

| Rank | Severity | Risk Score | Finding | Component | CWE/OWASP | Evidence | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-----------|----------|-------|-----|--------|
| 1 | Critical | 80 | SEC-C22: PipelinedBatch infinite loop on connection close | connection_pool.zig | CWE-835 / A05:2021 | connection_pool.zig:468,490 | [#154](https://gitlab.com/devnw/zig/dns/-/issues/154) (confidential) / GAP-0028 [#133] | 7d | **Resolved** |
| 2 | **High** | **64** | **SEC-SCAN-09: Trust anchor digest `@min` truncation allows partial digest match -- DNSSEC bypass** | dnssec.zig | CWE-187 / A02:2021 | dnssec.zig:556 | (not yet filed -- confidential) | 30d | **Resolved** |
| 3 | High | 64 | SEC-NEW-01: OOB read in extractTsig -- rdlength not validated before slice | tsig.zig | CWE-125 / A03:2021 | tsig.zig:633 | Commit 6d42d51 | 30d | **Resolved** |
| 4 | High | 64 | SEC-NEW-02: OOB read in extractSig0 -- rdlength not validated before slice | sig0.zig | CWE-125 / A03:2021 | sig0.zig:561 | Commit 8fef334 | 30d | **Resolved** |
| 5 | High | 64 | SEC-C02: Unchecked @enumFromInt (covers SEC-C20/C21) | record.zig, sig0.zig, tsig.zig + 3 more | CWE-704 / A03:2021 | sig0.zig:217, tsig.zig:217, record.zig:439+ | [#89](https://gitlab.com/devnw/zig/dns/-/issues/89) / GAP-0033 [#134] / GAP-0034 [#135] | 30d | **Resolved** |
| 6 | High | 64 | SEC-C05: Non-CSPRNG for transaction IDs (covers SEC-C24) | recursive.zig | CWE-330 / A02:2021 | recursive.zig:119,448 | [#94](https://gitlab.com/devnw/zig/dns/-/issues/94) | 30d | **Resolved** |
| 7 | High | 48 | SEC-C23: TSIG HMAC key truncation | tsig.zig | CWE-326 / A02:2021 | tsig.zig:442,457,472,487,502 | [#157](https://gitlab.com/devnw/zig/dns/-/issues/157) (confidential) | 30d | **Resolved** |
| 8 | High | 48 | SEC-C26: Partial write data loss (3 files) | connection_pool.zig, dot.zig, zone_transfer.zig | CWE-400 / A05:2021 | connection_pool.zig:454, dot.zig:305, zone_transfer.zig:523 | [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (confidential) / GAP-0027 [#132] | 30d | **Resolved** |
| 9 | **Medium** | **48** | **SEC-NEW-04b: NSEC3 iterations not capped -- CPU DoS with iterations=65535** | dnssec.zig | CWE-400 / A05:2021 | dnssec.zig:565-595 | (not yet filed -- confidential) | 90d | **Resolved** |
| 10 | Medium | 48 | SEC-NEW-03: skipRR returns offset+10+rdlength without bounds check | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:116 | Commit 6d42d51 | 90d | **Resolved** |
| 11 | Medium | 48 | SEC-NEW-06: Question skip adds +4 without bounds check | tsig.zig, sig0.zig | CWE-125 / A03:2021 | tsig.zig:599, sig0.zig:523 | Commit 6d42d51 | 90d | **Resolved** |
| 12 | Medium | 48 | SEC-C27: No glue record bailiwick validation | recursive.zig | CWE-345 / A01:2021 | recursive.zig:564-589 | [#165](https://gitlab.com/devnw/zig/dns/-/issues/165) (confidential) | 90d | **Resolved** |
| 13 | **Medium** | **36** | **SEC-SCAN-08: Non-constant-time DS digest comparison -- timing side-channel** | dnssec.zig | CWE-208 / A02:2021 | dnssec.zig:201,540,556 | (not yet filed -- confidential) | 90d | **Resolved** |
| 14 | **Medium** | **36** | **SEC-NEW-02b: Zone transfer question section OOB read** | zone_transfer.zig | CWE-125 / A03:2021 | zone_transfer.zig:584-592 | (not yet filed -- confidential) | 90d | **Resolved** |
| 15 | **Medium** | **36** | **SEC-NEW-03b: Zone transfer qdcount not validated** | zone_transfer.zig | CWE-20 / A03:2021 | zone_transfer.zig:575-592 | (not yet filed) | 90d | **Resolved** |
| 16 | Medium | 36 | SEC-C28: Zone transfer auth defaults off | zone_transfer.zig | CWE-1188 / A05:2021 | zone_transfer.zig:46 | [#169](https://gitlab.com/devnw/zig/dns/-/issues/169) (confidential) | 90d | **Resolved** |
| 17 | Medium | 36 | SEC-C29: SIG(0) no replay protection | sig0.zig | CWE-294 / A07:2021 | sig0.zig:341-391 | [#172](https://gitlab.com/devnw/zig/dns/-/issues/172) (confidential) | 90d | **Won't Do** |
| 18 | Medium | 32 | SEC-C30: dns_name.zig allows forward compression pointers | dns_name.zig | CWE-345 / A03:2021 | dns_name.zig:60-63 | [#175](https://gitlab.com/devnw/zig/dns/-/issues/175) (confidential) | 90d | **Resolved** |
| 19 | Medium | 27 | SEC-SCAN-03: Cache has no thread-safety -- data races under concurrent access | cache.zig | CWE-362 / A04:2021 | cache.zig:68-252 | -- (skip-issues) | 90d | **Won't Do** |
| 20 | **Medium** | **24** | **SEC-SCAN-10: resolver/edns.zig options.len @intCast unchecked** | resolver/edns.zig | CWE-190 / A03:2021 | resolver/edns.zig:47 | (not yet filed) | 90d | **Resolved** |
| 21 | **Medium** | **24** | **SEC-SCAN-11: resolver/config.zig user config @intCast unchecked** | resolver/config.zig | CWE-681 / A03:2021 | resolver/config.zig:345-354 | (not yet filed) | 90d | **Resolved** |
| 22 | **Medium** | **24** | **SEC-SCAN-12: zone_transfer.zig label.len @intCast unchecked** | zone_transfer.zig | CWE-190 / A03:2021 | zone_transfer.zig:517 | (not yet filed) | 90d | **Resolved** |
| 23 | **Medium** | **24** | **SEC-SCAN-13: zone_transfer.zig message.len @intCast unchecked** | zone_transfer.zig | CWE-190 / A03:2021 | zone_transfer.zig:527 | (not yet filed) | 90d | **Resolved** |
| 24 | Medium | 24 | SEC-C100: TSIG fudge value attacker-controlled (defense-in-depth) | tsig.zig | CWE-807 / A04:2021 | tsig.zig:384 | Commit 6d42d51 | 90d | **Resolved** |
| 25 | Medium | 24 | SEC-C06/C25: Key material not zeroed (stack + heap) | tsig.zig, sig0.zig | CWE-244 / A02:2021 | tsig.zig:435-495, sig0.zig:115-117 | [#104](https://gitlab.com/devnw/zig/dns/-/issues/104) / [#111](https://gitlab.com/devnw/zig/dns/-/issues/111) | 90d | **Resolved** |
| 26 | Medium | 24 | SEC-C14/C31: spice dependency pins main branch | build.zig.zon | CWE-829 / A06:2021 | build.zig.zon:29 | [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) / GAP-0047 | 90d | **Won't Do** |
| 27 | Medium | 16 | SEC-SCAN-01: TsigKey.secret not zeroed on destruction -- no deinit method | tsig.zig | CWE-244 / A02:2021 | tsig.zig:120-153 | -- (skip-issues) | 90d | **Resolved** |
| 28 | Medium | 9 | SEC-SCAN-02: ARCOUNT u16 overflow in TSIG/SIG(0) append | tsig.zig, sig0.zig | CWE-190 / A03:2021 | tsig.zig:555, sig0.zig:346 | -- (skip-issues) | 90d | **Resolved** |
| 29 | Low | 24 | SEC-NEW-07: skipName compression pointer returns offset+2 without checking offset+1 < data.len | dns_name.zig | CWE-125 / A03:2021 | dns_name.zig:101 | Commit 6d42d51 | 180d | **Resolved** |
| 30 | Low | 16 | SEC-C101: TSIG time check before MAC creates timing oracle | tsig.zig | CWE-208 / A02:2021 | tsig.zig:350-398 | Commit 6d42d51 | 180d | **Resolved** |
| 31 | Low | 16 | SEC-NEW-04: TSIG other_data silently truncated when other_len exceeds available data | tsig.zig | CWE-130 / A03:2021 | tsig.zig:229 | Commit 6d42d51 | 180d | **Resolved** |
| 32 | Low | 16 | SEC-NEW-05: @intCast(u16) on options.len without bounds check | edns.zig | CWE-190 / A03:2021 | edns.zig:167 | Commit 8fef334 | 180d | **Resolved** |
| 33 | Low | 16 | SEC-C33: Zone transfer short-read on length prefix | zone_transfer.zig | CWE-20 / A05:2021 | zone_transfer.zig:530-531 | [#178](https://gitlab.com/devnw/zig/dns/-/issues/178) (confidential) | 180d | **Resolved** |
| 34 | **Low** | **16** | **SEC-SCAN-15: zone_transfer.zig TsigKey.secret not zeroed on struct reassignment** | zone_transfer.zig | CWE-244 / A02:2021 | zone_transfer.zig:64-68 | (not yet filed) | 180d | **Resolved** |
| 35 | **Low** | **16** | **SEC-SCAN-16: connection_pool.zig time delta @intCast unchecked** | connection_pool.zig | CWE-681 / A03:2021 | connection_pool.zig:123,128 | (not yet filed) | 180d | **Resolved** |
| 36 | **Low** | **16** | **SEC-SCAN-17: happy_eyeballs.zig time delta @intCast unchecked** | happy_eyeballs.zig | CWE-681 / A03:2021 | happy_eyeballs.zig:199,239 | (not yet filed) | 180d | **Resolved** |
| 37 | Low | 12 | ADV-02: No TSIG replay protection within fudge window | tsig.zig | CWE-294 / A07:2021 | tsig.zig:302-408 | -- (skip-issues) | 180d | **Won't Do** |
| 38 | Low | 8 | SEC-C32: SIG(0) timestamp u32 overflow in 2106 | sig0.zig | CWE-190 / A05:2021 | sig0.zig:278,369 | [#176](https://gitlab.com/devnw/zig/dns/-/issues/176) (confidential) | 180d | **Won't Do** |
| 39 | Low | 8 | SEC-SCAN-05: dns_name.zig encodeName/encodeNameLower @intCast on label.len without max label check | dns_name.zig | CWE-190 / A03:2021 | dns_name.zig:127,139 | -- (skip-issues) | 180d | **Resolved** |
| 40 | **Low** | **8** | **SEC-SCAN-14: stub.zig query.len @intCast (structurally bounded)** | stub.zig | CWE-190 / A03:2021 | stub.zig:266 | (not yet filed) | 180d | **Resolved** |
| 41 | **Low** | **8** | **SEC-NEW-01b: logging.zig time delta @intCast unchecked** | logging.zig | CWE-681 / A03:2021 | logging.zig:391 | (not yet filed) | 180d | **Resolved** |
| 42 | Low | 6 | ADV-05: Large header counts cause CPU-bound parse loop | message.zig | CWE-400 / A05:2021 | message.zig:62-82 | -- (skip-issues) | 180d | **Resolved** |
| 43 | Low | 4 | SEC-SCAN-04: TCP/DoT/DoQ/ConnectionPool @intCast(u16) on wire_req.len without bounds check | tcp.zig, dot.zig, doq.zig, connection_pool.zig | CWE-190 / A03:2021 | tcp.zig:52, dot.zig:302, connection_pool.zig:557,662,707 | -- (skip-issues) | 180d | **Resolved** |
| 44 | Low | 2 | SEC-SCAN-06: SIG(0) sign @intCast(u16) rdlength without bounds check | sig0.zig | CWE-190 / A03:2021 | sig0.zig:360 | -- (skip-issues) | 180d | **Resolved** |
| 45 | Info | 1 | SEC-SCAN-07: name.zig toString doesn't enforce forward pointer rejection (defense-in-depth) | name.zig | CWE-345 / A03:2021 | name.zig:243 | -- (skip-issues) | Backlog | **Resolved** |
| 46 | **High** | **48** | **SEC-AUDIT-01 / GAP-0058: LabelIterator first compression pointer hop skips forward check** | name.zig | CWE-835 / A03:2021 | name.zig:107-114 | (not yet filed -- confidential) | 30d | **Resolved** |
| 47 | **Medium** | **36** | **SEC-AUDIT-02 / GAP-0059: UDP receive loops lack packet discard count limit -- CPU DoS** | stub.zig, recursive.zig, udp.zig | CWE-400 / A05:2021 | stub.zig:87, recursive.zig:130, udp.zig:16 | (not yet filed -- confidential) | 90d | **Resolved** |
| 48 | **Medium** | **24** | **SEC-AUDIT-03 / GAP-0061: TSIG MAC recomputation hardcodes error/other fields to zero** | tsig.zig | CWE-345 / A02:2021 | tsig.zig -- buildTsigVariables parameterized | (not yet filed -- confidential) | 90d | **Resolved** |
| 49 | **Medium** | **24** | **SEC-AUDIT-04 / GAP-0062: SIG(0) sign() u32 expiration addition can overflow** | sig0.zig | CWE-190 / A03:2021 | sig0.zig:308-309 | (not yet filed -- confidential) | 90d | **Resolved** |
| 50 | **Medium** | **24** | **SEC-AUDIT-05 / GAP-0063: NSEC NODATA validation uses case-sensitive comparison** | dnssec.zig | CWE-178 / A03:2021 | dnssec.zig:245 | (not yet filed) | 90d | **Resolved** |
| 51 | **High** | **48** | **SEC-AUDIT-06 / GAP-0064: compareDnsNames wrong ordering -- NSEC NXDOMAIN proof bypass** | dnssec.zig | CWE-697 / A03:2021 | dnssec.zig:821 -- rewritten with label extraction + root-first comparison | (not yet filed -- skip-issues) | 30d | **Resolved** |
| 52 | **High** | **48** | **SEC-AUDIT-07 / GAP-0065: NSEC3 owner hash format mismatch -- validation non-functional** | dnssec.zig | CWE-704 / A03:2021 | dnssec.zig -- decodeNsec3OwnerHash with base32hex codec | (not yet filed -- skip-issues) | 30d | **Resolved** |
| 53 | **Low** | **8** | **SEC-AUDIT-08: TSIG fudge u16*2 overflow** | tsig.zig | CWE-190 / A03:2021 | tsig.zig:417 -- u32 widening before multiplication | (not yet filed -- skip-issues) | 180d | **Resolved** |
| 54 | **Low** | **8** | **SEC-AUDIT-09: No explicit source port randomization (OS-dependent)** | stub.zig, recursive.zig | CWE-330 / A02:2021 | stub.zig:227, recursive.zig:575 -- doc comments added (RFC 5452) | (not yet filed -- skip-issues) | 180d | **Resolved** |
| 55 | **Low** | **4** | **SEC-AUDIT-10: TCP fallback response not re-validated after TC bit** | stub.zig | CWE-345 / A03:2021 | stub.zig:210-211 -- TXID + responseMatchesQuery on TCP response | (not yet filed -- skip-issues) | 180d | **Resolved** |
| 56 | **Medium** | **36** | **SEC-AUDIT-11: validateChainOfTrust ignores target_zone -- cross-zone DNSKEY/DS accepted** | dnssec.zig | CWE-863 / A01:2021 | dnssec.zig -- `isNameInZone(target_zone, ...)` check added | (not yet filed -- skip-issues) | 90d | **Resolved** |
| 57 | **Low** | **12** | **SEC-AUDIT-12: extractWireLabels silently truncates malformed names** | dnssec.zig | CWE-20 / A03:2021 | dnssec.zig -- error union return; rejects compression + OOB | (not yet filed -- skip-issues) | 180d | **Resolved** |
| 58 | **Low** | **8** | **SEC-AUDIT-13: base32hexDecode trailing bits not validated** | dnssec.zig | CWE-20 / A03:2021 | dnssec.zig -- trailing-bit check rejects non-zero per RFC 4648 | (not yet filed -- skip-issues) | 180d | **Resolved** |

### Adversarial Review Finding Details

#### SEC-NEW-01 (HIGH): OOB read in extractTsig -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + rdlength > message.len) return error.InvalidMessage;` added at `tsig.zig:633`. Test `SEC-NEW-01: extractTsig rejects rdlength exceeding message` added.
- **Resolution evidence:** `src/security/tsig.zig:633` -- bounds check; `src/security/tsig.zig:932+` -- test

#### SEC-NEW-02 (HIGH): OOB read in extractSig0 -- **RESOLVED** (commit 8fef334)

- **Status:** Resolved (2026-03-24). Bounds check added before `message[offset .. offset + rdlength]` in extractSig0. Test added for truncated SIG(0) record.
- **Resolution evidence:** `src/security/sig0.zig` -- bounds check before rdlength slice; commit 8fef334

#### SEC-NEW-03 (MEDIUM): skipRR returns offset+10+rdlength without bounds check -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (end > data.len) return error.InvalidRR;` added at `dns_name.zig:116`. Tests `SEC-NEW-03: skipRR rejects rdlength exceeding data` and `SEC-NEW-03: skipRR accepts valid rdlength` added.
- **Resolution evidence:** `src/security/dns_name.zig:116` -- bounds check; `src/security/dns_name.zig:252+` -- tests

#### SEC-NEW-06 (MEDIUM): Question skip adds +4 without bounds check -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + 4 > message.len) return error.InvalidMessage;` added before `offset += 4` in extractTsig at `tsig.zig:599`.
- **Resolution evidence:** `src/security/tsig.zig:599` -- bounds check

#### SEC-C100 (MEDIUM): TSIG fudge value attacker-controlled -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). After MAC verification passes, fudge is now clamped: `if (tsig.fudge > self.fudge * 2)` returns `bad_time`. This limits attacker-controlled fudge to at most 2x the verifier's configured fudge.
- **Resolution evidence:** `src/security/tsig.zig:384-386` -- fudge clamp after MAC check

#### SEC-C101 (LOW): TSIG time check before MAC creates timing oracle -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Verification reordered: MAC is now computed and verified first (tsig.zig:350-380), then time and fudge are checked (tsig.zig:384-398). Invalid MACs always return `bad_sig` regardless of time status.
- **Resolution evidence:** `src/security/tsig.zig:350-398` -- MAC-first verification order

#### SEC-NEW-04 (LOW): TSIG other_data silently truncated -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Returns `error.InvalidTsigRecord` when `offset + other_len > rdata.len` instead of silently truncating.
- **Resolution evidence:** `src/security/tsig.zig:229` -- error return on truncated other_data

#### SEC-NEW-05 (LOW): @intCast(u16) on options.len without bounds check -- **RESOLVED** (commit 8fef334)

- **Status:** Resolved (2026-03-24). Bounds check added before `@intCast` in EDNS encode and buildOption paths.
- **Resolution evidence:** `src/edns.zig` -- bounds validation before u16 cast; commit 8fef334

#### SEC-NEW-07 (LOW): skipName compression pointer returns offset+2 without checking offset+1 < data.len -- **RESOLVED** (commit 6d42d51)

- **Status:** Resolved (2026-03-24). Bounds check `if (offset + 1 >= data.len) return error.InvalidName;` added before `return offset + 2` in skipName. Test `SEC-NEW-07: skipName rejects truncated compression pointer` added.
- **Resolution evidence:** `src/security/dns_name.zig:101` -- bounds check; `src/security/dns_name.zig:241+` -- test

### Phase 2-3 Adversarial Scan Findings (2026-03-24)

#### SEC-SCAN-01 (MEDIUM): TsigKey.secret not zeroed on destruction -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `deinit()` method to `TsigKey` that calls `std.crypto.utils.secureZero` on the secret buffer before freeing via allocator. Test verifies secret bytes are zeroed after deinit.
- **Resolution evidence:** `src/security/tsig.zig` -- `TsigKey.deinit()` with `secureZero` call
- **Risk score:** 16 (Impact 2 x Likelihood 2 x 4)
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-02 (MEDIUM): ARCOUNT u16 overflow in TSIG/SIG(0) append -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added overflow check `if (arcount == std.math.maxInt(u16)) return error.TooManyAdditionalRecords;` before incrementing in both `tsig.zig` and `sig0.zig`.
- **Resolution evidence:** `src/security/tsig.zig` and `src/security/sig0.zig` -- overflow guard before ARCOUNT increment
- **Risk score:** 9
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-03 (MEDIUM): Cache has no thread-safety -- **WON'T DO**

- **Status:** **Won't Do** (2026-03-24). Cache documented as single-threaded-only. Thread safety requires architectural redesign (adding Mutex/RwLock to all public methods, or providing ThreadSafeCache wrapper). Single-threaded use is safe. Cross-ref PF-14 (also Won't Do).
- **Reason:** Architectural change outside scope. Cache is safe for single-threaded deployments.
- **Risk score:** 27
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-04 (LOW): TCP/DoT/DoQ/ConnectionPool @intCast(u16) on wire_req.len without bounds check -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `if (wire_req.len > std.math.maxInt(u16)) return error.MessageTooLarge;` bounds check before all `@intCast(u16)` casts on `wire_req.len` in tcp.zig, dot.zig, and connection_pool.zig.
- **Resolution evidence:** `src/transports/tcp.zig`, `src/transports/dot.zig`, `src/transports/connection_pool.zig` -- bounds checks before u16 casts
- **Risk score:** 4
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-05 (LOW): dns_name.zig encodeName/encodeNameLower @intCast on label.len without max label check -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `if (label.len > 63) return error.LabelTooLong;` check before `@intCast` in both `encodeName` and `encodeNameLower` in `dns_name.zig`.
- **Resolution evidence:** `src/security/dns_name.zig` -- label length validation in encodeName and encodeNameLower
- **Risk score:** 8
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-06 (LOW): SIG(0) sign @intCast(u16) rdlength without bounds check -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `if (rdlength > std.math.maxInt(u16)) return error.RdataTooLarge;` bounds check before `@intCast(u16)` cast in SIG(0) sign method.
- **Resolution evidence:** `src/security/sig0.zig` -- bounds check before rdlength cast
- **Risk score:** 2
- **Confidence:** `confidence::confirmed`

#### SEC-SCAN-07 (INFO): name.zig toString doesn't enforce forward pointer rejection -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added forward pointer rejection to `toString`, `toStringBuf`, `labelCount`, `parent`, and `eql` in `name.zig`. Forward pointers (where `ptr_offset >= current absolute offset`) now return error. Defense-in-depth improvement complementing existing hop limit and SEC-C30 fix in `dns_name.zig`.
- **Resolution evidence:** `src/name.zig` -- forward pointer checks in `toString`, `toStringBuf`, `labelCount`, `parent`, `eql`
- **Risk score:** 1
- **Confidence:** `confidence::confirmed`

#### ADV-02 (LOW): No TSIG replay protection within fudge window -- **WON'T DO**

- **Status:** **Won't Do** (2026-03-24). Defense-in-depth improvement. Requires bounded replay cache data structure with time-based eviction. Low practical risk with default 300-second fudge window. Complementary to SEC-C29 (SIG(0) replay, also Won't Do).
- **Reason:** Defense-in-depth. Replay requires on-path attacker + capture within fudge window. Bounded replay cache is a new data structure investment.
- **Risk score:** 12
- **Confidence:** `confidence::confirmed`

#### ADV-05 (LOW): Large header counts cause CPU-bound parse loop -- **RESOLVED**

- **Status:** **Resolved** (2026-03-24). Added `max_section_count = 4096` constant in `message.zig`. All section count fields (qdcount, ancount, nscount, arcount) are now validated against this limit before the parse loops execute. Messages with section counts exceeding 4096 return `error.TooManyRecords`.
- **Resolution evidence:** `src/message.zig` -- `max_section_count` constant; bounds check before parse loops
- **Risk score:** 6
- **Confidence:** `confidence::confirmed`

### Phase 3 + Adversarial Review Security Summary

**Previous findings (Phases 1-3):**

- **Critical:** 1 finding -- **1 resolved** (SEC-C22 infinite loop DoS)
- **High:** 7 findings -- **7 resolved** (SEC-C02 enum panic, SEC-C05 weak PRNG, SEC-C23 key truncation, SEC-C26 partial write, SEC-NEW-01 OOB in extractTsig, SEC-NEW-02 OOB in extractSig0, SEC-AUDIT-01 LabelIterator forward ptr)
- **Medium:** 16 findings -- **13 resolved**, **3 won't do** (SEC-C29 replay, SEC-C14/C31 supply chain, SEC-SCAN-03 cache thread-safety)
- **Low:** 11 findings -- **9 resolved**, **2 won't do** (SEC-C32, ADV-02)
- **Info:** 1 finding -- **1 resolved** (SEC-SCAN-07 forward pointer in name.zig)

**New findings (Phase 3 adversarial review, 2026-03-24) -- all resolved in Round 3:**

- **High:** 1 finding -- **1 resolved** (SEC-SCAN-09 trust anchor digest truncation -- exact length + constantTimeEql)
- **Medium:** 8 findings -- **8 resolved** (SEC-SCAN-08 constantTimeEql, SEC-SCAN-10/11/12/13 bounds checks, SEC-NEW-02b/03b zone transfer bounds, SEC-NEW-04b NSEC3 iterations capped at 150)
- **Low:** 5 findings -- **5 resolved** (SEC-SCAN-14 query.len check, SEC-SCAN-15 TsigKey.deinit volatile zero, SEC-SCAN-16/17 @max(0,delta), SEC-NEW-01b @max(0,delta))

**New findings (continued audit, 2026-03-25) -- all resolved:**

- **High:** 2 findings -- **2 resolved** (SEC-AUDIT-06/GAP-0064 NSEC name ordering bypass, SEC-AUDIT-07/GAP-0065 NSEC3 hash format mismatch)
- **Low:** 3 findings -- **3 resolved** (SEC-AUDIT-08 TSIG fudge overflow, SEC-AUDIT-09 source port randomization, SEC-AUDIT-10 TC bit re-validation)

**New findings (deep audit review, 2026-03-25) -- all resolved:**

- **Medium:** 1 finding -- **1 resolved** (SEC-AUDIT-11 validateChainOfTrust now uses target_zone via isNameInZone)
- **Low:** 2 findings -- **2 resolved** (SEC-AUDIT-12 extractWireLabels error union, SEC-AUDIT-13 base32hexDecode trailing bits)

**Combined totals (prior cycles, unified table): 58 security findings -- 53 resolved, 5 won't do, 0 open**

---

### 2026-06-12 Application Security + Adversarial Review Cycle (SEC-A / SEC-SR / SEC-SC)

New cycle: 25 security findings tracked from the OWASP 2025 / CIS v8.1.2 appsec review (`docs/APPSEC_REVIEW_2026-06-12.md`, A-series), an adversarial review of `record.zig` / `zone_file.zig` / `edns.zig` / `zdig.zig` / `zone_transfer.zig` (SR-series, all reproduced), and an automated supply-chain scan (SC-series). All 25 filed as GitLab issues; memory-safety/OOB/UB, terminal-injection, and DNSSEC-bypass items filed **confidential**. ~~All 25 are OPEN.~~ **Reconciled 2026-06-12 (ASR2-003):** most were remediated on `main` by the GAP-0839..0890 campaign and the parallel `fix(security)` stream; the table below carries per-row resolution commits.

Risk Score = Impact(1-5) x Likelihood(1-5) x 4.

| Rank | Severity | Risk Score | Finding | Component | CWE / OWASP | Evidence (file:line) | Issue | SLA | Status |
|------|----------|------------|---------|-----------|-------------|----------------------|-------|-----|--------|
| 1 | High | 64 | SEC-A1: DNSSEC security-theater -- `dnssec=true` requests but never validates (false posture) | recursive.zig, dnssec.zig | CWE-325 / A04:2025,A08:2025 | recursive.zig:110,594 | [#290](https://gitlab.com/devnw/zig/dns/-/issues/290) (confidential); x-ref #207/#255/#256 | 30d | **Closed** (`15258de`, `56939ea`, `1f7fe2d`) |
| 2 | High | 64 | SEC-SR-1: parseCAA `2+tag_length` u8 overflow -> OOB read / panic | record.zig | CWE-190,125 / A03:2025 | record.zig:390 | [#279](https://gitlab.com/devnw/zig/dns/-/issues/279) (confidential) | 30d | **Closed** (`b67f93b`) |
| 3 | High | 64 | SEC-SR-2: parseNSEC3PARAM `5+salt_length` u8 overflow -> OOB read / panic | record.zig | CWE-190,125 / A03:2025 | record.zig:1077 | [#280](https://gitlab.com/devnw/zig/dns/-/issues/280) (confidential) | 30d | **Closed** (`b67f93b`) |
| 4 | High | 48 | SEC-SR-3: ClientSubnet `(prefix+7)/8` u8 overflow -> OOB read | edns.zig | CWE-190,125 / A03:2025 | edns.zig:295,310,337,348 | [#281](https://gitlab.com/devnw/zig/dns/-/issues/281) (confidential); x-ref GAP-0071/#208 | 30d | **Closed** (`b67f93b`, `bce6714`) |
| 5 | High | 48 | SEC-SR-4: parseTTL unchecked u32 overflow -> panic / silent TTL+SOA-timer wrap | zone_file.zig | CWE-190 / A03:2025 | zone_file.zig:700,710 | [#282](https://gitlab.com/devnw/zig/dns/-/issues/282) (confidential) | 30d | **Closed** (`b67f93b`) |
| 6 | High | 48 | SEC-SR-5: zdig terminal escape injection -- raw TXT/CAA/name bytes in non-JSON output | cmd/zdig.zig | CWE-150,116 / A03:2025 | zdig.zig:707,739,869 | [#283](https://gitlab.com/devnw/zig/dns/-/issues/283) (confidential); x-ref #196 | 30d | **Closed** (`193b7fc`) |
| 7 | High | 48 | SEC-A2: NSEC/NSEC3 denial-of-existence accepted without RRSIG verification | dnssec.zig | CWE-347 / A08:2025 | dnssec.zig:220-354 | [#291](https://gitlab.com/devnw/zig/dns/-/issues/291) (confidential) | 30d | **Partially remediated (in-path)** (`15258de`) -- in-path validator never promotes denial-of-existence to `.secure`; standalone `validateChainOfTrust` NSEC/NSEC3 RRSIG verification still missing (ASR2-002/GAP-0839 scope) |
| 8 | High | 48 | SEC-A3: DS chain trusts unauthenticated DS; `.secure` on key presence -- chain forgery | dnssec.zig | CWE-345 / A08:2025 | dnssec.zig:559-580 | [#292](https://gitlab.com/devnw/zig/dns/-/issues/292) (confidential) | 30d | **Partially remediated (in-path)** (`15258de`) -- in-path `verifyAnswerRrset` requires a verified RRSIG over target data; standalone `validateChainOfTrust` remains fail-open (ASR2-002/GAP-0839 scope) |
| 9 | High | 32 | SEC-A4: DoH backend never receives verification hostname (SNI) | doh.zig | CWE-295 / A02:2025,A04:2025 | doh.zig:102-105,203-206 | [#293](https://gitlab.com/devnw/zig/dns/-/issues/293) | 30d | **Closed** (`bab5638`) |
| 10 | High | 32 | SEC-A5: DoQ discards `ca_pem`, passes no verification name to backend | doq.zig, channel.zig | CWE-295 / A02:2025,A04:2025 | doq.zig:36-42,179-186 | [#294](https://gitlab.com/devnw/zig/dns/-/issues/294) | 30d | **Closed** (`efa920a`, `06353b4`) |
| 11 | Medium | 36 | SEC-SR-6: AXFR unbounded receive loop; `timeout_ms` not enforced as transfer deadline | zone_transfer.zig | CWE-400,835 / A05:2025 | zone_transfer.zig:299,266,276 | [#284](https://gitlab.com/devnw/zig/dns/-/issues/284) | 90d | **Closed** (`ad95f02`, `6560230`) |
| 12 | Medium | 36 | SEC-SR-7: `verify_serial` dead config -- no RFC 1982 serial validation in AXFR/IXFR | zone_transfer.zig | CWE-345 / A08:2025 | zone_transfer.zig:43 | [#285](https://gitlab.com/devnw/zig/dns/-/issues/285) | 90d | **Closed** (`ad95f02`) |
| 13 | Medium | 36 | SEC-SR-8: ZoneParser leaks `makeAbsolute` owner-name buffer per explicit-owner record | zone_file.zig | CWE-401 / A05:2025 | zone_file.zig:429,462,476 | [#286](https://gitlab.com/devnw/zig/dns/-/issues/286) | 90d | **Closed** (`efbd179`) |
| 14 | Medium | 36 | SEC-SR-9: parseTransferResponse leaks record name on truncation break | zone_transfer.zig | CWE-401 / A05:2025 | zone_transfer.zig:623,626,634 | [#287](https://gitlab.com/devnw/zig/dns/-/issues/287) | 90d | **Closed** (`efbd179`) |
| 15 | Medium | 36 | SEC-A7: recursive resolver accepts upward/lateral referrals (no zone-descent check) | recursive.zig | CWE-345 / A06:2025 | recursive.zig:705-719,405-457 | [#296](https://gitlab.com/devnw/zig/dns/-/issues/296); x-ref #214 | 90d | **Closed** (`e7a13fd`) |
| 16 | Medium | 36 | SEC-A8: RRSIG verify omits key-tag + signer-bailiwick + labels/wildcard checks | dnssec.zig | CWE-347 / A08:2025 | dnssec.zig:361-394 | [#297](https://gitlab.com/devnw/zig/dns/-/issues/297) (confidential) | 90d | **Partially remediated (in-path)** (`53382d7`, `15258de`) -- labels validated in `verifyRrsig`; key-tag + signer-bailiwick enforced in-path; standalone `validateChainOfTrust` path lacks them (ASR2-002/GAP-0839 scope) |
| 17 | Medium | 24 | SEC-A6: no cert-verified/min-TLS enforcement; CA fail-closed guard only on DoT | dot.zig, doh.zig, doq.zig | CWE-1188,295 / A02:2025 | dot.zig:211-215; doh.zig:172-175 | [#295](https://gitlab.com/devnw/zig/dns/-/issues/295) | 90d | **Open** -- CA fail-closed parity landed for DoH/DoQ (`06353b4`); `peerVerified()`/min-TLS floor still absent |
| 18 | Low | 16 | SEC-SR-10: AXFR off-by-one drops valid final record (`<` should be `<=`) | zone_transfer.zig | CWE-193,345 / A04:2025 | zone_transfer.zig:621 | [#288](https://gitlab.com/devnw/zig/dns/-/issues/288) | 180d | **Closed** (`efbd179`) |
| 19 | Low | 16 | SEC-A9: SHA-1 DS digests + deprecated algorithms accepted without downgrade policy | dnssec.zig, record.zig | CWE-327 / A04:2025 | dnssec.zig:594-616,785-831 | [#298](https://gitlab.com/devnw/zig/dns/-/issues/298) | 180d | **Closed** (`1faa690`, `0f64fbf`) |
| 20 | Low | 16 | SEC-A12: DoH accepts response when `Content-Type` header absent | doh.zig | CWE-755 / A10:2025 | doh.zig:234-239,255-260 | [#301](https://gitlab.com/devnw/zig/dns/-/issues/301) | 180d | **Closed** (`af17aee`) |
| 21 | Low | 8 | SEC-SR-11: Padding.encode up-to-64KiB zero allocation from attacker-influenced length | edns.zig | CWE-789,400 / A05:2025 | edns.zig:557-561 | [#289](https://gitlab.com/devnw/zig/dns/-/issues/289) | 180d | **Open** -- verified still present: `Padding.encode` allocates uncapped `self.length` (edns.zig:576-580) |
| 22 | Low | 8 | SEC-A10: SystemRandom seeds non-CSPRNG (latent footgun) | util/random.zig | CWE-338,330 / A04:2025 | random.zig:43-70 | [#299](https://gitlab.com/devnw/zig/dns/-/issues/299) | 180d | **Open** -- security paths migrated to `fillSecure` CSPRNG (`4d5abf3`, `c0a6ba9`); non-CSPRNG `SystemRandom` struct itself remains |
| 23 | Low | 8 | SEC-A11: connection-pool key compares host by hash, omits TLS identity | connection_pool.zig | CWE-345 / A01:2025 | connection_pool.zig:213-223 | [#300](https://gitlab.com/devnw/zig/dns/-/issues/300) | 180d | **Open** -- verified: pool key still compares `host_hash` only, no TLS identity (connection_pool.zig:208) |
| 24 | Low | 8 | SEC-SC-1: pre-commit hooks tag-pinned, not SHA-pinned | .pre-commit-config.yaml | CWE-829 / A08:2025 | .pre-commit-config.yaml | [#302](https://gitlab.com/devnw/zig/dns/-/issues/302) | 180d | **Open** -- hooks still tag-pinned (`rev: vX.Y.Z`), not SHA-pinned |
| 25 | Low | 8 | SEC-SC-2: parse_target lacks format validation -- now validated (name/tag/40-hex-commit) in zig-tool | zig-tool: src/zig_tool/sync_diamond_deps.py:349-362 | CWE-20 / A08:2025 | parse_target (zig-tool) | [#303](https://gitlab.com/devnw/zig/dns/-/issues/303) | 180d | **Closed** (`117e8fe`; tooling extracted to zig-tool, vendored copy deleted) |

**2026-06-12 cycle totals (reconciled 2026-06-12, ASR2-003): 25 findings -- 17 closed, 3 partially remediated (in-path: SEC-A2/A3/A8), 5 open (SEC-A6, SEC-A10, SEC-A11, SEC-SR-11, SEC-SC-1), 0 won't do.** By severity: High 10, Medium 7, Low 8. Confidential: 9 (#279-#283, #290-#292, #297).

#### Findings by area (2026-06-12 cycle)

- **DNSSEC (auth/integrity):** SEC-A1 (#290), SEC-A2 (#291), SEC-A3 (#292), SEC-A8 (#297), SEC-A9 (#298). **Reconciled:** validation is now wired in-path (GAP-0839/`15258de`, `enforceDnssecPolicy`/`verifyAnswerRrset` in recursive.zig) and SEC-A1/A9 are Closed. A2/A3/A8 residuals are confined to the standalone `validateChainOfTrust` API (annotated experimental/fail-open) plus denial-of-existence and CNAME-hop scope (ASR2-002/GAP-0839 scope notes).
- **Wire/RDATA parsers (memory safety):** SEC-SR-1 (#279), SEC-SR-2 (#280), SEC-SR-3 (#281) -- `u8` length-arithmetic overflows defeating bounds checks; SEC-SR-4 (#282) `u32` TTL overflow.
- **Encrypted transports (TLS verification):** SEC-A4 (#293), SEC-A5 (#294), SEC-A6 (#295) -- library under-provisions verification material to backends; no `peerVerified()`/min-TLS floor.
- **Zone transfer (AXFR/IXFR):** SEC-SR-6 (#284), SEC-SR-7 (#285), SEC-SR-9 (#287), SEC-SR-10 (#288) -- unbounded loop, dead freshness config, leak on truncation, off-by-one.
- **Zone-file ingest:** SEC-SR-4 (#282), SEC-SR-8 (#286).
- **CLI/output:** SEC-SR-5 (#283) -- terminal escape injection in `zdig`.
- **EDNS:** SEC-SR-3 (#281), SEC-SR-11 (#289).
- **Referral trust:** SEC-A7 (#296).
- **Randomness:** SEC-A10 (#299).
- **Connection pool:** SEC-A11 (#300).
- **Supply chain / tooling:** SEC-SC-1 (#302), SEC-SC-2 (#303).

#### Remediation roadmap (2026-06-12 cycle)

- **Quick wins (< 1 day each):** SEC-SR-1/#279, SEC-SR-2/#280, SEC-SR-3/#281 (widen length arithmetic to `usize`); SEC-SR-4/#282 (checked `u32` add/mul); SEC-SR-10/#288 (`<` -> `<=`); SEC-A12/#301 (fail closed on missing `Content-Type`); SEC-SR-11/#289 (cap padding); SEC-SR-8/#286 + SEC-SR-9/#287 (add `errdefer`/free); SEC-A10/#299 (CSPRNG-back or delete); SEC-SC-1/#302 (SHA-pin hooks); SEC-SC-2/#303 (validate spec).
- **Medium (1-5 days):** SEC-SR-5/#283 (output sanitizer); SEC-SR-6/#284 (transfer deadline + caps); SEC-SR-7/#285 (RFC 1982); SEC-A4/#293 + SEC-A5/#294 + SEC-A6/#295 (thread `server_name`/`ca_pem`/`use_system_ca` + `peerVerified()`/`min_tls_version`); SEC-A7/#296 (zone-descent check); SEC-A1/#290 (rename/guard flag or wire validator, gated on #255+#207).
- **Strategic (> 5 days):** SEC-A2/#291 + SEC-A3/#292 + SEC-A8/#297 -- correct top-down DNSSEC validator (RRSIG-verify NSEC/NSEC3 and DS RRsets; `.secure` only on verified target data; key-tag/signer-bailiwick/labels), prerequisite to safely wiring DNSSEC validation (GAP-0070).

#### Immediate actions

- **No leaked secrets** were found in this cycle; no credential rotation required.
- **No active RCE.** SEC-SR-1/#279 and SEC-SR-2/#280 were OOB reads that were remotely triggerable and caused a guaranteed panic (DoS) in ReleaseSafe and UB in ReleaseFast -- both fixed within SLA (`b67f93b`). SEC-A1/#290 meant **`dnssec=true` provided no protection at review time**; since remediated -- the validator is wired in-path and fail-closed in strict mode (GAP-0839/`15258de`, GAP-0840/`56939ea`).

---

### Deduplication Notes

| Phase 3 ID | Existing Issue | Status |
|-------------|---------------|--------|
| SEC-C20 (SIG(0) enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C21 (TSIG enum panic) | #89 [SEC-C02] -- already listed in Evidence | Duplicate -- comment added |
| SEC-C24 (PRNG for TXIDs) | #94 [SEC-C05] -- same root cause | Duplicate -- comment added |
| SEC-C25 (Key not zeroed) | #104 [SEC-C06] + #111 [SEC-C07] -- same root cause | Duplicate -- comment added |
| SEC-C31 (spice pins main) | #107 [SEC-C14] -- identical finding | Duplicate -- comment added; cross-ref GAP-0047 |
| SEC-C11 (Thread pool page_allocator) | [#112](https://gitlab.com/devnw/zig/dns/-/issues/112) -- overlaps PF-17 (thread pool GPA wrapper) | Cross-reference -- both resolved |
| SEC-C12 (IPv4 format undefined trailing bytes) | [#115](https://gitlab.com/devnw/zig/dns/-/issues/115) -- overlaps QH-03 (Formatted struct with len) | Cross-reference -- both resolved |
| SEC-NEW-01 / SEC-NEW-02 | Same root cause (missing rdlength bounds check) in sibling functions | Both resolved: 6d42d51 / 8fef334 |
| SEC-NEW-03 / SEC-NEW-06 | Related root cause (missing bounds checks in wire parser helpers) | Both resolved: commit 6d42d51 |
| SEC-SCAN-01 / SEC-C06/C25 | Related root cause (key material not zeroed). SEC-C06/C25 covers HMAC state; SEC-SCAN-01 covers TsigKey struct secret | Tracked separately: different code paths, different lifecycle |
| ADV-02 / SEC-C29 | Same class of issue (replay attack) but different protocols: ADV-02 is TSIG, SEC-C29 is SIG(0) | Tracked separately: different code, different fix |
| SEC-SCAN-04 / SEC-NEW-05 / SEC-SCAN-06 | Same pattern (@intCast without bounds) across different call sites | Tracked separately: different files and data flows |
| SEC-SCAN-07 / SEC-C30 | Related (forward compression pointer). SEC-C30 fixed dns_name.zig; SEC-SCAN-07 covers name.zig | Tracked separately: different modules |
| GAP-0066 / GAP-0063 | GAP-0063 fixed case-sensitivity; GAP-0066 identified the remaining wire-format vs dotted-string mismatch at the same call site (dnssec.zig:245) | Both resolved: case fix (GAP-0063) + format fix (GAP-0066) |
| GAP-0067 / GAP-0064 | GAP-0064 fixed label ordering in compareDnsNames; GAP-0067 identified that qname was passed as dotted-string to the now-correct wire-format comparator | Both resolved: ordering fix (GAP-0064) + format fix (GAP-0067) |
| GAP-0068 / GAP-0065 | GAP-0065 fixed NSEC3 owner hash decode; GAP-0068 identified that qname hash input was dotted-string instead of wire-format | Both resolved: owner hash (GAP-0065) + query hash (GAP-0068) |
| GAP-0066 / GAP-0067 / GAP-0068 | All three shared a common root cause: missing dotted-string to wire-format conversion at NSEC/NSEC3 validation entry points | All resolved: dottedToWire conversion added at all entry points |
| SEC-A1 (#290) | GAP-0070/#207 (validator wiring), #255 (RD vs DO/no OPT), #256 (false advertising) | Cross-referenced, not duplicated -- #290 tracks security posture; functional wiring stays on #207; comments added to #207/#255/#256 |
| SEC-A7 (#296) | #214 (perf+security glue-to-NS O(glue x NS) CPU-DoS) | Cross-referenced -- same extractReferral region; complementary (A7 = trust/zone-descent, #214 = CPU-DoS); comment added to #214 |
| SEC-SR-3 (#281) | GAP-0071/#208 (ECS wiring) | Cross-referenced -- overflow becomes actively exploitable once ECS is injected into live queries |
| SEC-A2/A3/A8 (#291/#292/#297) | Prior SEC-AUDIT-11 (target_zone ownership) | Distinct -- prior fix added zone-ownership check; these are the deeper missing-RRSIG-over-NSEC/DS and key-tag/bailiwick/labels gaps |

### Remediation Roadmap

**Completed (previous cycles):**

- ~~SEC-C22~~: `outer:` label + `continue :outer` in connection_pool.zig -- **Resolved**
- ~~SEC-C30~~: Forward pointer rejection in dns_name.zig -- **Resolved**
- ~~SEC-C33~~: Read loop for 2-byte length prefix in zone_transfer.zig -- **Resolved**
- ~~SEC-C28~~: `require_auth` defaults to `true` -- **Resolved**
- ~~SEC-C26~~: `writeAll()` / `writeAllWithTimeout()` in 3 files -- **Resolved**
- ~~SEC-C23~~: HMAC key handling delegated to stdlib (RFC 2104) -- **Resolved**
- ~~SEC-C02~~: Non-exhaustive enums for sig0/tsig/record.zig -- **Resolved** (all enums confirmed non-exhaustive with `_` variant)
- ~~SEC-C05~~: `std.crypto.random` (OS CSPRNG) for all TXIDs -- **Resolved**
- ~~SEC-C27~~: `isSubdomainOf()` bailiwick validation -- **Resolved**
- ~~SEC-C06/C25~~: `secureZero` on key material -- **Resolved**

**Completed quick wins (commit 6d42d51):**

- ~~SEC-NEW-01~~: Bounds check added before `message[offset .. offset + rdlength]` in extractTsig -- **Resolved**
- ~~SEC-NEW-03~~: Bounds check `if (end > data.len) return error.InvalidRR` added in skipRR -- **Resolved**
- ~~SEC-NEW-06~~: Bounds check `if (offset + 4 > message.len) return error.InvalidMessage` before question skip -- **Resolved**
- ~~SEC-NEW-07~~: Bounds check `if (offset + 1 >= data.len) return error.InvalidName` for compression pointer -- **Resolved**
- ~~SEC-NEW-04~~: Returns `error.InvalidTsigRecord` instead of silently truncating other_data -- **Resolved**
- ~~SEC-C101~~: MAC verification now precedes time check; fudge clamped post-MAC -- **Resolved**
- ~~SEC-C100~~: Fudge clamped to `self.fudge * 2` after MAC verification -- **Resolved**

**Completed quick wins (commit 8fef334):**

- ~~SEC-NEW-02~~: Bounds check added before `message[offset .. offset + rdlength]` in extractSig0 -- **Resolved**
- ~~SEC-NEW-05~~: Bounds validation before `@intCast(u16)` in EDNS encode/buildOption -- **Resolved**

**Completed quick wins (final gap closure cycle):**

- ~~SEC-SCAN-01~~: `TsigKey.deinit()` with `secureZero` on `.secret` -- **Resolved**
- ~~SEC-SCAN-02~~: Overflow check before `arcount + 1` in tsig.zig and sig0.zig -- **Resolved**
- ~~SEC-SCAN-04~~: Bounds check before `@intCast(u16)` on wire_req.len in tcp.zig, dot.zig, connection_pool.zig -- **Resolved**
- ~~SEC-SCAN-05~~: Label length validation in dns_name.zig encodeName/encodeNameLower -- **Resolved**
- ~~SEC-SCAN-06~~: Bounds check before rdlength `@intCast(u16)` in sig0.zig -- **Resolved**
- ~~ADV-05~~: `max_section_count = 4096` enforced in message.zig parse loop -- **Resolved**
- ~~SEC-SCAN-07~~: Forward pointer rejection added to name.zig toString/toStringBuf/labelCount/parent/eql -- **Resolved**

**New findings resolved (Round 3 gap closure, 2026-03-24):**

*High priority (30-day SLA):*

- ~~SEC-SCAN-09~~: Trust anchor digest comparison now uses exact length + `constantTimeEql` -- **Resolved**

*Medium priority (90-day SLA):*

- ~~SEC-SCAN-08~~: All DS digest comparisons use `constantTimeEql` -- **Resolved**
- ~~SEC-SCAN-10~~: `options.len` checked before `@intCast` -- **Resolved**
- ~~SEC-SCAN-11~~: Config values clamped via `clampToUnsigned` -- **Resolved**
- ~~SEC-SCAN-12~~: Label length checked before `@intCast` -- **Resolved**
- ~~SEC-SCAN-13~~: Message length checked before `@intCast` -- **Resolved**
- ~~SEC-NEW-02b~~: Question section bounds checking added -- **Resolved**
- ~~SEC-NEW-03b~~: `qdcount` validated -- **Resolved**
- ~~SEC-NEW-04b~~: NSEC3 iterations capped at 150 (RFC 9276) -- **Resolved**

*Low priority (180-day SLA):*

- ~~SEC-SCAN-14~~: Query length checked before `@intCast` -- **Resolved**
- ~~SEC-SCAN-15~~: `TsigKey.deinit` with volatile zero -- **Resolved**
- ~~SEC-SCAN-16~~: `@max(0, delta)` in connection_pool -- **Resolved**
- ~~SEC-SCAN-17~~: `@max(0, delta)` in happy_eyeballs -- **Resolved**
- ~~SEC-NEW-01b~~: `@max(0, delta)` in logging -- **Resolved**

**Full audit findings resolved (2026-03-25):**

*High priority (30-day SLA):*

- ~~SEC-AUDIT-01 / GAP-0058~~: Forward pointer check on first hop in LabelIterator -- **Resolved**

*Medium priority (90-day SLA):*

- ~~SEC-AUDIT-02 / GAP-0059~~: max_spurious_discards=1000 in UDP receive loops -- **Resolved**
- ~~SEC-AUDIT-03 / GAP-0061~~: buildTsigVariables parameterized with error_code/other_data -- **Resolved**
- ~~SEC-AUDIT-04 / GAP-0062~~: std.math.add(u32,...) with error.TimestampOverflow in SIG(0) -- **Resolved**
- ~~SEC-AUDIT-05 / GAP-0063~~: std.ascii.eqlIgnoreCase in NSEC NODATA validation -- **Resolved**

**Findings resolved (continued audit, 2026-03-25):**

*High priority (30-day SLA):*

- ~~SEC-AUDIT-06 / GAP-0064~~: compareDnsNames rewritten for RFC 4034 S6.1 canonical label ordering; 9 new tests -- **Resolved**
- ~~SEC-AUDIT-07 / GAP-0065~~: decodeNsec3OwnerHash with base32hex codec replaces extractNsec3OwnerHash; 6 new tests -- **Resolved**

*Low priority (180-day SLA):*

- ~~SEC-AUDIT-08~~: TSIG fudge u16*2 overflow fixed with u32 widening; 2 new tests -- **Resolved**
- ~~SEC-AUDIT-09~~: Doc comments added about OS-dependent source port randomization (RFC 5452) -- **Resolved**
- ~~SEC-AUDIT-10~~: TCP fallback response re-validation (TXID + responseMatchesQuery) added -- **Resolved**

**New findings (continued audit, 2026-03-25) -- all resolved:**

*High priority (30-day SLA):*

- ~~GAP-0066~~: `validateNodataWithNsec` wire-format -- `dottedToWire` + `wireNamesEqlInsensitive` -- **Resolved** (2026-03-25)
- ~~GAP-0067~~: `validateNxdomainWithNsec` wire-format -- `dottedToWire` before `nameInNsecRange` -- **Resolved** (2026-03-25)

*Medium priority (90-day SLA):*

- ~~GAP-0068~~: `computeNsec3Hash` wire-format -- `dottedToWire` in both NSEC3 entry points -- **Resolved** (2026-03-25)
- ~~GAP-0069~~: TCP fallback `Message.parse` failure leaks `tcp_response` memory -- **Resolved** (2026-03-25)
- ~~SEC-AUDIT-11~~: `validateChainOfTrust` -- `target_zone` used via `isNameInZone` -- **Resolved** (2026-03-25)

*Low priority (180-day SLA):*

- ~~SEC-AUDIT-12~~: `extractWireLabels` returns error union, rejects compression + OOB -- **Resolved** (2026-03-25)
- ~~SEC-AUDIT-13~~: `base32hexDecode` rejects non-zero trailing bits per RFC 4648 -- **Resolved** (2026-03-25)

### Deep Audit Review Finding Details (2026-03-25)

#### SEC-AUDIT-11 (MEDIUM, Risk Score 36): validateChainOfTrust ignores target_zone -- **RESOLVED**

- **Summary:** The `validateChainOfTrust` function accepts a `target_zone` parameter but immediately discards it with `_ = target_zone;`. No zone-name checking is performed on DNSKEY/DS records during chain-of-trust validation.
- **Impact:** An attacker controlling any validly-signed zone could produce a "secure" validation result for a different target zone. The chain-of-trust validation does not verify that the DNSKEY and DS records actually belong to the zone being validated.
- **Likelihood:** Requires attacker to control a validly-signed zone and inject responses (Impact 3 x Likelihood 3 = Risk 36). Authenticated context required (recursive resolver).
- **Evidence:** `src/resolver/dnssec.zig:488` -- `_ = target_zone;` discards the zone parameter without use.
- **Attack scenario:** An attacker who controls a legitimately-signed zone (e.g., `evil.example`) could present DNSKEY/DS records from their zone during validation of a different target zone (e.g., `bank.example`). Since `target_zone` is never checked, the validator would accept the cross-zone records as valid for the target.
- **Fix guidance:** Remove `_ = target_zone;` and implement zone-name verification: at each step of the chain-of-trust walk, verify that DNSKEY RRsets and DS records have owner names matching the expected zone in the delegation path. Compare the owner name of each DNSKEY RRset against the current zone being validated.
- **Acceptance criteria:** (1) `target_zone` is used to verify DNSKEY/DS record ownership at each delegation step. (2) Validation fails when presented with DNSKEY/DS records from a different zone. (3) Test added with cross-zone DNSKEY injection.
- **References:** CWE-863 (Incorrect Authorization), OWASP A01:2021 (Broken Access Control), RFC 4035 Section 5
- **Affected paths:** `src/resolver/dnssec.zig`
- **SLA:** 90 days (Medium)
- **Confidence:** `confidence::confirmed`
- **Exploit surface:** Internal (recursive resolver)

#### SEC-AUDIT-12 (LOW, Risk Score 12): extractWireLabels silently truncates malformed names -- **RESOLVED**

- **Summary:** `extractWireLabels` returns a partial label list when encountering malformed wire-format input (compression pointers, truncated labels, overflow) without returning an error. The function silently breaks out of the parse loop.
- **Impact:** Incorrect NSEC range ordering with crafted names. A malformed name could produce a truncated label list that compares differently than expected, potentially causing incorrect NSEC denial-of-existence results.
- **Likelihood:** Requires crafted DNS response with specific malformed wire-format names (Impact 2 x Likelihood 1.5 ~= Risk 12). Low practical exploitability -- NSEC comparison uses canonical ordering and the truncated result would likely fail validation elsewhere.
- **Evidence:** `src/resolver/dnssec.zig:857-876` -- `break` statements at lines 865 (root label), 866 (compression pointer), 868 (overflow) return partial results without error indication.
- **Attack scenario:** Attacker sends a DNS response with a malformed wire-format name in an NSEC record. `extractWireLabels` silently returns a partial label list, causing `compareDnsNames` to produce incorrect ordering. This could cause a legitimate name to appear inside or outside an NSEC range incorrectly.
- **Fix guidance:** Return an error (or use an error union return type) when encountering unexpected compression pointers or label length overflow. Distinguish the root label terminator (expected) from malformed input (unexpected). The function should return `error.MalformedWireName` for truncated or compressed inputs in canonical wire-format contexts.
- **Acceptance criteria:** (1) `extractWireLabels` returns an error for compression pointers in canonical wire-format names. (2) `extractWireLabels` returns an error when `pos + label_len > wire_name.len`. (3) Root label terminator (label_len == 0) remains the normal loop exit. (4) Tests added for malformed input rejection.
- **References:** CWE-20 (Improper Input Validation), OWASP A03:2021 (Injection), RFC 4034 Section 6.1
- **Affected paths:** `src/resolver/dnssec.zig`
- **SLA:** 180 days (Low)
- **Confidence:** `confidence::confirmed`
- **Exploit surface:** Internal (recursive resolver, DNSSEC validation path)

#### SEC-AUDIT-13 (LOW, Risk Score 8): base32hexDecode trailing bits not validated -- **RESOLVED**

- **Summary:** `base32hexDecode` discards non-zero trailing bits when the encoded length is not a multiple of 8 characters. Two different base32hex encodings could decode to the same hash bytes, violating the uniqueness assumption in NSEC3 hash comparisons.
- **Impact:** Theoretical NSEC3 comparison confusion. In practice, SHA-1 digests are always 20 bytes (160 bits), which produces exactly 32 base32hex characters with zero trailing bits, so the non-zero trailing bits case does not arise in well-formed NSEC3 records.
- **Likelihood:** Theoretical only for valid NSEC3 records (Impact 1 x Likelihood 2 = Risk 8). Would require an attacker to craft an NSEC3 record with a non-standard hash length, which would fail other validation checks.
- **Evidence:** `src/resolver/dnssec.zig:969-988` -- after the `for` loop, remaining bits in `bit_buffer` are silently discarded without checking they are zero.
- **Attack scenario:** Attacker crafts an NSEC3 record with a non-standard-length hash owner name. Two different base32hex-encoded strings decode to identical byte sequences because trailing bits differ but are discarded. This could theoretically confuse NSEC3 range comparisons, though SHA-1 (20 bytes) always produces 32 base32hex chars with no trailing bits.
- **Fix guidance:** After the decode loop, check that any remaining bits in `bit_buffer` are zero: `if (bits_in_buffer > 0 and (bit_buffer & ((1 << bits_in_buffer) - 1)) != 0) return error.InvalidData;`. This enforces RFC 4648 Section 3.5 requirement that non-zero trailing bits are invalid.
- **Acceptance criteria:** (1) `base32hexDecode` returns `error.InvalidData` when trailing bits are non-zero. (2) Valid encodings (including 32-char SHA-1 hashes with zero trailing bits) continue to decode correctly. (3) Test added with non-zero trailing bits.
- **References:** CWE-20 (Improper Input Validation), OWASP A03:2021 (Injection), RFC 4648 Section 3.5
- **Affected paths:** `src/resolver/dnssec.zig`
- **SLA:** 180 days (Low)
- **Confidence:** `confidence::confirmed`
- **Exploit surface:** Internal (recursive resolver, NSEC3 validation path)

**Remaining (Won't Do / deferred):**

- SEC-C29: SIG(0) replay cache -- **Won't Do** (defense-in-depth; requires bounded replay cache data structure; low practical risk)
- ADV-02: TSIG replay cache -- **Won't Do** (defense-in-depth; complementary to SEC-C29; low practical risk)
- SEC-C32: SIG(0) timestamp u32 overflow in 2106 -- **Won't Do** (Year 2106 issue; not actionable)
- SEC-C14/C31: spice dependency pins main branch -- **Won't Do** (upstream concern; hash pinning provides partial mitigation; cross-ref GAP-0047)
- SEC-SCAN-03: Cache thread safety -- **Won't Do** (handled via different controls: document Cache as single-threaded-only; cross-ref PF-14)

---

## Gap Priority Matrix

> **Updated 2026-06-12:** 8 new open gaps added (GAP-0070..GAP-0077). Totals below reflect the cumulative state including all prior cycles.

| Severity | Total | Resolved | Won't Do | **Open** | Gap-IDs / SEC-IDs |
|----------|-------|----------|----------|----------|-------------------|
| Critical | 4 | 3 | 0 | **1** | **Open:** GAP-0070. **Resolved:** GAP-0027/SEC-C26, GAP-0028/SEC-C22, GAP-0057 |
| High | 19 | 15 | 2 | **2** | **Open:** GAP-0073, GAP-0075. **Resolved:** GAP-0026, GAP-0029, GAP-0030, GAP-0033/SEC-C20, GAP-0034/SEC-C21, SEC-C23, SEC-C05/C24, SEC-NEW-01, SEC-NEW-02, SEC-SCAN-09, GAP-0058/SEC-AUDIT-01, GAP-0064/SEC-AUDIT-06, GAP-0065/SEC-AUDIT-07, GAP-0066, GAP-0067. **Won't Do:** GAP-0045, GAP-0046. |
| Medium | 49 | 39 | 6 | **4** | **Open:** GAP-0071, GAP-0072, GAP-0074, GAP-0077. **Resolved:** GAP-0038, GAP-0039, GAP-0043, GAP-0049, SEC-SCAN-01, SEC-SCAN-02, SEC-SCAN-08, SEC-SCAN-10, SEC-SCAN-11, SEC-SCAN-12, SEC-SCAN-13, SEC-NEW-02b, SEC-NEW-03b, SEC-NEW-04b, GAP-0059/SEC-AUDIT-02, GAP-0060, GAP-0061/SEC-AUDIT-03, GAP-0062/SEC-AUDIT-04, GAP-0063/SEC-AUDIT-05, GAP-0068, GAP-0069, SEC-AUDIT-11. **Won't Do:** GAP-0015, GAP-0017, GAP-0041, GAP-0042, GAP-0044, GAP-0047, SEC-C29, SEC-SCAN-03, SEC-C14/C31. |
| Low | 33 | 27 | 3 | **1** | **Open:** GAP-0076. **Resolved:** GAP-0040, GAP-0048, GAP-0050, ADV-05, SEC-SCAN-04, SEC-SCAN-05, SEC-SCAN-06, SEC-SCAN-14, SEC-SCAN-15, SEC-SCAN-16, SEC-SCAN-17, SEC-NEW-01b, SEC-AUDIT-08, SEC-AUDIT-09, SEC-AUDIT-10, SEC-AUDIT-12, SEC-AUDIT-13. **Won't Do:** GAP-0051, SEC-C32, ADV-02. |
| Info | 1 | 1 | 0 | 0 | **Resolved:** SEC-SCAN-07 |

## Production Readiness Assessment

### Open Items (2026-06-12)

**8 open findings.** The prior "0 open / production-ready" state was accurate for the code at 2026-03-25. Gaps below were introduced by post-cycle changes (Zig 0.16 migration, benchmark addition, otel seam workaround).

| Gap-ID | Severity | Summary | Status |
|--------|----------|---------|--------|
| GAP-0070 | **Critical** | DNSSEC validator never invoked from resolution pipeline (`dnssec=true` only sets DO bit) | Open |
| GAP-0073 | High | `-Dwith_otel=true` build broken -- second `lazyDependency("otel")` omits 4 options | Open |
| GAP-0075 | High | `minimum_zig_version` / README claim 0.15.1 but 19 source files require Zig 0.16-only `std.Io.*` | Open |
| GAP-0071 | Medium | ECS (`ClientSubnet`) type complete but never injected into outgoing queries | Open |
| GAP-0072 | Medium | DNS Cookies (`Cookie`) type complete but never wired into query building | Open |
| GAP-0074 | Medium | OTel seam hardcodes `enabled = false` regardless of `-Dwith_otel` flag | Open |
| GAP-0077 | Medium | Benchmark harness (`bench.zig`, `compare.zig`) broken on Zig 0.16 | Open |
| GAP-0076 | Low | Zone-transfer `buildMinimalSoaRdata` emits placeholder MNAME/RNAME/timers | Open |

### Previously Resolved Items (last cycle, 2026-03-25)

| Gap-ID / SEC-ID | Severity | Risk Score | Summary | Status |
|-----------------|----------|------------|---------|--------|
| ~~GAP-0066~~ | High | -- | `validateNodataWithNsec` -- `dottedToWire` + `wireNamesEqlInsensitive` | **Resolved** (2026-03-25) |
| ~~GAP-0067~~ | High | -- | `validateNxdomainWithNsec` -- `dottedToWire` before `nameInNsecRange` | **Resolved** (2026-03-25) |
| ~~GAP-0068~~ | Medium | -- | `computeNsec3Hash` -- `dottedToWire` in both NSEC3 entry points | **Resolved** (2026-03-25) |
| ~~SEC-AUDIT-11~~ | Medium | 36 | `validateChainOfTrust` -- `target_zone` used via `isNameInZone` | **Resolved** (2026-03-25) |
| ~~SEC-AUDIT-12~~ | Low | 12 | `extractWireLabels` returns error union, rejects compression + OOB | **Resolved** (2026-03-25) |
| ~~SEC-AUDIT-13~~ | Low | 8 | `base32hexDecode` rejects non-zero trailing bits per RFC 4648 | **Resolved** (2026-03-25) |

### Won't Do Items

| Gap-ID / SEC-ID | Status | Blocks Production? | Rationale |
|-----------------|--------|-------------------|-----------|
| GAP-0015 | Won't Do | No | Admin tracker reconciliation; docs are accurate |
| GAP-0017 | Won't Do | No | Transport architecture refactor outside scope |
| GAP-0041 | Won't Do | No | Returns explicit errors; `client.Client` works |
| GAP-0042 | Won't Do | No | Feature addition; raw query API covers all types |
| GAP-0044 | Won't Do | No | Architecture refactor; inline code works correctly |
| GAP-0045 | Won't Do | Recommended | Core resolution loop zero tests; high regression risk |
| GAP-0046 | Won't Do | Recommended | Wire parsers no fuzz coverage; all known bugs fixed |
| GAP-0047 | Won't Do | No | Upstream concern; hash pinning provides integrity |
| SEC-C29 | Won't Do | No | Defense-in-depth; replay requires capture + time window |
| SEC-C14/C31 | Won't Do | No | Upstream concern; hash pinning provides integrity |
| SEC-C32 | Won't Do | No | Year 2106 issue |
| SEC-SCAN-03 | Won't Do | No (single-threaded) | Thread safety requires architecture redesign |
| ADV-02 | Won't Do | No | Defense-in-depth; same class as SEC-C29 |

### Production Blockers

**1 active critical production blocker (2026-06-12).** GAP-0070 invalidates the "DNSSEC production-ready" claim.

| Blocker | Severity | Status | Impact |
|---------|----------|--------|--------|
| **GAP-0070** | Critical | **Open** | `dnssec=true` provides no validation -- validator never called from resolution pipeline |

Previously resolved blockers (2026-03-25):

- ~~**GAP-0066**~~ (High, DNSSEC correctness): **RESOLVED** (2026-03-25). `validateNodataWithNsec` -- `dottedToWire` + `wireNamesEqlInsensitive`. 1 new test.
- ~~**GAP-0067**~~ (High, DNSSEC correctness): **RESOLVED** (2026-03-25). `validateNxdomainWithNsec` -- `dottedToWire` before `nameInNsecRange`. 1 new test.
- ~~**GAP-0068**~~ (Medium, DNSSEC correctness): **RESOLVED** (2026-03-25). `computeNsec3Hash` -- `dottedToWire` in both NSEC3 entry points. 1 new test.
- ~~**SEC-AUDIT-11**~~ (Medium, DNSSEC correctness): **RESOLVED** (2026-03-25). `validateChainOfTrust` -- `target_zone` used via `isNameInZone`. 1 new test.
- ~~**SEC-AUDIT-12**~~ (Low, defense-in-depth): **RESOLVED** (2026-03-25). `extractWireLabels` returns error union, rejects compression + OOB. 4 new tests.
- ~~**SEC-AUDIT-13**~~ (Low, defense-in-depth): **RESOLVED** (2026-03-25). `base32hexDecode` rejects non-zero trailing bits per RFC 4648. 2 new tests.
- ~~**GAP-0064 / SEC-AUDIT-06**~~ (High, DNSSEC correctness): **RESOLVED** (2026-03-25). `compareDnsNames` rewritten for RFC 4034 S6.1 canonical label ordering. 9 new tests.
- ~~**GAP-0065 / SEC-AUDIT-07**~~ (High, DNSSEC correctness): **RESOLVED** (2026-03-25). `decodeNsec3OwnerHash` with base32hex codec replaces `extractNsec3OwnerHash`. 6 new tests.
- ~~**GAP-0057**~~ (Critical, DNSSEC compile errors): **RESOLVED** (2026-03-25). 11 code fixes; DNSSEC module now compiles and passes 7 new integration tests.
- ~~**GAP-0058 / SEC-AUDIT-01**~~ (High, LabelIterator forward pointer): **RESOLVED** (2026-03-25). Forward pointer check on first hop added.
- ~~**SEC-SCAN-09**~~ (HIGH, DNSSEC validation bypass): **RESOLVED.** Trust anchor comparison now uses exact length + `constantTimeEql`.
- ~~**GAP-0049**~~ (Medium, DNSSEC correctness): **RESOLVED.** Canonical RRset sorting implemented via `appendCanonicalRrset`.
- ~~**GAP-0043**~~ (Medium, correctness bug): **RESOLVED.** Cache hits now format 9 record types via `formatCachedRdata`.
- ~~**SEC-SCAN-03**~~ (Medium, thread-safety): **Won't Do.** Cache documented as single-threaded-only.

Remaining production recommendations (non-blocking, Won't Do):

1. **GAP-0045** (High, test coverage): The core `resolveIterative` function (219 lines, 9 nesting levels) has zero test coverage. Won't Do -- requires mock DNS infrastructure.
2. **GAP-0046** (High, fuzz testing): Wire parsers have no fuzz testing despite 7 bounds-check bugs found by manual review. Won't Do -- fuzz targets exist but CI integration deferred.

**The library is NOT production-ready for DNSSEC-enabled deployments until GAP-0070 is resolved.** DNSSEC correctness at the validator level (wire-format conversion, canonical ordering, hash computation, chain-of-trust zone scoping) was fully resolved in the prior cycle. The remaining gap is that the validator is never invoked from the resolution pipeline. All four NSEC/NSEC3 validation functions are functional in isolation; they need to be wired into `recursive.zig`. Default (non-DNSSEC) resolution is unaffected. 543/543 tests pass in the default build.

---

## Parallelism & Spice Integration GAP Analysis

Last updated: 2026-03-30

## Executive Summary

The `spice` dependency is included in `build.zig.zon`, wired into `build.zig`, and fully integrated into the library. The `src/parallel.zig` module provides four parallel operations using spice's work-stealing thread pool with real DNS implementations:

- `parallelZoneRecordParse` — wire-format record parsing via `ResourceRecord.parse()`
- `parallelDnssecValidate` — structural RRSIG/DNSKEY validation (algorithm matching, protocol checks)
- `parallelBatchQuery` — concurrent DNS query message building via `message.buildQuery()`
- `parallelCachePrefetch` — expiration-aware prefetch with query construction

All resolver modules (`dnssec.zig`, `zone_transfer.zig`, `cache_prefetch.zig`) import and expose the parallel functions. The module is re-exported from `lib.zig` for consumer access.

## Spice Dependency Status

| Aspect | Status | Detail |
|--------|--------|--------|
| Listed in `build.zig.zon` | Yes | `gitlab.com/devnw/zig/spice/-/archive/main/spice-main.tar.gz` |
| Wired in `build.zig` | Yes | Conditionally fetched when `enable_spice=true` (default) |
| Imported in source | `src/parallel.zig` | Conditional: `if (build_options.enable_spice) @import("spice")` |
| Used by resolver modules | **Yes** | `dnssec.zig`, `zone_transfer.zig`, `cache_prefetch.zig` all import `parallel` |
| Re-exported from `lib.zig` | **Yes** | `pub const parallel = @import("parallel");` |
| Pinned to release tag | **No** | Blocked — spice fork has no tags yet. Hash provides content-addressing. |

## Stack-ranked Parallelism Gaps

| Rank | Severity | Finding | Fix Applied | Status |
|---:|---|---|---|---|
| P1 | High | `parallel` module not re-exported from `lib.zig` | Added `pub const parallel = @import("parallel")` to `lib.zig`; updated module docs | **Closed** |
| P2 | High | Parallel implementations are stubs | Wired real implementations: `parseRecord` uses `ResourceRecord.parse()`, `validateDnssec` does structural RRSIG/DNSKEY validation, `executeQuery` builds wire-format queries via `message.buildQuery()`, `prefetchEntry` checks expiration and builds refresh queries | **Closed** |
| P3 | High | Resolver modules don't use parallel functions | Added `parallel` import and public wrapper functions to `dnssec.zig` (`parallelValidateSignatures`), `zone_transfer.zig` (`parseRecordsParallel`), and `cache_prefetch.zig` (`prefetchEntriesParallel`). Updated build.zig module deps. | **Closed** |
| P4 | Medium | `recursive.zig` `parallel_queries` config is misleading | Renamed to `max_server_attempts` with accurate doc comment | **Closed** |
| P5 | Medium | `stub.zig` `parallel` field unused | Removed the unused `parallel: u2` field from `StubOptions` | **Closed** |
| P6 | Medium | Happy Eyeballs spin-wait with `Thread.sleep(10ms)` | Replaced per-socket `poll(0)` + `sleep(10ms)` with combined `poll()` on all sockets using proper timeout derived from RFC 8305 connection delay. Spice not applicable (I/O-bound, not CPU-bound). | **Closed** |
| P7 | Medium | Global thread pool has no shutdown documentation | Added `isPoolInitialized()` helper, documented `deinitPool()` with usage example, added lifecycle test | **Closed** |
| P8 | Medium | `spice` dependency unpinned | **Blocked** — spice fork has no release tags (only 2 commits). Hash in `build.zig.zon` already content-addresses the dependency. Will pin when a tag is published. | **Blocked** |
| P9 | Low | `parallel.zig` has unused `record`/`message` imports | Resolved by P2 — `parallel.zig` now imports and uses both `record` and `message` | **Closed** |
| P10 | Low | Connection pool / failover use raw mutexes | **Won't-Do** — `std.Thread.Mutex` is correct for I/O synchronization. Spice is for CPU-bound parallelism. These are complementary, not inconsistent. | **Won't-Do** |
| P11 | Low | `parallel.zig` `build_options` only import | Resolved by P2 — `parallel.zig` now imports `record`, `message`, and uses them in real implementations | **Closed** |

## Test Results

- **274/274 tests passing** (up from 262 baseline)
- **12 parallel-specific tests** in new `test-parallel` build step
- **No regressions** across all existing test groups

## Summary

| Severity | Total | Closed | Blocked | Won't-Do |
|----------|------:|-------:|--------:|---------:|
| High | 3 | 3 | 0 | 0 |
| Medium | 5 | 4 | 1 | 0 |
| Low | 3 | 2 | 0 | 1 |
| **Total** | **11** | **9** | **1** | **1** |
