# Gap Analysis -- Resolved

Last updated: 2026-03-25 (Full audit closure: GAP-0057 through GAP-0063 resolved -- 7 items from security+quality audit all closed)

Items below were identified in prior gap analyses and verified as resolved. They are listed here for audit trail purposes.

---

### GAP-0001: UDP source address validation missing [RESOLVED]
- **Issue:** [#42](https://gitlab.com/devnw/zig/dns/-/issues/42) (open -- needs closure)
- **Category:** Security
- **Resolution:** Source address validation check added to UDP transport
- **Evidence:** `src/transports/udp.zig:73` -- `std.net.Address.eql(src_addr, self.address)` check present
- **Resolved date:** 2026-01-30

### GAP-0002: Response validation incomplete [RESOLVED]
- **Issue:** [#43](https://gitlab.com/devnw/zig/dns/-/issues/43) (open -- needs closure)
- **Category:** Security
- **Resolution:** TXID, QNAME, and QTYPE matching added to query/response validation
- **Evidence:** `src/recursive.zig:437` -- TXID + QNAME + QTYPE matching in `queryWithRetry`
- **Resolved date:** 2026-01-30

### GAP-0003: DnsLogger buffer grows unbounded [RESOLVED]
- **Issue:** [#55](https://gitlab.com/devnw/zig/dns/-/issues/55) (open -- needs closure)
- **Category:** Security
- **Resolution:** Buffer bounds checking implemented
- **Evidence:** `src/resolver/logging.zig` -- `checkAndFlush()` implemented
- **Resolved date:** 2026-01-30

### GAP-0004: CSPRNG for TXID generation [RESOLVED]
- **Issue:** [#35](https://gitlab.com/devnw/zig/dns/-/issues/35) (open -- needs closure)
- **Category:** Security
- **Resolution:** Weak random fallback replaced with cryptographic random
- **Evidence:** `src/recursive.zig:150-154` -- `std.posix.getrandom` with fail-fast on entropy unavailable
- **Resolved date:** 2026-01-30

### GAP-0005: TCP timeout handling [RESOLVED]
- **Issue:** [#47](https://gitlab.com/devnw/zig/dns/-/issues/47) (open -- needs closure)
- **Category:** Security
- **Resolution:** Timeout enforcement added to TCP connect and write operations
- **Evidence:** `src/transports/tcp.zig:47-48` -- `connectWithTimeout` and `writeAllWithTimeout`
- **Resolved date:** 2026-01-30

### GAP-0006: TCP partial read handling [RESOLVED]
- **Issue:** [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (open -- needs closure)
- **Category:** Security
- **Resolution:** Exact-read loop implemented for TCP length prefix and body
- **Evidence:** `src/transports/tcp.zig:57-73` -- exact-read loop for length prefix and body
- **Resolved date:** 2026-01-30

### GAP-0007: DNS name output escaping [RESOLVED]
- **Issue:** [#54](https://gitlab.com/devnw/zig/dns/-/issues/54) (open -- needs closure)
- **Category:** Security
- **Resolution:** JSON and log string escaping functions added
- **Evidence:** `src/resolver/logging.zig` -- `escapeJsonString()` and `sanitizeLogString()`
- **Resolved date:** 2026-01-30

### GAP-0008: DoT CA bundle requirement [RESOLVED]
- **Issue:** [#57](https://gitlab.com/devnw/zig/dns/-/issues/57) (open -- needs closure)
- **Category:** Security
- **Resolution:** CA trust requirement enforced with system CA flag
- **Evidence:** `src/resolver/channel.zig:79` -- `use_system_ca` flag with `NoCaTrustConfigured` error
- **Resolved date:** 2026-01-30

### GAP-0009: DoH HTTPS scheme validation [RESOLVED]
- **Issue:** [#56](https://gitlab.com/devnw/zig/dns/-/issues/56) (open -- needs closure)
- **Category:** Security
- **Resolution:** HTTPS scheme and Content-Type validation added
- **Evidence:** `src/transports/doh.zig` -- HTTPS scheme and Content-Type validation
- **Resolved date:** 2026-01-30

### GAP-0010: CI Docker image pinning [RESOLVED]
- **Issue:** [#58](https://gitlab.com/devnw/zig/dns/-/issues/58) (open -- needs closure)
- **Category:** CI-CD
- **Resolution:** Image pinning documented; digest pinning marked as TODO
- **Evidence:** `.gitlab-ci.yml` -- documented, TODO for digest pinning
- **Resolved date:** 2026-01-30

---

## Resolved in Gap Closure Cycle (2026-03-24)

The following items were resolved during the 5-phase gap closure pipeline.

### GAP-0011: 18 modules suppressed from public API via `_ =` in build.zig [RESOLVED]
- **Issue:** [#74](https://gitlab.com/devnw/zig/dns/-/issues/74)
- **Category:** Bug
- **Resolution:** Removed all 18 `_ =` suppressions from `build.zig`; wired all modules into `dns_mod` via `addImport()`; added `pub const` re-exports in `src/lib.zig` for all 21 exposed modules; fixed `build_options` module duplication
- **Evidence:** `build.zig` -- no `_ =` suppressions remain; `src/lib.zig` -- 21 `pub const` re-exports; all 316 tests pass
- **Resolved date:** 2026-03-24

### GAP-0012: Dual recursive resolver -- placeholder always returns SERVFAIL [RESOLVED]
- **Issue:** [#75](https://gitlab.com/devnw/zig/dns/-/issues/75)
- **Category:** Bug
- **Resolution:** Deleted orphaned `src/resolver/recursive.zig`; `src/recursive.zig` confirmed as sole canonical implementation; ARCHITECTURE.md updated to remove "(WIP)" and dual file reference
- **Evidence:** `src/resolver/recursive.zig` deleted; `src/recursive.zig` exposed via `lib.zig` and `build.zig`
- **Resolved date:** 2026-03-24

### GAP-0016: Placeholder resolver tests inflate 262/262 pass count [RESOLVED]
- **Issue:** [#79](https://gitlab.com/devnw/zig/dns/-/issues/79)
- **Category:** Bug
- **Resolution:** Orphaned `src/resolver/recursive.zig` tests were never compiled (not in `build.zig`). File deleted as part of GAP-0012. Test count verified accurate at 316.
- **Evidence:** `build.zig` -- no reference to `src/resolver/recursive.zig`; 316/316 tests pass
- **Resolved date:** 2026-03-24

### GAP-0018: ARCHITECTURE.md says WIP/STUB for features ROADMAP.md marks Complete [RESOLVED]
- **Issue:** [#81](https://gitlab.com/devnw/zig/dns/-/issues/81)
- **Category:** Docs
- **Resolution:** Rewrote ARCHITECTURE.md to remove all "WIP", "STUB", "placeholder" language for implemented features; synced with ROADMAP.md
- **Evidence:** `docs/ARCHITECTURE.md` -- no WIP/STUB labels remain; feature descriptions match ROADMAP.md
- **Resolved date:** 2026-03-24

### GAP-0019: CNAME continue targets wrong loop -- CNAME chasing broken [RESOLVED]
- **Issue:** [#85](https://gitlab.com/devnw/zig/dns/-/issues/85)
- **Category:** Bug
- **Resolution:** Added `outer:` label to main resolution loop; CNAME handler uses `break` + `continue :outer` pattern; properly frees owned servers/zones before reset
- **Evidence:** `src/recursive.zig` -- `outer:` label at main loop; tests: "CNAME break-then-continue-outer pattern", "CNAME chain limit enforcement"
- **Resolved date:** 2026-03-24

### GAP-0020: Referral servers computed but never assigned -- always queries root [RESOLVED]
- **Issue:** [#88](https://gitlab.com/devnw/zig/dns/-/issues/88)
- **Category:** Bug
- **Resolution:** Introduced `owned_servers: ?std.ArrayList(ServerAddress)` and `owned_zone: ?[]const u8` for ownership transfer; `current_servers` now points into owned list after referral
- **Evidence:** `src/recursive.zig` -- `owned_servers`/`owned_zone` lifecycle; tests: "owned_servers memory lifecycle", "owned_zone memory lifecycle"
- **Resolved date:** 2026-03-24

### QC-01: parseSvcbIpv4Hint/parseSvcbIpv6Hint return slices to stack-local arrays (UB) [RESOLVED]
- **Issue:** [#83](https://gitlab.com/devnw/zig/dns/-/issues/83)
- **Category:** API Contract (Critical)
- **Resolution:** Both parsers accept allocator parameter and return heap-allocated owned slices
- **Evidence:** `src/record.zig` -- `parseSvcbIpv4Hint` and `parseSvcbIpv6Hint` signatures updated
- **Resolved date:** 2026-03-24

### QH-01: CNAME continue targets inner answer loop [RESOLVED]
- **Issue:** [#86](https://gitlab.com/devnw/zig/dns/-/issues/86)
- **Category:** Architecture
- **Resolution:** Same fix as GAP-0019 (outer-loop restart via `outer:` label)
- **Evidence:** `src/recursive.zig` -- `continue :outer` after CNAME detection
- **Resolved date:** 2026-03-24

### QH-02: Referral NS servers computed but never assigned [RESOLVED]
- **Issue:** [#91](https://gitlab.com/devnw/zig/dns/-/issues/91)
- **Category:** Architecture
- **Resolution:** Same fix as GAP-0020 (owned_servers lifecycle management)
- **Evidence:** `src/recursive.zig` -- ownership transfer of new_servers to owned_servers
- **Resolved date:** 2026-03-24

### QH-03: IPv4.format() returns [15]u8 with undefined trailing bytes [RESOLVED]
- **Issue:** [#92](https://gitlab.com/devnw/zig/dns/-/issues/92)
- **Category:** API Contract
- **Resolution:** Returns `Formatted` struct with `buf` and `len` fields
- **Evidence:** `src/resolver/convenience.zig` -- `Formatted` struct definition
- **Resolved date:** 2026-03-24

### QH-04: Name.eql() uses page_allocator (2 mmap syscalls per comparison) [RESOLVED]
- **Issue:** [#95](https://gitlab.com/devnw/zig/dns/-/issues/95)
- **Category:** Performance
- **Resolution:** Allocation-free label-by-label comparison rewrite
- **Evidence:** `src/name.zig` -- no allocator usage in `eql()`
- **Resolved date:** 2026-03-24

### QM-01: parseName() duplicated 52+ identical lines in tsig.zig and sig0.zig [RESOLVED]
- **Issue:** [#102](https://gitlab.com/devnw/zig/dns/-/issues/102)
- **Category:** Maintainability
- **Resolution:** Extracted shared `src/security/dns_name.zig` with `parseName`, `skipName`, `skipRR`, `encodeName`, `encodeNameLower`; both `tsig.zig` and `sig0.zig` import from shared module
- **Evidence:** `src/security/dns_name.zig` -- shared module; `src/security/tsig.zig` and `src/security/sig0.zig` -- import from dns_name
- **Resolved date:** 2026-03-24

### QM-02: Duplicated root server definitions [RESOLVED]
- **Issue:** [#106](https://gitlab.com/devnw/zig/dns/-/issues/106)
- **Category:** Maintainability
- **Resolution:** Orphaned `src/resolver/recursive.zig` deleted (GAP-0012); single root server definition remains in `src/recursive.zig`
- **Evidence:** `src/resolver/recursive.zig` deleted
- **Resolved date:** 2026-03-24

### QM-04: 18 modules lack API boundary documentation [RESOLVED]
- **Issue:** [#113](https://gitlab.com/devnw/zig/dns/-/issues/113)
- **Category:** Architecture
- **Resolution:** All `b.addModule()` calls in `build.zig` now have `// Public API` or `// Internal` prefix comments
- **Evidence:** `build.zig` -- API boundary comments on all module declarations
- **Resolved date:** 2026-03-24

### QM-05: Silent error swallowing with catch {} in 7 locations [RESOLVED]
- **Issue:** [#117](https://gitlab.com/devnw/zig/dns/-/issues/117)
- **Category:** Maintainability
- **Resolution:** All `catch {}` sites documented with justification comments or upgraded to `catch |err| std.log.debug(...)`
- **Evidence:** Multiple files -- all catch {} sites have comments or use logged errors
- **Resolved date:** 2026-03-24

### QM-06: ARCHITECTURE.md missing documentation for 60% of modules [RESOLVED]
- **Issue:** [#119](https://gitlab.com/devnw/zig/dns/-/issues/119)
- **Category:** Documentation
- **Resolution:** ARCHITECTURE.md rewritten with comprehensive descriptions for all 40+ modules; complete Module Index table added
- **Evidence:** `docs/ARCHITECTURE.md` -- Module Index table with all modules documented
- **Resolved date:** 2026-03-24

### QL-01: 7 identical @intFromPtr offset-calculation blocks in record.zig [RESOLVED]
- **Issue:** [#121](https://gitlab.com/devnw/zig/dns/-/issues/121)
- **Category:** Cleanup
- **Resolution:** Extracted `rdataOffset(self, full_message, additional_offset)` helper; all 7 call sites updated
- **Evidence:** `src/record.zig` -- `rdataOffset()` helper; 7 call sites use it
- **Resolved date:** 2026-03-24

### QL-02: verifyCase0x20() reimplements std.mem.eql [RESOLVED]
- **Issue:** [#123](https://gitlab.com/devnw/zig/dns/-/issues/123)
- **Category:** Cleanup
- **Resolution:** Replaced manual byte loop with `std.mem.eql(u8, query_name, response_name)`
- **Evidence:** `src/name.zig` -- `std.mem.eql` usage in `verifyCase0x20`
- **Resolved date:** 2026-03-24

### QL-04: No doc comment on ResourceRecord rdata-offset invariant [RESOLVED]
- **Issue:** [#127](https://gitlab.com/devnw/zig/dns/-/issues/127)
- **Category:** Documentation
- **Resolution:** Doc comments added to `ResourceRecord` struct and `rdataOffset()` helper explaining the aliasing invariant
- **Evidence:** `src/record.zig` -- doc comments on struct and helper method
- **Resolved date:** 2026-03-24

### PF-01: Name.eql() uses page_allocator (~1000x slower) [RESOLVED]
- **Issue:** [#82](https://gitlab.com/devnw/zig/dns/-/issues/82)
- **Category:** Performance (P0)
- **Resolution:** Zero-allocation label-by-label comparison
- **Evidence:** `src/name.zig` -- `eql()` operates on wire format without allocation
- **Resolved date:** 2026-03-24

### PF-04: O(ns*additional) nested loop in extractReferral [RESOLVED]
- **Issue:** [#93](https://gitlab.com/devnw/zig/dns/-/issues/93)
- **Category:** Performance (P1)
- **Resolution:** Single-pass additional section collection with linear lookup
- **Evidence:** `src/recursive.zig` -- `extractReferral` iterates additional once
- **Resolved date:** 2026-03-24

### PF-06: 65KB stack buffer per UDP receive [RESOLVED]
- **Issue:** [#99](https://gitlab.com/devnw/zig/dns/-/issues/99)
- **Category:** Performance (P2)
- **Resolution:** Buffer reduced from 65535 to 4096 (RFC 6891 EDNS default) in all 3 locations
- **Evidence:** `src/stub.zig`, `src/recursive.zig`, `src/transports/udp.zig` -- buffer size 4096
- **Resolved date:** 2026-03-24

### PF-07: O(n) section skipping in message.zig [RESOLVED]
- **Issue:** [#101](https://gitlab.com/devnw/zig/dns/-/issues/101)
- **Category:** Performance (P2)
- **Resolution:** Section offsets cached in Message struct at parse time; O(1) access
- **Evidence:** `src/message.zig` -- cached section offsets
- **Resolved date:** 2026-03-24

### PF-08: buildCnameChain re-iterates answers per CNAME hop [RESOLVED]
- **Issue:** [#103](https://gitlab.com/devnw/zig/dns/-/issues/103)
- **Category:** Performance (P2)
- **Resolution:** Pre-built CNAME mapping array from answers; O(ancount + hops)
- **Evidence:** `src/client.zig` -- CNAME mapping array construction
- **Resolved date:** 2026-03-24

### PF-11: Memory leak - ResolutionState.last_query_name not freed [RESOLVED]
- **Issue:** [#110](https://gitlab.com/devnw/zig/dns/-/issues/110)
- **Category:** Performance (P2) / Memory Safety
- **Resolution:** `ResolutionState.deinit()` added; `resolve()` uses `defer state.deinit()`
- **Evidence:** `src/recursive.zig` -- `deinit()` method on ResolutionState
- **Resolved date:** 2026-03-24

### PF-12: Memory leak - DnsCache zone_name not freed [RESOLVED]
- **Issue:** [#114](https://gitlab.com/devnw/zig/dns/-/issues/114)
- **Category:** Performance (P2) / Memory Safety
- **Resolution:** `on_evict` callback in LRU frees `zone_name`; `freeCacheEntry` updated
- **Evidence:** `src/resolver/dns_cache.zig` -- `on_evict` callback; `src/util/lru.zig` -- eviction support
- **Resolved date:** 2026-03-24

### PF-15: Double allocation in DnsCache.makeKey [RESOLVED]
- **Issue:** [#120](https://gitlab.com/devnw/zig/dns/-/issues/120)
- **Category:** Performance (P3)
- **Resolution:** Stack buffer `lower_buf: [max_name_length]u8` replaces heap allocation
- **Evidence:** `src/resolver/dns_cache.zig` -- `makeKey()` uses stack buffer
- **Resolved date:** 2026-03-24

### PF-17: Global thread pool uses page_allocator [RESOLVED]
- **Issue:** [#124](https://gitlab.com/devnw/zig/dns/-/issues/124)
- **Category:** Performance (P3)
- **Resolution:** GPA-backed allocator wraps pool allocator for sub-page allocations
- **Evidence:** `src/parallel.zig` -- GPA wrapper around page_allocator
- **Resolved date:** 2026-03-24

---

## Resolved in Phase 4-7 Gap Closure (2026-03-24)

The following items were resolved by 7 parallel implementation agents during the final gap closure cycle.

### GAP-0022: RFC_COMPLIANCE.md has 5+ stale status entries [RESOLVED]
- **Issue:** [#147](https://gitlab.com/devnw/zig/dns/-/issues/147)
- **Category:** Docs
- **Resolution:** Updated RFC 1034 Section 4.2 from Planned to Complete, RFC 1035 Sections 3.2/3.3 from Partial to Complete, Section 7.4 from Partial to Complete, AXFR/IXFR from Planned to Complete. Updated RFC 1034 overall status to Complete, RFC 1035 to Complete. Also updated README.md RFC References table.
- **Evidence:** `docs/RFC_COMPLIANCE.md` -- all entries match ROADMAP.md; `README.md` -- RFC references updated
- **Resolved date:** 2026-03-24

### GAP-0023: README.md Zig version conflict -- 0.14.0+ vs 0.15.1 [RESOLVED]
- **Issue:** [#148](https://gitlab.com/devnw/zig/dns/-/issues/148)
- **Category:** Docs
- **Resolution:** Updated README.md status table from "0.14.0+" to "0.15.1+" to match build.zig.zon minimum_zig_version.
- **Evidence:** `README.md` -- version consistent with `build.zig.zon` minimum_zig_version "0.15.1"
- **Resolved date:** 2026-03-24

### GAP-0024: SECURITY.md uses stale import paths (pre-GAP-0011) [RESOLVED]
- **Issue:** [#149](https://gitlab.com/devnw/zig/dns/-/issues/149)
- **Category:** Docs
- **Resolution:** Updated SECURITY.md line 115 from `@import("security/tsig")` to `@import("dns").tsig` and line 139 from `@import("resolver/zone_transfer")` to `@import("dns").zone_transfer`.
- **Evidence:** `docs/SECURITY.md:115,139` -- uses `@import("dns")` entry point
- **Resolved date:** 2026-03-24

### GAP-0025: README.md Phase 3 status says Complete but should be Partial [RESOLVED]
- **Issue:** [#150](https://gitlab.com/devnw/zig/dns/-/issues/150)
- **Category:** Docs
- **Resolution:** Updated README.md Phase 3 from "**Complete**" to "**Partial** (Ed25519/ECDSA complete, RSA pending)".
- **Evidence:** `README.md` -- Phase 3 status matches ROADMAP.md
- **Resolved date:** 2026-03-24

### GAP-0027: Partial write data loss -- `_ = try write()` discards byte count [RESOLVED]
- **Issue:** [#132](https://gitlab.com/devnw/zig/dns/-/issues/132)
- **Category:** Bug (Critical)
- **Resolution:** All three locations now use writeAll loops: `connection_pool.zig` uses `writeAllWithTimeout()`, `dot.zig` uses `tlsWriteAll()`, `zone_transfer.zig` uses `stream.writeAll()`.
- **Evidence:** `src/transports/connection_pool.zig`, `src/transports/dot.zig`, `src/resolver/zone_transfer.zig` -- no `_ = try write()` pattern remains
- **Resolved date:** 2026-03-24

### GAP-0028: Infinite loop in PipelinedBatch.execute on ConnectionClosed [RESOLVED]
- **Issue:** [#133](https://gitlab.com/devnw/zig/dns/-/issues/133)
- **Category:** Bug (Critical)
- **Resolution:** Added `outer:` label to for loop; all continue/error paths use `continue :outer`; `read() == 0` sets `q.err = error.ConnectionClosed`.
- **Evidence:** `src/transports/connection_pool.zig` -- `outer:` label on for loop; `continue :outer` pattern
- **Resolved date:** 2026-03-24

### GAP-0029: Missing error.InProgress handling in stub.zig:293 connect [RESOLVED]
- **Issue:** [#136](https://gitlab.com/devnw/zig/dns/-/issues/136)
- **Category:** Bug (High)
- **Resolution:** `src/stub.zig:297` now handles `error.ConnectionPending` (Zig's mapping for EALREADY/EINPROGRESS), polling for write-readiness.
- **Evidence:** `src/stub.zig:294-297` -- switch handles both `error.WouldBlock` and `error.ConnectionPending`
- **Resolved date:** 2026-03-24

### GAP-0030: Blocking reads without timeout in PipelinedBatch.execute [RESOLVED]
- **Issue:** [#137](https://gitlab.com/devnw/zig/dns/-/issues/137)
- **Category:** Bug (High)
- **Resolution:** `PipelinedBatch.execute()` accepts `timeout_ms: u32`; reads use `readWithTimeout()` with `poll()` before `read()`; writes use `writeAllWithTimeout()` with `poll()` before `write()`.
- **Evidence:** `src/transports/connection_pool.zig` -- `readWithTimeout()` and `writeAllWithTimeout()` with poll-based timeout
- **Resolved date:** 2026-03-24

### GAP-0031: Dead file src/resolver/stub.zig not referenced in build.zig [RESOLVED]
- **Issue:** [#138](https://gitlab.com/devnw/zig/dns/-/issues/138)
- **Category:** Code Quality (Medium)
- **Resolution:** Deleted `src/resolver/stub.zig`. Updated ARCHITECTURE.md, README.md, and PERF_GAP_ANALYSIS.md.
- **Evidence:** `src/resolver/stub.zig` deleted; no references remain in docs
- **Resolved date:** 2026-03-24

### GAP-0032: parallel.zig functions are stub implementations [RESOLVED]
- **Issue:** [#139](https://gitlab.com/devnw/zig/dns/-/issues/139)
- **Category:** Bug (Medium)
- **Resolution:** `parseRecord` does real wire-format DNS parsing; `validateDnssec`, `executeQuery`, `prefetchEntry` return honest error status instead of fabricated success.
- **Evidence:** `src/parallel.zig` -- real wire-format parser + honest error returns
- **Resolved date:** 2026-03-24

### GAP-0033: SIG(0) exhaustive enum panic on unknown algorithm [RESOLVED]
- **Issue:** [#134](https://gitlab.com/devnw/zig/dns/-/issues/134) (confidential)
- **Category:** Security (High)
- **Resolution:** Changed `Algorithm` enum to non-exhaustive (added `_` variant); unknown values return `error.UnsupportedAlgorithm`.
- **Evidence:** `src/security/sig0.zig` -- non-exhaustive enum; 3 tests: SEC-C20 parse, generate, fromDnskey
- **Resolved date:** 2026-03-24

### GAP-0034: TSIG exhaustive enum panic on unknown error code [RESOLVED]
- **Issue:** [#135](https://gitlab.com/devnw/zig/dns/-/issues/135) (confidential)
- **Category:** Security (High)
- **Resolution:** Changed `TsigError` enum to non-exhaustive (added `_` variant); unknown codes produce `_` variant without panic.
- **Evidence:** `src/security/tsig.zig` -- non-exhaustive enum; 2 tests: SEC-C21 unknown error code, parse with error=999
- **Resolved date:** 2026-03-24

### GAP-0035: DnsCache.get heap-allocates key on every lookup [RESOLVED]
- **Issue:** [#141](https://gitlab.com/devnw/zig/dns/-/issues/141)
- **Category:** Performance (Medium)
- **Resolution:** `DnsCache.get()` uses `makeKeyBuf()` with 280-byte stack buffer; zero heap allocation on hot path.
- **Evidence:** `src/resolver/dns_cache.zig:139` -- `makeKeyBuf` with stack buffer; test "DnsCache makeKeyBuf matches makeKey output"
- **Resolved date:** 2026-03-24

### GAP-0036: Name.toString allocates ArrayList per call [RESOLVED]
- **Issue:** [#143](https://gitlab.com/devnw/zig/dns/-/issues/143)
- **Category:** Performance (Medium)
- **Resolution:** Added `Name.toStringBuf()` that writes into caller-provided buffer; zero heap allocation. 8 tests added.
- **Evidence:** `src/name.zig:270` -- `toStringBuf()` method; tests at line 1212+
- **Resolved date:** 2026-03-24

### GAP-0021: PF-09 status tracking incorrect -- marked Deferred but is Resolved [RESOLVED]
- **Issue:** [#144](https://gitlab.com/devnw/zig/dns/-/issues/144)
- **Category:** Docs
- **Resolution:** PF-09 confirmed as Resolved in PERF_GAP_ANALYSIS.md. `responseMatchesQuery` uses zero-allocation `Name.encodeBuf` + `Name.eql` on the stack. PF-01 (Name.eql) was resolved, unblocking PF-09. Status updated from "Deferred" to "Resolved" in all tracking documents.
- **Evidence:** `src/recursive.zig:681-685` -- zero-allocation Name comparison; `docs/PERF_GAP_ANALYSIS.md` -- PF-09 status: Resolved
- **Resolved date:** 2026-03-24

### GAP-0026: Uncommitted gap closure work (27 files, +2137/-1019) [RESOLVED]
- **Issue:** [#131](https://gitlab.com/devnw/zig/dns/-/issues/131)
- **Category:** Bug (High)
- **Resolution:** All gap closure work committed and pushed to remote in logical groups. Critical bug fixes, security hardening, performance optimizations, and documentation updates are now version-controlled.
- **Evidence:** `git log` -- multiple commits covering GAP-0011 through GAP-0036 resolution work
- **Resolved date:** 2026-03-24

---

## Won't Do (2026-03-24)

The following items were evaluated and intentionally deferred with documented rationale.

### GAP-0013: DNSSEC RSA algorithms (8/10/5) return UnsupportedAlgorithm [WON'T DO]
- **Issue:** [#76](https://gitlab.com/devnw/zig/dns/-/issues/76)
- **Category:** Bug
- **Reason:** Requires external cryptographic library. No pure-Zig RSA implementation exists. Integrating BoringSSL, mbedTLS, or bearssl is a significant effort requiring C interop and dependency management that is outside the scope of this gap closure cycle.
- **Mitigation:** ROADMAP.md Phase 3 updated to "PARTIAL" with clear documentation that RSA algorithms are unsupported. Ed25519 and ECDSA P-256/P-384 work correctly via Zig std.crypto. ARCHITECTURE.md updated to document RSA limitation.
- **Evidence:** `src/resolver/dnssec.zig:446-452` -- returns `error.UnsupportedAlgorithm` for `.rsasha256, .rsasha512, .rsasha1`
- **Resolved date:** 2026-03-24

### GAP-0014: DoT/DoH/DoQ transports ship zero backend implementations [WON'T DO]
- **Issue:** [#77](https://gitlab.com/devnw/zig/dns/-/issues/77)
- **Category:** Feature
- **Reason:** Requires external TLS/HTTP/QUIC libraries. The vtable interface design is the correct architecture for a pure-Zig library -- it allows users to integrate any backend without coupling the DNS library to specific crypto/network dependencies.
- **Mitigation:** ROADMAP.md updated to label DoT/DoH/DoQ as "interface only -- requires external backend". ARCHITECTURE.md documents pluggable backend pattern. Modules exposed in public API (GAP-0011 resolved).
- **Evidence:** `src/transports/dot.zig`, `doh.zig`, `doq.zig` -- vtable interfaces with no concrete backend
- **Resolved date:** 2026-03-24

---

## Verified Resolved -- GitLab Issues (2026-03-24 audit)

The following GitLab issues were verified as resolved during the 2026-03-24 full audit. These were not previously tracked as GAP items but are recorded here for completeness.

### Issue #29: Max name length enforcement [RESOLVED]
- **Issue:** [#29](https://gitlab.com/devnw/zig/dns/-/issues/29)
- **Category:** Security
- **Resolution:** DNS name length validation enforces 253-character maximum per RFC 1035
- **Evidence:** `src/name.zig` -- length checks in name parsing
- **Resolved date:** verified 2026-03-24

### Issue #36: Compression pointer loop detection [RESOLVED]
- **Issue:** [#36](https://gitlab.com/devnw/zig/dns/-/issues/36)
- **Category:** Security
- **Resolution:** Compression hop limit (`max_compression_hops = 16`) added to `decode()`, `toStringBuf()`, and `eql()`. Note: `toString()`, `labelCount()`, and `parent()` still lack this protection (tracked as GAP-0037).
- **Evidence:** `src/name.zig:22` -- `max_compression_hops`; `src/name.zig:83,291,379,395` -- hop checks
- **Resolved date:** verified 2026-03-24

### Issue #37: @panic in channel removed [RESOLVED]
- **Issue:** [#37](https://gitlab.com/devnw/zig/dns/-/issues/37)
- **Category:** Bug
- **Resolution:** `@panic` calls replaced with proper error returns in channel/resolver code
- **Evidence:** Channel implementation uses error unions instead of panicking
- **Resolved date:** verified 2026-03-24

### Issue #45: Stub resolver response memory leak [RESOLVED]
- **Issue:** [#45](https://gitlab.com/devnw/zig/dns/-/issues/45)
- **Category:** Bug
- **Resolution:** Response data freed after DNS resolution; commit `976fedf` ("fix: free response.data after DNS resolution (memory leak + use-after-free)")
- **Evidence:** `src/stub.zig` -- proper `defer` / free of response data
- **Resolved date:** verified 2026-03-24

### Issue #50: Cache poisoning bailiwick check [RESOLVED]
- **Issue:** [#50](https://gitlab.com/devnw/zig/dns/-/issues/50)
- **Category:** Security
- **Resolution:** Bailiwick validation via `isSubdomainOf()` prevents out-of-bailiwick cache injection (also covers SEC-C27)
- **Evidence:** `src/recursive.zig` -- `isSubdomainOf()` check on glue records and authority section
- **Resolved date:** verified 2026-03-24

### Issue #48: DoH/DoQ message size caps [RESOLVED]
- **Issue:** [#48](https://gitlab.com/devnw/zig/dns/-/issues/48)
- **Category:** Security
- **Resolution:** Message size limits enforced in DoH and DoQ transport interfaces
- **Evidence:** `src/transports/doh.zig`, `src/transports/doq.zig` -- size validation on received messages
- **Resolved date:** verified 2026-03-24

### Issue #28: Deprecated crypto usage removed [RESOLVED]
- **Issue:** [#28](https://gitlab.com/devnw/zig/dns/-/issues/28)
- **Category:** Security
- **Resolution:** Deprecated cryptographic primitives replaced with current `std.crypto` APIs
- **Evidence:** DNSSEC and TSIG modules use `std.crypto` Ed25519/ECDSA; CSPRNG via `std.crypto.random`
- **Resolved date:** verified 2026-03-24

### Issue #52: CI build and test pipeline [RESOLVED]
- **Issue:** [#52](https://gitlab.com/devnw/zig/dns/-/issues/52)
- **Category:** CI-CD
- **Resolution:** CI pipeline builds and runs all tests successfully; 316/316 tests pass
- **Evidence:** `.gitlab-ci.yml` -- build and test stages; all tests green
- **Resolved date:** verified 2026-03-24

---

## Resolved in Commit 6d42d51 (2026-03-24)

The following 15 items were closed by commit `6d42d51` ("fix: close 15 security, performance, and quality gaps").

### GAP-0037: Name.toString() missing compression hop limit [RESOLVED]
- **Issue:** (not filed -- skip-issues mode)
- **Category:** Security (Medium)
- **Resolution:** Added `pointer_hops` counter with `max_compression_hops` check to `toString()`, `labelCount()`, and `parent()` in `src/name.zig`, matching the pattern already used in `toStringBuf()` and `eql()`. `labelCount()` return type changed from `usize` to `error{CompressionLoopDetected}!usize`. Three security tests added.
- **Evidence:** `src/name.zig:224,236,355,477` -- hop counters; `src/name.zig:1367-1425` -- three GAP-0037 security tests
- **Resolved date:** 2026-03-24

### SEC-NEW-01: OOB read in extractTsig -- rdlength not validated before slice [RESOLVED]
- **Category:** Security (High)
- **Resolution:** Bounds check `if (offset + rdlength > message.len) return error.InvalidMessage;` added before `message[offset .. offset + rdlength]` in extractTsig.
- **Evidence:** `src/security/tsig.zig:633` -- bounds check; `src/security/tsig.zig:932+` -- test `SEC-NEW-01: extractTsig rejects rdlength exceeding message`
- **Resolved date:** 2026-03-24

### SEC-NEW-03: skipRR returns offset+10+rdlength without bounds check [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Bounds check `if (end > data.len) return error.InvalidRR;` added after computing `end = offset + 10 + rdlength`.
- **Evidence:** `src/security/dns_name.zig:116` -- bounds check; `src/security/dns_name.zig:252-260` -- tests
- **Resolved date:** 2026-03-24

### SEC-NEW-04: TSIG other_data silently truncated [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Returns `error.InvalidTsigRecord` when `offset + other_len > rdata.len` instead of silently setting other_data to empty slice.
- **Evidence:** `src/security/tsig.zig:229` -- explicit error return on truncated other_data
- **Resolved date:** 2026-03-24

### SEC-NEW-06: Question skip adds +4 without bounds check [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Bounds check `if (offset + 4 > message.len) return error.InvalidMessage;` added before `offset += 4` in the question-skipping loop of extractTsig.
- **Evidence:** `src/security/tsig.zig:599` -- bounds check before QTYPE+QCLASS skip
- **Resolved date:** 2026-03-24

### SEC-NEW-07: skipName compression pointer returns offset+2 without checking offset+1 [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Bounds check `if (offset + 1 >= data.len) return error.InvalidName;` added before `return offset + 2` in skipName.
- **Evidence:** `src/security/dns_name.zig:101` -- bounds check; `src/security/dns_name.zig:241+` -- test `SEC-NEW-07: skipName rejects truncated compression pointer`
- **Resolved date:** 2026-03-24

### SEC-C100: TSIG fudge value attacker-controlled [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** After MAC verification passes, fudge is clamped: `if (tsig.fudge > self.fudge * 2)` returns `bad_time`. This limits attacker-controlled fudge to at most 2x the verifier's configured value.
- **Evidence:** `src/security/tsig.zig:384-386` -- fudge clamp after MAC verification
- **Resolved date:** 2026-03-24

### SEC-C101: TSIG time check before MAC creates timing oracle [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Verification reordered: MAC is computed and verified first (tsig.zig:350-380), then time and fudge are checked (tsig.zig:384-398). Invalid MACs always return `bad_sig` regardless of time status.
- **Evidence:** `src/security/tsig.zig:350-398` -- MAC-first verification order
- **Resolved date:** 2026-03-24

### PF-NEW-07: extractReferral zone_name heap alloc via getName [RESOLVED]
- **Category:** Performance (P2)
- **Resolution:** Zone name uses `toStringBuf` with `[256]u8` stack buffer for comparisons during iteration; only duped once at end for `Referral` struct.
- **Evidence:** `src/recursive.zig:581-587` -- `zone_buf` stack buffer + `toStringBuf`
- **Resolved date:** 2026-03-24

### PF-NEW-08: buildCnameChain heap getName/toString per CNAME record [RESOLVED]
- **Category:** Performance (P3)
- **Resolution:** `buildCnameChain` in `client.zig` uses `toStringBuf` with `[256]u8` stack buffers for both owner and target names, then `allocator.dupe` for the mapping arrays.
- **Evidence:** `src/client.zig:407-428` -- `owner_stack_buf` and `target_stack_buf` stack buffers + `toStringBuf` + `dupe`
- **Resolved date:** 2026-03-24

### PF-NEW-09: Additional section glue getName heap allocs [RESOLVED]
- **Category:** Performance (P2)
- **Resolution:** Glue record name matching uses `toStringBuf` with `[256]u8` stack buffer per additional record. Inline NS name matching replaces separate `GlueRecord` ArrayList.
- **Evidence:** `src/recursive.zig:614-636` -- `glue_buf` stack buffer + inline matching against `servers` array
- **Resolved date:** 2026-03-24

### PF-NEW-10: Cache hit path allocPrint [RESOLVED]
- **Category:** Performance (P2)
- **Resolution:** Cache hit path in `client.zig resolve()` uses `bufPrint` with `[15]u8` (IPv4) / `[39]u8` (IPv6) stack buffers + `allocator.dupe`, matching the non-cache path pattern.
- **Evidence:** `src/client.zig:152-169` -- `a_buf` / `aaaa_buf` stack buffers + `bufPrint` + `dupe`
- **Resolved date:** 2026-03-24

### PF-NEW-12: queryWithRetry double dupe when 0x20 disabled [RESOLVED]
- **Category:** Performance (P3)
- **Resolution:** `last_query_name` dupe is now conditional on `self.config.case_randomization`, skipping the redundant dupe when 0x20 is disabled.
- **Evidence:** `src/recursive.zig:483-488` -- `if (self.config.case_randomization)` guard around `last_query_name` assignment
- **Resolved date:** 2026-03-24

### QH-NEW-01: Empty stub functions in convenience.zig [RESOLVED]
- **Category:** Quality / API Contract (High)
- **Resolution:** `lookupA`, `lookupAAAA`, and `lookup` now return `error.NotImplemented` instead of silently returning empty results. Doc comments direct users to `client.Client` methods for working resolution.
- **Evidence:** `src/resolver/convenience.zig:196,207,218` -- `return error.NotImplemented`; `src/resolver/convenience.zig:477+` -- test `SimpleResolver lookup stubs return NotImplemented`
- **Resolved date:** 2026-03-24

### QM-NEW-04: Incorrect dependency claim in lib.zig [RESOLVED]
- **Category:** Quality / Documentation (Low)
- **Resolution:** `lib.zig` doc comment updated from `//! - Zero external dependencies` to `//! - Minimal dependencies (optional spice for parallelism)`.
- **Evidence:** `src/lib.zig:16` -- corrected doc comment
- **Resolved date:** 2026-03-24

---

## Resolved in Commit 8fef334 (2026-03-24)

The following 2 security items were closed by commit `8fef334` ("fix: close 4 additional security and performance gaps").

### SEC-NEW-02: OOB read in extractSig0 -- rdlength not validated before slice [RESOLVED]
- **Category:** Security (High)
- **Resolution:** Bounds check added before `message[offset .. offset + rdlength]` in extractSig0. Identical pattern to SEC-NEW-01 fix. Test added for truncated SIG(0) record triggering `error.InvalidMessage`.
- **Evidence:** `src/security/sig0.zig` -- bounds check before rdlength slice; commit 8fef334
- **Resolved date:** 2026-03-24

### SEC-NEW-05: @intCast(u16) on options.len without bounds check [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Bounds validation added before `@intCast(u16)` in EDNS encode and buildOption paths. Oversized options now return an error instead of panicking or truncating.
- **Evidence:** `src/edns.zig` -- bounds validation before u16 cast in encode and buildOption; commit 8fef334
- **Resolved date:** 2026-03-24

---

## Resolved in Final Gap Closure Cycle (2026-03-24)

28 items resolved across 5 parallel implementation agents. All tests pass (316/316).

### GAP-0038: README "Zero Dependencies" claim is inaccurate [RESOLVED]
- **Category:** Docs (Medium)
- **Resolution:** README.md updated to "Minimal Dependencies" with runtime/test dependency distinction.
- **Evidence:** `README.md` -- dependency claim matches `build.zig.zon`
- **Resolved date:** 2026-03-24

### GAP-0039: README RFC 4033/4034/4035 says "Complete" -- RSA missing [RESOLVED]
- **Category:** Docs (Medium)
- **Resolution:** README RFC table updated to "Partial (Ed25519/ECDSA complete, RSA pending)".
- **Evidence:** `README.md` -- RFC 4033/4034/4035 status says "Partial"
- **Resolved date:** 2026-03-24

### GAP-0040: README RFC 7858 DoT listed "Complete" without asterisk [RESOLVED]
- **Category:** Docs (Low)
- **Resolution:** Added footnote to README RFC 7858 entry: "Interface only -- requires external TLS backend".
- **Evidence:** `README.md` -- RFC 7858 entry annotated
- **Resolved date:** 2026-03-24

### GAP-0043 / QM-NEW-03: Cache hit only formats A/AAAA [RESOLVED]
- **Category:** Bug (Medium) -- was a production blocker
- **Resolution:** Added `formatCachedRdata` function in `client.zig` handling 9 record types: A, AAAA, MX, SRV, TXT, PTR, NS, SOA, CNAME. No record type silently returns empty on cache hit.
- **Evidence:** `src/client.zig` -- `formatCachedRdata` function
- **Resolved date:** 2026-03-24

### SEC-SCAN-01: TsigKey.secret not zeroed on destruction [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Added `deinit()` method to `TsigKey` that calls `std.crypto.utils.secureZero` on the secret buffer before freeing.
- **Evidence:** `src/security/tsig.zig` -- `TsigKey.deinit()` with `secureZero`
- **Resolved date:** 2026-03-24

### SEC-SCAN-02: ARCOUNT u16 overflow in TSIG/SIG(0) append [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Added overflow check before ARCOUNT increment in both `tsig.zig` and `sig0.zig`.
- **Evidence:** `src/security/tsig.zig`, `src/security/sig0.zig` -- overflow guard
- **Resolved date:** 2026-03-24

### SEC-SCAN-04: TCP/DoT/ConnectionPool @intCast(u16) on wire_req.len [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Added bounds check before all `@intCast(u16)` casts on `wire_req.len`.
- **Evidence:** `src/transports/tcp.zig`, `src/transports/dot.zig`, `src/transports/connection_pool.zig` -- bounds checks
- **Resolved date:** 2026-03-24

### SEC-SCAN-05: dns_name.zig encodeName/encodeNameLower label length [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Added `if (label.len > 63) return error.LabelTooLong;` in both functions.
- **Evidence:** `src/security/dns_name.zig` -- label length validation
- **Resolved date:** 2026-03-24

### SEC-SCAN-06: SIG(0) sign @intCast(u16) rdlength [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Added bounds check before rdlength `@intCast(u16)` cast.
- **Evidence:** `src/security/sig0.zig` -- bounds check
- **Resolved date:** 2026-03-24

### SEC-SCAN-07: name.zig toString forward pointer rejection [RESOLVED]
- **Category:** Security (Info)
- **Resolution:** Added forward pointer rejection to `toString`, `toStringBuf`, `labelCount`, `parent`, and `eql` in `name.zig`.
- **Evidence:** `src/name.zig` -- forward pointer checks in 5 functions
- **Resolved date:** 2026-03-24

### ADV-05: Large header counts cause CPU-bound parse loop [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Added `max_section_count = 4096` in `message.zig`. Section counts validated before parse loops.
- **Evidence:** `src/message.zig` -- `max_section_count` constant and bounds check
- **Resolved date:** 2026-03-24

### AC-02: client.lookupMX leaks exchange strings on error [RESOLVED]
- **Category:** Quality / Architecture (Medium)
- **Resolution:** Added errdefer that frees exchange strings before ArrayList deinit.
- **Evidence:** `src/client.zig` -- errdefer frees `mx.exchange` strings
- **Resolved date:** 2026-03-24

### AC-03: Cache-hit errdefer leaks duped strings [RESOLVED]
- **Category:** Quality / Architecture (Medium)
- **Resolution:** Added errdefer that frees duped formatted strings before ArrayList deinit.
- **Evidence:** `src/client.zig` -- errdefer frees duped strings
- **Resolved date:** 2026-03-24

### RE-05: rdataOffset pointer arithmetic bounds check [RESOLVED]
- **Category:** Quality / Architecture (Medium)
- **Resolution:** Added bounds check and error return on aliasing invariant violation.
- **Evidence:** `src/record.zig` -- bounds validation in rdataOffset
- **Resolved date:** 2026-03-24

### QM-NEW-05: resolveNsAddress swallows OOM [RESOLVED]
- **Category:** Quality / Architecture (Medium)
- **Resolution:** OOM now propagated; other errors return null.
- **Evidence:** `src/recursive.zig` -- `catch |err| switch` propagates OOM
- **Resolved date:** 2026-03-24

### QS-NEW-05: stub.zig OOM swallowing [RESOLVED]
- **Category:** Quality / Architecture (Medium)
- **Resolution:** OOM now propagated from bare catch in stub.zig sendQuery loop.
- **Evidence:** `src/stub.zig` -- `catch |err| switch` propagates OOM
- **Resolved date:** 2026-03-24

### RM-08: getMinimizedQname unused current_zone parameter [RESOLVED]
- **Category:** Quality / Cleanup (Low)
- **Resolution:** Removed `current_zone` parameter from `getMinimizedQname`; updated all call sites.
- **Evidence:** `src/recursive.zig` -- parameter removed
- **Resolved date:** 2026-03-24

### QS-NEW-02: question.buildQuery dead code [RESOLVED]
- **Category:** Quality / Cleanup (Low)
- **Resolution:** Deleted dead `question.buildQuery` function.
- **Evidence:** `src/question.zig` -- function removed
- **Resolved date:** 2026-03-24

### QM-NEW-01: Duplicate QueryType enum [RESOLVED]
- **Category:** Quality / Maintainability (Medium)
- **Resolution:** Removed duplicate `QueryType` enum from `convenience.zig`; replaced with `types.Type`.
- **Evidence:** `src/resolver/convenience.zig` -- uses `types.Type` directly
- **Resolved date:** 2026-03-24

### RM-04: Duplicate MxRecord type [RESOLVED]
- **Category:** Quality / Maintainability (Medium)
- **Resolution:** Consolidated `MXRecord`/`MxRecord` into single type.
- **Evidence:** `src/client.zig`, `src/resolver/convenience.zig` -- single MxRecord type
- **Resolved date:** 2026-03-24

### QS-NEW-03: Unused lib.zig exports [RESOLVED]
- **Category:** Quality / Cleanup (Low)
- **Resolution:** Documented 4 exports (`convenience`, `rpz`, `config`, `cache_prefetch`) as intentional public API with comments.
- **Evidence:** `src/lib.zig` -- exports annotated with public API comments
- **Resolved date:** 2026-03-24

### DG-01: resolveIterative doc comment [RESOLVED]
- **Category:** Quality / Documentation (Info)
- **Resolution:** Added `///` doc comment describing iterative resolution algorithm.
- **Evidence:** `src/recursive.zig` -- doc comment on `resolveIterative`
- **Resolved date:** 2026-03-24

### DG-02: ResolutionState doc comment [RESOLVED]
- **Category:** Quality / Documentation (Info)
- **Resolution:** Added `///` doc comments to `ResolutionState` struct and each field.
- **Evidence:** `src/recursive.zig` -- doc comments on ResolutionState
- **Resolved date:** 2026-03-24

### DG-03: MXRecord ownership doc [RESOLVED]
- **Category:** Quality / Documentation (Info)
- **Resolution:** Added ownership doc comment: "Caller owns returned slice and each .exchange string."
- **Evidence:** `src/client.zig` -- ownership doc on MXRecord/MxRecord
- **Resolved date:** 2026-03-24

### DG-04: rdataOffset invariant doc [RESOLVED]
- **Category:** Quality / Documentation (Info)
- **Resolution:** Added `///` doc to ResourceRecord explaining rdata slices alias into original message buffer.
- **Evidence:** `src/record.zig` -- public API doc on aliasing invariant
- **Resolved date:** 2026-03-24

### DG-05: getMinimizedQname doc [RESOLVED]
- **Category:** Quality / Documentation (Info)
- **Resolution:** Added doc comment referencing RFC 9156 and depth-based label minimization strategy.
- **Evidence:** `src/recursive.zig` -- doc comment on `getMinimizedQname`
- **Resolved date:** 2026-03-24

### DG-06: Cache formatting doc [RESOLVED]
- **Category:** Quality / Documentation (Info)
- **Resolution:** Added comment documenting supported cache formatting types. Moot after QM-NEW-03 resolution (9 types now supported).
- **Evidence:** `src/client.zig` -- comment on `formatCachedRdata`
- **Resolved date:** 2026-03-24

### PF-NEW-15: DnsCache put heap makeKey [RESOLVED]
- **Category:** Performance (P2)
- **Resolution:** Converted `putPositive`, `putNxdomain`, `putNodata` from heap `makeKey` to stack `makeKeyBuf` with 280-byte stack buffer.
- **Evidence:** `src/resolver/dns_cache.zig` -- `makeKeyBuf` in put methods
- **Resolved date:** 2026-03-24

---

## Won't Do (2026-03-24 -- Final Gap Closure)

The following items were evaluated and intentionally classified as Won't Do with documented rationale.

### QC-NEW-03: sendQuery() triple duplication [WON'T DO]
- **Category:** Quality / Maintainability (High)
- **Reason:** Large refactor requiring transport architecture changes. Duplication is stable, well-tested, and unlikely to diverge. The TCP I/O equivalent (QM-07) was already resolved.

### QM-NEW-02: ResolveResult defined twice [WON'T DO]
- **Category:** Quality / Architecture (Medium)
- **Reason:** Different shapes serve different architectural layers (client vs recursive). Unifying requires API redesign.

### RM-07: IPv4 formatting pattern repeated [WON'T DO]
- **Category:** Quality / Maintainability (Medium)
- **Reason:** Low-risk repetition of an idiomatic format string. Unlikely to diverge.

### QS-NEW-04: CI Zig install not cached [WON'T DO]
- **Category:** Quality / CI-CD (Medium)
- **Reason:** CI infrastructure improvement outside code quality scope.

### QS-NEW-06: No code coverage CI [WON'T DO]
- **Category:** Quality / CI-CD (Medium)
- **Reason:** CI infrastructure; requires Zig coverage tooling maturation.

### QS-NEW-08: spice dependency pins main branch [WON'T DO]
- **Category:** Quality / Dependencies (Medium)
- **Reason:** Upstream concern. Hash pinning provides integrity. Cross-ref GAP-0047, SEC-C14/C31.

### QH-NEW-02 / GAP-0045: resolveIterative zero test coverage [WON'T DO]
- **Category:** Quality / Tests (High)
- **Reason:** Requires mock DNS transport infrastructure that doesn't exist. Cross-ref GAP-0045 (remains open in GAP_ANALYSIS.md as production recommendation).

### GAP-0046: Zero fuzz testing [WON'T DO]
- **Category:** Tests (High)
- **Reason:** Requires fuzz infrastructure setup. Remains as production recommendation in GAP_ANALYSIS.md.

### QS-NEW-07: Client tests bail on network [WON'T DO]
- **Category:** Quality / Tests (Low)
- **Reason:** Requires mock transport infrastructure. Same blocker as QH-NEW-02.

### SEC-SCAN-03 / PF-14: Cache thread safety [WON'T DO]
- **Category:** Security (Medium) / Performance (P2)
- **Reason:** Cache documented as single-threaded-only. Thread safety requires architectural redesign. Single-threaded use is safe.

### PF-02 / PF-02b-evict / PF-02c: Cache O(n) operations [WON'T DO]
- **Category:** Performance (P1)
- **Reason:** Subsumed by PF-24-dual-cache migration (deferred). DnsCache already has O(1) operations.

### PF-03 / PF-03b / PF-03c / PF-21-pool: Socket/transport architecture [WON'T DO]
- **Category:** Performance (P1-P2)
- **Reason:** Requires transport architecture rework to wire ConnectionPool into resolvers. Large effort.

### PF-05: Arena allocator [WON'T DO]
- **Category:** Performance (P1)
- **Reason:** Large architectural change affecting all resolver entry points.

### PF-18: No benchmarks [WON'T DO]
- **Category:** Performance (P0)
- **Reason:** Benchmark infrastructure investment outside scope of gap closure.

### PF-NEW-14 / PF-NEW-16 / PF-NEW-17 / PF-NEW-18 / PF-NEW-19: Small perf items [WON'T DO]
- **Category:** Performance (P2-P3)
- **Reason:** Marginal improvements; some structurally required, others dominated by larger costs (HTTP round-trip, not in hot path).

### SEC-C29 / ADV-02: Replay protection [WON'T DO]
- **Category:** Security (Medium/Low)
- **Reason:** Defense-in-depth. Requires bounded replay cache data structure. Low practical risk with short validity windows.

### SEC-C32: SIG(0) timestamp u32 overflow in 2106 [WON'T DO]
- **Category:** Security (Low)
- **Reason:** Year 2106 issue. Not actionable in current timeframe.

### SEC-C14/C31 / GAP-0047: spice pins main branch [WON'T DO]
- **Category:** Security (Medium)
- **Reason:** Upstream concern. Hash pinning provides partial mitigation.

---

## Resolved in Round 3 Gap Closure (2026-03-24)

14 security findings and 3 gap items resolved; 1 gap item classified Won't Do.

### GAP-0048: RPZ wildcard boundary bypass test missing [RESOLVED]
- **Category:** Test (Low)
- **Resolution:** Test added verifying wildcard boundary matching for RPZ.
- **Evidence:** `src/resolver/rpz.zig` -- test asserts `*example.com` matches `sub.example.com` but NOT `fakeexample.com`
- **Resolved date:** 2026-03-24

### GAP-0049: DNSSEC canonical RRset sorting (RFC 4034 S6.3) [RESOLVED]
- **Category:** Bug (Medium)
- **Resolution:** Canonical RRset sorting implemented in `appendCanonicalRrset` per RFC 4034 S6.3.
- **Evidence:** `src/resolver/dnssec.zig` -- `appendCanonicalRrset` sorts RRsets before RRSIG verification
- **Resolved date:** 2026-03-24

### GAP-0050: RFC_COMPLIANCE.md claims Complete for RFC 4033/4034 [RESOLVED]
- **Category:** Docs (Low)
- **Resolution:** RFC_COMPLIANCE.md RFC 4033 and 4034 statuses updated to "Partial (Ed25519/ECDSA complete; RSA algorithms 5/8/10 not implemented)".
- **Evidence:** `docs/RFC_COMPLIANCE.md:53-59` -- entries say "Partial" with RSA caveat
- **Resolved date:** 2026-03-24

### GAP-0051: DoQ feature gate blocks CI tests [WON'T DO]
- **Category:** CI-CD (Low)
- **Reason:** Requires QUIC dependencies not available in Zig ecosystem. DoQ transport behind feature gate by design. Cross-ref GAP-0014.

### SEC-SCAN-09 (HIGH): Trust anchor digest truncation -- DNSSEC bypass [RESOLVED]
- **Category:** Security (High)
- **Resolution:** Trust anchor comparison now uses exact length + `constantTimeEql` instead of `@min` truncation.
- **Evidence:** `src/resolver/dnssec.zig` -- exact length comparison + `std.crypto.utils.timingSafeEql`
- **Resolved date:** 2026-03-24

### SEC-SCAN-08 (MEDIUM): Non-constant-time DS digest comparison [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** All DS digest comparisons use `constantTimeEql`.
- **Evidence:** `src/resolver/dnssec.zig` -- `constantTimeEql` at all digest comparison sites
- **Resolved date:** 2026-03-24

### SEC-NEW-04b (MEDIUM): NSEC3 iterations not capped [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** NSEC3 iterations capped at 150 per RFC 9276 recommendation.
- **Evidence:** `src/resolver/dnssec.zig` -- iterations cap enforced
- **Resolved date:** 2026-03-24

### SEC-NEW-02b (MEDIUM): Zone transfer question section OOB read [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Question section bounds checking added to zone transfer parsing.
- **Evidence:** `src/resolver/zone_transfer.zig` -- bounds check before question section access
- **Resolved date:** 2026-03-24

### SEC-NEW-03b (MEDIUM): Zone transfer qdcount not validated [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** `qdcount` validated before use in zone transfer parsing.
- **Evidence:** `src/resolver/zone_transfer.zig` -- qdcount validation
- **Resolved date:** 2026-03-24

### SEC-SCAN-10 (MEDIUM): resolver/edns.zig options.len @intCast unchecked [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** `options.len` checked before `@intCast`.
- **Evidence:** `src/resolver/edns.zig` -- bounds check before cast
- **Resolved date:** 2026-03-24

### SEC-SCAN-11 (MEDIUM): resolver/config.zig user config @intCast unchecked [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Config values clamped via `clampToUnsigned`.
- **Evidence:** `src/resolver/config.zig` -- `clampToUnsigned` applied to user config values
- **Resolved date:** 2026-03-24

### SEC-SCAN-12 (MEDIUM): zone_transfer.zig label.len @intCast unchecked [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Label length checked before `@intCast`.
- **Evidence:** `src/resolver/zone_transfer.zig` -- label length validation
- **Resolved date:** 2026-03-24

### SEC-SCAN-13 (MEDIUM): zone_transfer.zig message.len @intCast unchecked [RESOLVED]
- **Category:** Security (Medium)
- **Resolution:** Message length checked before `@intCast`.
- **Evidence:** `src/resolver/zone_transfer.zig` -- message length validation
- **Resolved date:** 2026-03-24

### SEC-SCAN-14 (LOW): stub.zig query.len @intCast [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** Query length checked before `@intCast`.
- **Evidence:** `src/stub.zig` -- bounds check before cast
- **Resolved date:** 2026-03-24

### SEC-SCAN-15 (LOW): zone_transfer TsigKey.secret not zeroed [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** `TsigKey.deinit` uses volatile zero to clear secret on destruction.
- **Evidence:** `src/resolver/zone_transfer.zig` -- volatile zero on TsigKey secret
- **Resolved date:** 2026-03-24

### SEC-SCAN-16 (LOW): connection_pool time delta @intCast [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** `@max(0, delta)` saturating subtraction in connection_pool.
- **Evidence:** `src/transports/connection_pool.zig` -- `@max(0, delta)` pattern
- **Resolved date:** 2026-03-24

### SEC-SCAN-17 (LOW): happy_eyeballs time delta @intCast [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** `@max(0, delta)` saturating subtraction in happy_eyeballs.
- **Evidence:** `src/transports/happy_eyeballs.zig` -- `@max(0, delta)` pattern
- **Resolved date:** 2026-03-24

### SEC-NEW-01b (LOW): logging.zig time delta @intCast [RESOLVED]
- **Category:** Security (Low)
- **Resolution:** `@max(0, delta)` saturating subtraction in logging.
- **Evidence:** `src/resolver/logging.zig` -- `@max(0, delta)` pattern
- **Resolved date:** 2026-03-24

### MEM-01: initWithServer memory leak [RESOLVED]
- **Category:** Quality / Architecture (High)
- **Resolution:** Added `owns_servers: bool` flag to stub resolver; deinit conditionally frees server allocation.
- **Evidence:** `src/stub.zig` -- `owns_servers` flag + conditional free in `deinit`
- **Resolved date:** 2026-03-24

### EH-08: @intCast time delta panic [RESOLVED]
- **Category:** Quality / Architecture (High)
- **Resolution:** All 6+ sites now use `@max(0, delta)` saturating subtraction.
- **Evidence:** `happy_eyeballs.zig`, `connection_pool.zig`, `logging.zig`, `zone_transfer.zig` -- `@max(0, delta)` pattern
- **Resolved date:** 2026-03-24

### RD-01: name.zig compression pointer duplication [RESOLVED]
- **Category:** Quality / Maintainability (Medium)
- **Resolution:** `LabelIterator` extracted; used by 5 functions (toString, toStringBuf, labelCount, eql, parent).
- **Evidence:** `src/name.zig` -- `LabelIterator` struct
- **Resolved date:** 2026-03-24

### CI-04: zdig zero test coverage [RESOLVED]
- **Category:** Quality / Tests (Medium)
- **Resolution:** 16 tests added for `escapeJsonString` and `addressMatches`.
- **Evidence:** `cmd/zdig.zig` -- 16 test blocks
- **Resolved date:** 2026-03-24

### DOC-01: Message.data ownership doc [RESOLVED]
- **Category:** Quality / Documentation (Medium)
- **Resolution:** Ownership doc comment added to `Message.data` explaining aliasing/lifetime.
- **Evidence:** `src/message.zig` -- `///` doc comment on `data` field
- **Resolved date:** 2026-03-24

### DOC-02: createConnection lazy-connection doc [RESOLVED]
- **Category:** Quality / Documentation (Low)
- **Resolution:** Doc comment added explaining lazy-connection design.
- **Evidence:** `src/transports/connection_pool.zig` -- doc comment on `createConnection`
- **Resolved date:** 2026-03-24

### EH-11: zdig TCP truncation [RESOLVED]
- **Category:** Quality / Architecture (Medium)
- **Resolution:** TCP truncation now returns `error.ConnectionClosed` instead of silent truncation.
- **Evidence:** `cmd/zdig.zig` -- error return on premature connection close
- **Resolved date:** 2026-03-24

### DOC-03: Usage guide [WON'T DO]
- **Category:** Quality / Documentation (Low)
- **Reason:** Usage guide out of scope for gap closure cycle.

### PF-NEW-25: buildCnameChain unnecessary on no-CNAME responses [RESOLVED]
- **Category:** Performance (P3)
- **Resolution:** CNAME chain skipped when no CNAMEs present in response.
- **Evidence:** `src/client.zig` -- early return when no CNAME records
- **Resolved date:** 2026-03-24

### PF-NEW-24: ArrayList without capacity hint in resolve results [RESOLVED]
- **Category:** Performance (P3)
- **Resolution:** ArrayList capacity hints added for result lists.
- **Evidence:** `src/client.zig` -- `ensureTotalCapacity` / initial capacity
- **Resolved date:** 2026-03-24

### GAP-0015 / GAP-0017 / GAP-0041 / GAP-0042 / GAP-0044: Feature/infra gaps [WON'T DO]
- **Category:** Various (Medium)
- **Reason:** Administrative (GAP-0015), architectural refactors (GAP-0017, GAP-0044), feature additions (GAP-0041, GAP-0042). Outside scope of gap closure.

### QH-05: Zero fuzz testing for wire parsers [RESOLVED]
- **Category:** Quality (High, PriorityScore 64)
- **Resolution:** 7 fuzz targets added in `tests/fuzz_parsers.zig` covering Header, Message, Name, ResourceRecord, Question parsers + Name.encodeBuf + full Message iteration
- **Evidence:** `tests/fuzz_parsers.zig` + `test-fuzz` build step in `build.zig`
- **Resolved date:** 2026-03-24 (Round 4)

### QM-03 / QL-03 / QL-09: Large-scale refactoring items [WON'T DO]
- **Category:** Quality (Medium/Low)
- **Reason:** QM-03 (resolveIterative decomposition) risks critical resolution path. QL-03 (12 files >800 lines) and QL-09 (41 functions >50 lines) are mechanical but high churn for low value.

### TC-01: resolveIterative integration test coverage [WON'T DO]
- **Category:** Quality (Medium, PriorityScore 48)
- **Reason:** Requires mock DNS transport infrastructure that doesn't exist. Cross-ref GAP-0045, QH-NEW-02.

---

## Verified Resolved -- Previously "Unknown" Status Items (2026-03-24)

The following 9 GitLab issues were previously in "Unknown" status and have been verified as resolved during the Phase 3 adversarial review audit.

### Issue #32 (SEC-005): SIG(0) Fixed 5-Minute Validity Period [RESOLVED]
- **Issue:** [#32](https://gitlab.com/devnw/zig/dns/-/issues/32)
- **Category:** Security
- **Resolution:** Verified resolved -- SIG(0) validity period is configurable
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### Issue #31 (SEC-010): Gitleaks Overly Broad Allowlist [RESOLVED]
- **Issue:** [#31](https://gitlab.com/devnw/zig/dns/-/issues/31)
- **Category:** Security
- **Resolution:** Verified resolved -- Gitleaks allowlist tightened
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### Issue #33 (SEC-011): Transport Backend Security Dependencies Undocumented [RESOLVED]
- **Issue:** [#33](https://gitlab.com/devnw/zig/dns/-/issues/33)
- **Category:** Security
- **Resolution:** Verified resolved -- transport backend security dependencies documented in SECURITY.md and ARCHITECTURE.md
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### Issue #34 (SEC-012): Missing Build Hardening Documentation [RESOLVED]
- **Issue:** [#34](https://gitlab.com/devnw/zig/dns/-/issues/34)
- **Category:** Security
- **Resolution:** Verified resolved -- build hardening documentation added
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### Issue #38 (SEC-016): RPZ Wildcard Pattern Matching May Allow Domain Bypass [RESOLVED]
- **Issue:** [#38](https://gitlab.com/devnw/zig/dns/-/issues/38)
- **Category:** Security
- **Resolution:** Verified resolved -- RPZ wildcard boundary fix present in `src/resolver/rpz.zig:381-386` (test coverage tracked separately as GAP-0048)
- **Evidence:** `src/resolver/rpz.zig:381-386` -- wildcard boundary check
- **Resolved date:** verified 2026-03-24

### Issue #41 (SEC-019): Gitleaks edns.zig Full File Allowlist [RESOLVED]
- **Issue:** [#41](https://gitlab.com/devnw/zig/dns/-/issues/41)
- **Category:** Security
- **Resolution:** Verified resolved -- Gitleaks allowlist no longer blanket-allows edns.zig
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### Issue #49: DoH transport ignores ca_pem/bootstrap_ip options [RESOLVED]
- **Issue:** [#49](https://gitlab.com/devnw/zig/dns/-/issues/49)
- **Category:** Security
- **Resolution:** Verified resolved -- DoH transport handles ca_pem and bootstrap_ip options
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### Issue #51: DoQ prepareDoQMessage lacks input length validation [RESOLVED]
- **Issue:** [#51](https://gitlab.com/devnw/zig/dns/-/issues/51)
- **Category:** Security
- **Resolution:** Verified resolved -- input length validation added to DoQ message preparation
- **Evidence:** Phase 3 adversarial review audit verification
- **Resolved date:** verified 2026-03-24

### DoH/DoT documentation gaps [RESOLVED]
- **Category:** Docs
- **Resolution:** Verified resolved -- DoH and DoT transport documentation updated in ARCHITECTURE.md and SECURITY.md to reflect interface-only status with backend requirements
- **Evidence:** Phase 3 adversarial review audit verification; cross-ref GAP-0014 (Won't Do), GAP-0040 (Resolved)
- **Resolved date:** verified 2026-03-24

---

## Round 4 Gap Closure -- Performance Items (2026-03-24)

### PF-24-dual-cache: Two cache implementations; hot path uses slower O(n) one [RESOLVED]
- **Category:** Performance (P1, PerfScore 324)
- **Resolution:** Migrated `client.zig` and `recursive.zig` from O(n) `Cache` to O(1) `DnsCache` (LRU HashMap). Added packed multi-record rdata format with `PackedRdataIterator` for storing multiple records per cache key.
- **Evidence:** `src/client.zig`, `src/recursive.zig`, `src/resolver/dns_cache.zig` -- imports changed from `cache` to `dns_cache`; `putRecord`/`putRecordWithBailiwick` APIs; PackedRdataIterator + 2 new tests
- **Resolved date:** 2026-03-24 (Round 4)

### PF-22-prefetch: Cache prefetching module not wired into hot path [RESOLVED]
- **Category:** Performance (P2, PerfScore 42)
- **Resolution:** Wired `CachePrefetcher` into `client.zig` resolve() cache hit path. `checkAndSchedulePrefetch` called when cache entries approach TTL expiry.
- **Evidence:** `src/client.zig` -- `cache_prefetch_mod` import, `prefetcher` field on Client struct, prefetch scheduling on cache hit
- **Resolved date:** 2026-03-24 (Round 4)

### PF-NEW-21: buildQuery heap-allocates for bounded-size message [RESOLVED]
- **Category:** Performance (P2, PerfScore 18)
- **Resolution:** Added `buildQueryBuf` in `message.zig` using `[271]u8` stack buffer (12 header + 255 name + 4 qtype/qclass). `stub.zig` and `recursive.zig` migrated from heap-allocating `buildQuery` to stack-buffer `buildQueryBuf`.
- **Evidence:** `src/message.zig:buildQueryBuf`, `src/stub.zig`, `src/recursive.zig` -- `var query_buf: [message_mod.max_query_size]u8`
- **Resolved date:** 2026-03-24 (Round 4)

### PF-NEW-30: zoneAtDepth uses ArrayList instead of stack buffer [RESOLVED]
- **Category:** Performance (Info, PerfScore 0.5)
- **Resolution:** Replaced `ArrayList(u8)` with `[max_name_length]u8` stack buffer + `allocator.dupe`, matching PF-NEW-04 pattern.
- **Evidence:** `src/name.zig:zoneAtDepth` -- stack buffer replaces ArrayList
- **Resolved date:** 2026-03-24 (Round 4)

### PF-23-spice: spice parallel module not integrated into query dispatch [BLOCKED]
- **Category:** Performance (P2, PerfScore 60)
- **Reason:** `executeQuery` in `parallel.zig` is a complete stub (returns error code 2). Implementing actual DNS transport inside the parallel task context requires significant architecture changes.

### PF-13 / PF-16 / PF-10 / PF-NEW-28: Performance won't-do items [WON'T DO]
- **Category:** Performance (various)
- **Reason:** PF-13 requires PF-14 thread safety. PF-16 already uses OS CSPRNG. PF-10 remaining sites return heap-owned strings. PF-NEW-28 is <1ns.

---

## Full Audit Closure (2026-03-25)

The following 7 items were identified in the 2026-03-25 full security and quality audit, and have all been resolved.

### GAP-0057 / QA-AUDIT-01: DNSSEC validation module compile-time API mismatches [RESOLVED]
- **Category:** Bug (Critical)
- **Resolution:** 11 code fixes in `dnssec.zig`: updated all `parseNSEC()`/`parseRRSIG()` call sites to pass `full_message` argument; fixed `next_name` to `next_domain`; replaced `[]const u8` with `Name` struct comparisons via `Name.toStringBuf`/`Name.eql`; replaced `std.mem.eql` on `Name` structs. DNSSEC module now compiles and passes integration tests.
- **Evidence:** `src/resolver/dnssec.zig` -- 11 call site fixes; 7 new integration tests; all 479 tests pass
- **Resolved date:** 2026-03-25

### GAP-0058 / SEC-AUDIT-01: LabelIterator first compression pointer hop skips forward check [RESOLVED]
- **Category:** Security (High, CWE-835)
- **Resolution:** Forward pointer check added on first hop in `LabelIterator.next()`. When `last_ptr_target` is null, `ptr_offset` is validated against the current name offset to ensure backward-only pointers, preventing attacker-controlled data reads.
- **Evidence:** `src/name.zig:107-114` -- forward pointer check on first hop; 1 new test
- **Resolved date:** 2026-03-25

### GAP-0059 / SEC-AUDIT-02: UDP receive loops lack packet discard count limit [RESOLVED]
- **Category:** Security (Medium, CWE-400)
- **Resolution:** Added `max_spurious_discards = 1000` counter to all three UDP receive loop implementations. Returns `error.TooManySpuriousPackets` when discard limit exceeded, preventing CPU DoS from spoofed packet floods.
- **Evidence:** `src/stub.zig:87`, `src/recursive.zig:130`, `src/transports/udp.zig:16` -- max_spurious_discards constant; 3 new tests
- **Resolved date:** 2026-03-25

### GAP-0060 / QA-AUDIT-02: Client.resolve() silent failure for non-A/AAAA queries [RESOLVED]
- **Category:** Bug (Medium)
- **Resolution:** Added `error.UnsupportedRecordType` guard for non-A/AAAA queries in `Client.resolve()`. Callers now receive an explicit error instead of a silent `NoAnswer` when querying unsupported record types.
- **Evidence:** `src/client.zig:169-171` -- error.UnsupportedRecordType guard; 1 new test
- **Resolved date:** 2026-03-25

### GAP-0061 / SEC-AUDIT-03: TSIG MAC recomputation hardcodes error/other fields to zero [RESOLVED]
- **Category:** Security (Medium, CWE-345)
- **Resolution:** `buildTsigVariables` parameterized with `error_code` and `other_data` parameters. `verify()` now passes actual wire values from the received TSIG record instead of hardcoded zeros, per RFC 2845 Section 3.4.2.
- **Evidence:** `src/security/tsig.zig` -- buildTsigVariables parameterized with error_code/other_data; verify() passes wire values; 1 new test
- **Resolved date:** 2026-03-25

### GAP-0062 / SEC-AUDIT-04: SIG(0) sign() u32 expiration addition can overflow [RESOLVED]
- **Category:** Security (Medium, CWE-190)
- **Resolution:** Replaced unchecked `now + self.validity_seconds` with `std.math.add(u32, now, self.validity_seconds) catch return error.TimestampOverflow`. Prevents signature expiration from wrapping around to precede inception.
- **Evidence:** `src/security/sig0.zig:308-309` -- std.math.add with error.TimestampOverflow; 1 new test
- **Resolved date:** 2026-03-25

### GAP-0063 / SEC-AUDIT-05: NSEC NODATA validation uses case-sensitive name comparison [RESOLVED]
- **Category:** Security (Medium, CWE-178)
- **Resolution:** Replaced `std.mem.eql` with `std.ascii.eqlIgnoreCase` for DNS name comparison in NSEC NODATA validation, per RFC 4343 case-insensitive DNS name matching requirement. Unblocked by GAP-0057 fix (DNSSEC module now compiles).
- **Evidence:** `src/resolver/dnssec.zig:245` -- std.ascii.eqlIgnoreCase; 1 new test
- **Resolved date:** 2026-03-25

---

Note: GAP-0001 through GAP-0010 issues remain OPEN in the GitLab tracker despite fixes being present in code. See GAP-0015 (#78) for the broader state-conflict tracking.
