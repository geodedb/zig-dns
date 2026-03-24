# Quality Gap Analysis

Last updated: 2026-03-24

## Summary

| Severity | Open | Resolved/Closed | Total |
|----------|------|-----------------|-------|
| Critical | 0 | 4 | 4 |
| High | 1 | 8 | 9 |
| Medium | 1 | 9 | 10 |
| Low | 2 | 7 | 9 |
| **Total** | **4** | **28** | **32** |

### Top 4 Active Risks

1. **QH-05** (PriorityScore 64) -- Zero fuzz testing for security-critical DNS wire parsers. Deferred from Phase 2.
2. **QM-07** (PriorityScore 48) -- 3x duplicate I/O helpers (~240 lines). Already diverged between stub.zig, tcp.zig, connection_pool.zig.
3. **QL-09** (PriorityScore 16) -- 30 functions exceed 50-line threshold.
4. **QL-03** (PriorityScore 16) -- 9 source files exceed 800-line threshold.

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | QC-03 | Critical | 80 | architecture | `_ = try write()` discards return value in 3 files, 6 sites -- partial write data loss | connection_pool, dot, zone_transfer | `connection_pool.zig:454-455`, `dot.zig:305-306`, `zone_transfer.zig:523-524` | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | Use writeAll loop or existing writeAllWithTimeout helper | Transport maintainer | S | **Resolved** |
| 2 | QH-02 | High | 80 | architecture | Referral NS servers computed but never assigned to `current_servers` | recursive.zig | `src/recursive.zig:296-316` | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | Assign `new_servers` items to `current_servers` with proper lifetime management | Resolver maintainer | M | Resolved |
| 3 | QH-07 | High | 64 | architecture | Blocking reads without timeout in PipelinedBatch.execute | connection_pool.zig | `connection_pool.zig:448-498` -- raw `std.posix.read/write` without poll/timeout | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | Add timeout_ms parameter, use readWithTimeout/writeAllWithTimeout | Transport maintainer | S | **Resolved** |
| 4 | QH-08 | High | 64 | architecture | Zone transfer receiveTcpMessage single read for 2-byte length prefix | zone_transfer.zig | `zone_transfer.zig:530-540` -- read loop with `while (len_read < 2)` | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | Read loop for 2-byte prefix; only n==0 means closed (SEC-C33/QH-08) | Resolver maintainer | S | **Resolved** |
| 5 | QH-01 | High | 64 | architecture | CNAME `continue` targets inner `ans_iter` loop, not outer resolution loop | recursive.zig | `src/recursive.zig:253-271` | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | Replace `continue` with `break` + flag pattern to target outer loop | Resolver maintainer | S | Resolved |
| 6 | QH-04 | High | 64 | perf | `Name.eql()` uses `page_allocator` -- 2 mmap+munmap syscalls per comparison | name.zig | `src/name.zig:254-264` | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | Compare labels directly without allocation | name.zig maintainer | M | Resolved |
| 7 | QH-05 | High | 64 | tests | Zero fuzz testing for security-critical DNS wire parsers | All parsers | No fuzz targets in build.zig | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | Add `std.testing.fuzz` targets | Security/testing lead | M | Deferred |
| 8 | QC-02 | Critical | 60 | architecture | ConnectionPool.acquire mutex race: defer lock/unlock dance leaves lines 278-286 unprotected | connection_pool.zig | `connection_pool.zig:247-287` -- `defer self.mutex.lock()` at line 273 fires at scope exit, not line 277 | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | Replace `defer self.mutex.lock()` with explicit `self.mutex.lock()` before mutations | Transport maintainer | S | **Resolved** |
| 9 | QC-04 | Critical | 60 | architecture | Infinite loop in PipelinedBatch.execute: `continue` targets inner while, not outer for | connection_pool.zig | `connection_pool.zig:468,490` -- `continue` after ConnectionClosed re-reads from closed fd forever | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | Add `outer:` label to for loop, use `continue :outer` | Transport maintainer | S | **Resolved** |
| 10 | QC-01 | Critical | 60 | api-contract | `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` return slices to stack-local arrays (UB) | record.zig | `src/record.zig:601-630` | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | Accept allocator parameter, return owned slice | record.zig maintainer | S | Closed |
| 11 | QH-06 | High | 48 | maintainability | Missing `error.InProgress` in stub.zig connectWithTimeout | stub.zig | `stub.zig:294-297` -- handles `error.WouldBlock` and `error.ConnectionPending` | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | Added `error.ConnectionPending` to switch (Zig maps EALREADY to ConnectionPending) | Resolver maintainer | S | **Resolved** |
| 12 | QM-07 | **Resolved** | 48 | maintainability | ~~3x duplicate I/O helpers: connectWithTimeout, writeAllWithTimeout, readWithTimeout, readExactWithTimeout~~ | stub.zig, tcp.zig, connection_pool.zig | Extracted shared `src/transports/io.zig`; all 3 files now import and use canonical implementations; also fixed incorrect `error.InProgress`/`error.IsConnected` catch arms (not valid in Zig 0.15.2 ConnectError) | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | Resolved: shared io.zig module with 4 tests | Transport maintainer | M | **Resolved** |
| 13 | QM-11 | Medium | 48 | perf | PooledTcpTransport.query calls connect on every query despite connection pooling | connection_pool.zig | `connection_pool.zig:537` -- `connectWithTimeout()` called unconditionally; `IsConnected` handled but wastes syscall | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | Track connected state in PooledConnection or connect in acquire() | Transport maintainer | S | **Resolved** |
| 14 | QH-03 | High | 48 | api-contract | `IPv4.format()` returns `[15]u8` with undefined trailing bytes | convenience.zig | `src/resolver/convenience.zig:34-43` | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | Return struct with buf+len, or zero-fill buffer | Convenience module maintainer | S | Closed |
| 15 | QM-01 | **Resolved** | 36 | maintainability | ~~`parseName()` copy-pasted ~52 identical lines in tsig.zig and sig0.zig~~ | tsig.zig, sig0.zig | Extracted shared `src/security/dns_name.zig` | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | Resolved by extracting shared dns_name module | Security module maintainer | S | Resolved |
| 16 | QM-09 | **Resolved** | 36 | architecture | ~~parallel.zig: 4 placeholder implementations return fabricated results~~ | parallel.zig | parseRecord now does real wire-format parsing; validateDnssec/executeQuery/prefetchEntry return honest error status instead of fabricated success | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | parseRecord: real wire-format parser; others: honest not-implemented status | Parallel module maintainer | M | Resolved |
| 17 | QM-03 | Medium | 36 | readability | `resolveIterative` is 208 lines with 9 levels of nesting (was 171 at QM-03 filing) | recursive.zig | `src/recursive.zig:187+` | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | Extract `handleCnameChain()`, `handleReferral()`, `handleNodataResponse()` | Resolver maintainer | M | Deferred |
| 18 | QM-05 | **Resolved** | 36 | maintainability | ~~Silent error swallowing with `catch {}` in 5+ locations~~ | Multiple files | All catch {} sites documented or upgraded | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | Resolved | Any contributor | S | Resolved |
| 19 | QL-07 | **Resolved** | 32 | ci-cd | ~~No `zig fmt --check` in CI pipeline~~ | .gitlab-ci.yml | zig-format job override now includes explicit `zig fmt --check src/ cmd/ build.zig` script | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | Added explicit script to zig-format job override; added fmt-check Makefile target | CI/CD maintainer | S | **Resolved** |
| 20 | QM-08 | **Resolved** | 24 | cleanup | ~~Dead file `src/resolver/stub.zig` -- 353 lines not in build.zig, never imported~~ | resolver/stub.zig (deleted) | File deleted; ARCHITECTURE.md stale references removed; PERF_GAP_ANALYSIS.md PF-16 annotated | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | Deleted file, updated ARCHITECTURE.md and PERF_GAP_ANALYSIS.md | Any contributor | S | **Resolved** |
| 21 | QM-10 | **Resolved** | 24 | cleanup | ~~Duplicate SOA parsing: extractSerial duplicates parseSoaRdata name-skipping logic~~ | zone_transfer.zig | `extractSerial` now delegates to `parseSoaRdata`; 24 duplicated lines removed | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | extractSerial calls parseSoaRdata and returns .serial | Resolver maintainer | S | **Resolved** |
| 22 | QM-02 | **Resolved** | 24 | maintainability | ~~Duplicated root server definitions~~ | recursive.zig | Deleted `src/resolver/recursive.zig` (GAP-0012) | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | Resolved | Resolver maintainer | S | Resolved |
| 23 | QM-04 | **Resolved** | 24 | architecture | ~~18 modules lack API boundary docs~~ | build.zig | Added API boundary comments | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | Resolved | Project maintainer | S | Resolved |
| 24 | QM-06 | **Resolved** | 24 | docs | ~~ARCHITECTURE.md missing 60% of modules~~ | docs/ARCHITECTURE.md | Rewritten with all modules documented | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | Resolved | Documentation lead | M | Resolved |
| 25 | QL-03 | Low | 16 | readability | 9 source files exceed 800-line threshold; `record.zig` at 1763 | Multiple files | `record.zig:1763`, `edns.zig:973`, `dnssec.zig:889`, `zone_transfer.zig:886`, +5 more | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | Split large files by responsibility domain | Project maintainer | L | Deferred |
| 26 | QL-09 | Low | 16 | readability | 30 functions exceed 50-line threshold; resolveIterative at 208 lines | Multiple files | `recursive.zig:187+` (208 lines), record.zig, edns.zig, zone_transfer.zig parsers | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Decompose long functions; add lint gate | Project maintainer | L | Open |
| 27 | QL-04 | **Resolved** | 16 | docs | ~~No doc comment on rdata-offset invariant~~ | record.zig | Doc comments added | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | Resolved | Any contributor | S | Resolved |
| 28 | QL-05 | **Resolved** | 16 | tests | ~~Mutable statics in MockTlsBackend~~ | dot.zig | `write_buffer` and `write_len` moved from struct-level statics to per-instance fields | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | Moved to per-instance state | Any contributor | S | Resolved |
| 29 | QL-06 | **Resolved** | 12 | readability | ~~Magic number 6 for SOA record type in zone_transfer.zig~~ | zone_transfer.zig | All 5 instances of `rtype == 6` replaced with `soa_rtype` named constant | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | Added `const soa_rtype: u16 = 6` and replaced all magic number usages | Any contributor | S | **Resolved** |
| 30 | QL-08 | **Resolved** | 12 | docs | ~~ARCHITECTURE.md references deleted/dead files (resolver/recursive.zig, resolver/stub.zig)~~ | docs/ARCHITECTURE.md | Stale references to `src/resolver/stub.zig` and `src/resolver/recursive.zig` removed | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | Removed all stale references to deleted files | Documentation maintainer | S | **Resolved** |
| 31 | QL-01 | **Resolved** | 12 | cleanup | ~~7 identical @intFromPtr blocks~~ | record.zig | Extracted rdataOffset() helper | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | Resolved | Any contributor | S | Resolved |
| 32 | QL-02 | Low | 8 | cleanup | `verifyCase0x20()` reimplements `std.mem.eql` | name.zig | `src/name.zig:451-462` | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | Replace with std.mem.eql | Any contributor | S | Resolved |

## Findings by Category

### Architecture (7 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-03 | Critical | 80 | Partial write data loss (3 files, 6 sites) | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | **Resolved** |
| QH-02 | High | 80 | Referral NS servers never assigned | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | **Resolved** |
| QH-07 | High | 64 | Blocking reads without timeout in PipelinedBatch | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | **Resolved** |
| QH-08 | High | 64 | Zone transfer short read on length prefix | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | **Resolved** |
| QH-01 | High | 64 | CNAME continue targets wrong loop | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | **Resolved** |
| QC-02 | Critical | 60 | ConnectionPool.acquire mutex race | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | **Resolved** |
| QC-04 | Critical | 60 | Infinite loop in PipelinedBatch.execute | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | **Resolved** |
| QM-09 | **Resolved** | 36 | parallel.zig placeholder implementations | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | **Resolved** |
| QM-04 | Medium | 24 | 18 modules lack API boundary docs | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | **Resolved** |

### API Contract (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-01 | Critical | 60 | SVCB hint parsers return dangling pointers | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | **Closed** |
| QH-03 | High | 48 | IPv4.format() undefined trailing bytes | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | **Closed** |

### Performance (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-04 | High | 64 | Name.eql() mmap syscalls | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | **Resolved** |
| QM-11 | Medium | 48 | PooledTcpTransport.query unnecessary connect per query | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | **Resolved** |

### Maintainability (5 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-06 | High | 48 | Missing error.InProgress in stub.zig | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | **Resolved** |
| QM-07 | **Resolved** | 48 | ~~3x duplicate I/O helpers (~240 lines)~~ Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | **Resolved** |
| QM-01 | **Resolved** | 36 | ~~parseName() duplicated in tsig/sig0~~ | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | **Resolved** |
| QM-05 | **Resolved** | 36 | ~~Silent error swallowing (catch {})~~ | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | **Resolved** |
| QM-02 | **Resolved** | 24 | ~~Duplicated root server definitions~~ | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | **Resolved** |

### Tests (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-05 | High | 64 | Zero fuzz testing for wire parsers | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | **Deferred** |
| QL-05 | **Resolved** | 16 | Mutable statics in MockTlsBackend | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | **Resolved** |

### Readability (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-03 | Medium | 36 | resolveIterative 208 lines / 9 nesting levels | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | **Deferred** |
| QL-07 | **Resolved** | 32 | ~~No zig fmt check in CI~~ | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | **Resolved** |
| QL-03 | Low | 16 | 9 files over 800 lines | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | **Deferred** |
| QL-09 | Low | 16 | 30 functions exceed 50 lines | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | Open |
| QL-06 | **Resolved** | 12 | ~~Magic number 6 for SOA~~ | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | **Resolved** |

### Documentation (3 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-06 | **Resolved** | 24 | ~~ARCHITECTURE.md missing 60% of modules~~ | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | **Resolved** |
| QL-04 | **Resolved** | 16 | ~~No doc comment on rdata-offset invariant~~ | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | **Resolved** |
| QL-08 | **Resolved** | 12 | ~~ARCHITECTURE.md references deleted/dead files~~ | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | **Resolved** |

### Cleanup (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-08 | **Resolved** | 24 | ~~Dead file src/resolver/stub.zig~~ | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | **Resolved** |
| QM-10 | **Resolved** | 24 | ~~Duplicate SOA parsing in zone_transfer.zig~~ | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | **Resolved** |
| QL-01 | **Resolved** | 12 | ~~7 identical @intFromPtr blocks~~ | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | **Resolved** |
| QL-02 | Low | 8 | verifyCase0x20 reimplements std.mem.eql | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | **Resolved** |

## Remediation Roadmap

### Quick Wins (< 1 day)

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QM-10 | 24 | extractSerial delegates to parseSoaRdata | S | **Resolved** |
| QL-06 | 12 | Replace magic number 6 with named constant | S | **Resolved** |

### Completed Quick Wins

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QC-02 | 60 | ConnectionPool.acquire mutex race | **Resolved** |
| QC-04 | 60 | PipelinedBatch.execute infinite loop | **Resolved** |
| QM-11 | 48 | Track connected state in PooledConnection | **Resolved** |
| QC-01 | 60 | SVCB hint parsers return dangling pointers | **Resolved** |
| QH-01 | 64 | CNAME continue targets wrong loop | **Resolved** |
| QH-03 | 48 | IPv4.format() undefined bytes | **Resolved** |
| QH-06 | 48 | stub.zig missing InProgress/ConnectionPending | **Resolved** |
| QH-08 | 64 | Zone transfer short read -- read loop added | **Resolved** |
| QM-01 | 36 | Duplicated parseName | **Resolved** |
| QM-05 | 36 | Silent catch {} | **Resolved** |
| QM-08 | 24 | Dead file src/resolver/stub.zig deleted | **Resolved** |
| QM-02 | 24 | Duplicated root servers | **Resolved** |
| QM-04 | 24 | API boundary docs | **Resolved** |
| QL-01 | 12 | @intFromPtr duplication | **Resolved** |
| QL-02 | 8 | verifyCase0x20 reimplements std.mem.eql | **Resolved** |
| QL-04 | 16 | rdata invariant doc | **Resolved** |
| QL-05 | 16 | Move mock statics to per-instance state | **Resolved** |
| QL-07 | 32 | zig fmt --check added to CI (explicit script in zig-format override) | **Resolved** |
| QL-08 | 12 | ARCHITECTURE.md stale references removed | **Resolved** |

### Medium Term (1-5 days)

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QM-07 | 48 | ~~Extract shared I/O helpers module (3 files, ~240 lines)~~ | M | **Resolved** |
| QM-09 | 36 | Connect parallel.zig placeholders to real implementations | M | **Resolved** |

### Completed Medium Term

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QC-03 | 80 | Partial write data loss (3 files) | **Resolved** |
| QH-07 | 64 | PipelinedBatch blocking reads | **Resolved** |
| QH-02 | 80 | Referral NS never assigned | **Resolved** |
| QH-04 | 64 | Name.eql() mmap | **Resolved** |
| QM-06 | 24 | ARCHITECTURE.md gaps | **Resolved** |

### Strategic (> 5 days) / Deferred

| ID | PriorityScore | Finding | Reason |
|----|---------------|---------|--------|
| QH-05 | 64 | Fuzz testing | Requires fuzz infrastructure setup |
| QM-03 | 36 | resolveIterative complexity | Bugs fixed; refactoring is lower risk |
| QL-03 | 16 | 9 files over 800 lines | Risky refactor with low priority |
| QL-09 | 16 | 30 functions over 50 lines | Large-scale refactoring effort |

## Related Issues (Pre-existing)

These existing issues overlap with or are related to quality findings:

| Existing Issue | Related Finding | Relationship |
|---------------|-----------------|--------------|
| [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (TCP length prefix short reads) | QH-08, QC-03 | Same root cause category -- QH-08 is zone_transfer specific, QC-03 covers writes |
| [#47](https://gitlab.com/devnw/zig/dns/-/issues/47) (TCP transports ignore timeout_ms) | QH-07 | Same category; #47 covers stub/tcp/pool query path, QH-07 covers PipelinedBatch |
| [#66](https://gitlab.com/devnw/zig/dns/-/issues/66) (Connection pooling module tracking) | QC-02, QC-04, QH-07, QM-11 | Feature tracking; quality findings are bugs within the module |
| [#68](https://gitlab.com/devnw/zig/dns/-/issues/68) (Parallel DNS operations module) | QM-09 | Feature tracking; QM-09 is about placeholder implementations within |
| [#75](https://gitlab.com/devnw/zig/dns/-/issues/75) (GAP-0012: Dual recursive resolver) | QM-02, QM-08 | Root server duplication resolved; QM-08 is the remaining dead resolver/stub.zig |
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication in name parsing) | QM-01, QM-07 | Same root cause pattern -- duplication leads to divergence |
| [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) (QM-03: resolveIterative) | QL-09 | QM-03 is a subset of the broader 30-function finding |
| [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (SEC-C26: Partial write in TCP framing) | QC-03 | Security perspective on the same partial write issue |

## Scoring Methodology

**PriorityScore = Impact(1-5) x Likelihood(1-5) x 4**

| Scale | Impact | Likelihood |
|-------|--------|------------|
| 5 | Outages / major perf cost | Ubiquitous / touched often |
| 4 | Frequent bugs / major dev drag | Often encountered |
| 3 | Moderate impact | Sometimes encountered |
| 2 | Minor impact | Rare |
| 1 | Polish | Edge-case |

All findings tagged `confidence::confirmed` -- verified via direct code inspection.
