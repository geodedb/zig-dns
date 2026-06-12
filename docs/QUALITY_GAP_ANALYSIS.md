# Quality Gap Analysis

Last updated: 2026-06-12 (Iterative convergence loop reached a fixpoint -- see "Iterative Convergence Loop" below. New audit round: 26 distinct findings filed as 24 issues #255-#278; 30 prior-run findings #225-#254 confirmed; R-02 folded into #230, B-03 into #210, plus C-05/DOC-4/R-04 dispositioned without new issues. See "Audit Round 2026-06-12" below. Prior cycle: all 88 historical findings resolved/closed/won't-do.)

## Iterative Convergence Loop (2026-06-12)

After the audit round filed the issues below, an iterative review+fix loop ran
(`/security:appsec-review` + `/codepros:audit`, fixing via TDD) until neither
review surfaced a new actionable issue. Each iteration re-ran the reviewers
against the freshly committed fixes:

- **Iteration 2 (quality)** found **Q-NEW-1** (HIGH): `zone_transfer.zig` `axfr`/`ixfr`
  never compiled -- a Zig-0.16 dormant-compile landmine (used `std.time.milliTimestamp`
  / `std.net` / `getrandom`, none wired). Fixed: migrated to `net_compat`/`transport_io`
  - force-reference test (commit `aebc166`).
- **Iteration 3 (quality)** found **QC-1** (MEDIUM): the three `*Parallel` wrappers
  (`parseRecordsParallel`, `parallelValidateSignatures`, `prefetchEntriesParallel`)
  imported `parallel` but the module was not wired into their standalone module/test
  artifacts -- same dormant-compile class, masked because the functions are unreferenced.
  Fixed: wired `parallel` into all three modules + test artifacts and added a
  force-reference test per wrapper (commit `0de1b83`). Security + perf reviewers
  CONVERGED (no new findings) on the same iteration.
- **Iteration 4 (convergence check on `0de1b83`)**: security **CONVERGED**, perf
  **CONVERGED**. Quality surfaced **Q-NEW-2** -- `src/observability_init.zig`
  (`Otel.init`/`installGlobals`/`deinit`) is a dormant-compile landmine of the same
  class. **Disposition: NOT a new issue -- maps to already-tracked [#210] (closed,
  by-design) and [#228] (open).** `observability.enabled` is hardcoded `false`
  (#210, 2026-05-02) to dodge a Zig-0.16 `otel`/`otel0` `build_options` module-dedup
  diamond that broke the downstream `geode` build, so `observability_init.zig` is
  dead-stripped in every config. Force-compiling it (a) re-triggers that diamond and
  (b) surfaces a genuine upstream otel bug: `otel.sdk.config.resolve` →
  `captureEnvironment` uses `std.process.Environ.Block.global`, but on Zig 0.16 `Block`
  is `PosixBlock` (no `.global`; that lives on `GlobalBlock`) -- identical in pinned
  otel v0.1.7 (config.zig:362) and v0.1.10 (config.zig:531), so NOT a dep-bump
  regression. Both are **blocked on the upstream Zig module-dedup fix** tracked by
  #210; full evidence recorded on #228. Two force-reference guard attempts (standalone
  test artifact; comptime-gated `lib.zig` guard) were reverted -- the first re-triggers
  the diamond, the second is dead-stripped (`enabled==false`). No code change landed.

**Loop result: CONVERGED.** All actionable findings from iterations 2-3 are fixed and
committed; iteration 4 found no new actionable security/perf/quality issue. The only
quality observation (Q-NEW-2) reduces to pre-existing tracked items -- issue #210
(closed-by-design) and issue #228 (open) -- both blocked on an upstream Zig toolchain fix.

[#210]: https://gitlab.com/devnw/zig/dns/-/issues/210
[#228]: https://gitlab.com/devnw/zig/dns/-/issues/228

## Audit Round 2026-06-12

This round scored automated-scan and manual-review findings against the existing
codebase and the open issue tracker. Findings already filed by the interrupted
prior run (#225-#254) were confirmed and skipped; cross-referenced gap/perf/security
issues (#206-#224) were not duplicated.

### New Issues Filed This Round (#255-#278)

| ID | Severity | PriorityScore | Category | Finding | Issue | Cross-Ref | Status |
|----|----------|---------------|----------|---------|-------|-----------|--------|
| API-1 | Critical | 80 | api-contract | dnssec flag sets RD bit, never emits EDNS OPT/DO -- validation never requested | [#255](https://gitlab.com/devnw/zig/dns/-/issues/255) | #207, #256 | Open |
| DOC-1/DOC-2 | High | 64 | docs | README/SECURITY/ARCHITECTURE/RFC_COMPLIANCE advertise DNSSEC as Implemented -- false security claim | [#256](https://gitlab.com/devnw/zig/dns/-/issues/256) | #207, #255 | Open |
| MNT-1 | High | 48 | maintainability | zone_file continuation detection reads line[0] after trim -- silent wrong owner | [#257](https://gitlab.com/devnw/zig/dns/-/issues/257) | -- | Open |
| M-01 | High | 48 | architecture | Client.initWithConfig has no errdefer for server_addresses -- leak on init failure | [#258](https://gitlab.com/devnw/zig/dns/-/issues/258) | -- | Open |
| REL-3 | High | 48 | architecture | UDP SO_RCVTIMEO is per-recvfrom -- each spurious packet resets full timeout (Nx) | [#259](https://gitlab.com/devnw/zig/dns/-/issues/259) | #236, #268 | Open |
| TEST-5 | Medium | 48 | tests | StubResolver has no mock-channel seam -- Client negative paths untestable | [#260](https://gitlab.com/devnw/zig/dns/-/issues/260) | #190, GAP-0045 | Open |
| TEST-1 | Medium | 36 | tests | client init tests use catch{return} -- silent-green vacuous passes | [#261](https://gitlab.com/devnw/zig/dns/-/issues/261) | #260 | Open |
| TEST-7 | Medium | 36 | tests | rdata parsers, edns.zig, zone_file.zig unfuzzed (harness covers envelope only) | [#262](https://gitlab.com/devnw/zig/dns/-/issues/262) | #98, #244 | Open |
| API-8 | Medium | 36 | api-contract | convenience lookupA/lookupAAAA/lookup all return error.NotImplemented | [#263](https://gitlab.com/devnw/zig/dns/-/issues/263) | QH-NEW-01, #272 | Open |
| TEST-2 | Medium | 36 | tests | parallel validateSignatures asserts only len>=12 -- I/O/result path untested | [#264](https://gitlab.com/devnw/zig/dns/-/issues/264) | #265, #246 | Open |
| REL-7 | Medium | 36 | architecture | parallel.zig 1-byte error sentinels conflate OutOfMemory with invalid input | [#265](https://gitlab.com/devnw/zig/dns/-/issues/265) | #264, #246 | Open |
| MNT-8 | Medium | 36 | maintainability | Dual rdata codecs (client.zig:595-700 vs zone_file.zig:480-595) -- drift risk | [#266](https://gitlab.com/devnw/zig/dns/-/issues/266) | #243, #262 | Open |
| API-6/DOC-6 | Low | 24 | docs | resolve()/result ownership annotations missing on stub & recursive paths | [#271](https://gitlab.com/devnw/zig/dns/-/issues/271) | #252, DOC-01 | Open |
| TEST-3 | Low | 24 | tests | spurious-discard tests assert the constant, not discard behavior | [#268](https://gitlab.com/devnw/zig/dns/-/issues/268) | #259, QR-R02 | Open |
| TEST-6 | Low | 24 | tests | global thread-pool state leaks across tests (parallel.zig:811-903) | [#269](https://gitlab.com/devnw/zig/dns/-/issues/269) | #246, #264 | Open |
| TEST-8 | Low | 24 | tests | assert-nothing tests (convenience.zig:440, udp.zig:110, tcp.zig:94) | [#270](https://gitlab.com/devnw/zig/dns/-/issues/270) | #260 | Open |
| DC-01 | Low | 24 | tests | rpz/config/convenience/cache_prefetch exported but untested via public API | [#272](https://gitlab.com/devnw/zig/dns/-/issues/272) | QS-NEW-03, #263 | Open |
| DOC-3 | Low | 24 | docs | lib.zig:23 quick-start omits try + defer deinit -- won't compile / leaks | [#274](https://gitlab.com/devnw/zig/dns/-/issues/274) | #271 | Open |
| TEST-4 | Low | 16 | tests | DoQ mock failures swallowed via catch return (accept.zig:289, doq.zig:660) | [#267](https://gitlab.com/devnw/zig/dns/-/issues/267) | #261 | Open |
| DC-02 | Low | 16 | tests | parallelValidateSignatures wrapper has no dedicated test coverage | [#273](https://gitlab.com/devnw/zig/dns/-/issues/273) | #264, #220 | Open |
| DOC-5 | Low | 16 | docs | Security contact mismatch (<security@codepros.dev> vs <security@devnw.com>) | [#275](https://gitlab.com/devnw/zig/dns/-/issues/275) | -- | Open |
| DOC-7 | Low | 16 | docs | convenience.zig + dnssec.zig module docs overstate capability | [#276](https://gitlab.com/devnw/zig/dns/-/issues/276) | #263, #255, #256 | Open |
| MNT-10 | Low | 12 | cleanup | Stale -Dwith_otel comments in lib/client/stub/recursive | [#278](https://gitlab.com/devnw/zig/dns/-/issues/278) | #210, #226, #206 | Open |
| DOC-8 | Info | 8 | docs | source-port randomization attributed to library; OS provides it | [#277](https://gitlab.com/devnw/zig/dns/-/issues/277) | -- | Open |

### Confirmed Already Filed by Prior Run (#225-#254) -- Not Duplicated

REL-1 (#225; #227 is a closed duplicate of #225), B-01/B-02 (#226), B-04 (#228),
B-05 (#229), R-01/R-03 (#230), D-01 (#231), D-02 (#232), D-03 (#233), M-02 (#234),
M-03 (#235), REL-2 (#236), REL-4 (#237), REL-5 (#238), REL-6 (#239), REL-8 (#240),
REL-9 (#241), REL-10 (#242), MNT-2 (#243), MNT-3 (#244), MNT-4 (#245), MNT-5 (#246),
MNT-6 (#247), MNT-7 (#248), MNT-9 (#249), MNT-11 (#250), API-2 (#251),
API-3/API-4 (#252), API-5 (#253), API-7 (#254).

### Deduplicated / Folded (no new issue)

| Finding | Disposition | Where |
|---------|-------------|-------|
| R-02 (IP bufPrint catch unreachable x3 production sites) | Folded into umbrella | comment on [#230](https://gitlab.com/devnw/zig/dns/-/issues/230) |
| R-04 (address-family unreachable x4) | Not filed -- evidence not located in net_compat/transports; **suspected**, needs confirmation of exact sites before filing | -- |
| B-03 (observability.enabled hardcoded false) | Cross-ref only | comment on [#210](https://gitlab.com/devnw/zig/dns/-/issues/210); also #226, #228 |
| C-05 (resolveIterative 229 lines / 9-level nesting) | Duplicate of QM-03/#109 + QL-09/#185 (Won't Do) | existing issues |
| DOC-4 (README Zig 0.15.1+/macOS/Windows stale) | Duplicate of #211 + MNT-11/#250 | existing issues |

### Roadmap (This Round)

**Quick wins (< 1 day):** DOC-5 (#275 reconcile security contact), DOC-3 (#274 fix quick-start), MNT-10 (#278 stale otel comments), DOC-8 (#277 reword source-port claim), DOC-7 (#276 reword module docs), M-01 (#258 add errdefer), MNT-1 (#257 fix continuation detection), TEST-8 (#270), API-6/DOC-6 (#271 ownership docs).

**Medium (1-5 days):** DOC-1/DOC-2 (#256 downgrade DNSSEC claims), REL-3 (#259 deadline-aware UDP timeout), REL-7 (#265 typed parallel results), TEST-5 (#260 mock seam -- unblocks TEST-1/2/3/8, DC-*), TEST-1/2/3/4/6 (behavioral test rewrites), TEST-7 (#262 fuzz rdata/edns/zone_file), API-8 (#263 implement-or-remove convenience), DC-01/DC-02 (#272/#273 public-API tests).

**Strategic (> 5 days):** API-1 (#255 wire EDNS OPT/DO; couples with #207 validator wiring), MNT-8 (#266 unify dual rdata codecs).

## Summary

Counts below cover the historical findings (resolved/won't-do from prior cycles)
plus the open findings filed in the 2026-06-12 audit round (#255-#278) and the
prior interrupted run (#225-#254). "Open" = filed and not yet resolved.

| Severity | Open (#225-#278) | Resolved/Closed (historical) | Won't Do (historical) | Total |
|----------|------------------|------------------------------|-----------------------|-------|
| Critical | 1 (API-1) | 5 | 0 | 6 |
| High | 6 | 14 | 2 | 22 |
| Medium | 23 | 29 | 6 | 58 |
| Low | 28 | 17 | 5 | 50 |
| Info | 1 (DOC-8) | 8 | 2 | 11 |
| **Total** | **59** | **73** | **15** | **147** |

> Of the 59 open: 26 findings filed this round as 24 issues (#255-#278) + 30 prior-run
> findings (#225-#254; #227 is a closed duplicate). The two bundled rows are DOC-1/DOC-2
> (#256) and API-6/DOC-6 (#271). All 88 historical findings remain resolved/closed/won't-do.

### Top Active Risks (after Audit Deep Review)

0 open findings. All 4 audit deep review findings have been addressed:

1. ~~**QR-NEW-01**~~ (PriorityScore 16, Low) -- **Resolved** (2026-03-25). `LabelList` comptime param removed; fixed at 128.
2. ~~**QR-NEW-02**~~ (PriorityScore 8, Low) -- **Resolved** (2026-03-25). 3 edge-case tests added for `compareDnsNames` (empty, truncated, missing root).
3. ~~**QR-NEW-03**~~ (PriorityScore 4, Info) -- **Won't Do.** `base32hexEncode` hardcoded to 20-byte input. Acceptable: SHA-1 is the only NSEC3 hash algorithm (RFC 5155).
4. ~~**QR-NEW-04**~~ (PriorityScore 4, Info) -- **Won't Do.** SEC-AUDIT-09 doc comment duplicated verbatim across stub.zig and recursive.zig. Intentional per-file documentation pattern.

Previously top risks (all Resolved or Won't Do):

- ~~**QR-01** (PriorityScore 36)~~ -- **Resolved.** `followPointer()` helper extracted in name.zig, deduplicating ~75 lines.
- ~~**QR-02** (PriorityScore 24)~~ -- **Resolved.** `max_spurious_discards` extracted to `types.zig`; imported by 3 files.
- ~~**MEM-01** (PriorityScore 60)~~ -- **Resolved.** `owns_servers` flag + conditional free in deinit.
- ~~**EH-08** (PriorityScore 60)~~ -- **Resolved.** All 6+ sites now use `@max(0, delta)`.
- **QC-NEW-03** (PriorityScore 64) -- sendQuery() triple duplication. **Won't Do** (large refactor).
- ~~**QH-05** (PriorityScore 64)~~ -- **Resolved.** 7 fuzz targets added.
- **TC-01** (PriorityScore 48) -- resolveIterative zero test coverage. **Won't Do**.
- ~~**RD-01** (PriorityScore 30)~~ -- **Resolved.** LabelIterator extracted, used by 5 functions.
- ~~**CI-04** (PriorityScore 30)~~ -- **Resolved.** 16 tests added.

Note: RE-05, QM-NEW-03 (GAP-0043), AC-02, AC-03, QM-NEW-05, QS-NEW-05, RM-08, QS-NEW-02, QM-NEW-01, RM-04, QS-NEW-03, and DG-01 through DG-06 all **resolved** in prior gap closure cycle.

## Stack-Ranked Findings

| Rank | ID | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | QC-03 | Critical | 80 | architecture | `_ = try write()` discards return value in 3 files, 6 sites -- partial write data loss | connection_pool, dot, zone_transfer | `connection_pool.zig:454-455`, `dot.zig:305-306`, `zone_transfer.zig:523-524` | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | Use writeAll loop or existing writeAllWithTimeout helper | Transport maintainer | S | **Resolved** |
| 2 | QH-02 | High | 80 | architecture | Referral NS servers computed but never assigned to `current_servers` | recursive.zig | `src/recursive.zig:296-316` | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | Assign `new_servers` items to `current_servers` with proper lifetime management | Resolver maintainer | M | **Resolved** |
| 3 | QH-07 | High | 64 | architecture | Blocking reads without timeout in PipelinedBatch.execute | connection_pool.zig | `connection_pool.zig:448-498` -- raw `std.posix.read/write` without poll/timeout | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | Add timeout_ms parameter, use readWithTimeout/writeAllWithTimeout | Transport maintainer | S | **Resolved** |
| 4 | QH-08 | High | 64 | architecture | Zone transfer receiveTcpMessage single read for 2-byte length prefix | zone_transfer.zig | `zone_transfer.zig:530-540` -- read loop with `while (len_read < 2)` | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | Read loop for 2-byte prefix; only n==0 means closed (SEC-C33/QH-08) | Resolver maintainer | S | **Resolved** |
| 5 | QH-01 | High | 64 | architecture | CNAME `continue` targets inner `ans_iter` loop, not outer resolution loop | recursive.zig | `src/recursive.zig:253-271` | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | Replace `continue` with `break` + flag pattern to target outer loop | Resolver maintainer | S | **Resolved** |
| 6 | QH-04 | High | 64 | perf | `Name.eql()` uses `page_allocator` -- 2 mmap+munmap syscalls per comparison | name.zig | `src/name.zig:254-264` | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | Compare labels directly without allocation | name.zig maintainer | M | **Resolved** |
| 7 | QH-05 | High | 64 | tests | Zero fuzz testing for security-critical DNS wire parsers | All parsers | 7 fuzz targets in `tests/fuzz_parsers.zig` + `test-fuzz` build step | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | Add `std.testing.fuzz` targets for Header, Message, Name, RR, Question, Name.encodeBuf, full Message iteration | Security/testing lead | M | **Resolved** |
| 8 | QC-NEW-03 | High | 64 | maintainability | sendQuery() triple duplication: ~50 lines of identical UDP socket+timeout+sendto+recvfrom logic copied verbatim in 3 files | stub.zig, recursive.zig, udp.zig | `stub.zig:198-246`, `recursive.zig:514-559`, `udp.zig:36-84` | -- | **Won't Do** (large refactor requiring transport architecture changes; duplication is stable and well-tested) | Transport maintainer | M | **Won't Do** |
| 9 | QC-NEW-01 | **Resolved** | 64 | architecture | `acquire()` returns pointer into ArrayList backing array; dangling after realloc/swapRemove | connection_pool.zig | `connection_pool.zig:251,291` | -- | Return ConnectionHandle (value type with generation-based lookup) | Transport maintainer | M | **Resolved** |
| 10 | MEM-01 | High | 60 | architecture | `initWithServer` allocates ServerAddress slice never freed; `deinit` is no-op. Memory leak every call. | stub.zig | `src/stub.zig:109-123` | [#186](https://gitlab.com/devnw/zig/dns/-/issues/186) | Add `owns_servers: bool` flag; free in deinit when true | Resolver maintainer | S | **Resolved** |
| 11 | EH-08 | High | 60 | architecture | `@intCast` on time deltas panics on NTP clock regression; 6+ sites across happy_eyeballs, connection_pool, logging, zone_transfer | happy_eyeballs.zig, connection_pool.zig, logging.zig, zone_transfer.zig | `happy_eyeballs.zig:199,239`, `connection_pool.zig:123,128`, `logging.zig:391`, `zone_transfer.zig:317,329,398,413` | [#192](https://gitlab.com/devnw/zig/dns/-/issues/192) | All 6+ sites now use `@max(0, delta)` saturating subtraction | Transport/Resolver maintainer | S | **Resolved** |
| 12 | QC-02 | Critical | 60 | architecture | ConnectionPool.acquire mutex race: defer lock/unlock dance leaves lines 278-286 unprotected | connection_pool.zig | `connection_pool.zig:247-287` | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | Replace `defer self.mutex.lock()` with explicit `self.mutex.lock()` before mutations | Transport maintainer | S | **Resolved** |
| 13 | QC-04 | Critical | 60 | architecture | Infinite loop in PipelinedBatch.execute: `continue` targets inner while, not outer for | connection_pool.zig | `connection_pool.zig:468,490` | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | Add `outer:` label to for loop, use `continue :outer` | Transport maintainer | S | **Resolved** |
| 14 | QC-01 | Critical | 60 | api-contract | `parseSvcbIpv4Hint`/`parseSvcbIpv6Hint` return slices to stack-local arrays (UB) | record.zig | `src/record.zig:601-630` | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | Accept allocator parameter, return owned slice | record.zig maintainer | S | **Closed** |
| 15 | QH-06 | High | 48 | maintainability | Missing `error.InProgress` in stub.zig connectWithTimeout | stub.zig | `stub.zig:294-297` | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | Added `error.ConnectionPending` to switch | Resolver maintainer | S | **Resolved** |
| 16 | QH-NEW-01 | High | 48 | api-contract | convenience.zig lookupA/lookupAAAA/lookup were empty stubs returning empty results | convenience.zig | `src/resolver/convenience.zig:194-226` | Commit 6d42d51 | Returns `error.NotImplemented` so callers get explicit signal | Convenience module maintainer | S | **Resolved** |
| 17 | QH-NEW-02 | High | 48 | tests | resolveIterative has zero direct test coverage; 219 lines, deepest nesting, most complex control flow in recursive resolver | recursive.zig | `src/recursive.zig:188-406` -- no test matches pattern `test.*resolveIterative` | -- | **Won't Do** (requires mock DNS transport infrastructure; cross-ref GAP-0045) | Resolver maintainer | L | **Won't Do** |
| 18 | TC-01 | Medium | 48 | tests | resolveIterative zero integration test coverage for 220-line core resolution function (deep review confirmation of QH-NEW-02) | recursive.zig | `src/recursive.zig:188-406` | [#190](https://gitlab.com/devnw/zig/dns/-/issues/190) | **Won't Do** -- requires mock DNS transport infrastructure (cross-ref GAP-0045, QH-NEW-02) | Resolver maintainer | L | **Won't Do** |
| 19 | QH-03 | High | 48 | api-contract | `IPv4.format()` returns `[15]u8` with undefined trailing bytes | convenience.zig | `src/resolver/convenience.zig:34-43` | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | Return struct with buf+len, or zero-fill buffer | Convenience module maintainer | S | **Closed** |
| 20 | QC-NEW-02 | **Resolved** | 48 | architecture | TOCTOU in connection limit: countServerConnections check races with createConnection | connection_pool.zig | `connection_pool.zig:268-296` | -- | Re-check countServerConnections after re-acquiring mutex | Transport maintainer | S | **Resolved** |
| 21 | QM-07 | **Resolved** | 48 | maintainability | ~~3x duplicate I/O helpers: connectWithTimeout, writeAllWithTimeout, readWithTimeout, readExactWithTimeout~~ | stub.zig, tcp.zig, connection_pool.zig | Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | Resolved: shared io.zig module with 4 tests | Transport maintainer | M | **Resolved** |
| 22 | QM-11 | Medium | 48 | perf | PooledTcpTransport.query calls connect on every query despite connection pooling | connection_pool.zig | `connection_pool.zig:537` | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | Track connected state in PooledConnection or connect in acquire() | Transport maintainer | S | **Resolved** |
| 23 | QS-NEW-01 | Medium | 45 | maintainability | responseMatchesQuery duplicated in stub.zig and recursive.zig (~20 lines) | stub.zig, recursive.zig | `src/stub.zig:132-151` and `src/recursive.zig:749-768` | -- | **Won't Do** (low-risk duplication; function is stable and small) | Resolver maintainer | S | **Won't Do** |
| 24 | RE-05 | Medium | 40 | architecture | rdataOffset pointer arithmetic has no runtime safety check; relies on aliasing invariant that `self.rdata.ptr` points into `full_message` | record.zig | `src/record.zig:77-79` -- bounds check added; returns error on invariant violation | -- | Added bounds check and error return on violation | record.zig maintainer | S | **Resolved** |
| 25 | QM-NEW-02 | Medium | 36 | architecture | ResolveResult defined twice with incompatible shapes: client.zig has `addresses: []const []const u8` + `from_cache: bool`; recursive.zig has `status: ResolveStatus` + `answer: ?[]u8` + `from_cache: bool` | client.zig, recursive.zig | `src/client.zig:318-332`, `src/recursive.zig:835-844` | -- | Unify into single type or rename to avoid confusion; client could wrap recursive result | Resolver maintainer | S | **Won't Do** (large refactor; different shapes serve different layers) |
| 26 | QM-NEW-03 | Medium | 36 | api-contract | Cache hit path in Client.resolve only formats A and AAAA records; MX, SRV, TXT, NS, PTR cache hits silently return empty results | client.zig | `src/client.zig` -- `formatCachedRdata` added covering 9 record types | -- | Added `formatCachedRdata` for A, AAAA, MX, SRV, TXT, PTR, NS, SOA, CNAME | Client maintainer | M | **Resolved** |
| 27 | QR-01 | Medium | 36 | maintainability | Forward-pointer security logic triplicated in LabelIterator methods next(), nextOrStop(), nextForEql() -- 3 copies of ~25 identical lines; future security fix risks partial application | name.zig | `src/name.zig:98` -- `followPointer()` helper extracted; used by all three methods | -- | Extracted `followPointer()` helper; ~75 lines deduplicated | name.zig maintainer | S | **Resolved** |
| 28 | AC-02 | Medium | 36 | architecture | client.lookupMX leaks exchange strings on error -- errdefer only calls `results.deinit()` | client.zig | `src/client.zig` -- errdefer now frees exchange strings before deinit | -- | Added `errdefer { for (results.items) \|mx\| self.allocator.free(mx.exchange); results.deinit(self.allocator); }` | Client maintainer | S | **Resolved** |
| 28 | QM-03 | Medium | 36 | readability | `resolveIterative` is 219 lines with 9 levels of nesting (was 171 at QM-03 filing, 208 at Phase 2, now 219) | recursive.zig | `src/recursive.zig:188-406` | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | **Won't Do** -- large refactor of critical resolution path; risks introducing regressions in well-tested code | Resolver maintainer | M | **Won't Do** |
| 26 | RD-01 | Medium | 30 | maintainability | name.zig compression pointer security checks repeated 7+ times across toString/toStringBuf/labelCount/eql/parent; no shared LabelIterator | name.zig | `src/name.zig` -- LabelIterator extracted and used by 5 functions | [#188](https://gitlab.com/devnw/zig/dns/-/issues/188) | Extracted `LabelIterator` struct; used by toString, toStringBuf, labelCount, eql, parent | name.zig maintainer | M | **Resolved** |
| 27 | CI-04 | Medium | 30 | tests | cmd/zdig.zig: 1051 lines, zero tests; security-sensitive escapeJsonString and addressMatches untested | zdig.zig | `cmd/zdig.zig` -- 16 tests added for escapeJsonString and addressMatches | [#196](https://gitlab.com/devnw/zig/dns/-/issues/196) | 16 unit tests added covering escapeJsonString and addressMatches | CLI maintainer | M | **Resolved** |
| 28 | QS-NEW-04 | Medium | 30 | ci-cd | CI downloads+installs Zig in every job; binary directory not cached | .gitlab-ci.yml | `.gitlab-ci.yml:25-28` | -- | **Won't Do** (CI infrastructure improvement; not a code quality issue) | CI/CD maintainer | S | **Won't Do** |
| 29 | QS-NEW-06 | Medium | 30 | ci-cd | No code coverage measurement tool or CI integration; no coverage gates in pipeline | .gitlab-ci.yml, build.zig | No coverage integration | -- | **Won't Do** (CI infrastructure improvement; requires Zig coverage tooling maturation) | CI/CD maintainer | M | **Won't Do** |
| 30 | DUP-02 | Medium | 24 | maintainability | responseMatchesQuery duplicated identically (~20 lines) in stub.zig:132-151 and recursive.zig:768-787 | stub.zig, recursive.zig | `src/stub.zig:140` made `pub`; `src/recursive.zig` imports via `StubResolver.responseMatchesQuery` | [#187](https://gitlab.com/devnw/zig/dns/-/issues/187) | Made stub.zig canonical; recursive.zig imports it (cross-ref QS-NEW-01) | Resolver maintainer | S | **Resolved** |
| 31 | RM-04 | Medium | 24 | maintainability | Duplicate MXRecord/MxRecord types: `client.zig:337` defines `MXRecord` (uppercase X) and `convenience.zig:87` defines `MxRecord` (lowercase x) with identical shape | client.zig, convenience.zig | `src/client.zig` -- MxRecord consolidated; duplicate removed | -- | Consolidated MxRecord type; removed duplicate | Resolver maintainer | S | **Resolved** |
| 32 | RM-07 | Medium | 24 | maintainability | IPv4 formatting pattern `"{d}.{d}.{d}.{d}"` repeated inline in 4+ places | record.zig, recursive.zig, client.zig, convenience.zig | Multiple sites | -- | **Won't Do** (low-risk repetition; format string is idiomatic and unlikely to diverge) | Any contributor | S | **Won't Do** |
| 33 | QM-NEW-01 | Medium | 24 | maintainability | Duplicate QueryType enum in convenience.zig mirrors types.Type | convenience.zig, types.zig | `src/resolver/convenience.zig` -- QueryType removed; replaced with `types.Type` | -- | Removed duplicate QueryType; now imports and uses types.Type directly | Convenience module maintainer | S | **Resolved** |
| 34 | QM-NEW-05 | Medium | 24 | architecture | resolveNsAddress catches all errors (including OOM) as null via `catch return null` | recursive.zig | `src/recursive.zig` -- OOM now propagated; other errors return null | -- | `catch \|err\| switch (err) { error.OutOfMemory => return err, else => return null }` | Resolver maintainer | S | **Resolved** |
| 35 | QR-02 | Low | 24 | maintainability | max_spurious_discards constant and entire UDP receive loop (~35 lines) triplicated across recursive.zig, stub.zig, udp.zig | stub.zig, recursive.zig, udp.zig | `src/types.zig:253` -- `max_spurious_discards` extracted to shared module; imported by 3 files | -- | `max_spurious_discards` and `SpuriousDiscardCounter` extracted to `types.zig` | Transport maintainer | S | **Resolved** |
| 36 | QS-NEW-08 | Medium | 20 | deps | Spice dependency pinned to main branch tarball; no semver tag | build.zig.zon | `build.zig.zon:29` | -- | **Won't Do** (upstream concern; hash pinning provides integrity; cross-ref GAP-0047, SEC-C14/C31) | Project maintainer | S | **Won't Do** |
| 37 | QR-R02 | Medium | 20 | tests | SEC-AUDIT-02 tests only verify constant bounds (>0, <=10000), not actual discard enforcement behavior; no test sends spurious packets | recursive.zig, stub.zig, udp.zig | `src/types.zig:289` -- `SpuriousDiscardCounter` struct with 3 new tests verifying increment, limit enforcement, and reset | -- | `SpuriousDiscardCounter` struct in `types.zig` with 3 tests; all 3 discard loops refactored to use it | Transport maintainer | M | **Resolved** |
| 38 | QS-NEW-05 | Medium | 18 | architecture | stub.zig:170 swallows OOM errors via bare `catch` | stub.zig | `src/stub.zig` -- OOM now propagated via `catch \|err\| switch (err) { error.OutOfMemory => return err, else => continue }` | -- | Propagate OOM from bare catch in stub.zig | Resolver maintainer | S | **Resolved** |
| 37 | AC-03 | Medium | 18 | architecture | Cache-hit errdefer in resolve() does not free duped strings on error | client.zig | `src/client.zig` -- errdefer now frees duped strings and ArrayList backing | -- | Added `errdefer { for (results.items) \|s\| self.allocator.free(s); results.deinit(self.allocator); }` | Client maintainer | S | **Resolved** |
| 38 | DOC-01 | Medium | 18 | docs | No ownership documentation for Message.data (aliases caller's buffer); use-after-free risk | message.zig | `src/message.zig` -- ownership doc comment added to `data` field | [#198](https://gitlab.com/devnw/zig/dns/-/issues/198) | Added `///` doc comment explaining aliasing/lifetime requirements | message.zig maintainer | S | **Resolved** |
| 39 | EH-11 | Medium | 18 | architecture | zdig TCP response read loop breaks on recv==0 without validating total_read==response_len; silent truncation | zdig.zig | `cmd/zdig.zig` -- TCP truncation now returns `error.ConnectionClosed` | [#194](https://gitlab.com/devnw/zig/dns/-/issues/194) | TCP truncation now returns `error.ConnectionClosed` instead of silent truncation | CLI maintainer | S | **Resolved** |
| 40 | QL-03 | Low | 16 | readability | 12 source files exceed 800-line threshold (was 9). New: `connection_pool.zig` (1070), `parallel.zig` (881), `enhanced_metrics.zig` (879). Largest: `record.zig` (1927) | Multiple files | `record.zig:1927`, `recursive.zig:1426`, `name.zig:1345`, `connection_pool.zig:1070`, `edns.zig:973`, `tsig.zig:916`, `zone_transfer.zig:894`, `dnssec.zig:889`, `parallel.zig:881`, `enhanced_metrics.zig:879`, `zone_file.zig:863`, `sig0.zig:814` | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | **Won't Do** -- large-scale file splits across 12 files; mechanical but high churn risk for low readability gain | Project maintainer | L | **Won't Do** |
| 41 | QL-09 | Low | 16 | readability | 41 functions exceed 50-line threshold (was 30); resolveIterative at 219 lines | Multiple files | `recursive.zig:188+` (219 lines), record.zig, edns.zig, zone_transfer.zig parsers | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | **Won't Do** -- mechanical decomposition of 41 functions across codebase; high churn, low value without lint gate | Project maintainer | L | **Won't Do** |
| 42 | QR-04 | Low | 16 | readability | CNAME limits differ 2x: max_cname_chain_length=8 (recursive.zig) vs max_cname_mappings=16 (client.zig); unidirectional documentation | recursive.zig, client.zig | `src/recursive.zig:135-138` -- cross-reference comment to client.zig constants added | -- | Cross-reference comments added documenting relationship between CNAME limits | Resolver maintainer | S | **Resolved** |
| 43 | QS-NEW-03 | Low | 12 | cleanup | 4 lib.zig module exports never imported by any consumer: `convenience`, `rpz`, `config`, `cache_prefetch` | lib.zig | `src/lib.zig` -- exports documented as intentional public API with comments | -- | Documented as intentional public API (modules available for downstream consumers) | Any contributor | S | **Resolved** |
| 43 | QS-NEW-07 | Low | 12 | tests | Client tests bail on network failure; test passes vacuously in CI | client.zig | `src/client.zig:458-469` | -- | **Won't Do** (requires mock transport infrastructure; cross-ref GAP-0045) | Client maintainer | M | **Won't Do** |
| 44 | QR-05 | Low | 12 | readability | client.zig:510 uses magic number 8 for CNAME depth despite named constants existing (max_cname_chain_length=8 in recursive.zig, max_cname_mappings=16 in client.zig) | client.zig | `src/client.zig` -- magic number 8 replaced with `max_cname_depth` named constant | -- | Magic number 8 replaced with `max_cname_depth` constant | Client maintainer | S | **Resolved** |
| 45 | QR-03 | Info | 12 | readability | nextForEql() pointer traversal style differs from next()/nextOrStop() without explanation; different variable names and control flow for identical logic | name.zig | `src/name.zig:98` -- style difference resolved by QR-01 `followPointer()` extraction; all three methods now share identical pointer traversal logic | -- | Resolved by QR-01: `followPointer()` extraction unified pointer traversal style | name.zig maintainer | S | **Resolved** |
| 46 | QS-NEW-02 | Low | 10 | cleanup | question.buildQuery at question.zig:102 is dead code | question.zig | `src/question.zig` -- dead code removed | -- | Deleted dead `question.buildQuery` function | Any contributor | S | **Resolved** |
| 45 | RM-08 | Low | 10 | cleanup | getMinimizedQname ignores `current_zone` parameter (dead parameter) | recursive.zig | `src/recursive.zig` -- `current_zone` parameter removed; all call sites updated | -- | Removed dead `current_zone` parameter from `getMinimizedQname` | Resolver maintainer | S | **Resolved** |
| 46 | QM-NEW-04 | Low | 16 | docs | lib.zig claimed "Zero external dependencies" but build.zig.zon declares `spice` dependency | lib.zig | `src/lib.zig:16` -- updated to `//! - Minimal dependencies (optional spice for parallelism)` | Commit 6d42d51 | Updated doc comment to accurately reflect spice dependency | Documentation maintainer | S | **Resolved** |
| 47 | QL-NEW-01 | **Resolved** | 8 | cleanup | Duplicated testSocketPair helper identical to io.zig:118-126 | connection_pool.zig | `connection_pool.zig:665-673` | -- | Make io.zig testSocketPair public; replace duplicate with const alias | Any contributor | S | **Resolved** |
| 48 | DOC-02 | Low | 8 | docs | connection_pool.zig createConnection accepts and discards server/timeout_ms params; misleading API (intentional lazy-connection design) | connection_pool.zig | `src/transports/connection_pool.zig` -- doc comment added explaining lazy-connection design | [#200](https://gitlab.com/devnw/zig/dns/-/issues/200) | Added doc comment explaining lazy-connection design | Transport maintainer | S | **Resolved** |
| 49 | QR-R01 | Info | 8 | reliability | `catch {}` on updateFamilyCache loses OOM observability; differs from recursive.zig:338 pattern which logs errors | happy_eyeballs.zig | `src/transports/happy_eyeballs.zig:212` -- `catch \|cache_err\| std.log.debug("updateFamilyCache failed: {}", .{cache_err})` | -- | `catch {}` replaced with `catch \|cache_err\| log.debug(...)` matching codebase pattern | Transport maintainer | S | **Resolved** |
| 50 | DOC-03 | Low | 8 | docs | No module-level library user guide for downstream consumers; onboarding friction | docs/ | No usage guide exists | [#201](https://gitlab.com/devnw/zig/dns/-/issues/201) | **Won't Do** -- Usage guide out of scope for gap closure | Documentation maintainer | M | **Won't Do** |
| 50 | QM-05 | **Resolved** | 36 | maintainability | ~~Silent error swallowing with `catch {}` in 5+ locations~~ | Multiple files | All catch {} sites documented or upgraded | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | Resolved | Any contributor | S | **Resolved** |
| 51 | QM-01 | **Resolved** | 36 | maintainability | ~~`parseName()` copy-pasted ~52 identical lines in tsig.zig and sig0.zig~~ | tsig.zig, sig0.zig | Extracted shared `src/security/dns_name.zig` | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | Resolved | Security module maintainer | S | **Resolved** |
| 52 | QM-09 | **Resolved** | 36 | architecture | ~~parallel.zig: 4 placeholder implementations return fabricated results~~ | parallel.zig | Real wire-format parsing; honest error status | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | Resolved | Parallel module maintainer | M | **Resolved** |
| 53 | QL-07 | **Resolved** | 32 | ci-cd | ~~No `zig fmt --check` in CI pipeline~~ | .gitlab-ci.yml | zig-format job override now includes explicit script | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | Resolved | CI/CD maintainer | S | **Resolved** |
| 54 | QM-08 | **Resolved** | 24 | cleanup | ~~Dead file `src/resolver/stub.zig`~~ | resolver/stub.zig (deleted) | File deleted | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | Resolved | Any contributor | S | **Resolved** |
| 55 | QM-10 | **Resolved** | 24 | cleanup | ~~Duplicate SOA parsing: extractSerial duplicates parseSoaRdata~~ | zone_transfer.zig | `extractSerial` now delegates to `parseSoaRdata` | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | Resolved | Resolver maintainer | S | **Resolved** |
| 56 | QM-02 | **Resolved** | 24 | maintainability | ~~Duplicated root server definitions~~ | recursive.zig | Deleted `src/resolver/recursive.zig` | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | Resolved | Resolver maintainer | S | **Resolved** |
| 57 | QM-04 | **Resolved** | 24 | architecture | ~~18 modules lack API boundary docs~~ | build.zig | Added API boundary comments | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | Resolved | Project maintainer | S | **Resolved** |
| 58 | QM-06 | **Resolved** | 24 | docs | ~~ARCHITECTURE.md missing 60% of modules~~ | docs/ARCHITECTURE.md | Rewritten with all modules documented | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | Resolved | Documentation lead | M | **Resolved** |
| 59 | QL-04 | **Resolved** | 16 | docs | ~~No doc comment on rdata-offset invariant~~ | record.zig | Doc comments added | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | Resolved | Any contributor | S | **Resolved** |
| 60 | QL-05 | **Resolved** | 16 | tests | ~~Mutable statics in MockTlsBackend~~ | dot.zig | Moved to per-instance state | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | Resolved | Any contributor | S | **Resolved** |
| 61 | QL-06 | **Resolved** | 12 | readability | ~~Magic number 6 for SOA record type~~ | zone_transfer.zig | Replaced with `soa_rtype` named constant | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | Resolved | Any contributor | S | **Resolved** |
| 62 | QL-08 | **Resolved** | 12 | docs | ~~ARCHITECTURE.md references deleted/dead files~~ | docs/ARCHITECTURE.md | Stale references removed | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | Resolved | Documentation maintainer | S | **Resolved** |
| 63 | QL-01 | **Resolved** | 12 | cleanup | ~~7 identical @intFromPtr blocks~~ | record.zig | Extracted rdataOffset() helper | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | Resolved | Any contributor | S | **Resolved** |
| 64 | QL-02 | Low | 8 | cleanup | `verifyCase0x20()` reimplements `std.mem.eql` | name.zig | `src/name.zig:451-462` | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | Replace with std.mem.eql | Any contributor | S | **Resolved** |
| -- | DG-01 | Info | -- | docs | resolveIterative (219 lines) has no function-level doc comment | recursive.zig | `src/recursive.zig` -- doc comment added describing iterative resolution algorithm | -- | Added `///` doc comment to resolveIterative | Resolver maintainer | S | **Resolved** |
| -- | DG-02 | Info | -- | docs | ResolutionState struct has no doc comment explaining field semantics | recursive.zig | `src/recursive.zig` -- doc comments added to ResolutionState and fields | -- | Added `///` doc comments to ResolutionState and each field | Resolver maintainer | S | **Resolved** |
| -- | DG-03 | Info | -- | docs | MXRecord ownership semantics undocumented | client.zig | `src/client.zig` -- ownership doc comment added to MXRecord/MxRecord | -- | Added `/// Caller owns the returned slice and each .exchange string` | Client maintainer | S | **Resolved** |
| -- | DG-04 | Info | -- | docs | rdataOffset invariant only documented in code comment, not in public API doc | record.zig | `src/record.zig` -- `///` doc added to ResourceRecord explaining rdata aliasing | -- | Added public API doc explaining rdata slices alias into original message buffer | record.zig maintainer | S | **Resolved** |
| -- | DG-05 | Info | -- | docs | getMinimizedQname has no doc comment (RFC 9156) | recursive.zig | `src/recursive.zig` -- doc comment added referencing RFC 9156 | -- | Added doc comment referencing RFC 9156 and depth-based label minimization | Resolver maintainer | S | **Resolved** |
| -- | DG-06 | Info | -- | docs | Cache formatting logic in resolve() has no comment explaining supported types | client.zig | `src/client.zig` -- comment added; QM-NEW-03 resolved (9 types now supported) | -- | Comment added; all cacheable types now formatted via `formatCachedRdata` | Client maintainer | S | **Resolved** |
| 65 | QA-AUDIT-01 | Critical | 125 | architecture | DNSSEC validation module compile-time API mismatches: `parseNSEC`/`parseRRSIG` missing `full_message`, `Name` vs `[]const u8` type mismatches, `next_name` field doesn't exist | dnssec.zig | `src/resolver/dnssec.zig` -- 11 call site fixes; 7 new tests | -- | 11 code fixes; 7 new integration tests; all 479 tests pass (cross-ref GAP-0057) | Security/DNSSEC maintainer | L | **Resolved** |
| 66 | QA-AUDIT-02 | Medium | 36 | api-contract | `Client.resolve()` silently returns `NoAnswer` for non-A/AAAA queries | client.zig | `src/client.zig:169-171` -- UnsupportedRecordType guard | -- | error.UnsupportedRecordType guard added; 1 new test (cross-ref GAP-0060) | Client maintainer | M | **Resolved** |
| 67 | QA-AUDIT-03 | Medium | 36 | docs | `Zone.getRecords` misleading "not a copy" comment; heap-allocates with no free path | zone_file.zig | `src/zone_file.zig` -- doc comment fixed; return type ![]const ResourceRecord | -- | Doc comment corrected; return type clarified; 1 new test | Zone file maintainer | S | **Resolved** |
| 68 | QA-AUDIT-04 | High | 48 | architecture | fd leak in happy_eyeballs.zig on OOM from `updateFamilyCache`: winning fd has `state=.connected` so `defer` cleanup skips it, but `try` propagates error before returning fd to caller | happy_eyeballs.zig | `src/transports/happy_eyeballs.zig:212` -- updateFamilyCache uses catch {} | -- | updateFamilyCache uses `catch {}` for best-effort cache update; fd not leaked on OOM; 1 new test | Transport maintainer | S | **Resolved** |
| 69 | QA-AUDIT-05 | Medium | 24 | cleanup | `RecursiveConfig.max_depth` (default 32) defined and tested but never referenced in resolution logic -- dead config field | recursive.zig | `src/recursive.zig:399,439` -- max_depth wired into resolveIterative | -- | max_depth now wired into resolveIterative depth check; 1 new test | Resolver maintainer | S | **Resolved** |
| 70 | QA-AUDIT-06 | Medium | 18 | readability | CNAME chain limit uses magic number `8` in recursive.zig; client.zig uses named `max_cname_mappings = 16` for its own limit | recursive.zig | `src/recursive.zig:136` -- max_cname_chain_length constant | -- | Extracted `max_cname_chain_length` named constant; existing test updated | Resolver maintainer | S | **Resolved** |
| 71 | QA-AUDIT-07 | Medium | 16 | maintainability | `buildOption` method duplicated 6x across EDNS option types with identical 4-byte header + data serialization pattern | edns.zig | `src/edns.zig:255` -- serializeEdnsOption alias | -- | Extracted `serializeEdnsOption` shared helper; 6 buildOption methods delegate to it | edns.zig maintainer | S | **Resolved** |
| 72 | QR-NEW-01 | Low | 16 | architecture | `extractWireLabels` comptime `max_labels` param removed; `LabelList` fixed at 128 | dnssec.zig | `src/resolver/dnssec.zig` -- comptime param removed | -- | Comptime param removed; LabelList fixed at 128 | DNSSEC maintainer | S | **Resolved** |
| 73 | QR-NEW-02 | Low | 8 | tests | Edge-case tests added for `compareDnsNames`: empty slice, truncated wire name, missing root terminator | dnssec.zig | `src/resolver/dnssec.zig` -- 3 new tests | -- | 3 tests added for empty, truncated, and missing root inputs | DNSSEC maintainer | S | **Resolved** |
| 74 | QR-NEW-03 | Info | 4 | architecture | `base32hexEncode` hardcoded to 20-byte `*const [20]u8` input; not generic | dnssec.zig | `src/resolver/dnssec.zig:993` -- SHA-1 is the only NSEC3 hash algorithm (RFC 5155) | -- | Won't Do: acceptable for current scope; SHA-1 is the only NSEC3 hash algorithm | DNSSEC maintainer | S | **Won't Do** |
| 75 | QR-NEW-04 | Info | 4 | docs | SEC-AUDIT-09 doc comment duplicated verbatim across stub.zig and recursive.zig | stub.zig, recursive.zig | Intentional per-file documentation pattern; not a code quality defect | -- | Won't Do: intentional per-file self-documentation pattern | Any contributor | S | **Won't Do** |

## Findings by Category

### Architecture (23 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-03 | Critical | 80 | Partial write data loss (3 files, 6 sites) | [#152](https://gitlab.com/devnw/zig/dns/-/issues/152) | **Resolved** |
| QH-02 | High | 80 | Referral NS servers never assigned | [#91](https://gitlab.com/devnw/zig/dns/-/issues/91) | **Resolved** |
| QH-07 | High | 64 | Blocking reads without timeout in PipelinedBatch | [#163](https://gitlab.com/devnw/zig/dns/-/issues/163) | **Resolved** |
| QH-08 | High | 64 | Zone transfer short read on length prefix | [#166](https://gitlab.com/devnw/zig/dns/-/issues/166) | **Resolved** |
| QH-01 | High | 64 | CNAME continue targets wrong loop | [#86](https://gitlab.com/devnw/zig/dns/-/issues/86) | **Resolved** |
| MEM-01 | High | 60 | initWithServer allocates ServerAddress slice never freed; deinit is no-op | [#186](https://gitlab.com/devnw/zig/dns/-/issues/186) | **Resolved** |
| EH-08 | High | 60 | @intCast on time deltas panics on NTP clock regression; 6+ sites | [#192](https://gitlab.com/devnw/zig/dns/-/issues/192) | **Resolved** |
| QC-02 | Critical | 60 | ConnectionPool.acquire mutex race | [#151](https://gitlab.com/devnw/zig/dns/-/issues/151) | **Resolved** |
| QC-04 | Critical | 60 | PipelinedBatch.execute infinite loop | [#156](https://gitlab.com/devnw/zig/dns/-/issues/156) | **Resolved** |
| RE-05 | Medium | 40 | rdataOffset pointer arithmetic -- bounds check added | -- | **Resolved** |
| QM-09 | **Resolved** | 36 | parallel.zig placeholder implementations | [#177](https://gitlab.com/devnw/zig/dns/-/issues/177) | **Resolved** |
| AC-02 | Medium | 36 | client.lookupMX leaks exchange strings on error -- errdefer fixed | -- | **Resolved** |
| QM-04 | **Resolved** | 24 | 18 modules lack API boundary docs | [#113](https://gitlab.com/devnw/zig/dns/-/issues/113) | **Resolved** |
| QC-NEW-01 | **Resolved** | 64 | acquire() returns dangling pointer into ArrayList | -- | **Resolved** |
| QC-NEW-02 | **Resolved** | 48 | TOCTOU in connection limit check | -- | **Resolved** |
| QM-NEW-02 | Medium | 36 | ResolveResult defined twice with incompatible shapes | -- | **Won't Do** |
| QM-NEW-05 | Medium | 24 | resolveNsAddress OOM now propagated | -- | **Resolved** |
| EH-11 | Medium | 18 | zdig TCP read loop silent truncation on connection close | [#194](https://gitlab.com/devnw/zig/dns/-/issues/194) | **Resolved** |
| AC-03 | Medium | 18 | Cache-hit errdefer in resolve() -- errdefer fixed | -- | **Resolved** |
| QS-NEW-05 | Medium | 18 | stub.zig OOM now propagated | -- | **Resolved** |
| QA-AUDIT-04 | High | 48 | fd leak in happy_eyeballs.zig on OOM from updateFamilyCache -- catch {} for best-effort | -- | **Resolved** |
| QR-NEW-01 | Low | 16 | extractWireLabels comptime max_labels removed; LabelList fixed at 128 | -- | **Resolved** |
| QR-NEW-03 | Info | 4 | base32hexEncode hardcoded to 20-byte input; acceptable for current NSEC3/SHA-1 scope | -- | **Won't Do** |

### API Contract (4 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-01 | Critical | 60 | SVCB hint parsers return dangling pointers | [#83](https://gitlab.com/devnw/zig/dns/-/issues/83) | **Closed** |
| QH-NEW-01 | High | 48 | convenience.zig lookupA/lookupAAAA/lookup now return error.NotImplemented | Commit 6d42d51 | **Resolved** |
| QH-03 | High | 48 | IPv4.format() undefined trailing bytes | [#92](https://gitlab.com/devnw/zig/dns/-/issues/92) | **Closed** |
| QM-NEW-03 | Medium | 36 | Cache formats 9 record types on cache hit (was A/AAAA only) | -- | **Resolved** |

### Performance (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-04 | High | 64 | Name.eql() mmap syscalls | [#95](https://gitlab.com/devnw/zig/dns/-/issues/95) | **Resolved** |
| QM-11 | Medium | 48 | PooledTcpTransport.query unnecessary connect per query | [#180](https://gitlab.com/devnw/zig/dns/-/issues/180) | **Resolved** |

### Maintainability (15 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QC-NEW-03 | High | 64 | sendQuery() triple duplication (~150 lines) | -- | **Won't Do** |
| QH-06 | High | 48 | Missing error.InProgress in stub.zig | [#160](https://gitlab.com/devnw/zig/dns/-/issues/160) | **Resolved** |
| QR-01 | Medium | 36 | Forward-pointer security logic triplicated in LabelIterator next/nextOrStop/nextForEql (~25 lines x3) -- `followPointer()` extracted | -- | **Resolved** |
| QS-NEW-01 | Medium | 45 | responseMatchesQuery duplicated (~20 lines) | -- | **Won't Do** |
| RD-01 | Medium | 30 | name.zig compression pointer checks -- LabelIterator extracted; used by 5 functions | [#188](https://gitlab.com/devnw/zig/dns/-/issues/188) | **Resolved** |
| DUP-02 | **Resolved** | 24 | ~~responseMatchesQuery duplicated in stub.zig and recursive.zig~~ Made stub.zig canonical; recursive.zig imports it | [#187](https://gitlab.com/devnw/zig/dns/-/issues/187) | **Resolved** |
| QM-07 | **Resolved** | 48 | ~~3x duplicate I/O helpers (~240 lines)~~ Extracted shared `src/transports/io.zig` | [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) | **Resolved** |
| QM-01 | **Resolved** | 36 | ~~parseName() duplicated in tsig/sig0~~ | [#102](https://gitlab.com/devnw/zig/dns/-/issues/102) | **Resolved** |
| QM-05 | **Resolved** | 36 | ~~Silent error swallowing (catch {})~~ | [#117](https://gitlab.com/devnw/zig/dns/-/issues/117) | **Resolved** |
| RM-04 | Medium | 24 | Duplicate MXRecord/MxRecord -- consolidated | -- | **Resolved** |
| RM-07 | Medium | 24 | IPv4 formatting pattern repeated inline in 4+ places | -- | **Won't Do** |
| QM-NEW-01 | Medium | 24 | Duplicate QueryType removed; uses types.Type | -- | **Resolved** |
| QM-02 | **Resolved** | 24 | ~~Duplicated root server definitions~~ | [#106](https://gitlab.com/devnw/zig/dns/-/issues/106) | **Resolved** |
| QA-AUDIT-07 | Medium | 16 | buildOption 6x duplication in edns.zig -- serializeEdnsOption extracted | -- | **Resolved** |
| QR-02 | Low | 24 | max_spurious_discards extracted to types.zig; imported by 3 files | -- | **Resolved** |

### Tests (8 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QH-05 | High | 64 | Zero fuzz testing for wire parsers | [#98](https://gitlab.com/devnw/zig/dns/-/issues/98) | **Resolved** |
| QH-NEW-02 | High | 48 | resolveIterative (219 lines) has zero direct test coverage | -- | **Won't Do** |
| TC-01 | Medium | 48 | resolveIterative zero integration test coverage (deep review confirmation of QH-NEW-02) | [#190](https://gitlab.com/devnw/zig/dns/-/issues/190) | **Won't Do** |
| CI-04 | Medium | 30 | cmd/zdig.zig: 16 tests added for escapeJsonString and addressMatches | [#196](https://gitlab.com/devnw/zig/dns/-/issues/196) | **Resolved** |
| QR-R02 | Medium | 20 | SpuriousDiscardCounter struct with 3 tests verifying discard enforcement | -- | **Resolved** |
| QS-NEW-07 | Low | 12 | Client tests bail on network failure | -- | **Won't Do** |
| QL-05 | **Resolved** | 16 | Mutable statics in MockTlsBackend | [#181](https://gitlab.com/devnw/zig/dns/-/issues/181) | **Resolved** |
| QR-NEW-02 | Low | 8 | Edge-case tests added for compareDnsNames (empty, truncated, missing root) -- 3 tests | -- | **Resolved** |

### Readability (9 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-03 | Medium | 36 | resolveIterative 219 lines / 9 nesting levels (was 208) | [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) | **Won't Do** |
| QL-07 | **Resolved** | 32 | ~~No zig fmt check in CI~~ | [#183](https://gitlab.com/devnw/zig/dns/-/issues/183) | **Resolved** |
| QL-03 | Low | 16 | 12 files over 800 lines (was 9) | [#126](https://gitlab.com/devnw/zig/dns/-/issues/126) | **Won't Do** |
| QL-09 | Low | 16 | 41 functions exceed 50 lines (was 30) | [#185](https://gitlab.com/devnw/zig/dns/-/issues/185) | **Won't Do** |
| QL-06 | **Resolved** | 12 | ~~Magic number 6 for SOA~~ | [#182](https://gitlab.com/devnw/zig/dns/-/issues/182) | **Resolved** |
| QA-AUDIT-06 | Medium | 18 | CNAME chain limit magic number `8` -- max_cname_chain_length extracted | -- | **Resolved** |
| QR-04 | Low | 16 | CNAME limits cross-reference comments added | -- | **Resolved** |
| QR-05 | Low | 12 | Magic number 8 replaced with `max_cname_depth` constant | -- | **Resolved** |
| QR-03 | Info | 12 | Style difference resolved by QR-01 `followPointer()` extraction | -- | **Resolved** |

### CI/CD (2 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QS-NEW-04 | Medium | 30 | CI Zig install not cached | -- | **Won't Do** |
| QS-NEW-06 | Medium | 30 | No code coverage measurement or CI integration | -- | **Won't Do** |

### Dependencies (1 finding)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QS-NEW-08 | Medium | 20 | Spice dependency pinned to main branch tarball | -- | **Won't Do** |

### Reliability (1 finding)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QR-R01 | Info | 8 | `catch {}` replaced with `catch \|err\| log.debug(...)` in happy_eyeballs.zig | -- | **Resolved** |

### Cleanup (9 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| QM-08 | **Resolved** | 24 | ~~Dead file src/resolver/stub.zig~~ | [#173](https://gitlab.com/devnw/zig/dns/-/issues/173) | **Resolved** |
| QM-10 | **Resolved** | 24 | ~~Duplicate SOA parsing in zone_transfer.zig~~ | [#179](https://gitlab.com/devnw/zig/dns/-/issues/179) | **Resolved** |
| QS-NEW-03 | Low | 12 | 4 lib.zig module exports -- documented as intentional | -- | **Resolved** |
| QS-NEW-02 | Low | 10 | question.buildQuery dead code deleted | -- | **Resolved** |
| RM-08 | Low | 10 | getMinimizedQname dead parameter removed | -- | **Resolved** |
| QL-01 | **Resolved** | 12 | ~~7 identical @intFromPtr blocks~~ | [#121](https://gitlab.com/devnw/zig/dns/-/issues/121) | **Resolved** |
| QL-02 | Low | 8 | verifyCase0x20 reimplements std.mem.eql | [#123](https://gitlab.com/devnw/zig/dns/-/issues/123) | **Resolved** |
| QL-NEW-01 | **Resolved** | 8 | Duplicated testSocketPair in connection_pool.zig | -- | **Resolved** |
| QA-AUDIT-05 | Medium | 24 | RecursiveConfig.max_depth wired into resolveIterative depth check | -- | **Resolved** |

### Documentation (14 findings)

| ID | Severity | PriorityScore | Finding | Issue | Status |
|----|----------|---------------|---------|-------|--------|
| DOC-01 | Medium | 18 | Ownership documentation added to Message.data | [#198](https://gitlab.com/devnw/zig/dns/-/issues/198) | **Resolved** |
| QM-06 | **Resolved** | 24 | ~~ARCHITECTURE.md missing 60% of modules~~ | [#119](https://gitlab.com/devnw/zig/dns/-/issues/119) | **Resolved** |
| QM-NEW-04 | Low | 16 | lib.zig updated: "Minimal dependencies (optional spice for parallelism)" | Commit 6d42d51 | **Resolved** |
| QL-04 | **Resolved** | 16 | ~~No doc comment on rdata-offset invariant~~ | [#127](https://gitlab.com/devnw/zig/dns/-/issues/127) | **Resolved** |
| QL-08 | **Resolved** | 12 | ~~ARCHITECTURE.md references deleted/dead files~~ | [#184](https://gitlab.com/devnw/zig/dns/-/issues/184) | **Resolved** |
| DOC-02 | Low | 8 | Lazy-connection doc comment added to createConnection | [#200](https://gitlab.com/devnw/zig/dns/-/issues/200) | **Resolved** |
| DOC-03 | Low | 8 | No module-level library user guide for downstream consumers | [#201](https://gitlab.com/devnw/zig/dns/-/issues/201) | **Won't Do** |
| DG-01 | Info | -- | resolveIterative doc comment added | -- | **Resolved** |
| DG-02 | Info | -- | ResolutionState doc comments added | -- | **Resolved** |
| DG-03 | Info | -- | MXRecord ownership doc added | -- | **Resolved** |
| DG-04 | Info | -- | rdataOffset invariant public API doc added | -- | **Resolved** |
| DG-05 | Info | -- | getMinimizedQname doc comment added (RFC 9156) | -- | **Resolved** |
| DG-06 | Info | -- | Cache formatting documented (9 types supported) | -- | **Resolved** |
| QR-NEW-04 | Info | 4 | SEC-AUDIT-09 doc comment duplicated verbatim across stub.zig and recursive.zig -- intentional | -- | **Won't Do** |

## Remediation Roadmap

### Quick Wins (< 1 day)

Audit deep review findings (2026-03-25) -- all addressed:

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QR-NEW-01 | 16 | LabelList comptime param removed; fixed at 128 | S | **Resolved** |
| QR-NEW-02 | 8 | 3 edge-case tests added for compareDnsNames (empty, truncated, missing root) | S | **Resolved** |
| QR-NEW-03 | 4 | base32hexEncode hardcoded to 20-byte input -- acceptable for current NSEC3/SHA-1 scope | S | **Won't Do** |
| QR-NEW-04 | 4 | SEC-AUDIT-09 doc comment duplication -- intentional per-file pattern; no action needed | S | **Won't Do** |

Quick wins from deep review round 2 -- all resolved (2026-03-25):

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QR-01 | 36 | Extract private followPointer() helper in LabelIterator (3 copies of ~25 lines) | S | **Resolved** |
| QR-02 | 24 | Extract max_spurious_discards + SpuriousDiscardCounter to types.zig | S | **Resolved** |
| QR-R02 | 20 | SpuriousDiscardCounter struct with 3 new tests; discard loops refactored | M | **Resolved** |
| QR-04 | 16 | Add cross-reference comment in client.zig for CNAME limit relationship | S | **Resolved** |
| QR-05 | 12 | Replace magic number 8 with max_cname_depth constant in client.zig | S | **Resolved** |
| QR-03 | 12 | Style difference resolved by QR-01 followPointer() extraction | S | **Resolved** |
| QR-R01 | 8 | catch {} replaced with debug log in happy_eyeballs.zig | S | **Resolved** |

Previously resolved quick wins from deep audit (2026-03-24):

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| MEM-01 | 60 | Add `owns_servers` flag to stub.zig; free in deinit when true | S | **Resolved** |
| EH-08 | 60 | Replace `@intCast(now - then)` with `@max(0, delta)` at 6+ sites | S | **Resolved** |
| DOC-01 | 18 | Add ownership doc comment to Message.data explaining aliasing | S | **Resolved** |
| EH-11 | 18 | TCP truncation now returns error.ConnectionClosed | S | **Resolved** |
| DUP-02 | 24 | Extract responseMatchesQuery to shared module | S | **Resolved** |
| DOC-02 | 8 | Add doc comment to createConnection explaining lazy-connection design | S | **Resolved** |

Previously resolved or Won't Do quick wins:

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| AC-02 | 36 | Fix errdefer in lookupMX to free exchange strings | S | **Resolved** |
| AC-03 | 18 | Fix errdefer in resolve() cache-hit path to free duped strings | S | **Resolved** |
| QS-NEW-05 | 18 | Propagate OOM from bare catch in stub.zig | S | **Resolved** |
| QM-NEW-01 | 24 | Remove duplicate QueryType; import types.Type | S | **Resolved** |
| QM-NEW-05 | 24 | Propagate OOM from resolveNsAddress | S | **Resolved** |
| RM-04 | 24 | Consolidate MXRecord/MxRecord into one type | S | **Resolved** |
| RE-05 | 40 | Add bounds check to rdataOffset pointer arithmetic | S | **Resolved** |
| QS-NEW-02 | 10 | Delete dead question.buildQuery function | S | **Resolved** |
| QS-NEW-03 | 12 | Document lib.zig exports as intentional public API | S | **Resolved** |
| RM-08 | 10 | Remove dead current_zone parameter from getMinimizedQname | S | **Resolved** |
| DG-01 to DG-06 | Info | Add doc comments to 6 undocumented public interfaces | S | **Resolved** |
| QS-NEW-01 | 45 | Extract responseMatchesQuery to shared module | S | **Won't Do** |
| RM-07 | 24 | Extract formatIpv4 helper to shared module | S | **Won't Do** |
| QS-NEW-04 | 30 | Add zig install directory to CI cache paths | S | **Won't Do** |
| QS-NEW-08 | 20 | Pin spice to versioned release tarball | S | **Won't Do** |

### Completed Quick Wins

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QH-NEW-01 | 48 | convenience.zig stubs return error.NotImplemented | **Resolved** (commit 6d42d51) |
| QM-NEW-04 | 16 | lib.zig "Zero external dependencies" claim fixed | **Resolved** (commit 6d42d51) |
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
| QM-10 | 24 | extractSerial delegates to parseSoaRdata | **Resolved** |
| QL-01 | 12 | @intFromPtr duplication | **Resolved** |
| QL-02 | 8 | verifyCase0x20 reimplements std.mem.eql | **Resolved** |
| QL-04 | 16 | rdata invariant doc | **Resolved** |
| QL-05 | 16 | Move mock statics to per-instance state | **Resolved** |
| QL-06 | 12 | Replace magic number 6 with named constant | **Resolved** |
| QL-07 | 32 | zig fmt --check added to CI (explicit script in zig-format override) | **Resolved** |
| QL-08 | 12 | ARCHITECTURE.md stale references removed | **Resolved** |
| QC-NEW-01 | 64 | acquire() returns ConnectionHandle instead of dangling pointer | **Resolved** |
| QC-NEW-02 | 48 | TOCTOU re-check after re-acquiring mutex in acquire() | **Resolved** |
| QL-NEW-01 | 8 | Deduplicated testSocketPair (import from io.zig) | **Resolved** |

### Medium Term (1-5 days)

New medium-term items from deep review round 2 (2026-03-25):

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QR-R02 | 20 | SpuriousDiscardCounter struct with 3 tests; all discard loops refactored | M | **Resolved** |

Previously identified medium-term items from deep audit (2026-03-24):

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| TC-01 | 48 | Add mock transport + integration tests for resolveIterative (confirms QH-NEW-02) | L | **Won't Do** |
| RD-01 | 30 | LabelIterator extracted; used by 5 functions in name.zig | M | **Resolved** |
| CI-04 | 30 | 16 tests added for escapeJsonString and addressMatches | M | **Resolved** |
| DOC-03 | 8 | Create module-level library user guide (docs/USAGE.md) | M | **Won't Do** |

Previously resolved or Won't Do medium-term items:

| ID | PriorityScore | Finding | Effort | Status |
|----|---------------|---------|--------|--------|
| QM-NEW-03 | 36 | Add cache formatting for MX, SRV, TXT, NS, PTR record types | M | **Resolved** |
| QC-NEW-03 | 64 | Extract shared sendUdpQuery() from 3 files (~150 lines) | M | **Won't Do** |
| QH-NEW-02 | 48 | Add integration tests for resolveIterative (219 lines, 0 coverage) | L | **Won't Do** |
| QM-NEW-02 | 36 | Unify or rename duplicate ResolveResult types | S | **Won't Do** |
| QS-NEW-06 | 30 | Add code coverage measurement tool and CI integration | M | **Won't Do** |
| QS-NEW-07 | 12 | Rewrite client tests with mock transport | M | **Won't Do** |

### Completed Medium Term

| ID | PriorityScore | Finding | Status |
|----|---------------|---------|--------|
| QC-03 | 80 | Partial write data loss (3 files) | **Resolved** |
| QH-07 | 64 | PipelinedBatch blocking reads | **Resolved** |
| QH-02 | 80 | Referral NS never assigned | **Resolved** |
| QH-04 | 64 | Name.eql() mmap | **Resolved** |
| QM-06 | 24 | ARCHITECTURE.md gaps | **Resolved** |
| QM-07 | 48 | 3x duplicate I/O helpers extracted to io.zig | **Resolved** |
| QM-09 | 36 | parallel.zig placeholder implementations | **Resolved** |

### Strategic (> 5 days) / Deferred

| ID | PriorityScore | Finding | Reason | Status |
|----|---------------|---------|--------|--------|
| QH-05 | 64 | Fuzz testing | 7 fuzz targets added in `tests/fuzz_parsers.zig` | **Resolved** |
| QM-03 | 36 | resolveIterative complexity (219 lines) | Large refactor risks critical path regressions | **Won't Do** |
| QL-03 | 16 | 12 files over 800 lines (was 9) | High churn, low readability gain | **Won't Do** |
| QL-09 | 16 | 41 functions over 50 lines (was 30) | Mechanical decomposition; needs lint gate | **Won't Do** |

## Related Issues (Pre-existing)

These existing issues overlap with or are related to quality findings:

| Existing Issue | Related Finding | Relationship |
|---------------|-----------------|--------------|
| [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (TCP length prefix short reads) | QH-08, QC-03 | Same root cause category -- QH-08 is zone_transfer specific, QC-03 covers writes |
| [#47](https://gitlab.com/devnw/zig/dns/-/issues/47) (TCP transports ignore timeout_ms) | QH-07 | Same category; #47 covers stub/tcp/pool query path, QH-07 covers PipelinedBatch |
| [#66](https://gitlab.com/devnw/zig/dns/-/issues/66) (Connection pooling module tracking) | QC-02, QC-04, QH-07, QM-11 | Feature tracking; quality findings are bugs within the module |
| [#68](https://gitlab.com/devnw/zig/dns/-/issues/68) (Parallel DNS operations module) | QM-09 | Feature tracking; QM-09 is about placeholder implementations within |
| [#75](https://gitlab.com/devnw/zig/dns/-/issues/75) (GAP-0012: Dual recursive resolver) | QM-02, QM-08 | Root server duplication resolved; QM-08 is the remaining dead resolver/stub.zig |
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication in name parsing) | QM-01, QM-07, QC-NEW-03, QS-NEW-01 | Same root cause pattern -- duplication leads to divergence; QS-NEW-01 is responseMatchesQuery variant |
| [#107](https://gitlab.com/devnw/zig/dns/-/issues/107) (SEC-C14: spice pins main) | QS-NEW-08 | Same finding from dependency security perspective; QS-NEW-08 is the quality/stability angle |
| [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) (QM-03: resolveIterative) | QL-09, QH-NEW-02 | QM-03 is a subset of the broader 41-function finding; QH-NEW-02 highlights zero test coverage |
| [#161](https://gitlab.com/devnw/zig/dns/-/issues/161) (SEC-C26: Partial write in TCP framing) | QC-03 | Security perspective on the same partial write issue |
| [#170](https://gitlab.com/devnw/zig/dns/-/issues/170) (QM-07: I/O dedup) | QC-NEW-03 | QC-NEW-03 is the UDP equivalent of the TCP I/O dedup that was resolved in QM-07 |
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication) | DUP-02, RD-01 | DUP-02 is responseMatchesQuery duplication (same as QS-NEW-01); RD-01 is compression pointer check duplication in name.zig |
| [#109](https://gitlab.com/devnw/zig/dns/-/issues/109) (QM-03: resolveIterative) | TC-01 | TC-01 confirms QH-NEW-02 (zero test coverage) via deep review; related to resolveIterative complexity |
| [#46](https://gitlab.com/devnw/zig/dns/-/issues/46) (TCP length prefix short reads) | EH-11 | EH-11 is a related TCP read completeness issue in zdig |
| [#40](https://gitlab.com/devnw/zig/dns/-/issues/40) (SEC-018: Code duplication) | QR-01, QR-02 | QR-01 is forward-pointer logic triplication within LabelIterator (same file); QR-02 is UDP receive loop triplication across 3 files (same pattern as QC-NEW-03) |
| [#188](https://gitlab.com/devnw/zig/dns/-/issues/188) (RD-01: LabelIterator extraction) | QR-01, QR-03 | RD-01 extracted LabelIterator but the three methods within it still contain triplicated pointer-following logic (QR-01); QR-03 notes style divergence in nextForEql |

## Scoring Methodology

**PriorityScore = Impact(1-5) x Likelihood(1-5) x 4**

| Scale | Impact | Likelihood |
|-------|--------|------------|
| 5 | Outages / major perf cost | Ubiquitous / touched often |
| 4 | Frequent bugs / major dev drag | Often encountered |
| 3 | Moderate impact | Sometimes encountered |
| 2 | Minor impact | Rare |
| 1 | Polish | Edge-case |

### New Finding Score Breakdown (Phase 2-3)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| QC-NEW-03 | 4 (dev drag, divergence risk) | 4 (UDP query on every resolution) | 64 | Same pattern as QM-07 (TCP I/O dedup); three copies already show minor divergence in variable naming |
| QH-NEW-01 | 4 (advertised API non-functional) | 3 (users calling convenience API) | 48 | Public API promises resolution but returns empty; misleads consumers |
| QH-NEW-02 | 4 (most complex function untested) | 3 (regressions likely during maintenance) | 48 | 219-line function with CNAME, referral, QNAME minimization logic has zero test coverage |
| QS-NEW-01 | 3 (duplication leads to divergence) | 3 (updated rarely but easy to diverge) | 45 | ~20 identical lines; any fix to query matching logic must be applied in two places |
| RE-05 | 4 (crash on invariant violation) | 2 (rare: requires rdata from non-message buffer) | 40 | Pointer subtraction underflows if rdata doesn't alias into full_message; debug assert is zero-cost in release |
| AC-02 | 3 (memory leak on error path) | 3 (any error during MX iteration) | 36 | errdefer frees ArrayList but not heap-allocated exchange strings; leak proportional to MX records parsed before error |
| QM-NEW-01 | 2 (minor confusion) | 3 (encountered when extending types) | 24 | QueryType has 10 variants; types.Type has 80+; will diverge silently |
| QM-NEW-02 | 3 (API confusion) | 3 (encountered integrating client + recursive) | 36 | Two types with same name, different shapes; callers must know which module they are in |
| QM-NEW-03 | 3 (silent data loss for non-A/AAAA) | 3 (any MX/SRV/TXT cache hit) | 36 | Cache stores all types but only formats two; cache hit for MX returns empty results array |
| QM-NEW-04 | 1 (misleading docs) | 4 (seen by every new user) | 16 | spice is declared in build.zig.zon; "Zero external dependencies" is factually incorrect |
| QM-NEW-05 | 3 (OOM becomes silent skip) | 2 (OOM during NS resolution is rare) | 24 | `catch return null` on line 688 swallows OOM; should propagate OutOfMemory |
| QS-NEW-04 | 3 (CI time/bandwidth waste) | 2 (every pipeline run) | 30 | Zig tarball is ~45MB; download+extract adds 15-30s per job; easily cacheable |
| QS-NEW-06 | 3 (no visibility into test coverage) | 2 (blocks quality improvement decisions) | 30 | Cannot measure impact of test additions; no coverage regression gate |
| QS-NEW-05 | 3 (OOM swallowed as retry/skip) | 1 (OOM in query path is rare) | 18 | Bare catch in hot path swallows all errors including fatal OOM |
| AC-03 | 3 (memory leak on error path) | 1 (error during cache-hit formatting is rare) | 18 | errdefer only frees ArrayList backing; duped formatted strings leak |
| QS-NEW-03 | 2 (dead code / API surface noise) | 1 (never encountered by consumers) | 12 | Exports pollute public API; may cause confusion when browsing lib.zig |
| QS-NEW-07 | 2 (tests provide no coverage guarantee) | 1 (only affects CI without network) | 12 | Tests pass vacuously when network unavailable; no behavioral verification |
| QS-NEW-02 | 1 (dead code) | 2 (encountered when searching for buildQuery) | 10 | Confusing: two buildQuery functions, one never called |
| RM-04 | 2 (naming confusion) | 3 (encountered when using MX APIs) | 24 | MXRecord vs MxRecord with identical fields; Zig naming convention prefers MxRecord |
| RM-07 | 2 (inline repetition) | 3 (4+ call sites, growing) | 24 | Same format string copied; any format change requires updating all sites |
| RM-08 | 1 (dead parameter) | 2 (encountered when reading minimization code) | 10 | `_ = current_zone;` on first line is a clear dead-code signal |
| QS-NEW-08 | 2 (API stability risk) | 2 (only on dependency update) | 20 | main branch tarball means any spice push can break the build |

All Phase 2-3 findings tagged `confidence::confirmed` -- verified via direct code inspection during Phase 2-3 review.

### Deep Audit Score Breakdown (2026-03-24)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| MEM-01 | 5 (resource leak, unbounded growth) | 3 (initWithServer used in examples/tests) | 60 | Every initWithServer call leaks a heap allocation; deinit is a no-op; comment "not owned" is incorrect for this constructor |
| EH-08 | 5 (panic/outage in resolver hot path) | 3 (NTP corrections happen in production) | 60 | @intCast to u32/u64 panics on negative delta from clock regression; 6+ sites across 4 files |
| TC-01 | 4 (most complex function untested) | 3 (regressions likely during maintenance) | 48 | Deep review confirmation of QH-NEW-02; 220-line function with CNAME/referral/QNAME minimization has zero coverage |
| RD-01 | 3 (security-adjacent duplication) | 2.5 (compression handling changes rare but high-stakes) | 30 | 7+ copies of identical ~10-line compression pointer traversal; missed fix in any copy is a security gap |
| CI-04 | 3 (security-sensitive functions) | 2.5 (CLI tool, output consumed by scripts) | 30 | 1051-line file with zero tests; escapeJsonString (JSON injection) and addressMatches (ACL) untested |
| DUP-02 | 2 (divergence risk) | 3 (updated rarely but easy to diverge) | 24 | Identical ~20-line responseMatchesQuery in two files; cross-ref QS-NEW-01 |
| DOC-01 | 3 (use-after-free risk from misunderstanding) | 1.5 (experienced devs understand aliasing) | 18 | Message.data aliases caller's buffer with no lifetime documentation |
| EH-11 | 3 (silent data truncation) | 1.5 (premature close uncommon) | 18 | TCP read loop breaks on recv==0 without checking total_read==response_len |
| DOC-02 | 1 (polish, misleading internal API) | 2 (internal API, rarely encountered) | 8 | createConnection accepts server/timeout but discards both; intentional lazy-connection design |
| DOC-03 | 1 (onboarding friction) | 2 (library not yet widely distributed) | 8 | No getting-started guide for downstream consumers |

All deep audit findings tagged `confidence::confirmed` -- verified via direct code inspection and source evidence.

### Full Audit Score Breakdown (2026-03-25, second quality reviewer)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| QA-AUDIT-04 | 4 (fd leak on successful connection) | 3 (OOM during cache update is rare but possible under load) | 48 | Winning fd has state=.connected, so defer cleanup skips it; try propagates error before fd returned to caller |
| QA-AUDIT-05 | 3 (dead config misleads users) | 2 (config is set but has no effect) | 24 | max_depth=32 is defined and tested but never read by resolution logic; users may believe they are configuring depth limits |
| QA-AUDIT-06 | 3 (magic number, inconsistency) | 1.5 (CNAME chain limits rarely reviewed) | 18 | Magic `8` in recursive.zig vs named `max_cname_mappings=16` in client.zig; limits should be consistent and named |
| QA-AUDIT-07 | 2 (code duplication) | 2 (EDNS options rarely change) | 16 | Six copies of identical 4-byte header + data serialization; any format change must be applied 6 times |

All full audit findings tagged `confidence::confirmed` -- verified via direct code inspection.

### Deep Review Round 2 Score Breakdown (2026-03-25)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| QR-01 | 3 (security fix risks partial application across 3 copies) | 3 (pointer-following code is security-critical and may need updates) | 36 | Three copies of ~25-line forward-pointer security logic in LabelIterator next/nextOrStop/nextForEql; a security fix applied to one method but not the others creates a vulnerability window |
| QR-02 | 2 (minor divergence risk) | 3 (UDP receive loop is exercised on every query) | 24 | max_spurious_discards constant (10000) and ~35-line receive loop copied identically in 3 files; values already show minor naming divergence |
| QR-R02 | 2 (tests provide false confidence) | 2.5 (discard enforcement only matters under attack) | 20 | Existing tests verify the constant value is >0 and <=10000 but never exercise the actual TooManySpuriousPackets error path with a mock socket |
| QR-04 | 2 (inconsistent limits confuse maintainers) | 2 (CNAME limit logic reviewed rarely) | 16 | max_cname_chain_length=8 in recursive.zig and max_cname_mappings=16 in client.zig serve different layers but no cross-reference explains the relationship |
| QR-05 | 2 (magic number despite named constant existing) | 1.5 (CNAME depth logic stable) | 12 | client.zig:510 hard-codes 8 for CNAME depth; recursive.zig already defines max_cname_chain_length=8 as a named constant |
| QR-03 | 1 (readability/consistency polish) | 3 (LabelIterator methods read together during review) | 12 | nextForEql() uses different variable names and control flow structure for identical pointer-following logic; no comment explains why |
| QR-R01 | 1 (observability loss for rare OOM) | 2 (OOM during cache update is rare) | 8 | catch {} on updateFamilyCache at happy_eyeballs.zig:212 silently swallows errors; recursive.zig:338 uses log.debug for same pattern |

All deep review round 2 findings tagged `confidence::confirmed` -- verified via direct code inspection of src/name.zig, src/recursive.zig, src/stub.zig, src/transports/udp.zig, src/transports/happy_eyeballs.zig, and src/client.zig.

### Audit Deep Review Score Breakdown (2026-03-25)

| ID | Impact | Likelihood | PriorityScore | Rationale |
|----|--------|------------|---------------|-----------|
| QR-NEW-01 | 2 (silent overflow if future caller exceeds 128) | 2 (only one call site today; max_labels=128 matches LabelList) | 16 | `extractWireLabels` accepts comptime `max_labels` but `LabelList.items` is hardcoded `[128][]const u8`; a future caller passing `max_labels > 128` would overflow the array without compile-time or runtime error |
| QR-NEW-02 | 1 (defensive guards exist; correctness unaffected) | 2 (malformed DNSSEC wire names are rare but possible from adversarial input) | 8 | `compareDnsNames` has break guards for empty labels, compression pointers, and truncated names (lines 865-868), but no test exercises these code paths; untested defensive code may silently regress |
| QR-NEW-03 | 1 (not generic but correct for current use) | 1 (SHA-1 is the only NSEC3 hash per RFC 5155) | 4 | `base32hexEncode` takes `*const [20]u8` -- hardcoded to SHA-1 digest size; acceptable because no other hash algorithm is defined for NSEC3; generalize only if RFC adds new algorithms |
| QR-NEW-04 | 1 (documentation consistency; no code impact) | 1 (doc comments rarely cause confusion) | 4 | SEC-AUDIT-09 doc comment appears in both stub.zig and recursive.zig; this is an intentional per-file documentation pattern so each module is self-documenting without cross-file navigation |

QR-NEW-01 and QR-NEW-02 tagged `confidence::confirmed` -- verified via direct code inspection of src/resolver/dnssec.zig. QR-NEW-03 and QR-NEW-04 tagged `confidence::confirmed` -- verified via code inspection and RFC 5155 reference.
