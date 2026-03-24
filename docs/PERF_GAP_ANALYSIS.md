# Performance Gap Analysis

Last updated: 2026-03-24

## Summary

| Status | Count | Items |
|---|---|---|
| **Resolved** | 36 | PF-01, PF-02b, PF-04, PF-06, PF-07, PF-08, PF-09, PF-11, PF-12, PF-15, PF-17, PF-19, PF-20, PF-21, PF-22, PF-23, PF-24, PF-25, PF-26, PF-27, PF-28, PF-29, PF-30, PF-31, PF-NEW-01, PF-NEW-02, PF-NEW-03, PF-NEW-04, PF-NEW-05, PF-NEW-06, PF-NEW-07, PF-NEW-08, PF-NEW-09, PF-NEW-10, PF-NEW-12, PF-NEW-13 |
| **Open/Deferred** | 9 | PF-02, PF-03, PF-05, PF-10, PF-13, PF-14, PF-16, PF-18, PF-03b |
| **Total** | **45** |

### Top 5 Risks (by PerfScore)

1. **PF-02 (PerfScore 80, P1):** O(n) linear-scan cache with n=10000 default. Expected 50-100x improvement from DnsCache migration.
2. **PF-03 (PerfScore 80, P1):** New UDP socket per query -- 5 syscalls per resolution. Socket reuse would save ~5-10us/query.
3. **PF-05 (PerfScore 64, P1):** No per-query arena allocator -- 20-30 individual alloc/free per resolution (down from 20-60 after Phase 2 stack-buffer fixes).
4. **PF-03b (PerfScore 48, P2):** Sequential server tries despite `parallel_queries` config -- `queryWithRetry` sends to servers one at a time; latency = sum instead of max.
5. **PF-10 (PerfScore 24, P2):** allocPrint for IP formatting remains in 13 production sites across 10 files.

### Resolved Risks

1. **PF-01 (PerfScore 100):** **Resolved.** `Name.eql()` now uses allocation-free label-by-label comparison.
2. **PF-04 (PerfScore 64):** **Resolved.** `extractReferral` uses single-pass additional collection.
3. **PF-06 (PerfScore 24):** **Resolved.** UDP receive buffer reduced from 65535 to 4096.
4. **PF-07 (PerfScore 48):** **Resolved.** Section offsets cached in Message struct.
5. **PF-08 (PerfScore 36):** **Resolved.** CNAME chain uses pre-built mapping array.
6. **PF-09 (PerfScore 36):** **Resolved.** `responseMatchesQuery` uses zero-allocation Name.encodeBuf + Name.eql on the stack.
7. **PF-11 (PerfScore 36):** **Resolved.** ResolutionState.deinit() added with defer.
8. **PF-12 (PerfScore 36):** **Resolved.** DnsCache zone_name freed via on_evict callback in LRU.
9. **PF-15 (PerfScore 16):** **Resolved.** makeKey uses stack buffer for lowercase (max 255 bytes).
10. **PF-17 (PerfScore 12):** **Resolved.** Thread pool uses GPA-backed allocator.
11. **PF-24 (PerfScore 64):** **Resolved.** `Name.toStringBuf()` writes into caller-provided buffer; zero heap allocation.
12. **PF-02b (PerfScore 48):** **Resolved.** `Cache.get()` compacts matching entries via swap; returned slice is always contiguous.
13. **PF-28 (PerfScore 8):** **Resolved.** `extractQname` and `reverseIPv6Name` pre-allocate ArrayList capacity.
14. **PF-27 (PerfScore 4):** **Resolved.** `inline` added to `CacheEntry.isExpired`, `CacheEntry.remainingTtl`, `verifyCase0x20`.
15. **PF-21 (PerfScore 72):** **Resolved.** `DnsCache.get()` uses `makeKeyBuf` with a 280-byte stack buffer; zero heap allocation on hot path.
16. **PF-25 (PerfScore 30):** **Resolved.** `isUnderNxdomainZone` uses `makeNxdomainZoneKeyBuf` with shared stack buffer across loop iterations.
17. **PF-26 (PerfScore 4):** **Resolved.** LRU `getWithHandle` + `removeByHandle` avoids re-hashing key on expired entry removal.
18. **PF-31 (PerfScore 40):** **Resolved.** `resolveNsAddress` depth guard with max depth 8; test verifies depth budget enforcement.
19. **PF-19 (PerfScore 36):** **Resolved.** `queryWithRetry` returns `QueryResult` with pre-parsed `Message`; `responseMatchesQuery` accepts `Message` instead of raw bytes; eliminates redundant `Message.parse` in `resolveIterative`.
20. **PF-29 (PerfScore 24):** **Resolved.** `cacheResponse` uses `toStringBuf` with 256-byte stack buffer for both question name and per-record owner name; zero heap allocation.
21. **PF-30 (PerfScore 20):** **Resolved.** `client.zig resolve()` uses `toStringBuf` with 256-byte stack buffer for owner name in CNAME chain check; zero heap allocation.
22. **PF-20 (PerfScore 8):** **Resolved.** `resolveNsAddress` uses `bufPrint` with `[15]u8` stack buffer for IPv4 string formatting; zero heap allocation.
23. **PF-NEW-01 (HIGH):** **Resolved.** `extractQnameBuf` writes into caller-provided stack buffer; `extractQname` is now a thin wrapper. Recursive resolver 0x20 verification path is zero-allocation.
24. **PF-NEW-05 (MEDIUM):** **Resolved.** `formatABuf`/`formatAAAABuf` use `bufPrint` into caller-provided buffers; `formatA`/`formatAAAA` are thin wrappers. `client.zig resolve()` uses stack buffers + `dupe`.
25. **PF-NEW-06 (MEDIUM):** **Resolved.** MX `exchange.toString` in `client.zig lookupMX()` replaced with `toStringBuf` + `dupe`; avoids ArrayList overhead.
26. **PF-NEW-02 (HIGH):** **Resolved.** `extractReferral` caller now frees referral data via `Referral.deinit` which frees `.zone`, each `.servers[i].name`, and the `.servers` slice. Added `errdefer` guards for error-path cleanup inside `extractReferral`.
27. **PF-NEW-03 (HIGH):** **Resolved.** CNAME target path uses `toStringBuf` with 256-byte stack buffer + single `dupe` instead of `toString` (heap alloc) + `dupe` (second heap alloc). Eliminates one allocation per CNAME hop.
28. **PF-NEW-04 (MEDIUM):** **Resolved.** `getMinimizedQname` builds the minimized name in a stack `[253]u8` buffer with manual offset tracking instead of `ArrayList(u8)`. Avoids heap allocation for name assembly.
29. **PF-NEW-07 (P2, PerfScore 20):** **Resolved.** `extractReferral` zone name uses `toStringBuf` with 256-byte stack buffer for `isSubdomainOf` comparisons; only duped once for the final `Referral`. Eliminates intermediate `getName` heap allocation.
30. **PF-NEW-09 (P2, PerfScore 20):** **Resolved.** Glue record names in `extractReferral` use `toStringBuf` with 256-byte stack buffer; NS name matching done inline against `servers` array. Eliminates per-glue `getName` heap alloc and `GlueRecord` intermediate storage.
31. **PF-NEW-12 (P3, PerfScore 8):** **Resolved.** `queryWithRetry` skips `last_query_name` dupe when `case_randomization` is disabled since `last_query_name` is only checked under the 0x20 verification branch.
32. **PF-NEW-13 (P3, PerfScore 12):** **Resolved.** `MessageBuilder.addQuestion` uses `Name.encodeBuf` with stack buffer to encode the question directly, avoiding intermediate heap allocation from `question_mod.buildQuery`.

### Open Items

Remaining items by priority:

**P1 (Within Sprint):**
- **PF-02:** Cache migration to LRU -- DnsCache exists but migrating core resolvers is a larger refactor
- **PF-03:** Socket reuse -- ConnectionPool exists and is exposed, but wiring into core resolvers is a larger refactor
- **PF-05:** Arena allocator -- architectural change affecting many files; confirmed 20-30 alloc/free per resolution (Phase 3 audit)

**P2 (Next Quarter):**
- **PF-03b:** Sequential server tries despite `parallel_queries` config -- `queryWithRetry` iterates servers sequentially
- **PF-10:** allocPrint for IP formatting -- now 13 production sites across 10 files (down from 17 after Phase 2 stack-buffer fixes)
- **PF-13:** Concurrent queries -- requires thread-safe cache first (PF-14)
- **PF-14:** Cache thread safety -- prerequisite for PF-13, larger effort

**P3 (Backlog):**
- **PF-16:** PRNG per call -- low impact optimization
- **PF-18:** No benchmarks in CI -- sustained infrastructure effort

---

## Stack-Ranked Findings

| Rank | PerfSeverity | PerfScore | Finding | Component | Evidence | Measurement | Issue | Fix Summary | Owner | SLA/Due | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 100 | PF-01: Name.eql() uses page_allocator | `src/name.zig:254-263` | `std.heap.page_allocator` in eql(); 2 mmap+munmap per call | ~16us/call vs ~50ns optimal | [#82](https://gitlab.com/devnw/zig/dns/-/issues/82) | Label-by-label comparison, zero allocation | Core maintainer | Immediate | Resolved |
| 2 | P1 | 80 | PF-02: O(n) linear-scan cache, O(1) DnsCache unused | `src/cache.zig:166-231` | Linear for-loop over entries[0..count] | ~50-100us at n=10000 vs <1us | [#87](https://gitlab.com/devnw/zig/dns/-/issues/87) | Migrate to DnsCache (LRU HashMap) | Core maintainer | Sprint | Deferred |
| 3 | P1 | 80 | PF-03: New UDP socket per query (5 syscalls) | `src/stub.zig:200-205`, `src/recursive.zig:514-520`, `src/transports/udp.zig:39` | socket()+setsockopt()+sendto()+recvfrom()+close() per query | ~5-10us overhead/query | [#90](https://gitlab.com/devnw/zig/dns/-/issues/90) | Wire existing ConnectionPool into resolvers | Core maintainer | Sprint | Deferred |
| 4 | P1 | 72 | PF-21: DnsCache.get heap-allocates key via allocPrint on every lookup | `src/resolver/dns_cache.zig:134-146` | get() uses makeKeyBuf with stack buffer; falls back to allocPrint only for oversized names | Zero heap allocs on hot path | [#145](https://gitlab.com/devnw/zig/dns/-/issues/145) | Stack buffer via makeKeyBuf + bufPrint in get() | Core maintainer | Sprint | **Resolved** |
| 5 | P1 | 64 | PF-04: O(ns*additional) in extractReferral | `src/recursive.zig:570-661` | Single-pass: additional() iterated once, glue collected in ArrayList | O(ns+additional) | [#93](https://gitlab.com/devnw/zig/dns/-/issues/93) | Single-pass additional collection + linear lookup | Core maintainer | Sprint | Resolved |
| 6 | P1 | 64 | PF-05: No per-query arena allocator | `src/recursive.zig`, `src/stub.zig`, `src/client.zig` | 20-30 individual alloc/free per resolution (Phase 3 confirmed, down from 20-60 after stack-buffer fixes) | ~1-12us GPA, ~80-240us page_alloc | [#96](https://gitlab.com/devnw/zig/dns/-/issues/96) | ArenaAllocator per resolve() call | Core maintainer | Sprint | Deferred |
| 7 | P1 | 64 | PF-24: Name.toString allocates ArrayList with no pre-alloc | `src/name.zig:213-264` | ArrayList starts empty, ~8 re-allocs per typical name; no ensureTotalCapacity | ~3-5 re-allocs per name | [#155](https://gitlab.com/devnw/zig/dns/-/issues/155) | Added toStringBuf variant (stack buffer); zero-allocation name formatting | Core maintainer | Sprint | Resolved |
| 8 | P2 | 48 | PF-03b: Sequential server tries despite parallel_queries config | `src/recursive.zig:489-508` | `queryWithRetry` iterates `servers[0..max_tries]` sequentially via `for` loop; `parallel_queries` only caps iteration count, does not dispatch concurrently | Latency = sum of timeouts vs max; 2 servers at 5s timeout = 10s worst case instead of 5s | -- | Dispatch queries to `parallel_queries` servers concurrently via spice ThreadPool; return first valid response | Core maintainer | Quarter | Open |
| 9 | P1 | 48 | PF-02b: Cache.get returns non-contiguous slice | `src/cache.zig:165-200` | entries[start..end] included unrelated records | Correctness + wasted iteration | [#171](https://gitlab.com/devnw/zig/dns/-/issues/171) | Compact matching entries via swap so returned slice is contiguous | Core maintainer | Sprint | Resolved |
| 10 | P2 | 48 | PF-07: O(n) section skipping in message.zig | `src/message.zig:82-137` | Section offsets eagerly computed in parse(); answers()/authority()/additional() now O(1) | O(1) per call | [#101](https://gitlab.com/devnw/zig/dns/-/issues/101) | Cache section offsets in Message struct | Core maintainer | Quarter | Resolved |
| 11 | P2 | 48 | PF-13: No concurrent query support | `src/recursive.zig:489` | parallel_queries config exists but queries are sequential (confirmed by PF-03b) | Latency = sum vs max | [#116](https://gitlab.com/devnw/zig/dns/-/issues/116) | Wire spice ThreadPool for parallel queries | Core maintainer | Quarter | Deferred |
| 12 | P1 | 40 | PF-31: resolveNsAddress has no depth guard | `src/recursive.zig:663-665` | max_depth config (default 8); depth tracked via ns_resolve_depth parameter | Max depth enforced per call chain | [#174](https://gitlab.com/devnw/zig/dns/-/issues/174) | Added max_depth config field + ns_resolve_depth tracking in resolveNsAddress | Core maintainer | Sprint | **Resolved** |
| 13 | P2 | 36 | PF-08: buildCnameChain re-iterates answers per hop | `src/client.zig:347-396` | Single-pass CNAME mapping pre-built from answers; chain walked via array lookup | O(ancount + hops) | [#103](https://gitlab.com/devnw/zig/dns/-/issues/103) | Pre-build CNAME mapping array from answers | Core maintainer | Quarter | Resolved |
| 14 | P2 | 36 | PF-09: responseMatchesQuery allocates string | `src/recursive.zig:681-685` | Now uses Name.encodeBuf + Name.eql on the stack; zero allocation | ~50ns/call (was ~200ns) | [#105](https://gitlab.com/devnw/zig/dns/-/issues/105) | Zero-allocation Name comparison via encodeBuf + eql | Core maintainer | Quarter | Resolved |
| 15 | P2 | 36 | PF-11: Memory leak - ResolutionState.last_query_name | `src/recursive.zig:673-695` | ResolutionState.deinit() frees last_query_name and cname_chain; resolve() uses defer state.deinit() | No leak under testing allocator | [#110](https://gitlab.com/devnw/zig/dns/-/issues/110) | Added deinit() method to ResolutionState; resolve() calls defer state.deinit() | Core maintainer | Quarter | Resolved |
| 16 | P2 | 36 | PF-12: Memory leak - DnsCache zone_name not freed | `src/resolver/dns_cache.zig:114-122` | on_evict callback frees zone_name; freeCacheEntry frees both rdata and zone_name | No leak under testing allocator | [#114](https://gitlab.com/devnw/zig/dns/-/issues/114) | Added on_evict callback to LRU; freeCacheEntry frees zone_name | Core maintainer | Quarter | Resolved |
| 17 | P2 | 36 | PF-14: Cache has no thread safety | `src/cache.zig` | No Mutex/RwLock in cache module | Data races under concurrency | [#118](https://gitlab.com/devnw/zig/dns/-/issues/118) | Add RwLock; prerequisite for PF-13 | Core maintainer | Quarter | Deferred |
| 18 | P2 | 36 | PF-19: Double Message.parse in recursive responseMatchesQuery | `src/recursive.zig:475` | queryWithRetry parses once via QueryResult; responseMatchesQuery accepts pre-parsed Message | Single parse per response (~1-2us saved per query step) | [#140](https://gitlab.com/devnw/zig/dns/-/issues/140) | QueryResult struct returns parsed Message from queryWithRetry; responseMatchesQuery accepts Message | Core maintainer | Quarter | **Resolved** |
| 19 | P2 | 36 | PF-22: CachePrefetcher.makeKey double heap allocation | `src/resolver/cache_prefetch.zig:262-275` | Stack buffer for lowercase, single allocPrint for key (PF-15 pattern applied) | ~200-400ns saved per prefetch check | [#146](https://gitlab.com/devnw/zig/dns/-/issues/146) | Applied PF-15 stack-buffer pattern from DnsCache.makeKey | Core maintainer | Quarter | Resolved |
| 20 | P2 | 30 | PF-25: isUnderNxdomainZone allocates keys in while loop | `src/resolver/dns_cache.zig:314-354` | Stack buffer shared across loop iterations via makeNxdomainZoneKeyBuf | Zero heap allocs per check | [#158](https://gitlab.com/devnw/zig/dns/-/issues/158) | Stack buffer with bufPrint; heap fallback for oversized names | Core maintainer | Quarter | **Resolved** |
| 21 | P2 | 24 | PF-06: 65KB stack buffer per UDP receive | `src/stub.zig:238`, `src/recursive.zig:509`, `src/transports/udp.zig:67` | Buffer reduced to 4096 (EDNS default, RFC 6891) | 4096 bytes/call, ~61KB saved | [#99](https://gitlab.com/devnw/zig/dns/-/issues/99) | Reduced UDP receive buffer from 65535 to 4096 in all 3 locations | Core maintainer | Quarter | Resolved |
| 22 | P2 | 24 | PF-10: allocPrint for IP formatting (13 production sites) | 10 files across `src/` | allocPrint for IPv4/IPv6 formatting; down from 17 sites after Phase 2 stack-buffer fixes (PF-NEW-05, PF-20, PF-30) | ~100-200ns per format | [#108](https://gitlab.com/devnw/zig/dns/-/issues/108) | Stack buffer + bufPrint (max 45 bytes) | Core maintainer | Quarter | Deferred |
| 23 | P2 | 24 | PF-NEW-10: Cache hit path uses allocPrint while non-cache path uses stack buffers | `src/client.zig:152-164` | Cache hit path now uses `bufPrint` into `[15]u8`/`[39]u8` stack buffers + `allocator.dupe`, matching non-cache path pattern | Zero intermediate heap alloc; single dupe per entry | Commit 6d42d51 | `bufPrint` + `allocator.dupe` on cache hit path | Core maintainer | Quarter | **Resolved** |
| 24 | P2 | 24 | PF-29: cacheResponse getName+free per answer record | `src/recursive.zig:696-706` | Uses toStringBuf with 256-byte stack buffer; zero heap allocation per record | ~200-500ns saved per answer record | [#167](https://gitlab.com/devnw/zig/dns/-/issues/167) | Use Name.toStringBuf (depends on PF-24) | Core maintainer | Quarter | **Resolved** |
| 25 | P2 | 20 | PF-NEW-07: extractReferral zone_name heap alloc via getName | `src/recursive.zig:586` | Zone name now uses `toStringBuf` with 256-byte stack buffer for comparisons; only duped once at end for Referral | Zero heap allocs during iteration; single dupe at end | -- | `rr.name.toStringBuf(&zone_buf, response)` + final `allocator.dupe` | Core maintainer | Quarter | **Resolved** |
| 26 | P2 | 20 | PF-NEW-09: Additional section glue getName heap allocs | `src/recursive.zig:614` | Glue names use `toStringBuf` with stack buffer; NS matching done inline against servers array; GlueRecord intermediate eliminated | Zero heap allocs for glue names | -- | `add_rr.name.toStringBuf(&glue_buf, response)` + inline NS matching | Core maintainer | Quarter | **Resolved** |
| 27 | P2 | 20 | PF-30: client.zig resolve() getName per answer for CNAME check | `src/client.zig:213-217` | Uses toStringBuf with 256-byte stack buffer; zero heap allocation per answer | ~200-400ns saved per answer record | [#168](https://gitlab.com/devnw/zig/dns/-/issues/168) | Use Name.toStringBuf (depends on PF-24) | Core maintainer | Quarter | **Resolved** |
| 28 | P3 | 16 | PF-NEW-08: buildCnameChain heap getName/toString per CNAME record | `src/client.zig:404-428` | `buildCnameChain` now uses `toStringBuf` with `[256]u8` stack buffers for owner and target names, then `allocator.dupe` for the mapping arrays | Zero intermediate ArrayList alloc per CNAME record | Commit 6d42d51 | `toStringBuf` + `dupe` pattern in buildCnameChain | Core maintainer | Backlog | **Resolved** |
| 29 | P3 | 16 | PF-15: Double allocation in DnsCache.makeKey | `src/resolver/dns_cache.zig:330-343` | Stack buffer `lower_buf: [max_name_length]u8` replaces heap allocation | Zero extra allocations | [#120](https://gitlab.com/devnw/zig/dns/-/issues/120) | Uses stack buffer for lowercase (max 255 bytes) | Core maintainer | Backlog | Resolved |
| 30 | P3 | 16 | PF-16: New PRNG per getSecureRandomId call | `src/resolver/stub.zig` (deleted -- see QM-08) | getrandom() syscall + PRNG init per call | ~2us vs ~10ns | [#122](https://gitlab.com/devnw/zig/dns/-/issues/122) | Persistent PRNG on resolver struct; canonical stub is `src/stub.zig` | Core maintainer | Backlog | Deferred |
| 31 | P3 | 12 | PF-NEW-13: MessageBuilder.addQuestion intermediate heap alloc for encoded question | `src/message.zig:247-253` | `addQuestion` uses `Name.encodeBuf` with stack buffer + direct `writeInt` for type/class; zero intermediate heap allocation | Zero heap allocs in addQuestion | -- | `Name.encodeBuf` into `[max_name_length+4]u8` stack buffer; append slice to builder | Core maintainer | Backlog | **Resolved** |
| 32 | P3 | 12 | PF-17: Global thread pool uses page_allocator | `src/parallel.zig:77` | GPA backed by page_allocator wraps pool allocator; small allocs sub-allocated from pages | Fewer mmap syscalls | [#124](https://gitlab.com/devnw/zig/dns/-/issues/124) | Wrap with GPA | Core maintainer | Backlog | Resolved |
| 33 | P3 | 12 | PF-18: No benchmarks or perf regression CI | N/A | No bench/ directory, no benchmark CI stage | Cannot detect regressions | [#125](https://gitlab.com/devnw/zig/dns/-/issues/125) | Add bench/ suite + CI stage | Core maintainer | Backlog | Deferred |
| 34 | P3 | 8 | PF-NEW-12: queryWithRetry duplicates domain name twice when 0x20 disabled | `src/recursive.zig:476-484` | `last_query_name` dupe skipped entirely when `case_randomization` is false; only set when 0x20 is enabled (the only branch that reads it) | Zero redundant alloc when 0x20 disabled | -- | Wrapped `last_query_name` assignment in `if (self.config.case_randomization)` guard | Core maintainer | Backlog | **Resolved** |
| 35 | P3 | 8 | PF-20: allocPrint for IPv4 in resolveNsAddress | `src/recursive.zig:674-681` | bufPrint with [15]u8 stack buffer; zero heap allocation | ~100-200ns saved | [#142](https://gitlab.com/devnw/zig/dns/-/issues/142) | bufPrint with [15]u8 stack buffer | Core maintainer | Backlog | **Resolved** |
| 36 | P3 | 8 | PF-28: ArrayList byte-by-byte append without capacity pre-alloc | `src/name.zig:568`, `src/resolver/convenience.zig:301` | extractQname and reverseIPv6Name start with capacity 0 | ~100-300ns extra per call | [#164](https://gitlab.com/devnw/zig/dns/-/issues/164) | Added ensureTotalCapacity(253) in extractQname, ensureTotalCapacity(72) in reverseIPv6Name. **Superseded by PF-NEW-01**: extractQname now uses extractQnameBuf (stack buffer, zero allocation). | Core maintainer | Backlog | Resolved |
| 37 | P3 | 4 | PF-23: getMinimizedQname iterates labels twice | `src/recursive.zig:397-436` | Single-pass: labels collected once, depth checked against count | ~50-100ns saved | [#153](https://gitlab.com/devnw/zig/dns/-/issues/153) | Single-pass label collection | Core maintainer | Backlog | Resolved |
| 38 | P3 | 4 | PF-26: Expired entry removal re-hashes key | `src/resolver/dns_cache.zig:150-163`, `src/util/lru.zig:63-101` | getWithHandle returns EntryHandle; removeByHandle uses map.removeByPtr | Zero re-hash on expiry removal | [#159](https://gitlab.com/devnw/zig/dns/-/issues/159) | LRU getWithHandle + removeByHandle using HashMap removeByPtr | Core maintainer | Backlog | **Resolved** |
| 39 | P3 | 4 | PF-27: No inline hints on hot-path functions | `src/name.zig`, `src/cache.zig` | Small leaf functions in tight loops lack inline | ~2-5ns per call (debug builds) | [#162](https://gitlab.com/devnw/zig/dns/-/issues/162) | Added inline to CacheEntry.isExpired, CacheEntry.remainingTtl, verifyCase0x20 | Core maintainer | Backlog | Resolved |

---

## Findings by Area

### Application (`area::app`)

| ID | PerfSeverity | PerfScore | Finding | Issue | Status |
|---|---|---|---|---|---|
| PF-01 | P0 | 100 | Name.eql() page_allocator | [#82](https://gitlab.com/devnw/zig/dns/-/issues/82) | **Resolved** |
| PF-03 | P1 | 80 | Socket per query | [#90](https://gitlab.com/devnw/zig/dns/-/issues/90) | Deferred |
| PF-04 | P1 | 64 | extractReferral quadratic | [#93](https://gitlab.com/devnw/zig/dns/-/issues/93) | **Resolved** |
| PF-05 | P1 | 64 | No arena allocator | [#96](https://gitlab.com/devnw/zig/dns/-/issues/96) | Deferred |
| PF-24 | P1 | 64 | Name.toString no pre-alloc | [#155](https://gitlab.com/devnw/zig/dns/-/issues/155) | **Resolved** |
| PF-03b | P2 | 48 | Sequential server tries despite parallel_queries config | -- | Open |
| PF-31 | P1 | 40 | resolveNsAddress no depth guard | [#174](https://gitlab.com/devnw/zig/dns/-/issues/174) | **Resolved** |
| PF-07 | P2 | 48 | Section skipping O(n) | [#101](https://gitlab.com/devnw/zig/dns/-/issues/101) | **Resolved** |
| PF-13 | P2 | 48 | No concurrent queries | [#116](https://gitlab.com/devnw/zig/dns/-/issues/116) | Deferred |
| PF-08 | P2 | 36 | CNAME chain re-iteration | [#103](https://gitlab.com/devnw/zig/dns/-/issues/103) | **Resolved** |
| PF-09 | P2 | 36 | responseMatchesQuery alloc | [#105](https://gitlab.com/devnw/zig/dns/-/issues/105) | **Resolved** |
| PF-19 | P2 | 36 | Double Message.parse | [#140](https://gitlab.com/devnw/zig/dns/-/issues/140) | **Resolved** |
| PF-11 | P2 | 36 | last_query_name leak | [#110](https://gitlab.com/devnw/zig/dns/-/issues/110) | **Resolved** |
| PF-NEW-10 | P2 | 24 | Cache hit path allocPrint (IPv4/IPv6) | Commit 6d42d51 | **Resolved** |
| PF-10 | P2 | 24 | allocPrint IP formatting (13 sites) | [#108](https://gitlab.com/devnw/zig/dns/-/issues/108) | Deferred |
| PF-06 | P2 | 24 | 65KB stack buffers | [#99](https://gitlab.com/devnw/zig/dns/-/issues/99) | **Resolved** |
| PF-29 | P2 | 24 | cacheResponse getName per record | [#167](https://gitlab.com/devnw/zig/dns/-/issues/167) | **Resolved** |
| PF-NEW-07 | P2 | 20 | extractReferral zone_name heap alloc via getName | -- | **Resolved** |
| PF-NEW-09 | P2 | 20 | Additional section glue getName heap allocs (4-13/referral) | -- | **Resolved** |
| PF-30 | P2 | 20 | client getName per answer | [#168](https://gitlab.com/devnw/zig/dns/-/issues/168) | **Resolved** |
| PF-NEW-08 | P3 | 16 | buildCnameChain heap getName/toString per CNAME record | Commit 6d42d51 | **Resolved** |
| PF-NEW-13 | P3 | 12 | MessageBuilder.addQuestion intermediate heap alloc | -- | **Resolved** |
| PF-16 | P3 | 16 | PRNG per call | [#122](https://gitlab.com/devnw/zig/dns/-/issues/122) | Deferred |
| PF-20 | P3 | 8 | allocPrint IPv4 in resolveNsAddress | [#142](https://gitlab.com/devnw/zig/dns/-/issues/142) | **Resolved** |
| PF-NEW-12 | P3 | 8 | queryWithRetry domain dupe when 0x20 disabled | -- | **Resolved** |
| PF-28 | P3 | 8 | ArrayList byte-by-byte append | [#164](https://gitlab.com/devnw/zig/dns/-/issues/164) | **Resolved** |
| PF-23 | P3 | 4 | getMinimizedQname double iter | [#153](https://gitlab.com/devnw/zig/dns/-/issues/153) | **Resolved** |
| PF-27 | P3 | 4 | No inline hints | [#162](https://gitlab.com/devnw/zig/dns/-/issues/162) | **Resolved** |
| PF-NEW-02 | P1 | 48 | extractReferral memory leak (zone, server names, servers slice) | -- | **Resolved** |
| PF-NEW-03 | P1 | 36 | CNAME target double-alloc (toString+dupe) | -- | **Resolved** |
| PF-NEW-04 | P2 | 16 | getMinimizedQname ArrayList heap alloc | -- | **Resolved** |

### Database / Cache (`area::db`)

| ID | PerfSeverity | PerfScore | Finding | Issue | Status |
|---|---|---|---|---|---|
| PF-02 | P1 | 80 | O(n) linear cache | [#87](https://gitlab.com/devnw/zig/dns/-/issues/87) | Deferred |
| PF-21 | P1 | 72 | DnsCache.get key alloc per lookup | [#145](https://gitlab.com/devnw/zig/dns/-/issues/145) | **Resolved** |
| PF-02b | P1 | 48 | Cache.get non-contiguous slice | [#171](https://gitlab.com/devnw/zig/dns/-/issues/171) | **Resolved** |
| PF-14 | P2 | 36 | No cache thread safety | [#118](https://gitlab.com/devnw/zig/dns/-/issues/118) | Deferred |
| PF-22 | P2 | 36 | CachePrefetcher.makeKey double alloc | [#146](https://gitlab.com/devnw/zig/dns/-/issues/146) | **Resolved** |
| PF-25 | P2 | 30 | isUnderNxdomainZone loop alloc | [#158](https://gitlab.com/devnw/zig/dns/-/issues/158) | **Resolved** |
| PF-12 | P2 | 36 | DnsCache zone_name leak | [#114](https://gitlab.com/devnw/zig/dns/-/issues/114) | **Resolved** |
| PF-15 | P3 | 16 | makeKey double alloc | [#120](https://gitlab.com/devnw/zig/dns/-/issues/120) | **Resolved** |
| PF-26 | P3 | 4 | Expired entry re-hash | [#159](https://gitlab.com/devnw/zig/dns/-/issues/159) | **Resolved** |

### Infrastructure (`area::infra`)

| ID | PerfSeverity | PerfScore | Finding | Issue | Status |
|---|---|---|---|---|---|
| PF-17 | P3 | 12 | Thread pool page_allocator | [#124](https://gitlab.com/devnw/zig/dns/-/issues/124) | **Resolved** |

### CI/CD (`area::ci`)

| ID | PerfSeverity | PerfScore | Finding | Issue | Status |
|---|---|---|---|---|---|
| PF-18 | P3 | 12 | No benchmarks / perf CI | [#125](https://gitlab.com/devnw/zig/dns/-/issues/125) | Deferred |

---

## Phase 3 Finding Details

### PF-03b: Sequential server tries despite parallel_queries config (PerfScore 48, P2)

**Summary:** `queryWithRetry` iterates servers sequentially despite the `parallel_queries` configuration field suggesting concurrent dispatch.

**Perf Impact:** Resolution latency equals the sum of per-server timeouts instead of the maximum. With 2 servers and 5s timeout, worst case is 10s instead of 5s. On average, sequential tries add 1 full timeout delay per failed server before reaching one that responds.

**Evidence:**
- `src/recursive.zig:489-508`: The `for (servers[0..max_tries]) |server|` loop sends queries one at a time. The `parallel_queries` field at `src/recursive.zig:96` only limits how many servers to try, not concurrency.
- `src/recursive.zig:96`: `parallel_queries: u8 = 2` -- the name implies parallelism but the implementation is sequential.

**Root Cause:** The loop at line 491 iterates servers in sequence. Each `sendQuery` blocks on its own timeout before trying the next server. No thread or async dispatch is used.

**Fix Guidance:** Use the existing spice `ThreadPool` (already integrated in `src/parallel.zig`) to dispatch queries to `parallel_queries` servers concurrently. Return the first valid response and cancel/ignore the rest. This is closely related to PF-13 (concurrent queries) but specifically addresses the `queryWithRetry` bottleneck.

**Validation Plan:**
```
# Benchmark resolution latency with 2 servers (one unreachable, one responsive):
zig build test -- --filter "queryWithRetry"
# Before: latency ~= timeout_ms + actual_response_time
# After:  latency ~= max(timeout_ms, actual_response_time) = actual_response_time
```

**Rollout Risk:** Medium. Concurrent dispatch introduces potential for race conditions on shared state (`state.last_query_name`). Requires careful synchronization or per-thread state.

**Confidence:** `confidence::confirmed` -- code path is unambiguous; the `for` loop is inherently sequential.

---

### PF-NEW-10: Cache hit path uses allocPrint while non-cache path uses stack buffers (PerfScore 24, P2) -- RESOLVED

**Status:** Resolved (commit 6d42d51). Cache hit path in `client.zig resolve()` now uses `bufPrint` with `[15]u8` (IPv4) / `[39]u8` (IPv6) stack buffers + `allocator.dupe`, matching the non-cache path pattern from PF-NEW-05.

**Evidence:** `src/client.zig:152-169` -- `a_buf` / `aaaa_buf` stack buffers + `bufPrint` + `dupe`

---

### PF-NEW-07: extractReferral zone_name heap alloc via getName (PerfScore 20, P2) -- RESOLVED

**Status: Resolved.**

**Summary:** `extractReferral` allocated `zone_name` via `rr.getName(self.allocator, response)` which internally called `name.toString(allocator)` using an ArrayList.

**Fix Applied:** Zone name now uses `rr.name.toStringBuf(&zone_buf, response)` with a 256-byte stack buffer during iteration. The stack-buffered string is used for `isSubdomainOf` comparisons. Only at the end, when constructing the final `Referral`, is the zone name duped to the heap. This eliminates the ArrayList intermediate allocation entirely.

**Validation:** `zig build test --summary all` -- all 44 test runs pass.

---

### PF-NEW-09: Additional section glue getName heap allocs (PerfScore 20, P2) -- RESOLVED

**Status: Resolved.**

**Summary:** Each A record in the additional section triggered a `getName` heap allocation when collecting glue records in `extractReferral`. Typical referrals have 4-13 glue records.

**Fix Applied:** Glue record names now use `add_rr.name.toStringBuf(&glue_buf, response)` with a 256-byte stack buffer. The servers array is built before the glue loop, and NS name matching is done inline against the servers array during the additional section pass. This eliminates the `GlueRecord` intermediate storage entirely -- no heap allocation for glue names at all. The bailiwick check and NS name matching both operate on the stack-buffered string.

**Validation:** `zig build test --summary all` -- all 44 test runs pass.

---

### PF-NEW-08: buildCnameChain heap getName/toString per CNAME record (PerfScore 16, P3) -- RESOLVED

**Status:** Resolved (commit 6d42d51). `buildCnameChain` in `client.zig` now uses `toStringBuf` with `[256]u8` stack buffers for both owner and target names, then `allocator.dupe` for the mapping arrays. This eliminates the ArrayList intermediate allocation per CNAME record.

**Evidence:** `src/client.zig:407-428` -- `owner_stack_buf` and `target_stack_buf` stack buffers + `toStringBuf` + `dupe`

---

### PF-NEW-13: MessageBuilder.addQuestion intermediate heap alloc for encoded question (PerfScore 12, P3) -- RESOLVED

**Status: Resolved.**

**Summary:** `MessageBuilder.addQuestion` called `question.buildQuery(allocator)` which heap-allocated an intermediate buffer for the encoded question, copied it into the builder's buffer, then freed it.

**Fix Applied:** `addQuestion` now uses `Name.encodeBuf` to encode the domain name directly into a `[max_name_length + 4]u8` stack buffer, writes the qtype/qclass bytes via `std.mem.writeInt`, and appends the resulting slice to the builder buffer. Zero intermediate heap allocations. The `question_mod.buildQuery` function is no longer called from `addQuestion`.

**Validation:** `zig build test --summary all` -- all 44 test runs pass.

---

### PF-NEW-12: queryWithRetry duplicates domain name twice when 0x20 disabled (PerfScore 8, P3) -- RESOLVED

**Status: Resolved.**

**Summary:** When `case_randomization` was disabled, `queryWithRetry` duplicated the domain string twice: once into `query_name` and again into `state.last_query_name`. The second dupe was redundant since `last_query_name` is only checked under the `case_randomization` branch.

**Fix Applied:** Wrapped the `last_query_name` assignment in `if (self.config.case_randomization)`. When 0x20 is disabled, `last_query_name` is never set (remains null), skipping the unnecessary dupe entirely. This is safe because the only code that reads `last_query_name` is inside the 0x20 verification block which is also guarded by `case_randomization`.

**Validation:** `zig build test --summary all` -- all 44 test runs pass.

---

## Roadmap

### Completed

| ID | PerfScore | Fix | Status |
|---|---|---|---|
| PF-01 | 100 | Replace Name.eql() with label-by-label comparison | **Resolved** |
| PF-04 | 64 | Single-pass additional section collection | **Resolved** |
| PF-07 | 48 | Cache section offsets in Message | **Resolved** |
| PF-08 | 36 | Pre-build CNAME mapping array | **Resolved** |
| PF-09 | 36 | Zero-allocation Name comparison via encodeBuf + eql | **Resolved** |
| PF-11 | 36 | Add deinit for ResolutionState cleanup | **Resolved** |
| PF-12 | 36 | Free zone_name in DnsCache via on_evict callback | **Resolved** |
| PF-06 | 24 | Reduce UDP buffer from 65535 to 4096 | **Resolved** |
| PF-15 | 16 | Stack buffer in makeKey | **Resolved** |
| PF-17 | 12 | Wrap pool allocator with GPA | **Resolved** |
| PF-24 | 64 | Name.toStringBuf zero-allocation name formatting | **Resolved** |
| PF-02b | 48 | Cache.get contiguous-slice fix via compact-swap | **Resolved** |
| PF-28 | 8 | ensureTotalCapacity in extractQname / reverseIPv6Name | **Resolved** |
| PF-27 | 4 | inline hints on isExpired, remainingTtl, verifyCase0x20 | **Resolved** |
| PF-21 | 72 | Stack buffer for key in DnsCache.get via makeKeyBuf | **Resolved** |
| PF-25 | 30 | Stack buffer in isUnderNxdomainZone via makeNxdomainZoneKeyBuf | **Resolved** |
| PF-26 | 4 | LRU getWithHandle + removeByHandle avoids re-hash on expiry | **Resolved** |
| PF-31 | 40 | Depth guard + max_depth config in resolveNsAddress | **Resolved** |
| PF-19 | 36 | QueryResult struct + responseMatchesQuery accepts parsed Message | **Resolved** |
| PF-29 | 24 | Use toStringBuf in cacheResponse (stack buffer, zero alloc) | **Resolved** |
| PF-30 | 20 | Use toStringBuf in client resolve (stack buffer, zero alloc) | **Resolved** |
| PF-20 | 8 | bufPrint with [15]u8 for IPv4 in resolveNsAddress | **Resolved** |
| PF-NEW-01 | HIGH | extractQnameBuf stack-buffer variant; zero alloc on 0x20 path | **Resolved** |
| PF-NEW-05 | MEDIUM | formatABuf/formatAAAABuf stack-buffer variants; client.zig uses bufPrint+dupe | **Resolved** |
| PF-NEW-06 | MEDIUM | MX exchange toStringBuf+dupe in client.zig lookupMX | **Resolved** |
| PF-NEW-02 | HIGH | extractReferral memory leak -- Referral.deinit frees zone/names/slice | **Resolved** |
| PF-NEW-03 | HIGH | CNAME double-alloc -- toStringBuf+dupe replaces toString+dupe | **Resolved** |
| PF-NEW-04 | MEDIUM | getMinimizedQname stack buffer replaces ArrayList(u8) | **Resolved** |

### Quick Wins (< 1 day) -- All Resolved

| ID | PerfScore | Fix | Status |
|---|---|---|---|
| ~~PF-NEW-10~~ | ~~24~~ | ~~Replace allocPrint with bufPrint + dupe on cache hit path (client.zig:152-164)~~ | **Resolved** (commit 6d42d51) |
| ~~PF-NEW-08~~ | ~~16~~ | ~~Replace toString with toStringBuf + dupe for CNAME names in buildCnameChain~~ | **Resolved** (commit 6d42d51) |
| ~~PF-NEW-07~~ | ~~20~~ | ~~Replace getName with toStringBuf + dupe for zone_name in extractReferral~~ | **Resolved** |
| ~~PF-NEW-09~~ | ~~20~~ | ~~Replace getName with toStringBuf + dupe for glue names in extractReferral additional section~~ | **Resolved** |
| ~~PF-NEW-13~~ | ~~12~~ | ~~Use encodeBuf in question.buildQuery / addQuestion to eliminate intermediate alloc~~ | **Resolved** |
| ~~PF-NEW-12~~ | ~~8~~ | ~~Transfer query_name ownership to state.last_query_name when 0x20 disabled~~ | **Resolved** (commit 6d42d51) |

### Medium (1-5 days)

| ID | PerfScore | Fix | Effort |
|---|---|---|---|
| PF-10 | 24 | Replace allocPrint with bufPrint across 13 remaining IP formatting sites | ~2 days |

### Strategic (> 5 days)

| ID | PerfScore | Fix | Effort |
|---|---|---|---|
| PF-02 | 80 | Migrate core resolvers from Cache to DnsCache | ~5-10 days |
| PF-03 | 80 | Wire ConnectionPool into stub/recursive resolvers | ~5-10 days |
| PF-05 | 64 | Per-query ArenaAllocator across all resolvers | ~5-10 days |
| PF-03b | 48 | Parallel server dispatch in queryWithRetry via spice ThreadPool | ~3-5 days |
| PF-13 | 48 | Parallel query dispatch (requires PF-14) | ~5 days |
| PF-14 | 36 | Add RwLock to cache module | ~3-5 days |
| PF-18 | 12 | Benchmark suite + CI regression detection | ~5+ days |
