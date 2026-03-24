#!/usr/bin/env bash
# GitLab Issue Closure Commands for Gap Closure Cycle (2026-03-24)
# Review each command before executing. Run from the dns repo root.
# Usage: bash docs/ISSUE_CLOSURE_COMMANDS.sh
#
# WARNING: This will close 30 issues and comment on 16. Review carefully.

set -euo pipefail

echo "=== Closing resolved gap issues ==="

# GAP_ANALYSIS.md resolved items
glab issue close 74 --comment "Closed via gap closure (GAP-0011). All 21 modules exposed via lib.zig re-exports + build.zig wiring. No \`_ =\` suppressions remain. 316/316 tests pass."
glab issue close 75 --comment "Closed via gap closure (GAP-0012). Orphaned src/resolver/recursive.zig deleted. src/recursive.zig is the sole canonical implementation."
glab issue close 79 --comment "Closed via gap closure (GAP-0016). Orphaned test file deleted with GAP-0012. Test count verified accurate at 316."
glab issue close 81 --comment "Closed via gap closure (GAP-0018). All WIP/STUB/placeholder labels removed from ARCHITECTURE.md. Synced with ROADMAP.md."
glab issue close 85 --comment "Closed via gap closure (GAP-0019). Added outer: label to resolution loop. CNAME handler uses break + continue :outer pattern. Tests: CNAME break-then-continue-outer, CNAME chain limit enforcement."
glab issue close 88 --comment "Closed via gap closure (GAP-0020). Introduced owned_servers/owned_zone for ownership transfer. current_servers now points into owned list after referral. Tests: owned_servers memory lifecycle, owned_zone memory lifecycle."

# QUALITY_GAP_ANALYSIS.md resolved items
glab issue close 83 --comment "Closed via gap closure (QC-01). parseSvcbIpv4Hint/parseSvcbIpv6Hint now accept allocator parameter and return heap-allocated owned slices. Eliminates use-after-return UB."
glab issue close 86 --comment "Closed via gap closure (QH-01). Same fix as GAP-0019: outer-loop restart via outer: label."
glab issue close 91 --comment "Closed via gap closure (QH-02). Same fix as GAP-0020: owned_servers lifecycle management."
glab issue close 92 --comment "Closed via gap closure (QH-03). IPv4.format() now returns Formatted struct with buf and len fields."
glab issue close 95 --comment "Closed via gap closure (QH-04). Name.eql() rewritten with zero-allocation label-by-label comparison."
glab issue close 102 --comment "Closed via gap closure (QM-01). Shared src/security/dns_name.zig extracted. tsig.zig and sig0.zig now import from shared module."
glab issue close 106 --comment "Closed via gap closure (QM-02). Orphaned src/resolver/recursive.zig deleted (GAP-0012). Single root server definition in src/recursive.zig."
glab issue close 113 --comment "Closed via gap closure (QM-04). All module declarations in build.zig now have API boundary comments."
glab issue close 117 --comment "Closed via gap closure (QM-05). All catch {} sites documented with justification or upgraded to logged errors."
glab issue close 119 --comment "Closed via gap closure (QM-06). ARCHITECTURE.md rewritten with comprehensive Module Index covering all 40+ modules."
glab issue close 121 --comment "Closed via gap closure (QL-01). rdataOffset() helper extracted. All 7 duplicate @intFromPtr blocks replaced."
glab issue close 123 --comment "Closed via gap closure (QL-02). verifyCase0x20 replaced with std.mem.eql."
glab issue close 127 --comment "Closed via gap closure (QL-04). Doc comments added to ResourceRecord struct and rdataOffset() helper."

# PERF_GAP_ANALYSIS.md resolved items
glab issue close 82 --comment "Closed via gap closure (PF-01). Name.eql() rewritten with zero-allocation label-by-label comparison. ~1000x improvement."
glab issue close 93 --comment "Closed via gap closure (PF-04). extractReferral uses single-pass additional section collection. O(ns+additional)."
glab issue close 99 --comment "Closed via gap closure (PF-06). UDP receive buffer reduced from 65535 to 4096 in stub.zig, recursive.zig, and udp.zig."
glab issue close 101 --comment "Closed via gap closure (PF-07). Section offsets cached in Message struct at parse time. O(1) section access."
glab issue close 103 --comment "Closed via gap closure (PF-08). Pre-built CNAME mapping array from answers. O(ancount + hops)."
glab issue close 110 --comment "Closed via gap closure (PF-11). ResolutionState.deinit() added. resolve() uses defer state.deinit()."
glab issue close 114 --comment "Closed via gap closure (PF-12). on_evict callback in LRU frees zone_name. freeCacheEntry updated."
glab issue close 120 --comment "Closed via gap closure (PF-15). makeKey uses stack buffer lower_buf: [max_name_length]u8."
glab issue close 124 --comment "Closed via gap closure (PF-17). GPA-backed allocator wraps pool allocator."

# Related security issues resolved by same fixes
glab issue close 84 --comment "Closed via gap closure. Same fix as QC-01: SVCB hint parsers now return heap-allocated slices instead of stack pointers."
glab issue close 97 --comment "Closed via gap closure. Same fix as QH-04/PF-01: Name.eql() uses allocation-free comparison, eliminating page_allocator DoS vector."

echo ""
echo "=== Commenting on Won't Do issues ==="

glab issue comment 76 --message "Gap closure update (GAP-0013): Marked Won't Do. Requires external crypto library for RSA (BoringSSL, mbedTLS, bearssl). No pure-Zig RSA exists. ROADMAP.md Phase 3 updated to PARTIAL. Ed25519/ECDSA work via std.crypto."
glab issue comment 77 --message "Gap closure update (GAP-0014): Marked Won't Do. Vtable interface is the correct architecture for a pure-Zig library. ROADMAP.md updated to 'interface only -- requires external backend'. Compatible libraries documented in ARCHITECTURE.md."

echo ""
echo "=== Commenting on partially resolved issues ==="

glab issue comment 78 --message "Gap closure update (GAP-0015): Partially resolved. ROADMAP.md statuses updated to reflect actual code state. Phase 3 downgraded to PARTIAL. Tracker reconciliation (closing issues #9-#22 and #42-#58) remains as a separate administrative task."
glab issue comment 80 --message "Gap closure update (GAP-0017): Partially resolved. Transport modules now exposed in public API via GAP-0011. Remaining work: refactor recursive.zig sendQuery() to use transport module abstractions instead of inline socket code."

echo ""
echo "=== Commenting on deferred issues ==="

glab issue comment 98 --message "Gap closure update (QH-05): Deferred. Fuzz testing infrastructure setup is important but non-blocking. Planned for future cycle."
glab issue comment 109 --message "Gap closure update (QM-03): Deferred. Bugs in resolveIterative fixed (GAP-0019, GAP-0020). Complexity refactor deferred as lower risk."
glab issue comment 126 --message "Gap closure update (QL-03): Deferred. File splitting is a low-priority refactor with no correctness impact."
glab issue comment 87 --message "Gap closure update (PF-02): Deferred. DnsCache zone_name leak fixed (PF-12). Migration of core resolvers to DnsCache is a larger refactor."
glab issue comment 90 --message "Gap closure update (PF-03): Deferred. ConnectionPool exists and is exposed in public API. Wiring into core resolvers is a larger refactor."
glab issue comment 96 --message "Gap closure update (PF-05): Deferred. Per-query ArenaAllocator is an architectural change affecting many files."
glab issue comment 105 --message "Gap closure update (PF-09): Deferred. Depends on further Name API work beyond PF-01."
glab issue comment 108 --message "Gap closure update (PF-10): Deferred. 17 sites across 12 files. Tedious but low-risk."
glab issue comment 116 --message "Gap closure update (PF-13): Deferred. Requires thread-safe cache (PF-14) first."
glab issue comment 118 --message "Gap closure update (PF-14): Deferred. Prerequisite for PF-13. Larger effort."
glab issue comment 122 --message "Gap closure update (PF-16): Deferred. Low impact optimization."
glab issue comment 125 --message "Gap closure update (PF-18): Deferred. Benchmark suite + CI regression detection requires sustained infrastructure effort."

echo ""
echo "=== Done. 30 issues closed, 16 issues commented. ==="
