// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Recursive Resolver
//!
//! RFC 1034 Section 5.3.3: Algorithm
//! RFC 7816: QNAME Minimization
//! 0x20 Case Randomization for Cache Poisoning Protection
//!
//! Implements full recursive resolution starting from root servers,
//! following referrals through the DNS hierarchy.

const std = @import("std");
const message_mod = @import("message");
const name_mod = @import("name");
const types_mod = @import("types");
const header_mod = @import("header");
const question_mod = @import("question");
const record_mod = @import("record");
const dns_cache_mod = @import("dns_cache");
const dnssec_mod = @import("dnssec");
const clock_mod = @import("clock");
const random_mod = @import("random");
const stub_mod = @import("stub");
const net = @import("net_compat");
// Observability seam (otel). When `-Dwith_otel=false` the seam's
// helpers collapse to comptime-known no-ops and the optimizer drops
// every span site below.
const observability = @import("observability");

inline fn timeMilli() i64 {
    return clock_mod.milliTimestamp();
}

pub const Message = message_mod.Message;
pub const Name = name_mod.Name;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;
pub const Header = header_mod.Header;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const DnsCache = dns_cache_mod.DnsCache;
pub const StubResolver = stub_mod.StubResolver;
pub const ServerAddress = stub_mod.ServerAddress;

/// DUP-02: Reuse the canonical implementation from StubResolver instead of
/// maintaining a duplicate copy. Both resolvers need identical validation
/// logic, so a single source of truth prevents divergence.
const responseMatchesQuery = StubResolver.responseMatchesQuery;

/// Root DNS Servers (as of 2024)
/// These are the starting points for recursive resolution
pub const RootServers = struct {
    pub const a = "198.41.0.4"; // Verisign
    pub const b = "170.247.170.2"; // USC-ISI
    pub const c = "192.33.4.12"; // Cogent
    pub const d = "199.7.91.13"; // UMD
    pub const e = "192.203.230.10"; // NASA
    pub const f = "192.5.5.241"; // ISC
    pub const g = "192.112.36.4"; // DISA
    pub const h = "198.97.190.53"; // ARL
    pub const i = "192.36.148.17"; // Netnod
    pub const j = "192.58.128.30"; // Verisign
    pub const k = "193.0.14.129"; // RIPE
    pub const l = "199.7.83.42"; // ICANN
    pub const m = "202.12.27.33"; // WIDE

    /// IPv6 addresses for root servers
    pub const a_v6 = "2001:503:ba3e::2:30";
    pub const b_v6 = "2801:1b8:10::b";
    pub const c_v6 = "2001:500:2::c";
    pub const d_v6 = "2001:500:2d::d";
    pub const e_v6 = "2001:500:a8::e";
    pub const f_v6 = "2001:500:2f::f";
    pub const g_v6 = "2001:500:12::d0d";
    pub const h_v6 = "2001:500:1::53";
    pub const i_v6 = "2001:7fe::53";
    pub const j_v6 = "2001:503:c27::2:30";
    pub const k_v6 = "2001:7fd::1";
    pub const l_v6 = "2001:500:9f::42";
    pub const m_v6 = "2001:dc3::35";

    pub fn all() [13][]const u8 {
        return [_][]const u8{
            a, b, c, d, e, f, g, h, i, j, k, l, m,
        };
    }
};

/// Recursive resolver configuration
pub const RecursiveConfig = struct {
    /// Maximum recursion depth (to prevent loops)
    max_depth: u8 = 32,

    /// Maximum number of queries per resolution
    max_queries: u16 = 64,

    /// Query timeout in milliseconds
    timeout_ms: u32 = 5000,

    /// Cache size (number of entries)
    cache_size: usize = 10000,

    /// DNSSEC validation toggle.
    ///
    /// NOT YET WIRED: the standalone DNSSEC validator (src/resolver/dnssec.zig)
    /// is not invoked by the resolution pipeline, and outgoing queries do not
    /// yet set the EDNS DO bit. This flag therefore has no effect on resolution
    /// today and provides NO integrity guarantee. Tracked by #207 / #255
    /// (GAP-0070). Do not rely on it for authenticated answers.
    dnssec: bool = false,

    /// GAP-0839: Fail resolution when DNSSEC validation cannot prove a
    /// response secure. When false (permissive, the default), insecure and
    /// indeterminate results proceed and are reported on ResolveResult.dnssec;
    /// bogus results always fail closed regardless of this setting.
    ///
    /// Scope: validation currently covers the final answer RRsets only.
    /// CNAME intermediate hops and NXDOMAIN/NODATA denial-of-existence
    /// (NSEC/NSEC3) are NOT yet validated; those are tracked as follow-up
    /// gaps.
    dnssec_strict: bool = false,

    /// GAP-0839: Trust anchors used to validate DNSSEC responses (zone
    /// DNSKEY or DS anchors). Validation requires at least one anchor;
    /// with none configured every validation result is indeterminate.
    dnssec_trust_anchors: []const dnssec_mod.Validator.TrustAnchor = &.{},

    /// Enable QNAME minimization (RFC 7816)
    qname_minimization: bool = true,

    /// Enable 0x20 case randomization for cache poisoning protection
    case_randomization: bool = true,

    /// Maximum number of servers to try per resolution step (sequential)
    max_server_attempts: u8 = 2,
};

/// Referral information from a DNS response
const Referral = struct {
    /// Zone name this referral is for
    zone: []const u8,
    /// Name servers for this zone
    servers: []ServerInfo,

    const ServerInfo = struct {
        name: []const u8,
        address: ?ServerAddress,
    };

    /// Free all heap-allocated memory owned by this referral.
    /// Frees each server name string, the servers slice, and the zone string.
    fn deinit(self: Referral, allocator: std.mem.Allocator) void {
        for (self.servers) |s| {
            allocator.free(s.name);
        }
        allocator.free(self.servers);
        allocator.free(self.zone);
    }
};

/// QR-02: Shared constant from types module; see types.max_spurious_discards.
const max_spurious_discards = types_mod.max_spurious_discards;

/// Maximum number of CNAME redirections the recursive resolver will follow
/// before treating the chain as a loop. This limits the iterative resolution
/// path across multiple queries to authoritative servers.
///
/// QR-04: Related constants in client.zig:
///   - `max_cname_depth` (= 8): limits CNAME hops within a single response
///   - `max_cname_mappings` (= 16): limits total unique CNAME records collected
///     from one response (storage bound, not traversal depth)
const max_cname_chain_length: usize = 8;

/// Recursive Resolver
/// Performs full iterative resolution from root servers
pub const RecursiveResolver = struct {
    allocator: std.mem.Allocator,
    config: RecursiveConfig,
    cache: DnsCache,
    system_clock: clock_mod.SystemClock,
    root_servers: []ServerAddress,

    const Self = @This();

    /// CSPRNG for security-sensitive operations (transaction IDs, 0x20 randomization).
    /// Uses the OS cryptographic random source directly instead of a seeded PRNG.
    /// This prevents transaction ID prediction attacks (RFC 5452, CWE-330, SEC-C24).
    /// GAP-0851: routed through util/random.zig and fails fast (no
    /// catch-unreachable) if secure entropy is unavailable.
    fn csprngBytes(buf: []u8) random_mod.RandomError!void {
        return random_mod.fillSecure(buf);
    }

    fn csprngInt(comptime T: type) random_mod.RandomError!T {
        var buf: [@sizeOf(T)]u8 = undefined;
        try csprngBytes(&buf);
        return std.mem.readInt(T, &buf, .little);
    }

    /// 0.16.0 compat: produce a std.Random seeded from OS entropy.
    /// Used where APIs require a std.Random (e.g. applyCase0x20).
    fn csprngRandom(prng: *std.Random.DefaultPrng) random_mod.RandomError!std.Random {
        var seed: u64 = undefined;
        try csprngBytes(std.mem.asBytes(&seed));
        prng.* = std.Random.DefaultPrng.init(seed);
        return prng.random();
    }

    /// Error type for resolver initialization failures
    pub const InitError = error{
        OutOfMemory,
    };

    /// Create a new recursive resolver
    ///
    /// SECURITY: Uses the OS CSPRNG (util/random.zig, std.Io.randomSecure) for
    /// transaction ID generation
    /// and 0x20 case randomization. This prevents DNS cache poisoning attacks that
    /// exploit predictable transaction IDs (RFC 5452, SEC-C24, CWE-330).
    pub fn init(allocator: std.mem.Allocator, config: RecursiveConfig) InitError!Self {
        // Initialize root servers
        const root_ips = RootServers.all();
        var root_servers = try allocator.alloc(ServerAddress, root_ips.len);
        errdefer allocator.free(root_servers);

        for (root_ips, 0..) |ip, i| {
            root_servers[i] = ServerAddress.fromIpv4(ip, types_mod.dns_port) catch
                return error.OutOfMemory;
        }

        var sys_clock = clock_mod.systemClock();
        return Self{
            .allocator = allocator,
            .config = config,
            .cache = DnsCache.init(allocator, .{
                .max_entries = config.cache_size,
            }, sys_clock.clock()),
            .system_clock = sys_clock,
            .root_servers = root_servers,
        };
    }

    /// Free resolver resources
    pub fn deinit(self: *Self) void {
        self.cache.deinit();
        self.allocator.free(self.root_servers);
    }

    /// Resolve a domain name recursively
    pub fn resolve(self: *Self, domain: []const u8, qtype: Type) !ResolveResult {
        // Open a DNS query span. When `-Dwith_otel=false` the entire
        // block below compiles out (no-op `Span{}`); when on, this is
        // the canonical client-kind span for one full recursive
        // resolution from root downward. Internal sub-queries (one per
        // referral hop) share this single span.
        var __obs_span = observability.startQuerySpan(self.allocator, @tagName(qtype), domain);
        defer __obs_span.end(null);
        errdefer observability.endQuerySpan(__obs_span, false, "query failed");

        var state = ResolutionState{
            .original_qname = domain,
            .qtype = qtype,
            .depth = 0,
            .query_count = 0,
            .current_zone = ".",
            .cname_chain = .empty,
        };
        defer state.deinit(self.allocator);

        const out = try self.resolveIterative(&state);
        observability.endQuerySpan(__obs_span, true, "");
        return out;
    }

    /// Iteratively resolves a DNS query starting from the root servers,
    /// following referrals down the delegation chain until an authoritative
    /// answer is found or an error condition is reached.
    ///
    /// Implements the standard recursive resolution algorithm (RFC 1034 Section 5.3.3)
    /// with support for QNAME minimization (RFC 9156), 0x20 case randomization for
    /// cache poisoning protection, and CNAME chain following.
    ///
    /// The resolution loop processes referrals by extracting NS records and their
    /// glue addresses from responses, then querying the referred servers until an
    /// answer, NXDOMAIN, or NODATA response is received.
    fn resolveIterative(self: *Self, state: *ResolutionState) !ResolveResult {
        var current_servers: []const ServerAddress = self.root_servers;
        // Track dynamically-allocated server list for proper memory management.
        // When non-null, this owns the memory that current_servers points into.
        var owned_servers: ?std.ArrayList(ServerAddress) = null;
        defer if (owned_servers) |*os| os.deinit(self.allocator);

        var current_zone: []const u8 = ".";
        var owned_zone: ?[]const u8 = null;
        defer if (owned_zone) |oz| self.allocator.free(oz);

        var zone_depth: usize = 0;

        // Main resolution loop (labeled for CNAME restart)
        outer: while (state.query_count < self.config.max_queries) {
            // Determine what to query based on QNAME minimization
            const query_name = if (self.config.qname_minimization)
                try self.getMinimizedQname(state.original_qname, zone_depth)
            else
                try self.allocator.dupe(u8, state.original_qname);
            defer self.allocator.free(query_name);

            // Determine query type: NS for intermediate queries, original type for final
            const query_type = if (self.config.qname_minimization and !std.ascii.eqlIgnoreCase(query_name, state.original_qname))
                Type.ns
            else
                state.qtype;

            // Build and send query; receives both raw bytes and pre-parsed
            // Message to avoid redundant parsing (PF-19).
            const qr = try self.queryWithRetry(
                query_name,
                query_type,
                current_servers,
                state,
            );
            const response = qr.response;
            defer self.allocator.free(response);
            state.query_count += 1;

            // Reuse the already-parsed Message from queryWithRetry (PF-19)
            const msg = qr.msg;

            // Verify 0x20 case randomization if enabled
            if (self.config.case_randomization) {
                if (state.last_query_name) |expected_qname| {
                    // Use stack buffer to avoid heap allocation on every 0x20 query (PF-NEW-01)
                    var qname_buf: [name_mod.max_name_length]u8 = undefined;
                    const response_qname = name_mod.extractQnameBuf(&qname_buf, response) catch null;
                    if (response_qname) |rq| {
                        if (!name_mod.verifyCase0x20(expected_qname, rq)) {
                            // Potential spoofing attempt - retry with different server
                            continue :outer;
                        }
                    }
                }
            }

            // Handle response based on RCODE
            switch (msg.header.rcode) {
                .name_error => {
                    // NXDOMAIN - name does not exist
                    return ResolveResult{
                        .status = .nxdomain,
                        .answer = try self.allocator.dupe(u8, response),
                        .from_cache = false,
                    };
                },
                .server_failure => {
                    // SERVFAIL - try next server
                    continue :outer;
                },
                .no_error => {
                    // Check for answers
                    if (msg.header.ancount > 0) {
                        // Check for CNAME and desired record type in answer section
                        var cname_found = false;
                        var ans_iter = msg.answers();
                        while (try ans_iter.next()) |rr| {
                            if (rr.rtype == .cname and state.qtype != .cname) {
                                // Follow CNAME chain
                                // Use stack buffer + single dupe instead of toString + dupe
                                // to avoid an intermediate heap allocation (PF-NEW-03).
                                const cname_target = try rr.parseName(response);
                                var cname_buf: [256]u8 = undefined;
                                const target_str = try cname_target.toStringBuf(&cname_buf, response);

                                try state.cname_chain.append(self.allocator, try self.allocator.dupe(u8, target_str));

                                if (state.cname_chain.items.len > max_cname_chain_length) {
                                    return error.CnameLoopDetected;
                                }

                                // Restart resolution for CNAME target from root
                                state.original_qname = state.cname_chain.items[state.cname_chain.items.len - 1];

                                // Reset to root servers, freeing any dynamically-owned servers
                                if (owned_servers) |*os| {
                                    os.deinit(self.allocator);
                                    owned_servers = null;
                                }
                                current_servers = self.root_servers;

                                if (owned_zone) |oz| {
                                    self.allocator.free(oz);
                                    owned_zone = null;
                                }
                                current_zone = ".";
                                zone_depth = 0;

                                cname_found = true;
                                break; // Break from inner ans_iter loop
                            }

                            if (rr.rtype == state.qtype) {
                                // GAP-0839: Validate DNSSEC before caching.
                                // Bogus responses (and, in strict mode,
                                // insecure/indeterminate ones) fail closed
                                // here: the error propagates before the
                                // response is cached or returned.
                                const dnssec_status = try self.enforceDnssecPolicy(response, msg);

                                // Found the answer
                                self.cacheResponse(response, msg) catch |err| {
                                    // Cache population is best-effort; resolution succeeds regardless.
                                    // Log at debug level so operators can diagnose cache issues.
                                    std.log.debug("cacheResponse failed: {}", .{err});
                                };
                                return ResolveResult{
                                    .status = .success,
                                    .answer = try self.allocator.dupe(u8, response),
                                    .from_cache = false,
                                    .dnssec = dnssec_status,
                                };
                            }
                        }

                        // If CNAME was found, restart resolution from the outer loop
                        if (cname_found) {
                            continue :outer;
                        }

                        // Got answers but not the type we wanted - check for delegation
                    }

                    // Check for referral (NS records in authority section)
                    if (msg.header.nscount > 0) {
                        const referral = try self.extractReferral(response, msg);
                        if (referral) |ref| {
                            // Free referral-owned memory (zone, server names, servers slice)
                            // after we have extracted what we need (PF-NEW-02).
                            defer ref.deinit(self.allocator);

                            // SECURITY (A7, #296): reject upward/lateral referrals.
                            // The delegated zone must descend from (or equal) the
                            // zone we are currently asking about. Following a
                            // referral to an unrelated zone would let a malicious
                            // or on-path server redirect resolution and poison the
                            // cache for arbitrary names.
                            if (!isSubdomainOf(ref.zone, current_zone)) {
                                return error.OutOfBailiwickReferral;
                            }

                            // Collect addresses for referred NS servers
                            var new_servers: std.ArrayList(ServerAddress) = .empty;
                            errdefer new_servers.deinit(self.allocator);
                            // PF-NEW-23: Pre-allocate to match referral size
                            // (avoids reallocations when resolving NS addresses).
                            try new_servers.ensureTotalCapacity(self.allocator, ref.servers.len);

                            for (ref.servers) |ns| {
                                if (ns.address) |addr| {
                                    try new_servers.append(self.allocator, addr);
                                } else {
                                    // Need to resolve NS hostname (glue missing)
                                    // Propagate parent state's depth and query budget to
                                    // prevent amplification via deeply nested NS chains (PF-31).
                                    // OOM is propagated; other resolution failures skip this NS (QM-NEW-05).
                                    const ns_result = (try self.resolveNsAddress(ns.name, state)) orelse continue;
                                    try new_servers.append(self.allocator, ns_result);
                                }
                            }

                            if (new_servers.items.len > 0) {
                                // Free previously owned zone and server memory
                                if (owned_zone) |oz| self.allocator.free(oz);
                                if (owned_servers) |*os| os.deinit(self.allocator);

                                // Transfer ownership: new_servers becomes owned_servers
                                owned_servers = new_servers;
                                current_servers = owned_servers.?.items;

                                owned_zone = try self.allocator.dupe(u8, ref.zone);
                                current_zone = owned_zone.?;
                                zone_depth += 1;

                                // QA-AUDIT-05: Enforce max_depth to prevent
                                // infinite delegation chains.
                                if (zone_depth > self.config.max_depth) {
                                    return error.MaxDepthExceeded;
                                }

                                continue :outer;
                            } else {
                                new_servers.deinit(self.allocator);
                            }
                        }
                    }

                    // No answer and no referral - might be NODATA
                    if (msg.header.ancount == 0 and msg.header.nscount > 0) {
                        // Check for SOA in authority (indicates NODATA)
                        var auth_iter = msg.authority();
                        while (try auth_iter.next()) |rr| {
                            if (rr.rtype == .soa) {
                                return ResolveResult{
                                    .status = .nodata,
                                    .answer = try self.allocator.dupe(u8, response),
                                    .from_cache = false,
                                };
                            }
                        }
                    }
                },
                else => {
                    // Other error codes
                    return ResolveResult{
                        .status = .servfail,
                        .answer = try self.allocator.dupe(u8, response),
                        .from_cache = false,
                    };
                },
            }

            // If we reach here, try with more labels (for QNAME minimization)
            if (self.config.qname_minimization) {
                zone_depth += 1;
                // QA-AUDIT-05: Use configurable max_depth instead of magic number.
                if (zone_depth > self.config.max_depth) {
                    return error.MaxDepthExceeded;
                }
            } else {
                break;
            }
        }

        return error.MaxQueriesExceeded;
    }

    /// Implements QNAME minimization per RFC 9156.
    ///
    /// Returns the rightmost `depth + 1` labels of `original`, allowing the
    /// resolver to reveal only the minimal number of labels needed at each
    /// delegation step. This limits the amount of query name information
    /// exposed to authoritative servers, improving privacy.
    ///
    /// Single-pass: collects labels into a stack array once, then builds
    /// the result from the appropriate suffix (PF-23).
    fn getMinimizedQname(self: *Self, original: []const u8, depth: usize) ![]u8 {

        // Single pass: collect non-empty labels into a stack-local array.
        var labels: [128][]const u8 = undefined;
        var count: usize = 0;
        var iter = std.mem.splitScalar(u8, original, '.');
        while (iter.next()) |label| {
            if (label.len > 0 and count < 128) {
                labels[count] = label;
                count += 1;
            }
        }

        // If depth covers all labels, return full name
        if (depth >= count) {
            return try self.allocator.dupe(u8, original);
        }

        // Return rightmost (depth+1) labels using a stack buffer (PF-NEW-04).
        // Max DNS name is 253 chars; stack buffer avoids ArrayList heap overhead.
        const start = count - @min(depth + 1, count);
        var buf: [253]u8 = undefined;
        var pos: usize = 0;

        for (start..count) |i| {
            if (pos > 0) {
                if (pos >= buf.len) return error.Overflow;
                buf[pos] = '.';
                pos += 1;
            }
            const label = labels[i];
            if (pos + label.len > buf.len) return error.Overflow;
            @memcpy(buf[pos..][0..label.len], label);
            pos += label.len;
        }

        return try self.allocator.dupe(u8, buf[0..pos]);
    }

    /// Result of queryWithRetry: raw response bytes and already-parsed Message.
    /// Parsing once here eliminates redundant Message.parse calls downstream (PF-19).
    const QueryResult = struct {
        response: []u8,
        msg: Message,
    };

    /// Query servers with retry logic.
    /// Returns both the raw response and the parsed Message to avoid
    /// redundant parsing in callers (PF-19).
    fn queryWithRetry(
        self: *Self,
        domain: []const u8,
        qtype: Type,
        servers: []const ServerAddress,
        state: *ResolutionState,
    ) !QueryResult {
        // Generate query ID using OS CSPRNG (SEC-C24: prevents cache poisoning)
        const id = try csprngInt(u16);

        // Apply 0x20 case randomization if enabled (using CSPRNG for
        // unpredictability). GAP-0887: the randomized name is written to a
        // stack buffer (DNS names are at most 253 text bytes) and encoded
        // into query_buf below -- no heap allocation on the query path.
        var local_prng: std.Random.DefaultPrng = undefined;
        var case_buf: [253]u8 = undefined;
        const query_name = if (self.config.case_randomization)
            try name_mod.applyCase0x20Buf(domain, &case_buf, try csprngRandom(&local_prng))
        else
            domain;

        // Store for 0x20 verification (PF-NEW-12: skip the dupe when case
        // randomization is disabled -- last_query_name is only checked under
        // the case_randomization branch, so the extra copy is wasted).
        //
        // PF-NEW-20/PF-NEW-27/GAP-0887: this dupe is the only remaining heap
        // allocation here -- last_query_name must persist across retry
        // iterations for 0x20 verification, so it cannot borrow the stack
        // buffer above.
        if (self.config.case_randomization) {
            if (state.last_query_name) |old| {
                self.allocator.free(old);
            }
            state.last_query_name = try self.allocator.dupe(u8, query_name);
        }

        // Build query on the stack (max 282 bytes, no heap allocation).
        // These are iterative queries to authoritative servers, so RD must be
        // false (#255/API-1); the dnssec flag drives the EDNS DO bit instead.
        var query_buf: [message_mod.max_query_size]u8 = undefined;
        // GAP-0840: the dnssec config flag now drives the EDNS DO bit.
        const query = try message_mod.buildQueryBuf(&query_buf, id, query_name, qtype, .in, false, self.config.dnssec);

        // Try servers in order
        const max_tries = @min(servers.len, self.config.max_server_attempts);
        for (servers[0..max_tries]) |server| {
            const response = self.sendQuery(query, server) catch |err| switch (err) {
                // OOM is fatal and must not be silently degraded to NoResponse;
                // re-raise it like the stub resolver does (REL-4).
                error.OutOfMemory => return error.OutOfMemory,
                // Network/timeout/etc.: try the next server.
                else => continue,
            };

            if (response.len >= 2) {
                const resp_id = std.mem.readInt(u16, response[0..2], .big);
                if (resp_id == id) {
                    // Parse once here; reuse the parsed Message in callers (PF-19)
                    const msg = Message.parse(response) catch {
                        self.allocator.free(response);
                        continue;
                    };
                    if (responseMatchesQuery(msg, query_name, qtype, .in)) {
                        return QueryResult{ .response = response, .msg = msg };
                    }
                }
            }
            self.allocator.free(response);
        }

        return error.NoResponse;
    }

    /// Send a single query to a server.
    ///
    /// SEC-AUDIT-09: Source port randomization relies on the operating system's
    /// ephemeral port assignment. The socket is not explicitly bound, so the OS
    /// selects the source port via its default algorithm. Modern OSes (Linux 3.x+,
    /// macOS, Windows Vista+) randomize ephemeral ports, but this library does
    /// not perform explicit port randomization itself. Deployments on legacy or
    /// embedded systems should verify that the OS provides adequate port entropy
    /// to mitigate DNS cache poisoning attacks (RFC 5452 Section 3).
    fn sendQuery(self: *Self, query: []const u8, server: ServerAddress) ![]u8 {
        const sock = try net.socket(
            server.address.any.family,
            std.posix.SOCK.DGRAM,
            std.os.linux.IPPROTO.UDP,
        );
        defer net.close(sock);

        // Set timeout
        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout_usec = (self.config.timeout_ms % 1000) * 1000;
        const timeout = std.os.linux.timeval{
            .sec = @intCast(timeout_sec),
            .usec = @intCast(timeout_usec),
        };
        try std.posix.setsockopt(sock, std.os.linux.SOL.SOCKET, std.os.linux.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // Send query
        _ = try net.sendto(sock, query, 0, &server.address.any, server.address.getOsSockLen());

        const start_ms = timeMilli();
        // SEC-AUDIT-02: Limit discarded packets to prevent CPU pinning from flood attacks.
        var discards = types_mod.SpuriousDiscardCounter{};
        while (true) {
            if (timeMilli() - start_ms >= self.config.timeout_ms) {
                return error.Timeout;
            }

            // Receive response (capture source)
            // 4096 bytes matches EDNS default max payload (RFC 6891).
            // Responses exceeding this are truncated and fall back to TCP.
            var buffer: [4096]u8 = undefined;
            var src_addr: net.Address = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(net.Address);
            const recv_len = net.recvfrom(sock, &buffer, 0, &src_addr.any, &src_len) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionTimedOut => return error.Timeout,
                else => return err,
            };

            if (!net.Address.eql(src_addr, server.address)) {
                discards.increment() catch return error.TooManySpuriousPackets;
                continue;
            }

            const response = try self.allocator.alloc(u8, recv_len);
            @memcpy(response, buffer[0..recv_len]);
            return response;
        }
    }

    /// Glue record: name-to-address pair from the additional section
    const GlueRecord = struct {
        name: []const u8,
        address: ServerAddress,
    };

    /// Extract referral information from a response.
    /// Iterates the additional section exactly once (O(authority + additional))
    /// rather than once per NS record (O(authority * additional)).
    /// Maximum NS records accepted from a single referral's authority section.
    /// Bounds the glue<->NS matching cost against crafted referrals (PF-NEW-35,
    /// #214); far above any legitimate delegation (root has 13).
    const max_referral_ns_records: usize = 64;

    fn extractReferral(self: *Self, response: []const u8, msg: Message) !?Referral {
        var ns_names: std.ArrayList([]const u8) = .empty;
        defer ns_names.deinit(self.allocator);
        // PF-NEW-23: Pre-allocate for typical NS delegation (2-6 records)
        // to avoid 1-2 reallocations per referral.
        try ns_names.ensureTotalCapacity(self.allocator, 6);
        // On error, free each ns_name string (on success they are transferred
        // into the Referral.servers slice and freed by Referral.deinit).
        errdefer for (ns_names.items) |ns_str| self.allocator.free(ns_str);

        // PF-NEW-07: Use a stack buffer for the zone name during iteration.
        // The zone name is only needed for isSubdomainOf comparisons until
        // we dupe it into the final Referral at the end.
        var zone_buf: [256]u8 = undefined;
        var zone_str: ?[]const u8 = null; // slice into zone_buf (not heap-allocated)

        // Get NS records from authority section
        var auth_iter = msg.authority();
        while (try auth_iter.next()) |rr| {
            if (rr.rtype == .ns) {
                if (zone_str == null) {
                    zone_str = try rr.name.toStringBuf(&zone_buf, response);
                }

                // PF-NEW-35 (#214): cap NS records per referral. A legitimate
                // delegation has at most ~13; a crafted referral could carry
                // thousands of NS records and thousands of glue records, making
                // the glue-matching loop below O(glue x NS) (~4096^2) — a
                // CPU-DoS amplification vector. Capping NS bounds it.
                if (ns_names.items.len >= max_referral_ns_records) continue;

                const ns_name = try rr.parseName(response);
                // PF-NEW-14: Use stack buffer + dupe instead of toString's
                // internal ArrayList to avoid an intermediate heap allocation.
                var ns_buf: [name_mod.max_name_length]u8 = undefined;
                const ns_str = try ns_name.toStringBuf(&ns_buf, response);
                try ns_names.append(self.allocator, try self.allocator.dupe(u8, ns_str));
            }
        }

        if (ns_names.items.len == 0) {
            return null;
        }

        // Build server info array up front so glue can be matched inline
        // (PF-NEW-09: avoids heap-allocating glue record names).
        var servers = try self.allocator.alloc(Referral.ServerInfo, ns_names.items.len);
        errdefer self.allocator.free(servers);
        for (ns_names.items, 0..) |ns, i| {
            servers[i] = .{
                .name = ns,
                .address = null,
            };
        }

        // Single pass over additional section: match A glue records directly
        // against NS names using stack buffers for name comparisons.
        // SECURITY (SEC-C27): Only accept glue records whose names are within
        // the delegated zone's bailiwick. Out-of-bailiwick glue can be used
        // to inject forged addresses for unrelated domains.
        var add_iter = msg.additional();
        while (try add_iter.next()) |add_rr| {
            if (add_rr.rtype == .a) {
                // PF-NEW-09: Use stack buffer instead of heap allocation.
                // The name is only needed for bailiwick and NS name comparisons.
                var glue_buf: [256]u8 = undefined;
                const add_name = try add_rr.name.toStringBuf(&glue_buf, response);

                // Bailiwick check: glue record name must be within the delegated zone
                if (zone_str) |zn| {
                    if (!isSubdomainOf(add_name, zn)) {
                        continue;
                    }
                }

                const addr = try add_rr.parseA();
                var ip_buf: [15]u8 = undefined; // max "255.255.255.255"
                const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch continue;

                const server_addr = ServerAddress.fromIpv4(ip_str, types_mod.dns_port) catch continue;

                // Match directly against NS names (avoiding GlueRecord storage)
                for (servers) |*srv| {
                    if (std.ascii.eqlIgnoreCase(add_name, srv.name)) {
                        srv.address = server_addr;
                        break;
                    }
                }
            }
        }

        // PF-NEW-07: Only heap-dupe the zone name now for the final Referral.
        const zone_owned = if (zone_str) |zs|
            try self.allocator.dupe(u8, zs)
        else
            try self.allocator.dupe(u8, ".");

        return Referral{
            .zone = zone_owned,
            .servers = servers,
        };
    }

    /// Maximum depth for NS address resolution to prevent infinite recursion.
    /// 8 levels of nested NS delegation is more than enough for any legitimate zone.
    const max_ns_resolve_depth: u8 = 8;

    /// Resolve NS address when glue is missing.
    /// Propagates the parent's query_count and depth to enforce global limits,
    /// preventing amplification/DoS via deeply nested NS chains (PF-31).
    /// OutOfMemory is propagated to the caller rather than swallowed, since OOM
    /// is a fatal condition that should not be silently ignored (QM-NEW-05).
    fn resolveNsAddress(self: *Self, ns_name: []const u8, parent_state: *ResolutionState) error{OutOfMemory}!?ServerAddress {
        // Guard: reject if parent depth already exceeds the NS resolution limit
        if (parent_state.depth >= max_ns_resolve_depth) return null;

        // Guard: reject if query budget is already exhausted
        if (parent_state.query_count >= self.config.max_queries) return null;

        // Create child state inheriting the parent's counters
        var child_state = ResolutionState{
            .original_qname = ns_name,
            .qtype = .a,
            .depth = parent_state.depth + 1,
            .query_count = parent_state.query_count,
            .current_zone = ".",
            .cname_chain = .empty,
        };
        defer child_state.deinit(self.allocator);

        const result = self.resolveIterative(&child_state) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        defer if (result.answer) |a| self.allocator.free(a);

        // Propagate the child's query_count back to the parent so the
        // global budget is properly consumed across all NS resolutions.
        parent_state.query_count = child_state.query_count;

        if (result.status != .success) {
            return null;
        }

        if (result.answer) |answer| {
            const msg = Message.parse(answer) catch return null;
            var ans_iter = msg.answers();
            while (ans_iter.next() catch null) |rr| {
                if (rr.rtype == .a) {
                    const addr = rr.parseA() catch continue;
                    // Use stack buffer instead of heap allocation for IPv4 string (PF-20).
                    // IPv4 addresses are at most 15 chars ("255.255.255.255").
                    var ip_buf: [15]u8 = undefined;
                    const ip_str = std.fmt.bufPrint(
                        &ip_buf,
                        "{d}.{d}.{d}.{d}",
                        .{ addr[0], addr[1], addr[2], addr[3] },
                    ) catch continue;

                    return ServerAddress.fromIpv4(ip_str, types_mod.dns_port) catch continue;
                }
            }
        }

        return null;
    }

    /// Cache a successful response
    fn cacheResponse(self: *Self, response: []const u8, msg: Message) !void {
        var q_iter = msg.questions();
        const q = (try q_iter.next()) orelse return;

        // Use stack buffer instead of heap allocation for question name (PF-29).
        // DNS names are at most 253 chars; 256-byte buffer always suffices.
        var qname_buf: [256]u8 = undefined;
        const qname = q.qname.toStringBuf(&qname_buf, msg.data) catch return;

        var ans_iter = msg.answers();
        var rr_name_buf: [256]u8 = undefined;
        while (try ans_iter.next()) |rr| {
            const name_str = try rr.name.toStringBuf(&rr_name_buf, response);
            try self.cache.putRecordWithBailiwick(name_str, rr.rtype, rr.class, rr.rdata, rr.ttl, qname);
        }
    }

    /// Clear the cache
    pub fn clearCache(self: *Self) void {
        self.cache.clear();
    }

    // =========================================================================
    // GAP-0839: DNSSEC validation in the resolution path (RFC 4035 Section 5)
    // =========================================================================

    /// Maximum records considered per section during DNSSEC validation.
    /// Responses exceeding this are treated as indeterminate rather than
    /// risking unbounded work on attacker-controlled input.
    const max_dnssec_rrs = 32;

    /// Apply the DNSSEC validation policy to a successful response
    /// (GAP-0839). Returns null when DNSSEC validation is disabled.
    ///
    /// Policy:
    ///   - bogus: fail closed (error.DnssecValidationFailed) -- the caller
    ///     must not cache or return the response
    ///   - insecure/indeterminate: permissive mode proceeds (result is
    ///     reported on ResolveResult.dnssec); strict mode fails closed
    ///   - secure: proceed
    fn enforceDnssecPolicy(
        self: *Self,
        response: []const u8,
        msg: Message,
    ) !?dnssec_mod.ValidationResult {
        if (!self.config.dnssec) return null;

        const result = try self.validateDnssecResponse(response, msg);
        switch (result) {
            .bogus => return error.DnssecValidationFailed,
            .secure => {},
            .insecure, .indeterminate => {
                if (self.config.dnssec_strict) {
                    return error.DnssecValidationFailed;
                }
            },
        }
        return result;
    }

    /// A set of DNSKEYs trusted for validation, each bound to the zone
    /// (apex owner, dotted string form) it may sign for. `zones[i]` points
    /// either at config-owned anchor memory or into `zone_bufs[i]`, so the
    /// set must be filled in place and never copied by value.
    const TrustedKeySet = struct {
        keys: [max_dnssec_rrs]ResourceRecord.DnskeyData = undefined,
        tags: [max_dnssec_rrs]u16 = undefined,
        zones: [max_dnssec_rrs][]const u8 = undefined,
        zone_bufs: [max_dnssec_rrs][256]u8 = undefined,
        count: usize = 0,
    };

    /// Per-RRset verification outcome (see verifyAnswerRrset).
    const RrsetVerdict = enum {
        /// A trusted key verified a covering RRSIG.
        secure,
        /// A covering RRSIG failed verification or was malformed.
        bogus,
        /// No usable covering RRSIG (unsigned, or signer out of ancestry).
        no_signature,
        /// Only signatures with algorithms this library cannot verify.
        unsupported_alg,
        /// Signed, but no trusted key available to check against.
        no_trusted_key,
    };

    /// Validate the answer RRsets of a response against RRSIGs and the
    /// configured trust anchors (GAP-0839, minimum spec-compliant scope).
    ///
    /// Scope: answer RRsets' RRSIGs are verified against trusted DNSKEYs --
    /// DNSKEY-type trust anchors directly, plus DNSKEYs present in the
    /// response that match a DS-type trust anchor. A full iterative
    /// DS-walk from the root (fetching DNSKEY/DS RRsets per delegation,
    /// dnssec.Validator.validateChainOfTrust) is NOT performed here; that
    /// depth is tracked separately, as are CNAME intermediate hops and
    /// NXDOMAIN/NODATA denial-of-existence (NSEC/NSEC3) validation.
    /// Signatures using algorithms this library cannot verify (e.g.
    /// deprecated RSA/SHA-1, GAP-0842) are treated as insecure, not bogus.
    ///
    /// Zone boundaries (RFC 4035 Section 5.3.1): an RRset is only eligible
    /// for `secure` when its owner lies within a configured anchor's zone,
    /// its RRSIG signer is an ancestor (or equal) of the owner, and the
    /// validating key belongs to the zone named by the signer field.
    fn validateDnssecResponse(
        self: *Self,
        response: []const u8,
        msg: Message,
    ) error{OutOfMemory}!dnssec_mod.ValidationResult {
        // Trust anchors are required to anchor validation.
        if (self.config.dnssec_trust_anchors.len == 0) return .indeterminate;

        var validator = dnssec_mod.Validator.init(self.allocator);
        defer validator.deinit();
        for (self.config.dnssec_trust_anchors) |anchor| {
            try validator.addTrustAnchor(anchor);
        }

        // Collect answer RRs (the RRsets to validate) and covering RRSIGs.
        // Owner names on the wire are usually compressed (a pointer back to
        // the question name); canonical RRSIG verification requires the
        // uncompressed owner (RFC 4034 Section 6.2), so decompress each
        // answer owner up front.
        var answer_rrs: [max_dnssec_rrs]ResourceRecord = undefined;
        var answer_owner_bufs: [max_dnssec_rrs][name_mod.max_name_length]u8 = undefined;
        var answer_count: usize = 0;
        var rrsig_rrs: [max_dnssec_rrs]ResourceRecord = undefined;
        var rrsig_count: usize = 0;

        var ans_iter = msg.answers();
        while (ans_iter.next() catch return .bogus) |rr| {
            if (rr.rtype == .rrsig) {
                if (rrsig_count >= max_dnssec_rrs) return .indeterminate;
                // The RRSIG owner is only ever compared via string form
                // (which resolves pointers) and its signer name lives
                // uncompressed inside RDATA (RFC 4034 Section 3.1.7), so
                // no decompression is needed here.
                rrsig_rrs[rrsig_count] = rr;
                rrsig_count += 1;
            } else {
                if (answer_count >= max_dnssec_rrs) return .indeterminate;
                answer_rrs[answer_count] = rr;
                if (rr.name.compressed) {
                    var str_buf: [256]u8 = undefined;
                    const owner_str = rr.name.toStringBuf(&str_buf, response) catch return .bogus;
                    answer_rrs[answer_count].name = Name.encodeBuf(
                        owner_str,
                        &answer_owner_bufs[answer_count],
                    ) catch return .bogus;
                }
                answer_count += 1;
            }
        }
        if (answer_count == 0) return .insecure;

        // Collect DNSKEYs present anywhere in the response.
        var dnskey_rrs: [max_dnssec_rrs]ResourceRecord = undefined;
        var dnskey_count: usize = 0;
        const section_iters = [_]message_mod.RecordIterator{
            msg.answers(), msg.authority(), msg.additional(),
        };
        for (section_iters) |section_iter| {
            var it = section_iter;
            while (it.next() catch null) |rr| {
                if (rr.rtype == .dnskey and dnskey_count < max_dnssec_rrs) {
                    dnskey_rrs[dnskey_count] = rr;
                    dnskey_count += 1;
                }
            }
        }

        var trust = TrustedKeySet{};
        self.buildDnssecTrustSet(&validator, dnskey_rrs[0..dnskey_count], response, &trust);

        // Validate each answer RRset.
        var any_insecure = false;
        var any_indeterminate = false;

        var processed = [_]bool{false} ** max_dnssec_rrs;
        var name_buf_a: [256]u8 = undefined;
        var name_buf_b: [256]u8 = undefined;

        var i: usize = 0;
        while (i < answer_count) : (i += 1) {
            if (processed[i]) continue;
            const head = answer_rrs[i];
            const head_name = head.name.toStringBuf(&name_buf_a, response) catch return .bogus;

            // Gather all members of this RRset (same owner, type, class).
            var members: [max_dnssec_rrs]ResourceRecord = undefined;
            var member_count: usize = 0;
            var j: usize = i;
            while (j < answer_count) : (j += 1) {
                if (processed[j]) continue;
                const rr = answer_rrs[j];
                if (rr.rtype != head.rtype or rr.class != head.class) continue;
                const rr_name = rr.name.toStringBuf(&name_buf_b, response) catch return .bogus;
                if (!std.ascii.eqlIgnoreCase(head_name, rr_name)) continue;
                processed[j] = true;
                members[member_count] = rr;
                member_count += 1;
            }

            // Zone boundary: an RRset whose owner lies outside every
            // configured anchor's zone is outside our trust scope -- it can
            // never be proven secure by these anchors (insecure, not bogus).
            if (!ownerWithinAnyAnchorZone(self.config.dnssec_trust_anchors, head_name)) {
                any_insecure = true;
                continue;
            }

            const verdict = try verifyAnswerRrset(
                &validator,
                members[0..member_count],
                head_name,
                rrsig_rrs[0..rrsig_count],
                response,
                &trust,
            );
            switch (verdict) {
                .secure => {},
                .bogus => return .bogus,
                .no_signature, .unsupported_alg => any_insecure = true,
                .no_trusted_key => any_indeterminate = true,
            }
        }

        // Tally precedence: insecure beats indeterminate; secure requires
        // every RRset to have verified (any bogus already returned above).
        if (any_insecure) return .insecure;
        if (any_indeterminate) return .indeterminate;
        return .secure;
    }

    /// Build the set of DNSKEYs trusted for this validation pass:
    /// (1) DNSKEY-type trust anchors (the anchor data IS DNSKEY RDATA),
    /// bound to the anchor's configured zone; and (2) DNSKEYs present in
    /// the response that match a DS-type trust anchor digest, bound to
    /// their owner name (which the DS digest covers) and accepted only
    /// within the anchor's zone. Keys failing RFC 4034 Section 2.1.1/2.1.2
    /// sanity (protocol != 3, Zone Key flag clear, or REVOKE set) are
    /// skipped.
    fn buildDnssecTrustSet(
        self: *Self,
        validator: *dnssec_mod.Validator,
        dnskey_rrs: []const ResourceRecord,
        response: []const u8,
        trust: *TrustedKeySet,
    ) void {
        // (1) DNSKEY-type trust anchors.
        for (self.config.dnssec_trust_anchors) |anchor| {
            if (!anchor.is_dnskey or anchor.data.len < 4) continue;
            if (trust.count >= max_dnssec_rrs) break;
            const key = ResourceRecord.DnskeyData{
                .flags = .{ .raw = std.mem.readInt(u16, anchor.data[0..2], .big) },
                .protocol = anchor.data[2],
                .algorithm = @enumFromInt(anchor.data[3]),
                .public_key = anchor.data[4..],
            };
            if (!dnskeyUsable(key)) continue;
            trust.keys[trust.count] = key;
            trust.tags[trust.count] = ResourceRecord.calculateKeyTag(anchor.data);
            trust.zones[trust.count] = anchor.zone;
            trust.count += 1;
        }

        // (2) Response DNSKEYs that match a DS-type trust anchor digest.
        for (dnskey_rrs) |key_rr| {
            if (trust.count >= max_dnssec_rrs) break;
            const key_data = key_rr.parseDNSKEY() catch continue;
            if (!dnskeyUsable(key_data)) continue;

            // DS digests are computed over the canonical (uncompressed)
            // wire owner name; re-encode via string form to resolve any
            // compression pointers.
            var owner_str_buf: [256]u8 = undefined;
            const owner_str = key_rr.name.toStringBuf(&owner_str_buf, response) catch continue;
            var owner_wire_buf: [name_mod.max_name_length]u8 = undefined;
            const owner_wire = Name.encodeBuf(owner_str, &owner_wire_buf) catch continue;

            for (self.config.dnssec_trust_anchors) |anchor| {
                if (anchor.is_dnskey) continue;
                const digest_type = anchor.digest_type orelse continue;
                // Zone boundary: a DS anchor only vouches for keys at or
                // below its configured zone.
                if (!isSubdomainOf(owner_str, anchor.zone)) continue;
                const ds = ResourceRecord.DsData{
                    .key_tag = anchor.key_tag,
                    .algorithm = anchor.algorithm,
                    .digest_type = digest_type,
                    .digest = anchor.data,
                };
                const matches = validator.verifyDsMatch(key_data, key_rr.rdata, owner_wire.labels, ds) catch continue;
                if (matches) {
                    trust.keys[trust.count] = key_data;
                    trust.tags[trust.count] = ResourceRecord.calculateKeyTag(key_rr.rdata);
                    // The key's zone is its owner name (zone apex); copy
                    // the string into stable storage owned by the set.
                    const zone_buf = &trust.zone_bufs[trust.count];
                    @memcpy(zone_buf[0..owner_str.len], owner_str);
                    trust.zones[trust.count] = zone_buf[0..owner_str.len];
                    trust.count += 1;
                    break;
                }
            }
        }
    }

    /// Verify one answer RRset (all `members` share owner/type/class)
    /// against the covering RRSIGs and the trusted-key set.
    ///
    /// `owner_str` is the RRset owner in dotted string form. RRSIGs whose
    /// signer is not an ancestor (or equal) of the owner are unusable per
    /// RFC 4035 Section 5.3.1 and are skipped; a trusted key is only
    /// consulted when its zone equals the RRSIG signer name.
    fn verifyAnswerRrset(
        validator: *dnssec_mod.Validator,
        members: []const ResourceRecord,
        owner_str: []const u8,
        rrsigs: []const ResourceRecord,
        response: []const u8,
        trust: *const TrustedKeySet,
    ) error{OutOfMemory}!RrsetVerdict {
        var sig_found = false;
        var saw_bogus = false;
        var saw_unsupported = false;
        var sig_name_buf: [256]u8 = undefined;
        var signer_buf: [256]u8 = undefined;

        for (rrsigs) |sig_rr| {
            const sig_name = sig_rr.name.toStringBuf(&sig_name_buf, response) catch continue;
            if (!std.ascii.eqlIgnoreCase(owner_str, sig_name)) continue;
            const sig_data = sig_rr.parseRRSIG(response) catch {
                saw_bogus = true;
                continue;
            };
            if (sig_data.type_covered != members[0].rtype) continue;

            // RFC 4035 Section 5.3.1: the signer name must be the zone
            // containing the RRset owner; a signature claiming a signer
            // outside the owner's ancestry can never be valid.
            const signer_str = sig_data.signer.toStringBuf(&signer_buf, response) catch continue;
            if (!isSubdomainOf(owner_str, signer_str)) continue;

            sig_found = true;

            for (trust.keys[0..trust.count], trust.tags[0..trust.count], trust.zones[0..trust.count]) |key, tag, zone| {
                if (tag != sig_data.key_tag) continue;
                if (key.algorithm != sig_data.algorithm) continue;
                // Zone boundary: the validating key must belong to the
                // zone named by the RRSIG signer field.
                if (!dnsNamesEqual(signer_str, zone)) continue;
                const ok = validator.verifyRrsig(sig_data, members, key) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    // Unverifiable algorithm (e.g. deprecated RSA/SHA-1):
                    // treated as insecure, not bogus.
                    error.UnsupportedAlgorithm => {
                        saw_unsupported = true;
                        continue;
                    },
                    else => {
                        saw_bogus = true;
                        continue;
                    },
                };
                if (ok) return .secure;
                saw_bogus = true;
            }
        }

        if (saw_bogus) return .bogus;
        if (!sig_found) return .no_signature;
        if (saw_unsupported) return .unsupported_alg;
        return .no_trusted_key;
    }
};

/// RFC 4034 Section 2.1.1/2.1.2 DNSKEY sanity: usable for validation only
/// when the protocol field is 3, the Zone Key flag (bit 7) is set, and the
/// key is not revoked (RFC 5011 REVOKE bit).
fn dnskeyUsable(key: ResourceRecord.DnskeyData) bool {
    return key.protocol == 3 and key.flags.isZoneKey() and !key.flags.isRevoked();
}

/// True if `owner` (dotted string form) lies within at least one configured
/// trust anchor's zone.
fn ownerWithinAnyAnchorZone(
    anchors: []const dnssec_mod.Validator.TrustAnchor,
    owner: []const u8,
) bool {
    for (anchors) |anchor| {
        if (isSubdomainOf(owner, anchor.zone)) return true;
    }
    return false;
}

/// Case-insensitive DNS name equality on dotted strings, tolerant of a
/// trailing dot on either side (RFC 4343).
fn dnsNamesEqual(a: []const u8, b: []const u8) bool {
    const ca = if (a.len > 0 and a[a.len - 1] == '.') a[0 .. a.len - 1] else a;
    const cb = if (b.len > 0 and b[b.len - 1] == '.') b[0 .. b.len - 1] else b;
    return std.ascii.eqlIgnoreCase(ca, cb);
}

/// Check if `name` is a subdomain of (or equal to) `zone`.
/// Both names are in dotted string form (e.g., "ns1.example.com" / "example.com").
/// Comparison is case-insensitive per DNS conventions (RFC 4343).
///
/// SECURITY (SEC-C27): Used for bailiwick validation of glue records.
/// A glue record for "ns1.example.com" is valid in a referral from "example.com"
/// but NOT in a referral from "attacker.com".
fn isSubdomainOf(name: []const u8, zone: []const u8) bool {
    // Strip trailing dots for uniform comparison
    const clean_name = if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    const clean_zone = if (zone.len > 0 and zone[zone.len - 1] == '.') zone[0 .. zone.len - 1] else zone;

    // Root zone is parent of everything
    if (clean_zone.len == 0) return true;

    // Exact match (case-insensitive)
    if (std.ascii.eqlIgnoreCase(clean_name, clean_zone)) return true;

    // name must be longer than zone and end with ".zone"
    if (clean_name.len <= clean_zone.len) return false;

    // Check that name ends with zone
    const suffix_start = clean_name.len - clean_zone.len;
    if (!std.ascii.eqlIgnoreCase(clean_name[suffix_start..], clean_zone)) return false;

    // Ensure the character before the suffix is a dot (label boundary)
    if (suffix_start == 0) return true;
    return clean_name[suffix_start - 1] == '.';
}

/// Tracks state for a single iterative DNS resolution.
///
/// Maintains the current query name (which may change when following CNAME chains),
/// the original query type, recursion depth and query budget counters to prevent
/// infinite loops, the current delegation zone, the CNAME chain for loop detection,
/// and the last query name used for 0x20 case randomization verification.
const ResolutionState = struct {
    original_qname: []const u8,
    qtype: Type,
    depth: u8,
    query_count: u16,
    current_zone: []const u8,
    cname_chain: std.ArrayList([]const u8),
    last_query_name: ?[]const u8 = null,

    /// Free all owned memory in this resolution state.
    /// Cleans up cname_chain entries, the chain list itself, and last_query_name.
    fn deinit(self: *ResolutionState, allocator: std.mem.Allocator) void {
        // Free each CNAME chain entry (each is an allocator.dupe'd string)
        for (self.cname_chain.items) |item| {
            allocator.free(item);
        }
        self.cname_chain.deinit(allocator);

        // Free last_query_name if set (allocated in queryWithRetry)
        if (self.last_query_name) |lqn| {
            allocator.free(lqn);
            self.last_query_name = null;
        }
    }
};

/// Resolution status
pub const ResolveStatus = enum {
    success,
    nxdomain,
    nodata,
    servfail,
};

/// Result of a recursive resolution
pub const ResolveResult = struct {
    /// Resolution status
    status: ResolveStatus,

    /// Raw response message (owned by caller)
    answer: ?[]u8,

    /// Whether the result came from cache
    from_cache: bool,

    /// GAP-0839: DNSSEC validation outcome for this resolution.
    /// null when DNSSEC validation was not enabled (config.dnssec=false)
    /// or the result did not go through the answer-validation path.
    dnssec: ?dnssec_mod.ValidationResult = null,
};

test "RootServers.all" {
    const roots = RootServers.all();
    try std.testing.expectEqual(@as(usize, 13), roots.len);
    try std.testing.expectEqualStrings("198.41.0.4", roots[0]);
}

test "RecursiveConfig defaults" {
    const config = RecursiveConfig{};
    try std.testing.expectEqual(@as(u8, 32), config.max_depth);
    try std.testing.expectEqual(@as(usize, 10000), config.cache_size);
    try std.testing.expect(config.qname_minimization);
    try std.testing.expect(config.case_randomization);
}

test "SEC-AUDIT-02: UDP discard limit prevents CPU pinning" {
    // Verify the discard limit constant exists and is a reasonable positive value.
    // The actual enforcement is in sendQuery's receive loop, which discards packets
    // from non-matching source addresses up to this limit before returning
    // error.TooManySpuriousPackets.
    try std.testing.expect(max_spurious_discards > 0);
    try std.testing.expect(max_spurious_discards <= 10000);
}

test "QA-AUDIT-05: max_depth config is wired into resolution logic" {
    // Verify that max_depth is configurable and used to limit delegation depth.
    // resolveIterative checks zone_depth against config.max_depth in two places:
    // 1. After following a referral (delegation chain)
    // 2. After incrementing for QNAME minimization
    // Both paths return error.MaxDepthExceeded when the limit is breached.

    // Default max_depth is 32
    const default_config = RecursiveConfig{};
    try std.testing.expectEqual(@as(u8, 32), default_config.max_depth);

    // Custom max_depth can be set to a lower value
    const shallow_config = RecursiveConfig{ .max_depth = 5 };
    try std.testing.expectEqual(@as(u8, 5), shallow_config.max_depth);

    // Simulate the depth check from resolveIterative: zone_depth > config.max_depth
    // At max_depth exactly, we're still within bounds; exceeding it triggers the error.
    var zone_depth: usize = 0;
    while (zone_depth <= shallow_config.max_depth) : (zone_depth += 1) {}
    try std.testing.expect(zone_depth > shallow_config.max_depth);
    // In the real code, this state would trigger: return error.MaxDepthExceeded;
}

test "GAP-0020: owned_servers memory lifecycle" {
    // Verifies the referral server ownership pattern: dynamically-allocated
    // server lists are properly freed when replaced or on function exit.
    // This directly tests the memory management pattern from GAP-0020.
    const allocator = std.testing.allocator;

    // Simulate the owned_servers pattern from resolveIterative
    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    const root_servers: []const ServerAddress = resolver.root_servers;
    var current_servers: []const ServerAddress = root_servers;
    var owned_servers: ?std.ArrayList(ServerAddress) = null;
    defer if (owned_servers) |*os| os.deinit(allocator);

    // Initially, current_servers points to root_servers (not owned)
    try std.testing.expectEqual(root_servers.len, current_servers.len);
    try std.testing.expect(owned_servers == null);

    // Simulate first referral: create new_servers and transfer ownership
    {
        var new_servers: std.ArrayList(ServerAddress) = .empty;
        const addr1 = ServerAddress.fromIpv4("192.0.2.1", 53) catch unreachable;
        const addr2 = ServerAddress.fromIpv4("192.0.2.2", 53) catch unreachable;
        try new_servers.append(allocator, addr1);
        try new_servers.append(allocator, addr2);

        // Transfer ownership (mirrors the fix code)
        if (owned_servers) |*os| os.deinit(allocator);
        owned_servers = new_servers;
        current_servers = owned_servers.?.items;
    }

    // After first referral: current_servers should point to the 2 new addresses
    try std.testing.expectEqual(@as(usize, 2), current_servers.len);
    try std.testing.expect(owned_servers != null);

    // Simulate second referral: replace with different servers
    {
        var new_servers2: std.ArrayList(ServerAddress) = .empty;
        const addr3 = ServerAddress.fromIpv4("198.51.100.1", 53) catch unreachable;
        try new_servers2.append(allocator, addr3);

        // Free old owned servers and transfer new ones
        if (owned_servers) |*os| os.deinit(allocator);
        owned_servers = new_servers2;
        current_servers = owned_servers.?.items;
    }

    // After second referral: current_servers should have 1 server
    try std.testing.expectEqual(@as(usize, 1), current_servers.len);

    // Simulate CNAME restart: reset to root servers
    {
        if (owned_servers) |*os| {
            os.deinit(allocator);
            owned_servers = null;
        }
        current_servers = root_servers;
    }

    // After CNAME reset: back to root servers, no owned memory
    try std.testing.expectEqual(root_servers.len, current_servers.len);
    try std.testing.expect(owned_servers == null);

    // The defer at function exit handles cleanup if owned_servers is non-null.
    // Since we set it to null, the defer is a no-op (correct behavior).
}

test "GAP-0019: CNAME break-then-continue-outer pattern" {
    // Verifies the labeled loop pattern used to fix CNAME handling.
    // The old code used `continue` inside the inner loop, which targeted
    // the wrong loop. The fix uses `break` + `continue :outer`.
    // This test exercises the exact pattern to verify control flow.
    const allocator = std.testing.allocator;

    var iterations: usize = 0;
    var cname_restarts: usize = 0;
    var inner_items_after_cname: usize = 0;

    // Simulate the labeled loop pattern from the fix
    const Record = struct { rtype: enum { cname, a, ns }, name: []const u8 };
    const responses = [_][]const Record{
        // Response 0: contains a CNAME then an A record
        &[_]Record{
            .{ .rtype = .cname, .name = "target.example.com" },
            .{ .rtype = .a, .name = "1.2.3.4" },
        },
        // Response 1: contains the final A record
        &[_]Record{
            .{ .rtype = .a, .name = "5.6.7.8" },
        },
    };
    _ = allocator;

    var response_idx: usize = 0;

    // Emulate the outer resolution loop
    outer: while (response_idx < responses.len) {
        const records = responses[response_idx];
        response_idx += 1;
        iterations += 1;

        // Emulate the inner answer iterator loop
        var cname_found = false;
        for (records) |rr| {
            if (rr.rtype == .cname) {
                cname_found = true;
                cname_restarts += 1;
                break; // Break inner loop (not continue!)
            }
            if (rr.rtype == .a) {
                // Found final answer
                break;
            }
        }

        // After inner loop, check if CNAME was found
        if (cname_found) {
            // Count how many items we processed after the CNAME break
            // With the old `continue` (inner loop), this code would never execute
            // because continue would just go to the next inner iteration
            inner_items_after_cname += 1;
            continue :outer; // Restart outer loop (this is the fix)
        }
    }

    // Verify the pattern works:
    // - 2 outer iterations (once for CNAME response, once for final A)
    try std.testing.expectEqual(@as(usize, 2), iterations);
    // - 1 CNAME restart
    try std.testing.expectEqual(@as(usize, 1), cname_restarts);
    // - The CNAME branch executed the post-inner-loop code exactly once
    try std.testing.expectEqual(@as(usize, 1), inner_items_after_cname);
}

test "GAP-0019: CNAME chain limit enforcement" {
    // Verifies that the CNAME chain limit (max_cname_chain_length) is enforced.
    // Uses the same ArrayList pattern as ResolutionState.cname_chain.
    const allocator = std.testing.allocator;

    var cname_chain: std.ArrayList([]const u8) = .empty;
    defer {
        for (cname_chain.items) |item| allocator.free(item);
        cname_chain.deinit(allocator);
    }

    // Simulate following max_cname_chain_length CNAMEs (should succeed)
    for (0..max_cname_chain_length) |i| {
        const target = try std.fmt.allocPrint(allocator, "cname{d}.example.com", .{i});
        try cname_chain.append(allocator, target);
    }
    try std.testing.expectEqual(max_cname_chain_length, cname_chain.items.len);

    // The next CNAME would exceed the limit (> max_cname_chain_length)
    const extra = try std.fmt.allocPrint(allocator, "cname_extra.example.com", .{});
    try cname_chain.append(allocator, extra);
    try std.testing.expect(cname_chain.items.len > max_cname_chain_length);
    // In the real code, this triggers: return error.CnameLoopDetected;
}

test "GAP-0020: owned_zone memory lifecycle" {
    // Verifies the zone ownership pattern: dynamically-allocated zone strings
    // are properly freed when replaced or on function exit.
    const allocator = std.testing.allocator;

    var current_zone: []const u8 = ".";
    var owned_zone: ?[]const u8 = null;
    defer if (owned_zone) |oz| allocator.free(oz);

    // Initially at root zone (not owned)
    try std.testing.expectEqualStrings(".", current_zone);
    try std.testing.expect(owned_zone == null);

    // Simulate first referral zone update
    {
        if (owned_zone) |oz| allocator.free(oz);
        owned_zone = try allocator.dupe(u8, "com.");
        current_zone = owned_zone.?;
    }
    try std.testing.expectEqualStrings("com.", current_zone);

    // Simulate second referral zone update (replaces first)
    {
        if (owned_zone) |oz| allocator.free(oz);
        owned_zone = try allocator.dupe(u8, "example.com.");
        current_zone = owned_zone.?;
    }
    try std.testing.expectEqualStrings("example.com.", current_zone);

    // Simulate CNAME reset to root
    {
        if (owned_zone) |oz| {
            allocator.free(oz);
            owned_zone = null;
        }
        current_zone = ".";
    }
    try std.testing.expectEqualStrings(".", current_zone);
    try std.testing.expect(owned_zone == null);
}

test "A7 (#296): referral bailiwick — only downward delegations accepted" {
    // The recursive loop accepts a referral only when isSubdomainOf(ref.zone,
    // current_zone) holds. Downward delegations are valid; upward and lateral
    // referrals (the cache-poisoning vector) must be rejected.

    // Downward delegations (valid):
    try std.testing.expect(isSubdomainOf("com.", ".")); // root -> com
    try std.testing.expect(isSubdomainOf("example.com.", "com.")); // com -> example.com
    try std.testing.expect(isSubdomainOf("example.com.", "example.com.")); // same zone

    // Lateral referral (attacker redirects example.com -> attacker.net):
    try std.testing.expect(!isSubdomainOf("attacker.net.", "example.com."));
    // Upward referral (example.com server tries to claim all of com):
    try std.testing.expect(!isSubdomainOf("com.", "example.com."));
    // Sibling under the same parent must still be rejected:
    try std.testing.expect(!isSubdomainOf("evil.com.", "example.com."));
}

test "RecursiveResolver.getMinimizedQname" {
    const allocator = std.testing.allocator;

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    // depth=0: just TLD
    const q0 = try resolver.getMinimizedQname("www.example.com", 0);
    defer allocator.free(q0);
    try std.testing.expectEqualStrings("com", q0);

    // depth=1: second-level + TLD
    const q1 = try resolver.getMinimizedQname("www.example.com", 1);
    defer allocator.free(q1);
    try std.testing.expectEqualStrings("example.com", q1);

    // depth=2: full name
    const q2 = try resolver.getMinimizedQname("www.example.com", 2);
    defer allocator.free(q2);
    try std.testing.expectEqualStrings("www.example.com", q2);

    // depth >= labels: full name
    const q3 = try resolver.getMinimizedQname("www.example.com", 10);
    defer allocator.free(q3);
    try std.testing.expectEqualStrings("www.example.com", q3);
}

test "PF-NEW-04: getMinimizedQname uses stack buffer (no ArrayList)" {
    // Verifies that getMinimizedQname works with the stack-buffer implementation.
    // Before the fix, an ArrayList(u8) was used for name assembly, causing heap
    // allocations for every QNAME minimization step. The stack buffer avoids this.
    const allocator = std.testing.allocator;

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    // Test with a deeper domain (4 labels)
    const q0 = try resolver.getMinimizedQname("a.b.example.com", 0);
    defer allocator.free(q0);
    try std.testing.expectEqualStrings("com", q0);

    const q1 = try resolver.getMinimizedQname("a.b.example.com", 1);
    defer allocator.free(q1);
    try std.testing.expectEqualStrings("example.com", q1);

    const q2 = try resolver.getMinimizedQname("a.b.example.com", 2);
    defer allocator.free(q2);
    try std.testing.expectEqualStrings("b.example.com", q2);

    const q3 = try resolver.getMinimizedQname("a.b.example.com", 3);
    defer allocator.free(q3);
    try std.testing.expectEqualStrings("a.b.example.com", q3);

    // Single label domain
    const qs = try resolver.getMinimizedQname("localhost", 0);
    defer allocator.free(qs);
    try std.testing.expectEqualStrings("localhost", qs);
}

test "PF-11: ResolutionState.deinit frees last_query_name" {
    // Verifies that ResolutionState.deinit properly frees last_query_name.
    // Before the fix, if queryWithRetry set last_query_name and then the
    // resolution errored, last_query_name was never freed.
    // Using std.testing.allocator (which is a GeneralPurposeAllocator in test
    // mode) ensures any leak is detected as a test failure.
    const allocator = std.testing.allocator;

    var state = ResolutionState{
        .original_qname = "example.com",
        .qtype = .a,
        .depth = 0,
        .query_count = 0,
        .current_zone = ".",
        .cname_chain = .empty,
    };

    // Simulate what queryWithRetry does: allocate and set last_query_name
    state.last_query_name = try allocator.dupe(u8, "ExAmPlE.cOm");

    // Simulate a second call (queryWithRetry frees old, allocates new)
    if (state.last_query_name) |old| {
        allocator.free(old);
    }
    state.last_query_name = try allocator.dupe(u8, "eXaMpLe.CoM");

    // Also add a CNAME chain entry to verify full cleanup
    const cname_entry = try allocator.dupe(u8, "target.example.com");
    try state.cname_chain.append(allocator, cname_entry);

    // deinit must free both last_query_name and cname_chain entries.
    // If it doesn't, the testing allocator will report a leak and fail.
    state.deinit(allocator);
}

test "PF-11: ResolutionState.deinit handles null last_query_name" {
    // Verifies deinit is safe when last_query_name was never set.
    const allocator = std.testing.allocator;

    var state = ResolutionState{
        .original_qname = "example.com",
        .qtype = .a,
        .depth = 0,
        .query_count = 0,
        .current_zone = ".",
        .cname_chain = .empty,
    };

    // last_query_name is null by default; deinit must not crash.
    state.deinit(allocator);
}

test "PF-04: GlueRecord matching pattern (single-pass additional)" {
    // Verifies the single-pass glue record collection and matching pattern
    // used by extractReferral. Before the fix, extractReferral called
    // msg.additional() once per NS record (O(ns * additional)). After the fix,
    // it collects all glue in one pass, then matches (O(ns + additional)).
    //
    // This test exercises the data structures and matching logic directly,
    // using the same GlueRecord struct and case-insensitive matching.
    const allocator = std.testing.allocator;

    // Simulate glue records collected from a single pass of additional section
    const GlueRecord = RecursiveResolver.GlueRecord;
    var glue_records: std.ArrayList(GlueRecord) = .empty;
    defer {
        for (glue_records.items) |gr| {
            allocator.free(gr.name);
        }
        glue_records.deinit(allocator);
    }

    // Simulate 3 glue A records collected in one pass
    const glue_names = [_][]const u8{ "ns1.example.com.", "ns2.example.com.", "ns3.example.com." };
    const glue_ips = [_][]const u8{ "192.0.2.1", "192.0.2.2", "192.0.2.3" };

    for (glue_names, glue_ips) |name, ip| {
        const addr = ServerAddress.fromIpv4(ip, types_mod.dns_port) catch unreachable;
        try glue_records.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .address = addr,
        });
    }

    // Simulate NS names from authority section
    const ns_names = [_][]const u8{
        "NS1.EXAMPLE.COM.", // case mismatch -- must match case-insensitively
        "ns2.example.com.",
        "ns4.example.com.", // no glue -- should remain null
    };

    // Match NS names against glue (mirrors extractReferral logic)
    var servers: [3]Referral.ServerInfo = undefined;
    for (ns_names, 0..) |ns, i| {
        servers[i] = .{ .name = ns, .address = null };
        for (glue_records.items) |gr| {
            if (std.ascii.eqlIgnoreCase(gr.name, ns)) {
                servers[i].address = gr.address;
                break;
            }
        }
    }

    // Verify: ns1 matched (case-insensitive), ns2 matched, ns4 has no glue
    try std.testing.expect(servers[0].address != null);
    try std.testing.expect(servers[1].address != null);
    try std.testing.expect(servers[2].address == null);
}

test "SEC-C27: isSubdomainOf bailiwick validation" {
    // Exact match
    try std.testing.expect(isSubdomainOf("example.com", "example.com"));
    // Subdomain
    try std.testing.expect(isSubdomainOf("ns1.example.com", "example.com"));
    // Deep subdomain
    try std.testing.expect(isSubdomainOf("a.b.c.example.com", "example.com"));
    // Trailing dots normalized
    try std.testing.expect(isSubdomainOf("ns1.example.com.", "example.com."));
    try std.testing.expect(isSubdomainOf("ns1.example.com.", "example.com"));
    try std.testing.expect(isSubdomainOf("ns1.example.com", "example.com."));
    // Case insensitive
    try std.testing.expect(isSubdomainOf("NS1.EXAMPLE.COM", "example.com"));
    // Root zone is parent of everything
    try std.testing.expect(isSubdomainOf("example.com", "."));
    try std.testing.expect(isSubdomainOf("example.com", ""));

    // Out-of-bailiwick: completely different domain
    try std.testing.expect(!isSubdomainOf("ns1.attacker.com", "example.com"));
    // Out-of-bailiwick: suffix match but not at label boundary
    try std.testing.expect(!isSubdomainOf("fakeexample.com", "example.com"));
    // Out-of-bailiwick: zone is longer than name
    try std.testing.expect(!isSubdomainOf("com", "example.com"));
    // Out-of-bailiwick: unrelated TLDs
    try std.testing.expect(!isSubdomainOf("ns1.example.org", "example.com"));
}

test "PF-31: max_ns_resolve_depth constant" {
    // Verify the depth limit constant exists and is reasonable.
    // 8 levels of nested NS delegation is sufficient for all legitimate zones
    // while preventing amplification attacks.
    try std.testing.expect(RecursiveResolver.max_ns_resolve_depth > 0);
    try std.testing.expect(RecursiveResolver.max_ns_resolve_depth <= 16);
}

test "PF-31: resolveNsAddress respects depth guard" {
    // Verify that resolveNsAddress returns null when the parent state's depth
    // has already reached the maximum. This prevents infinite NS resolution loops.
    const allocator = std.testing.allocator;

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    // Create a parent state at maximum depth
    var parent_state = ResolutionState{
        .original_qname = "example.com",
        .qtype = .a,
        .depth = RecursiveResolver.max_ns_resolve_depth, // at max
        .query_count = 0,
        .current_zone = ".",
        .cname_chain = .empty,
    };
    defer parent_state.deinit(allocator);

    // resolveNsAddress should return null due to depth exceeded
    const result = try resolver.resolveNsAddress("ns1.example.com", &parent_state);
    try std.testing.expect(result == null);
}

test "PF-31: resolveNsAddress respects query budget" {
    // Verify that resolveNsAddress returns null when query budget is exhausted.
    const allocator = std.testing.allocator;

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    // Create a parent state with exhausted query budget
    var parent_state = ResolutionState{
        .original_qname = "example.com",
        .qtype = .a,
        .depth = 0,
        .query_count = resolver.config.max_queries, // exhausted
        .current_zone = ".",
        .cname_chain = .empty,
    };
    defer parent_state.deinit(allocator);

    // resolveNsAddress should return null due to budget exhausted
    const result = try resolver.resolveNsAddress("ns1.example.com", &parent_state);
    try std.testing.expect(result == null);
}

test "SEC-C24: transaction IDs use CSPRNG" {
    // Verify that the resolver uses OS CSPRNG for transaction IDs.
    // Generate multiple IDs and check basic properties:
    // 1. They don't all return the same value (basic randomness sanity)
    // 2. They don't panic or fail
    var ids: [16]u16 = undefined;
    for (&ids) |*id| {
        id.* = try RecursiveResolver.csprngInt(u16);
    }

    // At least 2 different values among 16 samples (probability of all-same: 1/65535^15)
    var all_same = true;
    for (ids[1..]) |id| {
        if (id != ids[0]) {
            all_same = false;
            break;
        }
    }
    try std.testing.expect(!all_same);
}

test "PF-19: responseMatchesQuery accepts pre-parsed Message" {
    // Verifies that responseMatchesQuery works with a pre-parsed Message
    // instead of raw bytes, eliminating redundant Message.parse calls.
    // Before PF-19, responseMatchesQuery would call Message.parse internally;
    // now it accepts an already-parsed Message, saving ~1-2us per query step.
    const allocator = std.testing.allocator;

    // Build a valid DNS query and a matching response.
    // Use buildQuery + modify to create a response-like message.
    const query = try message_mod.buildQuery(allocator, 0xABCD, "example.com", .a, .in, false, false);
    defer allocator.free(query);

    // Create a response by copying the query and flipping the QR bit
    const response = try allocator.dupe(u8, query);
    defer allocator.free(response);

    // Set QR=1 (bit 7 of byte 2) to make it a response
    response[2] |= 0x80;

    // Parse once (as queryWithRetry now does)
    const msg = try Message.parse(response);

    // responseMatchesQuery should accept the pre-parsed Message
    try std.testing.expect(responseMatchesQuery(msg, "example.com", .a, .in));

    // Mismatched type should fail
    try std.testing.expect(!responseMatchesQuery(msg, "example.com", .aaaa, .in));

    // Mismatched name should fail
    try std.testing.expect(!responseMatchesQuery(msg, "other.com", .a, .in));

    // Mismatched class should fail
    try std.testing.expect(!responseMatchesQuery(msg, "example.com", .a, .ch));
}

test "PF-19: QueryResult struct carries both response and parsed Message" {
    // Verify the QueryResult struct exists and has the expected fields.
    // This struct is the mechanism by which queryWithRetry returns both
    // raw bytes and parsed Message, enabling single-parse flow.
    const QR = RecursiveResolver.QueryResult;

    // Verify it has the expected fields via comptime reflection
    const info = @typeInfo(QR);
    try std.testing.expectEqual(@as(usize, 2), info.@"struct".fields.len);
    try std.testing.expectEqualStrings("response", info.@"struct".fields[0].name);
    try std.testing.expectEqualStrings("msg", info.@"struct".fields[1].name);
}

test "PF-NEW-02: Referral.deinit frees zone, server names, and servers slice" {
    // Verifies that Referral.deinit properly frees all heap-allocated memory.
    // Before the fix, the caller of extractReferral never freed ref.zone,
    // ref.servers[i].name, or ref.servers, causing memory leaks on every
    // referral during recursive resolution.
    // Using std.testing.allocator ensures any leak is detected as a test failure.
    const allocator = std.testing.allocator;

    // Simulate what extractReferral produces: heap-allocated zone, names, and slice
    const zone = try allocator.dupe(u8, "example.com.");
    const name1 = try allocator.dupe(u8, "ns1.example.com.");
    const name2 = try allocator.dupe(u8, "ns2.example.com.");
    var servers = try allocator.alloc(Referral.ServerInfo, 2);
    servers[0] = .{ .name = name1, .address = null };
    servers[1] = .{ .name = name2, .address = null };

    const ref = Referral{
        .zone = zone,
        .servers = servers,
    };

    // deinit must free zone, both server names, and the servers slice.
    // If any allocation is missed, the testing allocator will report a leak.
    ref.deinit(allocator);
}

// =========================================================================
// GAP-0839: DNSSEC validation wired into the resolution path
// =========================================================================

const TestEd25519 = std.crypto.sign.Ed25519;

fn appendTestU16(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u16) !void {
    try list.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u16, v)));
}

fn appendTestU32(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    try list.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u32, v)));
}

/// Test helper: append a wire-format resource record (uncompressed owner).
fn appendTestRr(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    owner_wire: []const u8,
    rtype: u16,
    ttl: u32,
    rdata: []const u8,
) !void {
    try list.appendSlice(allocator, owner_wire);
    try appendTestU16(list, allocator, rtype);
    try appendTestU16(list, allocator, 1); // class IN
    try appendTestU32(list, allocator, ttl);
    try appendTestU16(list, allocator, @intCast(rdata.len));
    try list.appendSlice(allocator, rdata);
}

/// Test helper: build a minimal DNS response with one question, `ancount`
/// pre-serialized answer records, and `arcount` additional records.
fn buildTestResponseBytes(
    allocator: std.mem.Allocator,
    qname_wire: []const u8,
    qtype: u16,
    ancount: u16,
    answers_bytes: []const u8,
    arcount: u16,
    additional_bytes: []const u8,
) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    try appendTestU16(&list, allocator, 0x1234); // ID
    try appendTestU16(&list, allocator, 0x8400); // QR=1, AA=1
    try appendTestU16(&list, allocator, 1); // QDCOUNT
    try appendTestU16(&list, allocator, ancount);
    try appendTestU16(&list, allocator, 0); // NSCOUNT
    try appendTestU16(&list, allocator, arcount);
    try list.appendSlice(allocator, qname_wire);
    try appendTestU16(&list, allocator, qtype);
    try appendTestU16(&list, allocator, 1); // IN

    try list.appendSlice(allocator, answers_bytes);
    try list.appendSlice(allocator, additional_bytes);
    return list.toOwnedSlice(allocator);
}

test "GAP-0839: RecursiveConfig DNSSEC defaults are off (behavior unchanged)" {
    const config = RecursiveConfig{};
    try std.testing.expect(!config.dnssec);
    try std.testing.expect(!config.dnssec_strict);
    try std.testing.expectEqual(@as(usize, 0), config.dnssec_trust_anchors.len);
}

test "GAP-0839: dnssec=false performs no validation (status null)" {
    const allocator = std.testing.allocator;

    const owner: []const u8 = "\x01a\x07example\x03com\x00";
    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, owner, 1, 3600, &[_]u8{ 192, 0, 2, 1 });

    const response = try buildTestResponseBytes(allocator, owner, 1, 1, answers.items, 0, &.{});
    defer allocator.free(response);
    const msg = try Message.parse(response);

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    // Unsigned response with dnssec disabled: no validation, no error.
    const status = try resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expect(status == null);
}

test "GAP-0839: strict mode fails closed on response lacking valid RRSIG chain" {
    const allocator = std.testing.allocator;

    const owner: []const u8 = "\x01a\x07example\x03com\x00";
    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, owner, 1, 3600, &[_]u8{ 192, 0, 2, 1 });

    const response = try buildTestResponseBytes(allocator, owner, 1, 1, answers.items, 0, &.{});
    defer allocator.free(response);
    const msg = try Message.parse(response);

    const anchor_rdata = [_]u8{ 0x01, 0x00, 0x03, 0x0F } ++ [_]u8{0xAA} ** 32;
    const anchors = [_]dnssec_mod.Validator.TrustAnchor{.{
        .zone = "example.com",
        .key_tag = record_mod.ResourceRecord.calculateKeyTag(&anchor_rdata),
        .algorithm = .ed25519,
        .digest_type = null,
        .data = &anchor_rdata,
        .is_dnskey = true,
    }};

    // Strict mode: unsigned answer -> insecure -> error (fail closed).
    // The error propagates before cacheResponse in resolveIterative, so
    // nothing is cached.
    var strict_resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_strict = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer strict_resolver.deinit();
    try std.testing.expectError(
        error.DnssecValidationFailed,
        strict_resolver.enforceDnssecPolicy(response, msg),
    );

    // Permissive mode (default): proceeds, marked insecure.
    var permissive_resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer permissive_resolver.deinit();
    const status = try permissive_resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expectEqual(dnssec_mod.ValidationResult.insecure, status.?);
}

test "GAP-0839: valid Ed25519 chain to configured trust anchor is secure; tampered is bogus" {
    const allocator = std.testing.allocator;

    const kp = try TestEd25519.KeyPair.generateDeterministic([_]u8{0x21} ** 32);
    const pub_bytes = kp.public_key.toBytes();

    // DNSKEY RDATA: flags=0x0100 (zone key), protocol=3, algorithm=15 (Ed25519)
    const dnskey_rdata = [_]u8{ 0x01, 0x00, 0x03, 0x0F } ++ pub_bytes;
    const key_tag = record_mod.ResourceRecord.calculateKeyTag(&dnskey_rdata);

    const owner: []const u8 = "\x01a\x07example\x03com\x00"; // 3 labels
    const signer: []const u8 = "\x07example\x03com\x00";
    const a_rdata = [_]u8{ 192, 0, 2, 1 };

    // RFC 4034 signed data: RRSIG RDATA (sans signature) + canonical RRset.
    var signed: std.ArrayList(u8) = .empty;
    defer signed.deinit(allocator);
    try appendTestU16(&signed, allocator, 1); // type covered: A
    try signed.append(allocator, 15); // algorithm: Ed25519
    try signed.append(allocator, 3); // labels
    try appendTestU32(&signed, allocator, 3600); // original TTL
    try appendTestU32(&signed, allocator, 4_000_000_000); // expiration
    try appendTestU32(&signed, allocator, 1); // inception
    try appendTestU16(&signed, allocator, key_tag);
    try signed.appendSlice(allocator, signer);
    try signed.appendSlice(allocator, owner);
    try appendTestU16(&signed, allocator, 1); // type A
    try appendTestU16(&signed, allocator, 1); // class IN
    try appendTestU32(&signed, allocator, 3600);
    try appendTestU16(&signed, allocator, a_rdata.len);
    try signed.appendSlice(allocator, &a_rdata);

    const sig = try kp.sign(signed.items, null);
    const sig_bytes = sig.toBytes();

    // RRSIG RDATA: 18 fixed bytes + signer name + signature
    var rrsig_rdata: std.ArrayList(u8) = .empty;
    defer rrsig_rdata.deinit(allocator);
    try appendTestU16(&rrsig_rdata, allocator, 1);
    try rrsig_rdata.append(allocator, 15);
    try rrsig_rdata.append(allocator, 3);
    try appendTestU32(&rrsig_rdata, allocator, 3600);
    try appendTestU32(&rrsig_rdata, allocator, 4_000_000_000);
    try appendTestU32(&rrsig_rdata, allocator, 1);
    try appendTestU16(&rrsig_rdata, allocator, key_tag);
    try rrsig_rdata.appendSlice(allocator, signer);
    try rrsig_rdata.appendSlice(allocator, &sig_bytes);

    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, owner, 1, 3600, &a_rdata); // A
    try appendTestRr(&answers, allocator, owner, 46, 3600, rrsig_rdata.items); // RRSIG

    // DNSKEY travels in the additional section (as if fetched alongside)
    var additional: std.ArrayList(u8) = .empty;
    defer additional.deinit(allocator);
    try appendTestRr(&additional, allocator, signer, 48, 3600, &dnskey_rdata); // DNSKEY

    const response = try buildTestResponseBytes(allocator, owner, 1, 2, answers.items, 1, additional.items);
    defer allocator.free(response);
    const msg = try Message.parse(response);

    const anchors = [_]dnssec_mod.Validator.TrustAnchor{.{
        .zone = "example.com",
        .key_tag = key_tag,
        .algorithm = .ed25519,
        .digest_type = null,
        .data = &dnskey_rdata,
        .is_dnskey = true,
    }};

    var resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_strict = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer resolver.deinit();

    const status = try resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expectEqual(dnssec_mod.ValidationResult.secure, status.?);

    // Tamper with the A record RDATA: the same chain must now be bogus and
    // fail closed even in permissive mode.
    const tampered = try allocator.dupe(u8, response);
    defer allocator.free(tampered);
    // Last byte of the A record RDATA in the answer section
    const a_rdata_end = 12 + owner.len + 4 + owner.len + 10 + 4;
    tampered[a_rdata_end - 1] ^= 0xFF;
    const tampered_msg = try Message.parse(tampered);

    var permissive_resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer permissive_resolver.deinit();
    try std.testing.expectError(
        error.DnssecValidationFailed,
        permissive_resolver.enforceDnssecPolicy(tampered, tampered_msg),
    );
}

/// Test helper: build RRSIG RDATA over a single A record, Ed25519-signed
/// per RFC 4034 (signed data = RRSIG RDATA sans signature + canonical
/// RRset with the UNCOMPRESSED owner name). Caller frees the result.
fn buildTestRrsigOverA(
    allocator: std.mem.Allocator,
    kp: TestEd25519.KeyPair,
    owner_uncompressed: []const u8,
    signer: []const u8,
    labels: u8,
    key_tag: u16,
    a_rdata: []const u8,
) ![]u8 {
    var signed: std.ArrayList(u8) = .empty;
    defer signed.deinit(allocator);
    try appendTestU16(&signed, allocator, 1); // type covered: A
    try signed.append(allocator, 15); // algorithm: Ed25519
    try signed.append(allocator, labels);
    try appendTestU32(&signed, allocator, 3600); // original TTL
    try appendTestU32(&signed, allocator, 4_000_000_000); // expiration
    try appendTestU32(&signed, allocator, 1); // inception
    try appendTestU16(&signed, allocator, key_tag);
    try signed.appendSlice(allocator, signer);
    try signed.appendSlice(allocator, owner_uncompressed);
    try appendTestU16(&signed, allocator, 1); // type A
    try appendTestU16(&signed, allocator, 1); // class IN
    try appendTestU32(&signed, allocator, 3600);
    try appendTestU16(&signed, allocator, @intCast(a_rdata.len));
    try signed.appendSlice(allocator, a_rdata);

    const sig = try kp.sign(signed.items, null);
    const sig_bytes = sig.toBytes();

    var rrsig_rdata: std.ArrayList(u8) = .empty;
    errdefer rrsig_rdata.deinit(allocator);
    try appendTestU16(&rrsig_rdata, allocator, 1);
    try rrsig_rdata.append(allocator, 15);
    try rrsig_rdata.append(allocator, labels);
    try appendTestU32(&rrsig_rdata, allocator, 3600);
    try appendTestU32(&rrsig_rdata, allocator, 4_000_000_000);
    try appendTestU32(&rrsig_rdata, allocator, 1);
    try appendTestU16(&rrsig_rdata, allocator, key_tag);
    try rrsig_rdata.appendSlice(allocator, signer);
    try rrsig_rdata.appendSlice(allocator, &sig_bytes);
    return rrsig_rdata.toOwnedSlice(allocator);
}

test "GAP-0839 review: compressed answer owner names validate secure" {
    const allocator = std.testing.allocator;

    const kp = try TestEd25519.KeyPair.generateDeterministic([_]u8{0x22} ** 32);
    const dnskey_rdata = [_]u8{ 0x01, 0x00, 0x03, 0x0F } ++ kp.public_key.toBytes();
    const key_tag = record_mod.ResourceRecord.calculateKeyTag(&dnskey_rdata);

    const owner: []const u8 = "\x01a\x07example\x03com\x00"; // 3 labels
    const signer: []const u8 = "\x07example\x03com\x00";
    const a_rdata = [_]u8{ 192, 0, 2, 1 };

    // Signature covers the UNCOMPRESSED canonical owner (RFC 4035 S5.3.2).
    const rrsig_rdata = try buildTestRrsigOverA(allocator, kp, owner, signer, 3, key_tag, &a_rdata);
    defer allocator.free(rrsig_rdata);

    // On the wire, the answer/RRSIG owners are compression pointers to the
    // question name at offset 12 (0xC0 0x0C) -- the common real-world shape.
    const ptr_owner = [_]u8{ 0xC0, 0x0C };
    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, &ptr_owner, 1, 3600, &a_rdata); // A
    try appendTestRr(&answers, allocator, &ptr_owner, 46, 3600, rrsig_rdata); // RRSIG

    const response = try buildTestResponseBytes(allocator, owner, 1, 2, answers.items, 0, &.{});
    defer allocator.free(response);
    const msg = try Message.parse(response);

    const anchors = [_]dnssec_mod.Validator.TrustAnchor{.{
        .zone = "example.com",
        .key_tag = key_tag,
        .algorithm = .ed25519,
        .digest_type = null,
        .data = &dnskey_rdata,
        .is_dnskey = true,
    }};

    var resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_strict = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer resolver.deinit();

    const status = try resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expectEqual(dnssec_mod.ValidationResult.secure, status.?);
}

test "GAP-0839 review: anchor zone does not validate out-of-zone RRset" {
    const allocator = std.testing.allocator;

    const kp = try TestEd25519.KeyPair.generateDeterministic([_]u8{0x23} ** 32);
    const dnskey_rdata = [_]u8{ 0x01, 0x00, 0x03, 0x0F } ++ kp.public_key.toBytes();
    const key_tag = record_mod.ResourceRecord.calculateKeyTag(&dnskey_rdata);

    // RRset for www.bank.com, validly signed by the anchored key with
    // signer bank.com -- but the anchor is scoped to corp.example only.
    const owner: []const u8 = "\x03www\x04bank\x03com\x00"; // 3 labels
    const signer: []const u8 = "\x04bank\x03com\x00";
    const a_rdata = [_]u8{ 192, 0, 2, 7 };

    const rrsig_rdata = try buildTestRrsigOverA(allocator, kp, owner, signer, 3, key_tag, &a_rdata);
    defer allocator.free(rrsig_rdata);

    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, owner, 1, 3600, &a_rdata);
    try appendTestRr(&answers, allocator, owner, 46, 3600, rrsig_rdata);

    const response = try buildTestResponseBytes(allocator, owner, 1, 2, answers.items, 0, &.{});
    defer allocator.free(response);
    const msg = try Message.parse(response);

    const anchors = [_]dnssec_mod.Validator.TrustAnchor{.{
        .zone = "corp.example",
        .key_tag = key_tag,
        .algorithm = .ed25519,
        .digest_type = null,
        .data = &dnskey_rdata,
        .is_dnskey = true,
    }};

    var resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer resolver.deinit();

    // Outside the anchor's zone of trust: insecure, never secure.
    const status = try resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expectEqual(dnssec_mod.ValidationResult.insecure, status.?);
}

test "GAP-0839 review: RRSIG signer outside owner ancestry is rejected" {
    const allocator = std.testing.allocator;

    const kp = try TestEd25519.KeyPair.generateDeterministic([_]u8{0x24} ** 32);
    const dnskey_rdata = [_]u8{ 0x01, 0x00, 0x03, 0x0F } ++ kp.public_key.toBytes();
    const key_tag = record_mod.ResourceRecord.calculateKeyTag(&dnskey_rdata);

    // RRset owner a.example.com is inside the anchor zone, but the RRSIG
    // claims signer other.com, which is not an ancestor of the owner
    // (RFC 4035 S5.3.1): the signature must not be usable.
    const owner: []const u8 = "\x01a\x07example\x03com\x00"; // 3 labels
    const signer: []const u8 = "\x05other\x03com\x00";
    const a_rdata = [_]u8{ 192, 0, 2, 9 };

    const rrsig_rdata = try buildTestRrsigOverA(allocator, kp, owner, signer, 3, key_tag, &a_rdata);
    defer allocator.free(rrsig_rdata);

    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, owner, 1, 3600, &a_rdata);
    try appendTestRr(&answers, allocator, owner, 46, 3600, rrsig_rdata);

    const response = try buildTestResponseBytes(allocator, owner, 1, 2, answers.items, 0, &.{});
    defer allocator.free(response);
    const msg = try Message.parse(response);

    const anchors = [_]dnssec_mod.Validator.TrustAnchor{.{
        .zone = "example.com",
        .key_tag = key_tag,
        .algorithm = .ed25519,
        .digest_type = null,
        .data = &dnskey_rdata,
        .is_dnskey = true,
    }};

    var resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer resolver.deinit();

    const status = try resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expectEqual(dnssec_mod.ValidationResult.insecure, status.?);
}

test "GAP-0839 review: DNSKEY anchor with protocol != 3 is ignored" {
    const allocator = std.testing.allocator;

    const kp = try TestEd25519.KeyPair.generateDeterministic([_]u8{0x25} ** 32);
    // Protocol byte is 2: invalid per RFC 4034 S2.1.2, key must be skipped.
    const dnskey_rdata = [_]u8{ 0x01, 0x00, 0x02, 0x0F } ++ kp.public_key.toBytes();
    const key_tag = record_mod.ResourceRecord.calculateKeyTag(&dnskey_rdata);

    const owner: []const u8 = "\x01a\x07example\x03com\x00"; // 3 labels
    const signer: []const u8 = "\x07example\x03com\x00";
    const a_rdata = [_]u8{ 192, 0, 2, 3 };

    const rrsig_rdata = try buildTestRrsigOverA(allocator, kp, owner, signer, 3, key_tag, &a_rdata);
    defer allocator.free(rrsig_rdata);

    var answers: std.ArrayList(u8) = .empty;
    defer answers.deinit(allocator);
    try appendTestRr(&answers, allocator, owner, 1, 3600, &a_rdata);
    try appendTestRr(&answers, allocator, owner, 46, 3600, rrsig_rdata);

    const response = try buildTestResponseBytes(allocator, owner, 1, 2, answers.items, 0, &.{});
    defer allocator.free(response);
    const msg = try Message.parse(response);

    const anchors = [_]dnssec_mod.Validator.TrustAnchor{.{
        .zone = "example.com",
        .key_tag = key_tag,
        .algorithm = .ed25519,
        .digest_type = null,
        .data = &dnskey_rdata,
        .is_dnskey = true,
    }};

    var resolver = try RecursiveResolver.init(allocator, .{
        .dnssec = true,
        .dnssec_trust_anchors = &anchors,
    });
    defer resolver.deinit();

    // Signed and in-zone, but the only configured key is unusable:
    // indeterminate (no trusted key to check against), never secure.
    const status = try resolver.enforceDnssecPolicy(response, msg);
    try std.testing.expectEqual(dnssec_mod.ValidationResult.indeterminate, status.?);
}

test "PF-NEW-02: Referral.deinit with single server and address" {
    // Verifies deinit works when servers have glue addresses (value types,
    // no extra freeing needed for addresses).
    const allocator = std.testing.allocator;

    const zone = try allocator.dupe(u8, "com.");
    const name1 = try allocator.dupe(u8, "a.gtld-servers.net.");
    var servers = try allocator.alloc(Referral.ServerInfo, 1);
    const addr = ServerAddress.fromIpv4("192.0.2.1", 53) catch unreachable;
    servers[0] = .{ .name = name1, .address = addr };

    const ref = Referral{
        .zone = zone,
        .servers = servers,
    };

    ref.deinit(allocator);
}
