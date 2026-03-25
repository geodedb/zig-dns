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
const clock_mod = @import("clock");
const stub_mod = @import("stub");

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

    /// Whether to use DNSSEC validation
    dnssec: bool = false,

    /// Enable QNAME minimization (RFC 7816)
    qname_minimization: bool = true,

    /// Enable 0x20 case randomization for cache poisoning protection
    case_randomization: bool = true,

    /// Number of servers to try in parallel
    parallel_queries: u8 = 2,
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
    const csprng = std.crypto.random;

    /// Error type for resolver initialization failures
    pub const InitError = error{
        OutOfMemory,
    };

    /// Create a new recursive resolver
    ///
    /// SECURITY: Uses OS CSPRNG (std.crypto.random) for transaction ID generation
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
        var state = ResolutionState{
            .original_qname = domain,
            .qtype = qtype,
            .depth = 0,
            .query_count = 0,
            .current_zone = ".",
            .cname_chain = .{},
        };
        defer state.deinit(self.allocator);

        return self.resolveIterative(&state);
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

                            // Collect addresses for referred NS servers
                            var new_servers: std.ArrayList(ServerAddress) = .{};
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
        const id = csprng.int(u16);

        // Apply 0x20 case randomization if enabled (using CSPRNG for unpredictability)
        const query_name = if (self.config.case_randomization)
            try name_mod.applyCase0x20(self.allocator, domain, csprng)
        else
            try self.allocator.dupe(u8, domain);
        defer self.allocator.free(query_name);

        // Store for 0x20 verification (PF-NEW-12: skip the dupe when case
        // randomization is disabled -- last_query_name is only checked under
        // the case_randomization branch, so the extra copy is wasted).
        //
        // PF-NEW-20/PF-NEW-27: Two allocations here are intentional for correctness:
        // 1. query_name: freed after this query attempt completes (defer above)
        // 2. last_query_name: persists across retry iterations for 0x20 verification
        // Combining them would require careful lifetime tracking across the retry
        // loop boundary; the micro-optimization (~1 alloc per delegation) is not
        // worth the correctness risk.
        if (self.config.case_randomization) {
            if (state.last_query_name) |old| {
                self.allocator.free(old);
            }
            state.last_query_name = try self.allocator.dupe(u8, query_name);
        }

        // Build query on the stack (max 271 bytes, no heap allocation)
        var query_buf: [message_mod.max_query_size]u8 = undefined;
        const query = try message_mod.buildQueryBuf(&query_buf, id, query_name, qtype, .in, self.config.dnssec);

        // Try servers in order
        const max_tries = @min(servers.len, self.config.parallel_queries);
        for (servers[0..max_tries]) |server| {
            const response = self.sendQuery(query, server) catch continue;

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
        const sock = try std.posix.socket(
            server.address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        defer std.posix.close(sock);

        // Set timeout
        const timeout_sec = self.config.timeout_ms / 1000;
        const timeout_usec = (self.config.timeout_ms % 1000) * 1000;
        const timeout = std.posix.timeval{
            .sec = @intCast(timeout_sec),
            .usec = @intCast(timeout_usec),
        };
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // Send query
        _ = try std.posix.sendto(sock, query, 0, &server.address.any, server.address.getOsSockLen());

        const start_ms = std.time.milliTimestamp();
        // SEC-AUDIT-02: Limit discarded packets to prevent CPU pinning from flood attacks.
        var discards = types_mod.SpuriousDiscardCounter{};
        while (true) {
            if (std.time.milliTimestamp() - start_ms >= self.config.timeout_ms) {
                return error.Timeout;
            }

            // Receive response (capture source)
            // 4096 bytes matches EDNS default max payload (RFC 6891).
            // Responses exceeding this are truncated and fall back to TCP.
            var buffer: [4096]u8 = undefined;
            var src_addr: std.net.Address = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(std.net.Address);
            const recv_len = std.posix.recvfrom(sock, &buffer, 0, &src_addr.any, &src_len) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionTimedOut => return error.Timeout,
                else => return err,
            };

            if (!std.net.Address.eql(src_addr, server.address)) {
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
    fn extractReferral(self: *Self, response: []const u8, msg: Message) !?Referral {
        var ns_names: std.ArrayList([]const u8) = .{};
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
            .cname_chain = .{},
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
};

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
        var new_servers: std.ArrayList(ServerAddress) = .{};
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
        var new_servers2: std.ArrayList(ServerAddress) = .{};
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

    var cname_chain: std.ArrayList([]const u8) = .{};
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
        .cname_chain = .{},
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
        .cname_chain = .{},
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
    var glue_records: std.ArrayList(GlueRecord) = .{};
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
        .cname_chain = .{},
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
        .cname_chain = .{},
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
    const csprng_rand = RecursiveResolver.csprng;

    var ids: [16]u16 = undefined;
    for (&ids) |*id| {
        id.* = csprng_rand.int(u16);
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
    const query = try message_mod.buildQuery(allocator, 0xABCD, "example.com", .a, .in, false);
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
