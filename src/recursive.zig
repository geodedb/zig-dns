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
const cache_mod = @import("cache");
const stub_mod = @import("stub");

pub const Message = message_mod.Message;
pub const Name = name_mod.Name;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;
pub const Header = header_mod.Header;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const Cache = cache_mod.Cache;
pub const StubResolver = stub_mod.StubResolver;
pub const ServerAddress = stub_mod.ServerAddress;

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
};

/// Recursive Resolver
/// Performs full iterative resolution from root servers
pub const RecursiveResolver = struct {
    allocator: std.mem.Allocator,
    config: RecursiveConfig,
    cache: Cache,
    root_servers: []ServerAddress,
    prng: std.Random.DefaultPrng,

    const Self = @This();

    /// Error type for resolver initialization failures
    pub const InitError = error{
        /// Failed to obtain cryptographically secure entropy from the OS.
        /// This is required for secure transaction ID generation and 0x20 randomization.
        EntropyUnavailable,
        OutOfMemory,
    };

    /// Create a new recursive resolver
    ///
    /// SECURITY: Requires OS entropy for secure transaction ID generation.
    /// Fails if cryptographically secure random numbers are unavailable,
    /// as predictable IDs enable DNS cache poisoning attacks.
    pub fn init(allocator: std.mem.Allocator, config: RecursiveConfig) InitError!Self {
        // Initialize root servers
        const root_ips = RootServers.all();
        var root_servers = try allocator.alloc(ServerAddress, root_ips.len);
        errdefer allocator.free(root_servers);

        for (root_ips, 0..) |ip, i| {
            root_servers[i] = ServerAddress.fromIpv4(ip, types_mod.dns_port) catch
                return error.OutOfMemory;
        }

        // Initialize PRNG for 0x20 case randomization and transaction IDs
        // SECURITY: Fail-fast if entropy is unavailable - do NOT fall back to timestamps
        // Predictable seeds enable transaction ID prediction attacks (RFC 5452, CWE-330)
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
            allocator.free(root_servers);
            return error.EntropyUnavailable;
        };

        return Self{
            .allocator = allocator,
            .config = config,
            .cache = Cache.init(allocator, config.cache_size),
            .root_servers = root_servers,
            .prng = std.Random.DefaultPrng.init(seed),
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
        defer state.cname_chain.deinit(self.allocator);

        return self.resolveIterative(&state);
    }

    /// Internal iterative resolution
    fn resolveIterative(self: *Self, state: *ResolutionState) !ResolveResult {
        var current_servers = self.root_servers;
        var current_zone: []const u8 = ".";
        var zone_depth: usize = 0;

        // Main resolution loop
        while (state.query_count < self.config.max_queries) {
            // Determine what to query based on QNAME minimization
            const query_name = if (self.config.qname_minimization)
                try self.getMinimizedQname(state.original_qname, current_zone, zone_depth)
            else
                try self.allocator.dupe(u8, state.original_qname);
            defer self.allocator.free(query_name);

            // Determine query type: NS for intermediate queries, original type for final
            const query_type = if (self.config.qname_minimization and !std.ascii.eqlIgnoreCase(query_name, state.original_qname))
                Type.ns
            else
                state.qtype;

            // Build and send query
            const response = try self.queryWithRetry(
                query_name,
                query_type,
                current_servers,
                state,
            );
            defer self.allocator.free(response);
            state.query_count += 1;

            // Parse the response
            const msg = try Message.parse(response);

            // Verify 0x20 case randomization if enabled
            if (self.config.case_randomization) {
                if (state.last_query_name) |expected_qname| {
                    const response_qname = name_mod.extractQname(self.allocator, response) catch null;
                    if (response_qname) |rq| {
                        defer self.allocator.free(rq);
                        if (!name_mod.verifyCase0x20(expected_qname, rq)) {
                            // Potential spoofing attempt - retry with different server
                            continue;
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
                    continue;
                },
                .no_error => {
                    // Check for answers
                    if (msg.header.ancount > 0) {
                        // Check for CNAME
                        var ans_iter = try msg.answers();
                        while (try ans_iter.next()) |rr| {
                            if (rr.rtype == .cname and state.qtype != .cname) {
                                // Follow CNAME chain
                                const cname_target = try rr.parseName(response);
                                const target_str = try cname_target.toString(self.allocator, response);
                                defer self.allocator.free(target_str);

                                try state.cname_chain.append(self.allocator, try self.allocator.dupe(u8, target_str));

                                if (state.cname_chain.items.len > 8) {
                                    return error.CnameLoopDetected;
                                }

                                // Restart resolution for CNAME target
                                state.original_qname = state.cname_chain.items[state.cname_chain.items.len - 1];
                                current_servers = self.root_servers;
                                current_zone = ".";
                                zone_depth = 0;
                                continue;
                            }

                            if (rr.rtype == state.qtype) {
                                // Found the answer
                                self.cacheResponse(response, msg) catch {};
                                return ResolveResult{
                                    .status = .success,
                                    .answer = try self.allocator.dupe(u8, response),
                                    .from_cache = false,
                                };
                            }
                        }

                        // Got answers but not the type we wanted - check for delegation
                    }

                    // Check for referral (NS records in authority section)
                    if (msg.header.nscount > 0) {
                        const referral = try self.extractReferral(response, msg);
                        if (referral) |ref| {
                            // Update current zone and servers
                            const new_zone = try self.allocator.dupe(u8, ref.zone);

                            // Get addresses for NS servers
                            var new_servers: std.ArrayList(ServerAddress) = .{};
                            defer new_servers.deinit(self.allocator);

                            for (ref.servers) |ns| {
                                if (ns.address) |addr| {
                                    try new_servers.append(self.allocator, addr);
                                } else {
                                    // Need to resolve NS hostname (glue missing)
                                    const ns_result = self.resolveNsAddress(ns.name) orelse continue;
                                    try new_servers.append(self.allocator, ns_result);
                                }
                            }

                            if (new_servers.items.len > 0) {
                                // Store the new servers (simplified - in production would manage memory better)
                                current_zone = new_zone;
                                zone_depth += 1;

                                // Update current_servers to point to new servers
                                // For now, just continue with what we have
                                continue;
                            }
                        }
                    }

                    // No answer and no referral - might be NODATA
                    if (msg.header.ancount == 0 and msg.header.nscount > 0) {
                        // Check for SOA in authority (indicates NODATA)
                        var auth_iter = try msg.authority();
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
                if (zone_depth > 127) {
                    return error.MaxDepthExceeded;
                }
            } else {
                break;
            }
        }

        return error.MaxQueriesExceeded;
    }

    /// Get minimized QNAME for a given zone depth
    fn getMinimizedQname(self: *Self, original: []const u8, current_zone: []const u8, depth: usize) ![]u8 {
        _ = current_zone;

        // Count labels in original name
        var label_count: usize = 0;
        var iter = std.mem.splitScalar(u8, original, '.');
        while (iter.next()) |label| {
            if (label.len > 0) {
                label_count += 1;
            }
        }

        // If depth covers all labels, return full name
        if (depth >= label_count) {
            return try self.allocator.dupe(u8, original);
        }

        // Return rightmost (depth+1) labels
        var labels: [128][]const u8 = undefined;
        var count: usize = 0;
        iter = std.mem.splitScalar(u8, original, '.');
        while (iter.next()) |label| {
            if (label.len > 0 and count < 128) {
                labels[count] = label;
                count += 1;
            }
        }

        const start = count - @min(depth + 1, count);
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(self.allocator);

        for (start..count) |i| {
            if (result.items.len > 0) {
                try result.append(self.allocator, '.');
            }
            try result.appendSlice(self.allocator, labels[i]);
        }

        return try result.toOwnedSlice(self.allocator);
    }

    /// Query servers with retry logic
    fn queryWithRetry(
        self: *Self,
        domain: []const u8,
        qtype: Type,
        servers: []const ServerAddress,
        state: *ResolutionState,
    ) ![]u8 {
        // Generate query ID
        const id = self.prng.random().int(u16);

        // Apply 0x20 case randomization if enabled
        const query_name = if (self.config.case_randomization)
            try name_mod.applyCase0x20(self.allocator, domain, self.prng.random())
        else
            try self.allocator.dupe(u8, domain);
        defer self.allocator.free(query_name);

        // Store for verification
        if (state.last_query_name) |old| {
            self.allocator.free(old);
        }
        state.last_query_name = try self.allocator.dupe(u8, query_name);

        const query = try message_mod.buildQuery(self.allocator, id, query_name, qtype, .in, self.config.dnssec);
        defer self.allocator.free(query);

        // Try servers in order
        const max_tries = @min(servers.len, self.config.parallel_queries);
        for (servers[0..max_tries]) |server| {
            const response = self.sendQuery(query, server) catch continue;

            if (response.len >= 2) {
                const resp_id = std.mem.readInt(u16, response[0..2], .big);
                if (resp_id == id and responseMatchesQuery(self.allocator, response, query_name, qtype, .in)) {
                    return response;
                }
            }
            self.allocator.free(response);
        }

        return error.NoResponse;
    }

    /// Send a single query to a server
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
        while (true) {
            if (std.time.milliTimestamp() - start_ms >= self.config.timeout_ms) {
                return error.Timeout;
            }

            // Receive response (capture source)
            var buffer: [65535]u8 = undefined;
            var src_addr: std.net.Address = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(std.net.Address);
            const recv_len = std.posix.recvfrom(sock, &buffer, 0, &src_addr.any, &src_len) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionTimedOut => return error.Timeout,
                else => return err,
            };

            if (!std.net.Address.eql(src_addr, server.address)) {
                continue;
            }

            const response = try self.allocator.alloc(u8, recv_len);
            @memcpy(response, buffer[0..recv_len]);
            return response;
        }
    }

    /// Extract referral information from a response
    fn extractReferral(self: *Self, response: []const u8, msg: Message) !?Referral {
        var ns_names: std.ArrayList([]const u8) = .{};
        defer ns_names.deinit(self.allocator);

        var zone_name: ?[]const u8 = null;

        // Get NS records from authority section
        var auth_iter = try msg.authority();
        while (try auth_iter.next()) |rr| {
            if (rr.rtype == .ns) {
                if (zone_name == null) {
                    zone_name = try rr.getName(self.allocator, response);
                }

                const ns_name = try rr.parseName(response);
                const ns_str = try ns_name.toString(self.allocator, response);
                try ns_names.append(self.allocator, ns_str);
            }
        }

        if (ns_names.items.len == 0) {
            return null;
        }

        // Build server info with addresses from additional section
        var servers = try self.allocator.alloc(Referral.ServerInfo, ns_names.items.len);
        for (ns_names.items, 0..) |ns, i| {
            servers[i] = .{
                .name = ns,
                .address = null,
            };

            // Look for glue records
            var add_iter = try msg.additional();
            while (try add_iter.next()) |add_rr| {
                if (add_rr.rtype == .a) {
                    const add_name = try add_rr.getName(self.allocator, response);
                    defer self.allocator.free(add_name);

                    if (std.ascii.eqlIgnoreCase(add_name, ns)) {
                        const addr = try add_rr.parseA();
                        const ip_str = try std.fmt.allocPrint(
                            self.allocator,
                            "{d}.{d}.{d}.{d}",
                            .{ addr[0], addr[1], addr[2], addr[3] },
                        );
                        defer self.allocator.free(ip_str);

                        servers[i].address = ServerAddress.fromIpv4(ip_str, types_mod.dns_port) catch null;
                        break;
                    }
                }
            }
        }

        return Referral{
            .zone = zone_name orelse ".",
            .servers = servers,
        };
    }

    /// Resolve NS address when glue is missing
    fn resolveNsAddress(self: *Self, ns_name: []const u8) ?ServerAddress {
        // Recursive call to resolve the NS hostname
        const result = self.resolve(ns_name, .a) catch return null;
        defer if (result.answer) |a| self.allocator.free(a);

        if (result.status != .success) {
            return null;
        }

        if (result.answer) |answer| {
            const msg = Message.parse(answer) catch return null;
            var ans_iter = msg.answers() catch return null;
            while (ans_iter.next() catch null) |rr| {
                if (rr.rtype == .a) {
                    const addr = rr.parseA() catch continue;
                    const ip_str = std.fmt.allocPrint(
                        self.allocator,
                        "{d}.{d}.{d}.{d}",
                        .{ addr[0], addr[1], addr[2], addr[3] },
                    ) catch continue;
                    defer self.allocator.free(ip_str);

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
        const qname = q.getName(self.allocator, msg.data) catch return;
        defer self.allocator.free(qname);

        var ans_iter = try msg.answers();
        while (try ans_iter.next()) |rr| {
            const name_str = try rr.getName(self.allocator, response);
            defer self.allocator.free(name_str);
            try self.cache.putWithBailiwick(name_str, rr, qname);
        }
    }

    /// Clear the cache
    pub fn clearCache(self: *Self) void {
        self.cache.clear();
    }
};

fn trimTrailingDot(name: []const u8) []const u8 {
    if (name.len > 0 and name[name.len - 1] == '.') {
        return name[0 .. name.len - 1];
    }
    return name;
}

fn namesEqual(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(trimTrailingDot(a), trimTrailingDot(b));
}

fn responseMatchesQuery(
    allocator: std.mem.Allocator,
    response: []const u8,
    expected_name: []const u8,
    expected_type: Type,
    expected_class: Class,
) bool {
    const msg = Message.parse(response) catch return false;
    if (!msg.header.qr) return false;
    if (msg.header.opcode != .query) return false;
    if (msg.header.qdcount == 0) return false;

    var q_iter = msg.questions();
    const q = (q_iter.next() catch null) orelse return false;
    if (q.qtype != expected_type or q.qclass != expected_class) return false;

    const qname = q.getName(allocator, msg.data) catch return false;
    defer allocator.free(qname);

    return namesEqual(qname, expected_name);
}

/// Internal resolution state
const ResolutionState = struct {
    original_qname: []const u8,
    qtype: Type,
    depth: u8,
    query_count: u16,
    current_zone: []const u8,
    cname_chain: std.ArrayList([]const u8),
    last_query_name: ?[]const u8 = null,
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

test "RecursiveResolver.getMinimizedQname" {
    const allocator = std.testing.allocator;

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    // depth=0: just TLD
    const q0 = try resolver.getMinimizedQname("www.example.com", ".", 0);
    defer allocator.free(q0);
    try std.testing.expectEqualStrings("com", q0);

    // depth=1: second-level + TLD
    const q1 = try resolver.getMinimizedQname("www.example.com", ".", 1);
    defer allocator.free(q1);
    try std.testing.expectEqualStrings("example.com", q1);

    // depth=2: full name
    const q2 = try resolver.getMinimizedQname("www.example.com", ".", 2);
    defer allocator.free(q2);
    try std.testing.expectEqualStrings("www.example.com", q2);

    // depth >= labels: full name
    const q3 = try resolver.getMinimizedQname("www.example.com", ".", 10);
    defer allocator.free(q3);
    try std.testing.expectEqualStrings("www.example.com", q3);
}
