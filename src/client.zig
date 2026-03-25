// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Client
//!
//! High-level DNS resolution interface combining stub and recursive
//! resolution capabilities.

const std = @import("std");
const message_mod = @import("message");
const name_mod = @import("name");
const types_mod = @import("types");
const header_mod = @import("header");
const question_mod = @import("question");
const record_mod = @import("record");
const stub_mod = @import("stub");
const recursive_mod = @import("recursive");
const dns_cache_mod = @import("dns_cache");
const clock_mod = @import("clock");
const cache_prefetch_mod = @import("cache_prefetch");
const edns_mod = @import("edns");

pub const Message = message_mod.Message;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const StubResolver = stub_mod.StubResolver;
pub const RecursiveResolver = recursive_mod.RecursiveResolver;
pub const DnsCache = dns_cache_mod.DnsCache;
pub const PackedRdataIterator = dns_cache_mod.PackedRdataIterator;
pub const CachePrefetcher = cache_prefetch_mod.CachePrefetcher;

/// DNS Client mode
pub const Mode = enum {
    /// Use system resolver (stub mode)
    stub,
    /// Use recursive resolution from root servers
    recursive,
};

/// DNS Client configuration
pub const ClientConfig = struct {
    /// Resolution mode
    mode: Mode = .stub,

    /// DNS servers for stub mode (if empty, uses system servers)
    servers: []const []const u8 = &[_][]const u8{},

    /// Query timeout in milliseconds
    timeout_ms: u32 = 5000,

    /// Cache size (0 to disable)
    cache_size: usize = 1000,

    /// Whether to use EDNS
    use_edns: bool = true,

    /// EDNS UDP payload size
    edns_payload_size: u16 = 4096,
};

/// DNS Client
/// Provides a high-level interface for DNS resolution
pub const Client = struct {
    allocator: std.mem.Allocator,
    config: ClientConfig,
    stub: ?StubResolver,
    recursive: ?RecursiveResolver,
    cache: ?DnsCache,
    prefetcher: ?CachePrefetcher,
    system_clock: clock_mod.SystemClock,
    servers_owned: bool,
    server_addresses: []stub_mod.ServerAddress,

    const Self = @This();

    /// Create a new DNS client with default configuration
    pub fn init(allocator: std.mem.Allocator) !Self {
        return initWithConfig(allocator, .{});
    }

    /// Create a new DNS client with custom configuration
    pub fn initWithConfig(allocator: std.mem.Allocator, config: ClientConfig) !Self {
        var self = Self{
            .allocator = allocator,
            .config = config,
            .stub = null,
            .recursive = null,
            .cache = null,
            .prefetcher = null,
            .system_clock = clock_mod.systemClock(),
            .servers_owned = false,
            .server_addresses = &[_]stub_mod.ServerAddress{},
        };

        // Initialize cache if enabled (PF-24-dual-cache: O(1) LRU HashMap)
        if (config.cache_size > 0) {
            self.cache = DnsCache.init(allocator, .{
                .max_entries = config.cache_size,
            }, self.system_clock.clock());
            // PF-22-prefetch: Schedule proactive cache refresh for entries nearing expiry
            self.prefetcher = CachePrefetcher.init(allocator, .{}, self.system_clock.clock());
        }

        // Initialize resolver based on mode
        switch (config.mode) {
            .stub => {
                // Get server addresses
                if (config.servers.len > 0) {
                    self.server_addresses = try allocator.alloc(stub_mod.ServerAddress, config.servers.len);
                    self.servers_owned = true;
                    for (config.servers, 0..) |server_ip, i| {
                        self.server_addresses[i] = try stub_mod.ServerAddress.fromIpv4(server_ip, types_mod.dns_port);
                    }
                } else {
                    self.server_addresses = try stub_mod.getSystemServers(allocator);
                    self.servers_owned = true;
                }

                self.stub = try StubResolver.init(allocator, .{
                    .servers = self.server_addresses,
                    .timeout_ms = config.timeout_ms,
                });
            },
            .recursive => {
                self.recursive = try RecursiveResolver.init(allocator, .{
                    .timeout_ms = config.timeout_ms,
                    .cache_size = config.cache_size,
                });
            },
        }

        return self;
    }

    /// Free client resources
    pub fn deinit(self: *Self) void {
        if (self.stub) |*stub| {
            stub.deinit();
        }
        if (self.recursive) |*recursive| {
            recursive.deinit();
        }
        if (self.prefetcher) |*pf| {
            pf.deinit();
        }
        if (self.cache) |*cache| {
            cache.deinit();
        }
        if (self.servers_owned) {
            self.allocator.free(self.server_addresses);
        }
    }

    /// Resolve a hostname to string-formatted addresses.
    ///
    /// This method only formats A and AAAA records into string results.
    /// For other record types (MX, SRV, TXT, NS, etc.), use the
    /// type-specific lookup methods (lookupMX, lookupSRV, etc.) or
    /// the lower-level stub/recursive resolvers directly.
    ///
    /// Returns `error.UnsupportedRecordType` if called with a record type
    /// other than A or AAAA (QA-AUDIT-02).
    pub fn resolve(self: *Self, hostname: []const u8, qtype: Type) !ResolveResult {
        // QA-AUDIT-02: Only A and AAAA records can be formatted by resolve().
        // Return an explicit error instead of silently returning NoAnswer for
        // types we cannot format. Callers should use type-specific methods
        // (lookupMX, lookupSRV, etc.) for other record types.
        if (qtype != .a and qtype != .aaaa) {
            return error.UnsupportedRecordType;
        }

        // Check cache first (PF-24-dual-cache: O(1) lookup)
        if (self.cache) |*cache| {
            if (cache.get(hostname, qtype, .in)) |entry| {
                if (entry.entry_type == .positive) {
                    var results: std.ArrayList([]const u8) = .empty;
                    try results.ensureTotalCapacity(self.allocator, 4);
                    errdefer {
                        for (results.items) |item| {
                            self.allocator.free(item);
                        }
                        results.deinit(self.allocator);
                    }

                    // Iterate packed rdata segments [u16 len][rdata]...
                    var rdata_iter = PackedRdataIterator.init(entry.rdata);
                    while (rdata_iter.next()) |rdata| {
                        const formatted_opt: ?[]const u8 = formatCachedRdata(self.allocator, qtype, rdata) catch null;
                        if (formatted_opt) |formatted| {
                            errdefer self.allocator.free(formatted);
                            try results.append(self.allocator, formatted);
                        }
                    }

                    if (results.items.len > 0) {
                        // PF-22-prefetch: schedule background refresh if entry nearing expiry
                        if (self.prefetcher) |*pf| {
                            cache_prefetch_mod.checkAndSchedulePrefetch(pf, entry, hostname, qtype, .in);
                        }
                        return ResolveResult{
                            .addresses = try results.toOwnedSlice(self.allocator),
                            .from_cache = true,
                        };
                    }
                }
            }
        }

        // Perform resolution
        const response = switch (self.config.mode) {
            .stub => blk: {
                const msg = try self.stub.?.resolve(hostname, qtype);
                break :blk msg;
            },
            .recursive => blk: {
                const result = try self.recursive.?.resolve(hostname, qtype);
                if (result.answer) |answer| {
                    break :blk try Message.parse(answer);
                }
                return error.NoAnswer;
            },
        };
        defer self.allocator.free(response.data);

        // Process response -- skip CNAME chain building when no CNAMEs present (PF-NEW-25).
        // The common case (A/AAAA with no aliases) avoids the full buildCnameChain cost.
        const has_cnames = hasCnameRecords(response);
        var cname_chain: std.ArrayList([]const u8) = .empty;
        if (has_cnames) {
            cname_chain = try buildCnameChain(self.allocator, response, response.data, hostname);
        } else {
            // No CNAMEs: the chain is just the query name itself.
            try cname_chain.ensureTotalCapacity(self.allocator, 1);
            const qname_copy = try self.allocator.dupe(u8, trimTrailingDot(hostname));
            cname_chain.appendAssumeCapacity(qname_copy);
        }
        defer {
            for (cname_chain.items) |name_item| {
                self.allocator.free(name_item);
            }
            cname_chain.deinit(self.allocator);
        }

        // Pre-allocate for typical small result sets (PF-NEW-24).
        var results: std.ArrayList([]const u8) = .empty;
        try results.ensureTotalCapacity(self.allocator, 4);
        errdefer {
            for (results.items) |item| {
                self.allocator.free(item);
            }
            results.deinit(self.allocator);
        }

        // Extract answers
        var ans_iter = response.answers();
        var owner_buf: [256]u8 = undefined;
        while (try ans_iter.next()) |rr| {
            // Use stack buffer instead of heap allocation for owner name (PF-30).
            // DNS names are at most 253 chars; 256-byte buffer always suffices.
            const owner = rr.name.toStringBuf(&owner_buf, response.data) catch continue;

            if (!nameInChain(cname_chain.items, owner)) {
                continue;
            }

            // Cache the record under its owner name
            if (self.cache) |*cache| {
                cache.putRecord(owner, rr.rtype, rr.class, rr.rdata, rr.ttl) catch |err| {
                    // Cache population is best-effort; resolution succeeds regardless.
                    // Log at debug level so operators can diagnose cache issues.
                    std.log.debug("cache put failed: {}", .{err});
                };
            }

            if (rr.rtype == qtype) {
                if (qtype == .a) {
                    // Use stack buffer to avoid allocPrint overhead (PF-NEW-05)
                    var a_buf: [15]u8 = undefined;
                    const formatted = try rr.formatABuf(&a_buf);
                    try results.append(self.allocator, try self.allocator.dupe(u8, formatted));
                } else if (qtype == .aaaa) {
                    // Use stack buffer to avoid allocPrint overhead (PF-NEW-06)
                    var aaaa_buf: [39]u8 = undefined;
                    const formatted = try rr.formatAAAABuf(&aaaa_buf);
                    try results.append(self.allocator, try self.allocator.dupe(u8, formatted));
                }
            }
        }

        if (results.items.len == 0) {
            // Check for NXDOMAIN
            if (response.isNxdomain()) {
                return error.NameNotFound;
            }
            return error.NoAnswer;
        }

        return ResolveResult{
            .addresses = try results.toOwnedSlice(self.allocator),
            .from_cache = false,
        };
    }

    /// Resolve hostname to IPv4 addresses
    pub fn resolveA(self: *Self, hostname: []const u8) !ResolveResult {
        return self.resolve(hostname, .a);
    }

    /// Resolve hostname to IPv6 addresses
    pub fn resolveAAAA(self: *Self, hostname: []const u8) !ResolveResult {
        return self.resolve(hostname, .aaaa);
    }

    /// Lookup MX records
    pub fn lookupMX(self: *Self, domain: []const u8) ![]MXRecord {
        const response = switch (self.config.mode) {
            .stub => try self.stub.?.resolve(domain, .mx),
            .recursive => blk: {
                const result = try self.recursive.?.resolve(domain, .mx);
                if (result.answer) |answer| {
                    break :blk try Message.parse(answer);
                }
                return error.NoAnswer;
            },
        };
        defer self.allocator.free(response.data);

        var results: std.ArrayList(MXRecord) = .empty;
        errdefer {
            for (results.items) |mx| {
                self.allocator.free(mx.exchange);
            }
            results.deinit(self.allocator);
        }

        var ans_iter = response.answers();
        while (try ans_iter.next()) |rr| {
            if (rr.rtype == .mx) {
                const mx_data = try rr.parseMX(response.data);
                // Use stack buffer to avoid ArrayList overhead (PF-NEW-05)
                var mx_buf: [256]u8 = undefined;
                const exchange_str = try mx_data.exchange.toStringBuf(&mx_buf, response.data);
                const exchange = try self.allocator.dupe(u8, exchange_str);
                errdefer self.allocator.free(exchange);
                try results.append(self.allocator, .{
                    .preference = mx_data.preference,
                    .exchange = exchange,
                });
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Clear the cache
    pub fn clearCache(self: *Self) void {
        if (self.prefetcher) |*pf| {
            pf.clear();
        }
        if (self.cache) |*cache| {
            cache.clear();
        }
        if (self.recursive) |*recursive| {
            recursive.clearCache();
        }
    }
};

/// Result of a DNS resolution
pub const ResolveResult = struct {
    /// Resolved addresses
    addresses: []const []const u8,

    /// Whether the result came from cache
    from_cache: bool,

    /// Free the result
    pub fn deinit(self: *ResolveResult, allocator: std.mem.Allocator) void {
        for (self.addresses) |addr| {
            allocator.free(addr);
        }
        allocator.free(self.addresses);
    }
};

/// MX Record result returned by `Client.lookupMX`.
///
/// **Ownership:** The caller owns each `exchange` string and the returned
/// slice itself. Both must be freed with the same allocator that was used
/// to create the `Client`. For example:
///
/// ```zig
/// const mx_records = try client.lookupMX("example.com");
/// defer {
///     for (mx_records) |mx| allocator.free(mx.exchange);
///     allocator.free(mx_records);
/// }
/// ```
pub const MXRecord = struct {
    preference: u16,
    exchange: []const u8,
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

fn nameInChain(chain: []const []const u8, name: []const u8) bool {
    for (chain) |item| {
        if (namesEqual(item, name)) {
            return true;
        }
    }
    return false;
}

/// Quick check for CNAME records in the answer section (PF-NEW-25).
/// Uses a lightweight iteration that only inspects rtype fields without
/// allocating or parsing rdata, so the common no-CNAME path is fast.
fn hasCnameRecords(msg: Message) bool {
    var iter = msg.answers();
    while (iter.next() catch null) |rr| {
        if (rr.rtype == .cname) return true;
    }
    return false;
}

/// A CNAME mapping from owner name to target name.
const CnameMapping = struct {
    owner: []const u8,
    target: []const u8,
};

/// Maximum number of CNAME records we collect from a single response.
/// RFC 1034 recommends following CNAME chains; 16 is generous enough to
/// hold all unique CNAME records that a single DNS response might contain.
///
/// QR-04: This limit is distinct from `max_cname_depth` (below) and from
/// `max_cname_chain_length` in recursive.zig. `max_cname_mappings` bounds
/// the total number of CNAME owner->target pairs extracted from one response
/// (storage), while `max_cname_depth` and `max_cname_chain_length` bound
/// the traversal depth when following the CNAME chain (loop prevention).
const max_cname_mappings = 16;

/// Maximum depth when traversing a CNAME chain within a single response.
/// This limits how many hops `buildCnameChain` will follow from the query
/// name through successive CNAME targets before stopping.
///
/// QR-04: This serves a similar purpose to `max_cname_chain_length` (= 8)
/// in recursive.zig, but in a different context: recursive.zig limits CNAME
/// redirections across multiple iterative queries to authoritative servers,
/// while this limits CNAME hops within a single already-received response.
/// Both values are set to 8 intentionally, matching the common DNS practice
/// of allowing at most 8 CNAME hops.
const max_cname_depth: u8 = 8;

fn buildCnameChain(
    allocator: std.mem.Allocator,
    msg: Message,
    response: []const u8,
    qname: []const u8,
) !std.ArrayList([]const u8) {
    var chain: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (chain.items) |item| {
            allocator.free(item);
        }
        chain.deinit(allocator);
    }

    // Pre-build CNAME owner->target mappings in a single pass over answers.
    // This replaces O(hops * ancount) with O(ancount + hops).
    var mappings: [max_cname_mappings]CnameMapping = undefined;
    var mapping_count: usize = 0;

    // Track allocated strings so we can free them on exit
    var mapping_owners: [max_cname_mappings][]const u8 = undefined;
    var mapping_targets: [max_cname_mappings][]const u8 = undefined;

    defer {
        for (0..mapping_count) |i| {
            allocator.free(mapping_owners[i]);
            allocator.free(mapping_targets[i]);
        }
    }

    var ans_iter = msg.answers();
    while (try ans_iter.next()) |rr| {
        if (rr.rtype != .cname) continue;
        if (mapping_count >= max_cname_mappings) break;

        // Use stack buffers for temporary name formatting (PF-NEW-08).
        // Only dupe into heap for the mapping arrays that outlive this iteration.
        var owner_stack_buf: [256]u8 = undefined;
        const owner_str = rr.name.toStringBuf(&owner_stack_buf, response) catch continue;

        var target_stack_buf: [256]u8 = undefined;
        const target_name = rr.parseName(response) catch continue;
        const target_str = target_name.toStringBuf(&target_stack_buf, response) catch continue;

        const owner = allocator.dupe(u8, owner_str) catch continue;
        errdefer allocator.free(owner);
        const target = allocator.dupe(u8, target_str) catch {
            allocator.free(owner);
            continue;
        };

        mapping_owners[mapping_count] = owner;
        mapping_targets[mapping_count] = target;
        mappings[mapping_count] = .{ .owner = owner, .target = target };
        mapping_count += 1;
    }

    // Build the chain by walking the pre-built mappings
    const qname_copy = try allocator.dupe(u8, trimTrailingDot(qname));
    try chain.append(allocator, qname_copy);

    var current: []const u8 = qname_copy;
    var depth: u8 = 0;

    while (depth < max_cname_depth) : (depth += 1) {
        var found = false;
        for (mappings[0..mapping_count]) |m| {
            if (!namesEqual(m.owner, current)) continue;

            if (nameInChain(chain.items, m.target)) {
                return chain;
            }

            const target_copy = try allocator.dupe(u8, m.target);
            try chain.append(allocator, target_copy);
            current = target_copy;
            found = true;
            break;
        }

        if (!found) break;
    }

    return chain;
}

/// Format cached rdata bytes into a human-readable string for the given record type.
///
/// Supported types (DG-06):
///   - A:     dotted-decimal IPv4 ("1.2.3.4")
///   - AAAA:  colon-hex IPv6 ("2001:0db8:...")
///   - TXT:   concatenated text strings
///   - MX:    "preference exchange" (e.g., "10 mail.example.com")
///   - NS, CNAME, PTR: domain name string
///   - SRV:   "priority weight port target"
///   - SOA:   "mname rname serial refresh retry expire minimum"
///
/// Name-based types (MX, NS, CNAME, PTR, SRV, SOA) attempt to parse DNS
/// wire-format names from the cached rdata buffer. If the original rdata
/// used compression pointers (which reference the now-freed full message),
/// parsing will fail and this function returns `error.InvalidOffset` or
/// similar -- callers should treat this as a cache miss.
///
/// Returns an allocator-owned string on success, or null/error when the
/// rdata cannot be interpreted for the given type.
fn formatCachedRdata(allocator: std.mem.Allocator, qtype: Type, rdata: []const u8) ![]const u8 {
    switch (qtype) {
        .a => {
            if (rdata.len != 4) return error.InvalidRdataLength;
            var buf: [15]u8 = undefined;
            const formatted = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                rdata[0], rdata[1], rdata[2], rdata[3],
            }) catch unreachable;
            return try allocator.dupe(u8, formatted);
        },
        .aaaa => {
            if (rdata.len != 16) return error.InvalidRdataLength;
            var buf: [39]u8 = undefined;
            const formatted = std.fmt.bufPrint(&buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                rdata[0],  rdata[1],  rdata[2],  rdata[3],
                rdata[4],  rdata[5],  rdata[6],  rdata[7],
                rdata[8],  rdata[9],  rdata[10], rdata[11],
                rdata[12], rdata[13], rdata[14], rdata[15],
            }) catch unreachable;
            return try allocator.dupe(u8, formatted);
        },
        .txt => {
            // TXT rdata: one or more length-prefixed strings, concatenated.
            var total_len: usize = 0;
            var pos: usize = 0;
            while (pos < rdata.len) {
                const str_len = rdata[pos];
                pos += 1;
                if (pos + str_len > rdata.len) return error.InvalidRdataLength;
                total_len += str_len;
                pos += str_len;
            }
            const result = try allocator.alloc(u8, total_len);
            errdefer allocator.free(result);
            var write_pos: usize = 0;
            pos = 0;
            while (pos < rdata.len) {
                const str_len = rdata[pos];
                pos += 1;
                @memcpy(result[write_pos..][0..str_len], rdata[pos..][0..str_len]);
                write_pos += str_len;
                pos += str_len;
            }
            return result;
        },
        .mx => {
            // MX rdata: 2-byte preference + DNS name.
            if (rdata.len < 3) return error.InvalidRdataLength;
            const preference = std.mem.readInt(u16, rdata[0..2], .big);
            const exchange_name = try name_mod.Name.parse(rdata, 2);
            var name_buf: [256]u8 = undefined;
            const exchange_str = try exchange_name.toStringBuf(&name_buf, rdata);
            // Format: "preference exchange"
            var fmt_buf: [280]u8 = undefined;
            const formatted = std.fmt.bufPrint(&fmt_buf, "{d} {s}", .{ preference, exchange_str }) catch
                return error.NameTooLong;
            return try allocator.dupe(u8, formatted);
        },
        .ns, .cname, .ptr => {
            // NS/CNAME/PTR rdata: a single DNS name.
            if (rdata.len < 1) return error.InvalidRdataLength;
            const parsed_name = try name_mod.Name.parse(rdata, 0);
            var name_buf: [256]u8 = undefined;
            const name_str = try parsed_name.toStringBuf(&name_buf, rdata);
            return try allocator.dupe(u8, name_str);
        },
        .srv => {
            // SRV rdata: 2-byte priority + 2-byte weight + 2-byte port + DNS name.
            if (rdata.len < 7) return error.InvalidRdataLength;
            const priority = std.mem.readInt(u16, rdata[0..2], .big);
            const weight = std.mem.readInt(u16, rdata[2..4], .big);
            const port = std.mem.readInt(u16, rdata[4..6], .big);
            const target_name = try name_mod.Name.parse(rdata, 6);
            var name_buf: [256]u8 = undefined;
            const target_str = try target_name.toStringBuf(&name_buf, rdata);
            var fmt_buf: [300]u8 = undefined;
            const formatted = std.fmt.bufPrint(&fmt_buf, "{d} {d} {d} {s}", .{ priority, weight, port, target_str }) catch
                return error.NameTooLong;
            return try allocator.dupe(u8, formatted);
        },
        .soa => {
            // SOA rdata: mname + rname + 5x u32 (serial, refresh, retry, expire, minimum).
            if (rdata.len < 22) return error.InvalidRdataLength;
            const mname = try name_mod.Name.parse(rdata, 0);
            var mname_buf: [256]u8 = undefined;
            const mname_str = try mname.toStringBuf(&mname_buf, rdata);
            const rname_offset = mname.wire_length;
            const rname = try name_mod.Name.parse(rdata, rname_offset);
            var rname_buf: [256]u8 = undefined;
            const rname_str = try rname.toStringBuf(&rname_buf, rdata);
            const int_offset = rname_offset + rname.wire_length;
            if (int_offset + 20 > rdata.len) return error.InvalidRdataLength;
            const serial = std.mem.readInt(u32, rdata[int_offset..][0..4], .big);
            const refresh = std.mem.readInt(u32, rdata[int_offset + 4 ..][0..4], .big);
            const retry = std.mem.readInt(u32, rdata[int_offset + 8 ..][0..4], .big);
            const expire = std.mem.readInt(u32, rdata[int_offset + 12 ..][0..4], .big);
            const minimum = std.mem.readInt(u32, rdata[int_offset + 16 ..][0..4], .big);
            var fmt_buf: [600]u8 = undefined;
            const formatted = std.fmt.bufPrint(&fmt_buf, "{s} {s} {d} {d} {d} {d} {d}", .{
                mname_str, rname_str, serial, refresh, retry, expire, minimum,
            }) catch return error.NameTooLong;
            return try allocator.dupe(u8, formatted);
        },
        else => return error.UnsupportedRecordType,
    }
}

test "Client.init default" {
    // Note: This test requires network access and system DNS
    // In practice, we'd mock the network layer
    const allocator = std.testing.allocator;

    var client = Client.initWithConfig(allocator, .{
        .servers = &[_][]const u8{"8.8.8.8"},
        .cache_size = 0,
    }) catch {
        // Expected to fail without network
        return;
    };
    defer client.deinit();

    try std.testing.expect(client.stub != null);
}

test "ClientConfig defaults" {
    const config = ClientConfig{};
    try std.testing.expectEqual(Mode.stub, config.mode);
    try std.testing.expectEqual(@as(u32, 5000), config.timeout_ms);
    try std.testing.expectEqual(@as(usize, 1000), config.cache_size);
}

test "buildCnameChain from response" {
    const allocator = std.testing.allocator;

    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x02, // ANCOUNT: 2
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: www.example.com A IN
        3,    'w',
        'w',  'w',
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
        // Answer 1: CNAME www.example.com -> alias.example.net
        0xC0, 0x0C, // Name pointer to question
        0x00, 0x05, // TYPE: CNAME
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x13, // RDLENGTH: 19
        5,    'a',
        'l',  'i',
        'a',  's',
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'n',
        'e',  't',
        0,
        // Answer 2: alias.example.net A IN 1.2.3.4
           5,
        'a',  'l',
        'i',  'a',
        's',  7,
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  3,
        'n',  'e',
        't',  0,
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // RDLENGTH: 4
        1, 2, 3, 4, // RDATA
    };

    const msg = try Message.parse(&data);
    var chain = try buildCnameChain(allocator, msg, msg.data, "www.example.com");
    defer {
        for (chain.items) |item| {
            allocator.free(item);
        }
        chain.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 2), chain.items.len);
    try std.testing.expectEqualStrings("www.example.com", chain.items[0]);
    try std.testing.expectEqualStrings("alias.example.net", chain.items[1]);
    try std.testing.expect(nameInChain(chain.items, "ALIAS.EXAMPLE.NET"));
}

test "formatCachedRdata A record" {
    const allocator = std.testing.allocator;
    const rdata = [_]u8{ 93, 184, 216, 34 };
    const result = try formatCachedRdata(allocator, .a, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("93.184.216.34", result);
}

test "formatCachedRdata AAAA record" {
    const allocator = std.testing.allocator;
    const rdata = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const result = try formatCachedRdata(allocator, .aaaa, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("2001:0db8:0000:0000:0000:0000:0000:0001", result);
}

test "formatCachedRdata TXT record" {
    const allocator = std.testing.allocator;
    // TXT rdata: length-prefixed string "hello"
    const rdata = [_]u8{ 5, 'h', 'e', 'l', 'l', 'o' };
    const result = try formatCachedRdata(allocator, .txt, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "formatCachedRdata TXT record multiple strings" {
    const allocator = std.testing.allocator;
    // TXT rdata: "hi" + "there"
    const rdata = [_]u8{ 2, 'h', 'i', 5, 't', 'h', 'e', 'r', 'e' };
    const result = try formatCachedRdata(allocator, .txt, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("hithere", result);
}

test "formatCachedRdata MX record uncompressed" {
    const allocator = std.testing.allocator;
    // MX rdata: preference=10, exchange=mail.example.com (uncompressed)
    const rdata = [_]u8{
        0x00, 0x0A, // preference: 10
        4,    'm',
        'a',  'i',
        'l',  7,
        'e',  'x',
        'a',  'm',
        'p',  'l',
        'e',  3,
        'c',  'o',
        'm',
        0, // root label
    };
    const result = try formatCachedRdata(allocator, .mx, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("10 mail.example.com", result);
}

test "formatCachedRdata NS record uncompressed" {
    const allocator = std.testing.allocator;
    // NS rdata: ns1.example.com (uncompressed)
    const rdata = [_]u8{
        3,   'n', 's', '1',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };
    const result = try formatCachedRdata(allocator, .ns, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("ns1.example.com", result);
}

test "formatCachedRdata CNAME record uncompressed" {
    const allocator = std.testing.allocator;
    const rdata = [_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };
    const result = try formatCachedRdata(allocator, .cname, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("www.example.com", result);
}

test "formatCachedRdata SRV record uncompressed" {
    const allocator = std.testing.allocator;
    // SRV rdata: priority=10 weight=20 port=5060 target=sip.example.com
    const rdata = [_]u8{
        0x00, 0x0A, // priority: 10
        0x00, 0x14, // weight: 20
        0x13, 0xC4, // port: 5060
        3,    's',
        'i',  'p',
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
    };
    const result = try formatCachedRdata(allocator, .srv, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("10 20 5060 sip.example.com", result);
}

test "formatCachedRdata SOA record uncompressed" {
    const allocator = std.testing.allocator;
    // SOA rdata: mname=ns.example.com rname=admin.example.com serial=1 refresh=3600 retry=900 expire=86400 minimum=300
    const rdata = [_]u8{
        2,   'n', 's',
        7,   'e', 'x',
        'a', 'm', 'p',
        'l', 'e', 3,
        'c', 'o', 'm',
        0, // mname: ns.example.com
        5,
        'a',
        'd',
        'm',
        'i',
        'n',
        7,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        3,
        'c',
        'o',
        'm',
        0, // rname: admin.example.com
        0x00, 0x00, 0x00, 0x01, // serial: 1
        0x00, 0x00, 0x0E, 0x10, // refresh: 3600
        0x00, 0x00, 0x03, 0x84, // retry: 900
        0x00, 0x01, 0x51, 0x80, // expire: 86400
        0x00, 0x00, 0x01, 0x2C, // minimum: 300
    };
    const result = try formatCachedRdata(allocator, .soa, &rdata);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("ns.example.com admin.example.com 1 3600 900 86400 300", result);
}

test "formatCachedRdata A record wrong length" {
    const allocator = std.testing.allocator;
    const rdata = [_]u8{ 1, 2, 3 }; // too short
    try std.testing.expectError(error.InvalidRdataLength, formatCachedRdata(allocator, .a, &rdata));
}

test "formatCachedRdata compressed name returns error" {
    const allocator = std.testing.allocator;
    // NS rdata with a compression pointer (0xC0, 0x0C) -- invalid without full message.
    // Name.parse detects that the pointer target (offset 12) exceeds the current
    // position in the small 2-byte buffer, returning ForwardPointer.
    const rdata = [_]u8{ 0xC0, 0x0C };
    try std.testing.expectError(error.ForwardPointer, formatCachedRdata(allocator, .ns, &rdata));
}

test "QA-AUDIT-02: resolve rejects unsupported record types" {
    // resolve() only supports A and AAAA formatting. For other types it must
    // return UnsupportedRecordType instead of silently returning NoAnswer.
    const allocator = std.testing.allocator;

    var client = Client.initWithConfig(allocator, .{
        .servers = &[_][]const u8{"8.8.8.8"},
        .cache_size = 0,
    }) catch {
        // Expected to fail without network -- skip.
        return;
    };
    defer client.deinit();

    // MX, TXT, SRV, NS, CNAME, PTR, SOA should all return UnsupportedRecordType.
    const unsupported_types = [_]Type{ .mx, .txt, .srv, .ns, .cname, .ptr, .soa };
    for (unsupported_types) |rtype| {
        try std.testing.expectError(error.UnsupportedRecordType, client.resolve("example.com", rtype));
    }
}
