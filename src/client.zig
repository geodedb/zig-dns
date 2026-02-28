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
const cache_mod = @import("cache");
const edns_mod = @import("edns");

pub const Message = message_mod.Message;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const StubResolver = stub_mod.StubResolver;
pub const RecursiveResolver = recursive_mod.RecursiveResolver;
pub const Cache = cache_mod.Cache;

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
    cache: ?Cache,
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
            .servers_owned = false,
            .server_addresses = &[_]stub_mod.ServerAddress{},
        };

        // Initialize cache if enabled
        if (config.cache_size > 0) {
            self.cache = Cache.init(allocator, config.cache_size);
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
        if (self.cache) |*cache| {
            cache.deinit();
        }
        if (self.servers_owned) {
            self.allocator.free(self.server_addresses);
        }
    }

    /// Resolve a hostname to IP addresses
    pub fn resolve(self: *Self, hostname: []const u8, qtype: Type) !ResolveResult {
        // Check cache first
        if (self.cache) |*cache| {
            if (cache.get(hostname, qtype, .in)) |entries| {
                const now = std.time.timestamp();
                var results: std.ArrayList([]const u8) = .empty;
                errdefer results.deinit(self.allocator);

                for (entries) |entry| {
                    if (!entry.isExpired(now)) {
                        // Format based on type
                        if (qtype == .a and entry.rdata.len == 4) {
                            const formatted = try std.fmt.allocPrint(self.allocator, "{d}.{d}.{d}.{d}", .{
                                entry.rdata[0], entry.rdata[1], entry.rdata[2], entry.rdata[3],
                            });
                            try results.append(self.allocator, formatted);
                        } else if (qtype == .aaaa and entry.rdata.len == 16) {
                            const formatted = try std.fmt.allocPrint(self.allocator, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                                entry.rdata[0],  entry.rdata[1],  entry.rdata[2],  entry.rdata[3],
                                entry.rdata[4],  entry.rdata[5],  entry.rdata[6],  entry.rdata[7],
                                entry.rdata[8],  entry.rdata[9],  entry.rdata[10], entry.rdata[11],
                                entry.rdata[12], entry.rdata[13], entry.rdata[14], entry.rdata[15],
                            });
                            try results.append(self.allocator, formatted);
                        }
                    }
                }

                if (results.items.len > 0) {
                    return ResolveResult{
                        .addresses = try results.toOwnedSlice(self.allocator),
                        .from_cache = true,
                    };
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

        // Process response
        var cname_chain = try buildCnameChain(self.allocator, response, response.data, hostname);
        defer {
            for (cname_chain.items) |name_item| {
                self.allocator.free(name_item);
            }
            cname_chain.deinit(self.allocator);
        }

        var results: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (results.items) |item| {
                self.allocator.free(item);
            }
            results.deinit(self.allocator);
        }

        // Extract answers
        var ans_iter = try response.answers();
        while (try ans_iter.next()) |rr| {
            const owner = rr.getName(self.allocator, response.data) catch continue;
            defer self.allocator.free(owner);

            if (!nameInChain(cname_chain.items, owner)) {
                continue;
            }

            // Cache the record under its owner name
            if (self.cache) |*cache| {
                cache.put(owner, rr) catch {};
            }

            if (rr.rtype == qtype) {
                if (qtype == .a) {
                    const formatted = try rr.formatA(self.allocator);
                    try results.append(self.allocator, formatted);
                } else if (qtype == .aaaa) {
                    const formatted = try rr.formatAAAA(self.allocator);
                    try results.append(self.allocator, formatted);
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
        errdefer results.deinit(self.allocator);

        var ans_iter = try response.answers();
        while (try ans_iter.next()) |rr| {
            if (rr.rtype == .mx) {
                const mx_data = try rr.parseMX(response.data);
                const exchange = try mx_data.exchange.toString(self.allocator, response.data);
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

/// MX Record result
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

    const qname_copy = try allocator.dupe(u8, trimTrailingDot(qname));
    try chain.append(allocator, qname_copy);

    var current = qname_copy;
    var depth: u8 = 0;

    while (depth < 8) : (depth += 1) {
        var found = false;
        var ans_iter = try msg.answers();
        while (try ans_iter.next()) |rr| {
            if (rr.rtype != .cname) continue;

            const owner = rr.getName(allocator, response) catch continue;
            defer allocator.free(owner);

            if (!namesEqual(owner, current)) continue;

            const target_name = rr.parseName(response) catch continue;
            const target_str = target_name.toString(allocator, response) catch continue;

            if (nameInChain(chain.items, target_str)) {
                allocator.free(target_str);
                return chain;
            }

            try chain.append(allocator, target_str);
            current = target_str;
            found = true;
            break;
        }

        if (!found) break;
    }

    return chain;
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
        3, 'w', 'w', 'w',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
        // Answer 1: CNAME www.example.com -> alias.example.net
        0xC0, 0x0C, // Name pointer to question
        0x00, 0x05, // TYPE: CNAME
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x13, // RDLENGTH: 19
        5, 'a', 'l', 'i', 'a', 's',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'n', 'e', 't',
        0,
        // Answer 2: alias.example.net A IN 1.2.3.4
        5, 'a', 'l', 'i', 'a', 's',
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'n', 'e', 't',
        0,
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
