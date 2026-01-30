// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Stub Resolver
//!
//! RFC 1034 Section 5.3.1: Stub Resolvers
//!
//! A stub resolver forwards queries to a configured recursive resolver
//! (like your ISP's DNS server or a public resolver like 8.8.8.8).

const std = @import("std");
const builtin = @import("builtin");
const message_mod = @import("message");
const name_mod = @import("name");
const types_mod = @import("types");
const header_mod = @import("header");
const question_mod = @import("question");
const record_mod = @import("record");

pub const Message = message_mod.Message;
pub const Name = name_mod.Name;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;
pub const Header = header_mod.Header;
pub const Question = question_mod.Question;
pub const ResourceRecord = record_mod.ResourceRecord;

/// DNS server address
pub const ServerAddress = struct {
    /// IP address (IPv4 or IPv6)
    address: std.net.Address,

    /// Create from IPv4 address string
    pub fn fromIpv4(ip: []const u8, port: u16) !ServerAddress {
        return ServerAddress{
            .address = try std.net.Address.parseIp4(ip, port),
        };
    }

    /// Create from IPv6 address string
    pub fn fromIpv6(ip: []const u8, port: u16) !ServerAddress {
        return ServerAddress{
            .address = try std.net.Address.parseIp6(ip, port),
        };
    }
};

/// Well-known public DNS servers
pub const PublicServers = struct {
    /// Google Public DNS (8.8.8.8)
    pub const google_primary = "8.8.8.8";
    /// Google Public DNS Secondary (8.8.4.4)
    pub const google_secondary = "8.8.4.4";
    /// Cloudflare DNS (1.1.1.1)
    pub const cloudflare_primary = "1.1.1.1";
    /// Cloudflare DNS Secondary (1.0.0.1)
    pub const cloudflare_secondary = "1.0.0.1";
    /// Quad9 DNS (9.9.9.9)
    pub const quad9_primary = "9.9.9.9";
    /// OpenDNS (208.67.222.222)
    pub const opendns_primary = "208.67.222.222";
};

/// Stub Resolver Configuration
pub const StubConfig = struct {
    /// DNS servers to query
    servers: []const ServerAddress,

    /// Query timeout in milliseconds
    timeout_ms: u32 = 5000,

    /// Number of retries per server
    retries: u8 = 2,

    /// Whether to use TCP if response is truncated
    use_tcp_on_truncation: bool = true,

    /// Maximum UDP response size (for EDNS)
    udp_payload_size: u16 = 4096,
};

/// Stub Resolver
/// Forwards DNS queries to configured upstream servers
pub const StubResolver = struct {
    allocator: std.mem.Allocator,
    config: StubConfig,

    const Self = @This();

    /// Error returned when secure entropy is unavailable
    pub const InitError = error{EntropyUnavailable};

    /// Create a new stub resolver
    /// Returns error.EntropyUnavailable if secure random is not available
    pub fn init(allocator: std.mem.Allocator, config: StubConfig) InitError!Self {
        // Ensure cryptographically secure entropy is available
        var probe: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&probe)) catch {
            return error.EntropyUnavailable;
        };
        return Self{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Create with default configuration using a single server
    pub fn initWithServer(allocator: std.mem.Allocator, server_ip: []const u8) !Self {
        const server = try ServerAddress.fromIpv4(server_ip, types_mod.dns_port);
        const servers = try allocator.alloc(ServerAddress, 1);
        servers[0] = server;

        return Self.init(allocator, .{
            .servers = servers,
        });
    }

    /// Free resolver resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // Note: servers array is not owned by the resolver
    }

    /// Generate a unique query ID
    fn nextId(self: *Self) u16 {
        _ = self;
        // Use OS CSPRNG for each ID to avoid predictability
        return std.crypto.random.int(u16);
    }

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
        msg: Message,
        expected_name: []const u8,
        expected_type: Type,
        expected_class: Class,
    ) bool {
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

    /// Resolve a domain name
    pub fn resolve(self: *Self, domain: []const u8, qtype: Type) !Message {
        return self.resolveClass(domain, qtype, .in);
    }

    /// Resolve with specific class
    pub fn resolveClass(self: *Self, domain: []const u8, qtype: Type, qclass: Class) !Message {
        const id = self.nextId();

        // Build query
        const query = try message_mod.buildQuery(self.allocator, id, domain, qtype, qclass, true);
        defer self.allocator.free(query);

        // Try each server
        for (self.config.servers) |server| {
            var attempt: u8 = 0;
            while (attempt < self.config.retries) : (attempt += 1) {
                const response = self.sendQuery(query, server) catch {
                    // Error occurred, try next attempt/server
                    continue;
                };

                const msg = Message.parse(response) catch {
                    self.allocator.free(response);
                    continue;
                };
                if (msg.header.id != id or !responseMatchesQuery(self.allocator, msg, domain, qtype, qclass)) {
                    self.allocator.free(response);
                    continue;
                }

                // Check for truncation
                if (msg.header.tc and self.config.use_tcp_on_truncation) {
                    const tcp_response = self.sendQueryTcp(query, server) catch continue;
                    self.allocator.free(response);
                    return Message.parse(tcp_response) catch continue;
                }

                return msg;
            }
        }

        return error.NoResponse;
    }

    /// Send a query over UDP
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

            // Copy response
            const response = try self.allocator.alloc(u8, recv_len);
            @memcpy(response, buffer[0..recv_len]);

            return response;
        }
    }

    /// Send a query over TCP
    fn sendQueryTcp(self: *Self, query: []const u8, server: ServerAddress) ![]u8 {
        const sock = try std.posix.socket(
            server.address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        defer std.posix.close(sock);

        try connectWithTimeout(sock, server.address, self.config.timeout_ms);

        // TCP DNS messages are prefixed with 2-byte length
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(query.len), .big);

        // Send length prefix and query
        try writeAllWithTimeout(sock, &length_prefix, self.config.timeout_ms);
        try writeAllWithTimeout(sock, query, self.config.timeout_ms);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        try readExactWithTimeout(sock, &resp_len_buf, self.config.timeout_ms);
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
        if (resp_len == 0 or resp_len > 65535) {
            return error.MessageTooLarge;
        }

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try readWithTimeout(sock, response[total_read..], self.config.timeout_ms);
            if (n == 0) {
                return error.ConnectionClosed;
            }
            total_read += n;
        }

        return response;
    }
};

fn connectWithTimeout(sock: std.posix.socket_t, address: std.net.Address, timeout_ms: u32) !void {
    std.posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock => {},
        else => return err,
    };

    var poll_fds = [_]std.posix.pollfd{.{
        .fd = sock,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const rc = try std.posix.poll(&poll_fds, @intCast(timeout_ms));
    if (rc == 0) return error.Timeout;
    if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) {
        return error.ConnectionClosed;
    }
    try std.posix.getsockoptError(sock);
}

fn writeAllWithTimeout(sock: std.posix.socket_t, data: []const u8, timeout_ms: u32) !void {
    var sent: usize = 0;
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (sent < data.len) {
        const now = std.time.milliTimestamp();
        if (now >= deadline) return error.Timeout;
        const remaining: i32 = @intCast(@max(@as(i64, 0), deadline - now));

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const rc = try std.posix.poll(&poll_fds, remaining);
        if (rc == 0) return error.Timeout;
        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) {
            return error.ConnectionClosed;
        }

        const n = std.posix.write(sock, data[sent..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        sent += n;
    }
}

fn readWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !usize {
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (true) {
        const now = std.time.milliTimestamp();
        if (now >= deadline) return error.Timeout;
        const remaining: i32 = @intCast(@max(@as(i64, 0), deadline - now));

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const rc = try std.posix.poll(&poll_fds, remaining);
        if (rc == 0) return error.Timeout;
        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) {
            return error.ConnectionClosed;
        }

        return std.posix.read(sock, buffer) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
    }
}

fn readExactWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !void {
    var read_total: usize = 0;
    while (read_total < buffer.len) {
        const n = try readWithTimeout(sock, buffer[read_total..], timeout_ms);
        if (n == 0) return error.ConnectionClosed;
        read_total += n;
    }
}

/// Read system DNS servers from /etc/resolv.conf (Unix) or registry (Windows)
pub fn getSystemServers(allocator: std.mem.Allocator) ![]ServerAddress {
    var servers: std.ArrayList(ServerAddress) = .empty;
    errdefer servers.deinit(allocator);

    if (builtin.os.tag == .windows) {
        // On Windows, we'd need to query the registry or use GetNetworkParams
        // For now, return Google DNS as fallback
        try servers.append(allocator, try ServerAddress.fromIpv4(PublicServers.google_primary, types_mod.dns_port));
    } else {
        // Unix-like systems: parse /etc/resolv.conf
        const file = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch {
            // Fallback to Google DNS
            try servers.append(allocator, try ServerAddress.fromIpv4(PublicServers.google_primary, types_mod.dns_port));
            return servers.toOwnedSlice(allocator);
        };
        defer file.close();

        // Read the entire file content
        var content_buf: [4096]u8 = undefined;
        const content_len = file.readAll(&content_buf) catch {
            try servers.append(allocator, try ServerAddress.fromIpv4(PublicServers.google_primary, types_mod.dns_port));
            return servers.toOwnedSlice(allocator);
        };
        const content = content_buf[0..content_len];

        // Parse line by line
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            // Skip comments and empty lines
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#' or trimmed[0] == ';') {
                continue;
            }

            // Look for "nameserver" directive
            if (std.mem.startsWith(u8, trimmed, "nameserver")) {
                const rest = std.mem.trim(u8, trimmed["nameserver".len..], " \t");
                if (rest.len > 0) {
                    // Try IPv4 first, then IPv6
                    const server = ServerAddress.fromIpv4(rest, types_mod.dns_port) catch
                        ServerAddress.fromIpv6(rest, types_mod.dns_port) catch continue;
                    try servers.append(allocator, server);
                }
            }
        }
    }

    // Fallback if no servers found
    if (servers.items.len == 0) {
        try servers.append(allocator, try ServerAddress.fromIpv4(PublicServers.google_primary, types_mod.dns_port));
    }

    return servers.toOwnedSlice(allocator);
}

test "StubResolver.nextId" {
    var servers = [_]ServerAddress{};
    var resolver = try StubResolver.init(std.testing.allocator, .{ .servers = &servers });
    defer resolver.deinit();

    const id = resolver.nextId();
    try std.testing.expect(id <= std.math.maxInt(u16));
}

test "ServerAddress.fromIpv4" {
    const server = try ServerAddress.fromIpv4("8.8.8.8", 53);
    try std.testing.expectEqual(@as(u16, 53), server.address.getPort());
}

test "PublicServers constants" {
    try std.testing.expectEqualStrings("8.8.8.8", PublicServers.google_primary);
    try std.testing.expectEqualStrings("1.1.1.1", PublicServers.cloudflare_primary);
}
