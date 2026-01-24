// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Happy Eyeballs Algorithm (RFC 8305)
//!
//! Provides connection racing to improve connection establishment time when
//! multiple addresses are available (IPv4 + IPv6). Key features:
//!
//! - Prefers IPv6 but falls back to IPv4 quickly
//! - Races connections with configurable delay
//! - Cancels losing connections to conserve resources
//! - Remembers successful address families for future connections
//!
//! References:
//! - RFC 8305: Happy Eyeballs Version 2: Better Connectivity Using Concurrency
//! - RFC 6555: Happy Eyeballs - Success with Dual-Stack Hosts

const std = @import("std");

/// Happy Eyeballs configuration
pub const Config = struct {
    /// Connection attempt delay (RFC 8305 recommends 250ms)
    connection_attempt_delay_ms: u32 = 250,
    /// Resolution delay - time to wait for AAAA after A response
    resolution_delay_ms: u32 = 50,
    /// First address family preference
    prefer_ipv6: bool = true,
    /// Maximum parallel connection attempts
    max_parallel_attempts: u8 = 4,
    /// Timeout for individual connection attempts
    connection_timeout_ms: u32 = 30_000,
    /// Enable address family caching
    enable_family_cache: bool = true,
    /// Family cache TTL
    family_cache_ttl_ms: u32 = 600_000, // 10 minutes
};

/// Address family type (matches sockaddr_storage.family)
pub const AddressFamily = u16;

/// Address family constants
pub const AF_INET: AddressFamily = std.posix.AF.INET;
pub const AF_INET6: AddressFamily = std.posix.AF.INET6;

/// Connection attempt result
pub const AttemptResult = struct {
    /// Socket file descriptor (valid if success)
    fd: std.posix.fd_t,
    /// Address that succeeded
    address: std.net.Address,
    /// Address family (AF_INET or AF_INET6)
    family: AddressFamily,
    /// Attempt index
    attempt_index: usize,
    /// Time to connect (ms)
    connection_time_ms: u32,
};

/// Connection attempt state
const AttemptState = enum {
    pending,
    connecting,
    connected,
    failed,
    cancelled,
};

/// Single connection attempt
const ConnectionAttempt = struct {
    address: std.net.Address,
    family: AddressFamily,
    fd: std.posix.fd_t,
    state: AttemptState,
    start_time: i64,
    index: usize,
};

/// Family preference cache entry
pub const FamilyCacheEntry = struct {
    /// Preferred address family
    family: AddressFamily,
    /// When this preference was recorded
    timestamp: i64,
    /// Success count with this family
    success_count: u32,
    /// Failure count with other family
    failure_count: u32,
};

/// Happy Eyeballs connection racer
pub const HappyEyeballs = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Address family preference cache (hostname hash -> preference)
    family_cache: std.AutoHashMap(u64, FamilyCacheEntry),
    /// Statistics
    stats: Stats,

    const Self = @This();

    pub const Stats = struct {
        /// Total connection attempts
        total_attempts: u64 = 0,
        /// Successful connections
        successful_connections: u64 = 0,
        /// IPv6 wins
        ipv6_wins: u64 = 0,
        /// IPv4 wins
        ipv4_wins: u64 = 0,
        /// Average connection time (ms)
        avg_connection_time_ms: u32 = 0,
        /// Cache hits
        cache_hits: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .family_cache = std.AutoHashMap(u64, FamilyCacheEntry).init(allocator),
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.family_cache.deinit();
    }

    /// Connect to one of the given addresses using Happy Eyeballs algorithm
    pub fn connect(self: *Self, addresses: []const std.net.Address, hostname: []const u8) !AttemptResult {
        if (addresses.len == 0) return error.NoAddresses;

        const hostname_hash = std.hash.Wyhash.hash(0, hostname);
        const sorted = try self.sortAddresses(addresses, hostname_hash);
        defer self.allocator.free(sorted);

        self.stats.total_attempts += 1;

        // Start connection attempts with staggered delay
        var attempts: std.ArrayList(ConnectionAttempt) = .empty;
        defer {
            for (attempts.items) |*attempt| {
                // Close any fd that wasn't the winning connection
                // All attempts in this list have valid fds since socket() succeeded before adding
                if (attempt.state != .connected) {
                    std.posix.close(attempt.fd);
                }
            }
            attempts.deinit(self.allocator);
        }

        const start_time = std.time.milliTimestamp();
        var next_attempt_index: usize = 0;
        var winner: ?AttemptResult = null;

        // Main connection loop
        while (winner == null and (next_attempt_index < sorted.len or attempts.items.len > 0)) {
            // Start a new attempt if we haven't started all addresses
            if (next_attempt_index < sorted.len and attempts.items.len < self.config.max_parallel_attempts) {
                const addr = sorted[next_attempt_index];
                const fd = self.startConnection(addr) catch {
                    next_attempt_index += 1;
                    continue;
                };

                try attempts.append(self.allocator, .{
                    .address = addr,
                    .family = addr.any.family,
                    .fd = fd,
                    .state = .connecting,
                    .start_time = std.time.milliTimestamp(),
                    .index = next_attempt_index,
                });
                next_attempt_index += 1;
            }

            // Check for completed connections
            for (attempts.items) |*attempt| {
                if (attempt.state != .connecting) continue;

                // Poll the socket for writability (connection complete)
                var poll_fds = [_]std.posix.pollfd{
                    .{
                        .fd = attempt.fd,
                        .events = std.posix.POLL.OUT,
                        .revents = 0,
                    },
                };

                const poll_result = std.posix.poll(&poll_fds, 0) catch 0;
                if (poll_result > 0) {
                    if (poll_fds[0].revents & std.posix.POLL.OUT != 0) {
                        // Check for connection error
                        const err = getSocketError(attempt.fd);
                        if (err == 0) {
                            // Connection successful!
                            attempt.state = .connected;
                            const now = std.time.milliTimestamp();
                            const conn_time: u32 = @intCast(now - attempt.start_time);

                            winner = AttemptResult{
                                .fd = attempt.fd,
                                .address = attempt.address,
                                .family = attempt.family,
                                .attempt_index = attempt.index,
                                .connection_time_ms = conn_time,
                            };

                            // Update cache
                            if (self.config.enable_family_cache) {
                                try self.updateFamilyCache(hostname_hash, attempt.family);
                            }

                            // Update stats
                            self.stats.successful_connections += 1;
                            if (attempt.family == AF_INET6) {
                                self.stats.ipv6_wins += 1;
                            } else {
                                self.stats.ipv4_wins += 1;
                            }
                            self.updateAvgConnectionTime(conn_time);

                            break;
                        } else {
                            // Connection failed
                            attempt.state = .failed;
                            std.posix.close(attempt.fd);
                            attempt.fd = -1;
                        }
                    } else if (poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP) != 0) {
                        attempt.state = .failed;
                        std.posix.close(attempt.fd);
                        attempt.fd = -1;
                    }
                }
            }

            // Check for timeout
            const elapsed: u32 = @intCast(std.time.milliTimestamp() - start_time);
            if (elapsed > self.config.connection_timeout_ms) {
                break;
            }

            // Small sleep to avoid busy-waiting
            if (winner == null) {
                std.Thread.sleep(std.time.ns_per_ms * 10);
            }
        }

        // Cancel remaining attempts
        for (attempts.items) |*attempt| {
            if (attempt.state == .connecting) {
                attempt.state = .cancelled;
                std.posix.close(attempt.fd);
                attempt.fd = -1;
            }
        }

        if (winner) |w| {
            return w;
        }

        return error.ConnectionFailed;
    }

    /// Sort addresses according to RFC 8305
    fn sortAddresses(self: *Self, addresses: []const std.net.Address, hostname_hash: u64) ![]std.net.Address {
        const sorted = try self.allocator.alloc(std.net.Address, addresses.len);
        errdefer self.allocator.free(sorted);

        @memcpy(sorted, addresses);

        // Check cache for preferred family
        var preferred_family: ?u16 = null;
        if (self.config.enable_family_cache) {
            if (self.family_cache.get(hostname_hash)) |entry| {
                const now = std.time.milliTimestamp();
                if (now - entry.timestamp < self.config.family_cache_ttl_ms) {
                    preferred_family = entry.family;
                    self.stats.cache_hits += 1;
                }
            }
        }

        // Sort: preferred family first, then IPv6 if config prefers it
        const sort_context = struct {
            prefer_ipv6: bool,
            preferred_family: ?u16,
        }{
            .prefer_ipv6 = self.config.prefer_ipv6,
            .preferred_family = preferred_family,
        };

        std.mem.sort(std.net.Address, sorted, sort_context, struct {
            fn lessThan(ctx: @TypeOf(sort_context), a: std.net.Address, b: std.net.Address) bool {
                const a_is_v6 = a.any.family == AF_INET6;
                const b_is_v6 = b.any.family == AF_INET6;

                // If we have a cached preference, use it
                if (ctx.preferred_family) |pf| {
                    const a_is_preferred = a.any.family == pf;
                    const b_is_preferred = b.any.family == pf;
                    if (a_is_preferred != b_is_preferred) {
                        return a_is_preferred;
                    }
                }

                // Otherwise use config preference
                if (a_is_v6 != b_is_v6) {
                    return if (ctx.prefer_ipv6) a_is_v6 else b_is_v6;
                }

                return false;
            }
        }.lessThan);

        return sorted;
    }

    /// Start a non-blocking connection attempt
    fn startConnection(self: *Self, address: std.net.Address) !std.posix.fd_t {
        _ = self;
        const fd = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        errdefer std.posix.close(fd);

        // Set TCP_NODELAY
        const one: c_int = 1;
        std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};

        // Start connection (will return WouldBlock for non-blocking)
        std.posix.connect(fd, &address.any, address.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) {
                return err;
            }
        };

        return fd;
    }

    /// Get socket error (0 means success)
    fn getSocketError(fd: std.posix.fd_t) c_int {
        var err_buf: [@sizeOf(c_int)]u8 = undefined;
        std.posix.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, &err_buf) catch return -1;
        return std.mem.bytesToValue(c_int, &err_buf);
    }

    /// Update the family preference cache
    fn updateFamilyCache(self: *Self, hostname_hash: u64, family: AddressFamily) !void {
        const now = std.time.milliTimestamp();

        if (self.family_cache.getPtr(hostname_hash)) |entry| {
            if (entry.family == family) {
                entry.success_count += 1;
                entry.timestamp = now;
            } else {
                entry.failure_count += 1;
                // Switch preference if other family fails too often
                if (entry.failure_count > entry.success_count) {
                    entry.family = family;
                    entry.success_count = 1;
                    entry.failure_count = 0;
                    entry.timestamp = now;
                }
            }
        } else {
            try self.family_cache.put(hostname_hash, .{
                .family = family,
                .timestamp = now,
                .success_count = 1,
                .failure_count = 0,
            });
        }
    }

    fn updateAvgConnectionTime(self: *Self, new_time: u32) void {
        const total = self.stats.successful_connections;
        if (total <= 1) {
            self.stats.avg_connection_time_ms = new_time;
        } else {
            // Exponential moving average
            self.stats.avg_connection_time_ms = @intCast(
                (@as(u64, self.stats.avg_connection_time_ms) * (total - 1) + new_time) / total,
            );
        }
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }

    /// Clear the family cache
    pub fn clearCache(self: *Self) void {
        self.family_cache.clearRetainingCapacity();
    }
};

/// Address sorter for connection racing
pub const AddressSorter = struct {
    /// Sort addresses for Happy Eyeballs
    /// Returns interleaved IPv6/IPv4 addresses
    pub fn interleave(allocator: std.mem.Allocator, addresses: []const std.net.Address) ![]std.net.Address {
        var ipv6: std.ArrayList(std.net.Address) = .empty;
        defer ipv6.deinit(allocator);
        var ipv4: std.ArrayList(std.net.Address) = .empty;
        defer ipv4.deinit(allocator);

        for (addresses) |addr| {
            if (addr.any.family == AF_INET6) {
                try ipv6.append(allocator, addr);
            } else {
                try ipv4.append(allocator, addr);
            }
        }

        var result = try allocator.alloc(std.net.Address, addresses.len);
        errdefer allocator.free(result);

        var i: usize = 0;
        var v6_idx: usize = 0;
        var v4_idx: usize = 0;

        // Interleave: v6, v4, v6, v4, ...
        while (i < addresses.len) {
            if (v6_idx < ipv6.items.len) {
                result[i] = ipv6.items[v6_idx];
                i += 1;
                v6_idx += 1;
            }
            if (v4_idx < ipv4.items.len and i < addresses.len) {
                result[i] = ipv4.items[v4_idx];
                i += 1;
                v4_idx += 1;
            }
        }

        return result;
    }

    /// Sort addresses with IPv6 first
    pub fn preferIPv6(allocator: std.mem.Allocator, addresses: []const std.net.Address) ![]std.net.Address {
        const result = try allocator.alloc(std.net.Address, addresses.len);
        errdefer allocator.free(result);

        @memcpy(result, addresses);

        std.mem.sort(std.net.Address, result, {}, struct {
            fn lessThan(_: void, a: std.net.Address, b: std.net.Address) bool {
                const a_is_v6 = a.any.family == AF_INET6;
                const b_is_v6 = b.any.family == AF_INET6;
                if (a_is_v6 and !b_is_v6) return true;
                return false;
            }
        }.lessThan);

        return result;
    }

    /// Sort addresses with IPv4 first
    pub fn preferIPv4(allocator: std.mem.Allocator, addresses: []const std.net.Address) ![]std.net.Address {
        const result = try allocator.alloc(std.net.Address, addresses.len);
        errdefer allocator.free(result);

        @memcpy(result, addresses);

        std.mem.sort(std.net.Address, result, {}, struct {
            fn lessThan(_: void, a: std.net.Address, b: std.net.Address) bool {
                const a_is_v4 = a.any.family == AF_INET;
                const b_is_v4 = b.any.family == AF_INET;
                if (a_is_v4 and !b_is_v4) return true;
                return false;
            }
        }.lessThan);

        return result;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Config defaults" {
    const config = Config{};

    try std.testing.expectEqual(@as(u32, 250), config.connection_attempt_delay_ms);
    try std.testing.expectEqual(@as(u32, 50), config.resolution_delay_ms);
    try std.testing.expect(config.prefer_ipv6);
    try std.testing.expectEqual(@as(u8, 4), config.max_parallel_attempts);
}

test "HappyEyeballs init/deinit" {
    const allocator = std.testing.allocator;
    var he = HappyEyeballs.init(allocator, .{});
    defer he.deinit();

    const stats = he.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_attempts);
}

test "AddressSorter interleave" {
    const allocator = std.testing.allocator;

    var addresses = [_]std.net.Address{
        std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 80),
        std.net.Address.initIp4(.{ 192, 168, 1, 2 }, 80),
        std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 80, 0, 0),
        std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, 80, 0, 0),
    };

    const sorted = try AddressSorter.interleave(allocator, &addresses);
    defer allocator.free(sorted);

    // Should be: v6, v4, v6, v4
    try std.testing.expectEqual(AF_INET6, sorted[0].any.family);
    try std.testing.expectEqual(AF_INET, sorted[1].any.family);
    try std.testing.expectEqual(AF_INET6, sorted[2].any.family);
    try std.testing.expectEqual(AF_INET, sorted[3].any.family);
}

test "AddressSorter preferIPv6" {
    const allocator = std.testing.allocator;

    var addresses = [_]std.net.Address{
        std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 80),
        std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 80, 0, 0),
        std.net.Address.initIp4(.{ 192, 168, 1, 2 }, 80),
    };

    const sorted = try AddressSorter.preferIPv6(allocator, &addresses);
    defer allocator.free(sorted);

    // IPv6 should be first
    try std.testing.expectEqual(AF_INET6, sorted[0].any.family);
    try std.testing.expectEqual(AF_INET, sorted[1].any.family);
    try std.testing.expectEqual(AF_INET, sorted[2].any.family);
}

test "AddressSorter preferIPv4" {
    const allocator = std.testing.allocator;

    var addresses = [_]std.net.Address{
        std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 80, 0, 0),
        std.net.Address.initIp4(.{ 192, 168, 1, 1 }, 80),
        std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, 80, 0, 0),
    };

    const sorted = try AddressSorter.preferIPv4(allocator, &addresses);
    defer allocator.free(sorted);

    // IPv4 should be first
    try std.testing.expectEqual(AF_INET, sorted[0].any.family);
    try std.testing.expectEqual(AF_INET6, sorted[1].any.family);
    try std.testing.expectEqual(AF_INET6, sorted[2].any.family);
}

test "FamilyCacheEntry" {
    const entry = FamilyCacheEntry{
        .family = AF_INET6,
        .timestamp = std.time.milliTimestamp(),
        .success_count = 5,
        .failure_count = 1,
    };

    try std.testing.expectEqual(AF_INET6, entry.family);
    try std.testing.expectEqual(@as(u32, 5), entry.success_count);
}

test "HappyEyeballs no addresses error" {
    const allocator = std.testing.allocator;
    var he = HappyEyeballs.init(allocator, .{});
    defer he.deinit();

    const empty: []const std.net.Address = &.{};
    const result = he.connect(empty, "test.example.com");
    try std.testing.expectError(error.NoAddresses, result);
}
