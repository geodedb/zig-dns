// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Server Failover and Load Balancing
//!
//! Provides intelligent server selection with:
//! - Multiple load balancing strategies (round-robin, weighted, least-connections, latency-based)
//! - Automatic failover on server errors
//! - Health checking and server status tracking
//! - Circuit breaker pattern for failing servers
//!
//! References:
//! - RFC 2782: DNS SRV Records (for weight/priority concepts)

const std = @import("std");

/// Load balancing strategy
pub const Strategy = enum {
    /// Simple round-robin across all healthy servers
    round_robin,
    /// Weighted round-robin based on server weights
    weighted,
    /// Route to server with fewest active connections
    least_connections,
    /// Route to server with lowest observed latency
    latency_based,
    /// Random selection among healthy servers
    random,
    /// Always use primary, failover to secondary on error
    primary_secondary,
};

/// Server health status
pub const ServerStatus = enum {
    /// Server is healthy and accepting requests
    healthy,
    /// Server is degraded but still functional
    degraded,
    /// Server is unhealthy (circuit breaker open)
    unhealthy,
    /// Server health is unknown (not yet checked)
    unknown,
};

/// Server configuration
pub const ServerConfig = struct {
    /// Server address (IP or hostname)
    address: []const u8,
    /// Server port
    port: u16 = 53,
    /// Server weight for weighted load balancing (1-100)
    weight: u8 = 50,
    /// Priority (lower = higher priority for primary_secondary)
    priority: u8 = 0,
    /// Is this a backup server?
    is_backup: bool = false,
};

/// Server runtime state
pub const ServerState = struct {
    config: ServerConfig,
    /// Current health status
    status: ServerStatus = .unknown,
    /// Number of active connections
    active_connections: u32 = 0,
    /// Total requests sent
    total_requests: u64 = 0,
    /// Total successful responses
    successful_responses: u64 = 0,
    /// Total failed requests
    failed_requests: u64 = 0,
    /// Consecutive failures (for circuit breaker)
    consecutive_failures: u32 = 0,
    /// Average response time (ms)
    avg_latency_ms: u32 = 0,
    /// Last successful response time
    last_success: i64 = 0,
    /// Last failure time
    last_failure: i64 = 0,
    /// Circuit breaker open until
    circuit_open_until: i64 = 0,

    pub fn isAvailable(self: *const ServerState, now: i64) bool {
        if (self.status == .unhealthy) {
            // Check if circuit breaker timeout expired
            if (now < self.circuit_open_until) {
                return false;
            }
        }
        return self.status != .unhealthy or now >= self.circuit_open_until;
    }

    pub fn recordSuccess(self: *ServerState, latency_ms: u32, now: i64) void {
        self.total_requests += 1;
        self.successful_responses += 1;
        self.consecutive_failures = 0;
        self.last_success = now;
        self.status = .healthy;

        // Update average latency (exponential moving average)
        if (self.avg_latency_ms == 0) {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = @intCast((@as(u64, self.avg_latency_ms) * 7 + latency_ms) / 8);
        }
    }

    pub fn recordFailure(self: *ServerState, now: i64, circuit_timeout_ms: u32) void {
        self.total_requests += 1;
        self.failed_requests += 1;
        self.consecutive_failures += 1;
        self.last_failure = now;

        // Open circuit breaker after threshold
        if (self.consecutive_failures >= 3) {
            self.status = .unhealthy;
            self.circuit_open_until = now + circuit_timeout_ms;
        } else if (self.consecutive_failures >= 1) {
            self.status = .degraded;
        }
    }

    pub fn successRate(self: *const ServerState) f32 {
        if (self.total_requests == 0) return 1.0;
        return @as(f32, @floatFromInt(self.successful_responses)) / @as(f32, @floatFromInt(self.total_requests));
    }
};

/// Failover manager configuration
pub const FailoverConfig = struct {
    /// Load balancing strategy
    strategy: Strategy = .round_robin,
    /// Circuit breaker timeout (ms)
    circuit_timeout_ms: u32 = 30_000,
    /// Health check interval (ms)
    health_check_interval_ms: u32 = 10_000,
    /// Maximum retries before giving up
    max_retries: u8 = 3,
    /// Retry delay (ms)
    retry_delay_ms: u32 = 100,
    /// Minimum healthy servers required
    min_healthy_servers: u8 = 1,
    /// Enable automatic health checks
    enable_health_checks: bool = true,
};

/// Failover and load balancing manager
pub const FailoverManager = struct {
    allocator: std.mem.Allocator,
    config: FailoverConfig,
    /// Server states
    servers: std.ArrayList(ServerState),
    /// Round-robin index
    rr_index: usize = 0,
    /// Weighted round-robin accumulated weights
    weighted_accumulator: u32 = 0,
    /// Random number generator
    rng: std.Random.DefaultPrng,
    /// Statistics
    stats: Stats,
    /// Mutex for thread safety
    mutex: std.Thread.Mutex,

    const Self = @This();

    pub const Stats = struct {
        /// Total queries processed
        total_queries: u64 = 0,
        /// Successful queries
        successful_queries: u64 = 0,
        /// Failed queries (all retries exhausted)
        failed_queries: u64 = 0,
        /// Failover events
        failover_events: u64 = 0,
        /// Circuit breaker trips
        circuit_breaker_trips: u64 = 0,
    };

    /// Error returned when secure entropy is unavailable
    pub const InitError = error{EntropyUnavailable};

    pub fn init(allocator: std.mem.Allocator, config: FailoverConfig) InitError!Self {
        // Use secure random for server selection
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
            return error.EntropyUnavailable;
        };
        return Self{
            .allocator = allocator,
            .config = config,
            .servers = .empty,
            .rr_index = 0,
            .weighted_accumulator = 0,
            .rng = std.Random.DefaultPrng.init(seed),
            .stats = .{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.servers.deinit(self.allocator);
    }

    /// Add a server to the pool
    pub fn addServer(self: *Self, config: ServerConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.servers.append(self.allocator, ServerState{
            .config = config,
        });
    }

    /// Remove a server from the pool
    pub fn removeServer(self: *Self, address: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.servers.items, 0..) |server, i| {
            if (std.mem.eql(u8, server.config.address, address)) {
                _ = self.servers.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Select the next server based on strategy
    pub fn selectServer(self: *Self) ?*ServerState {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // Get available servers
        var available: std.ArrayList(*ServerState) = .empty;
        defer available.deinit(self.allocator);

        for (self.servers.items) |*server| {
            if (server.isAvailable(now)) {
                available.append(self.allocator, server) catch continue;
            }
        }

        if (available.items.len == 0) {
            // No healthy servers, try to find any server
            if (self.servers.items.len > 0) {
                return &self.servers.items[0];
            }
            return null;
        }

        return switch (self.config.strategy) {
            .round_robin => self.selectRoundRobin(available.items),
            .weighted => self.selectWeighted(available.items),
            .least_connections => self.selectLeastConnections(available.items),
            .latency_based => self.selectLatencyBased(available.items),
            .random => self.selectRandom(available.items),
            .primary_secondary => self.selectPrimarySecondary(available.items),
        };
    }

    fn selectRoundRobin(self: *Self, servers: []*ServerState) ?*ServerState {
        if (servers.len == 0) return null;
        const server = servers[self.rr_index % servers.len];
        self.rr_index = (self.rr_index + 1) % servers.len;
        return server;
    }

    fn selectWeighted(self: *Self, servers: []*ServerState) ?*ServerState {
        if (servers.len == 0) return null;

        var total_weight: u32 = 0;
        for (servers) |server| {
            total_weight += server.config.weight;
        }

        if (total_weight == 0) return servers[0];

        self.weighted_accumulator = (self.weighted_accumulator + 1) % total_weight;
        var accumulated: u32 = 0;

        for (servers) |server| {
            accumulated += server.config.weight;
            if (self.weighted_accumulator < accumulated) {
                return server;
            }
        }

        return servers[0];
    }

    fn selectLeastConnections(self: *Self, servers: []*ServerState) ?*ServerState {
        _ = self;
        if (servers.len == 0) return null;

        var min_conn: u32 = std.math.maxInt(u32);
        var selected: ?*ServerState = null;

        for (servers) |server| {
            if (server.active_connections < min_conn) {
                min_conn = server.active_connections;
                selected = server;
            }
        }

        return selected;
    }

    fn selectLatencyBased(self: *Self, servers: []*ServerState) ?*ServerState {
        _ = self;
        if (servers.len == 0) return null;

        var min_latency: u32 = std.math.maxInt(u32);
        var selected: ?*ServerState = null;

        for (servers) |server| {
            // Prefer servers with known latency
            const latency = if (server.avg_latency_ms > 0) server.avg_latency_ms else 1000;
            if (latency < min_latency) {
                min_latency = latency;
                selected = server;
            }
        }

        return selected;
    }

    fn selectRandom(self: *Self, servers: []*ServerState) ?*ServerState {
        if (servers.len == 0) return null;
        const idx = self.rng.random().intRangeLessThan(usize, 0, servers.len);
        return servers[idx];
    }

    fn selectPrimarySecondary(self: *Self, servers: []*ServerState) ?*ServerState {
        _ = self;
        if (servers.len == 0) return null;

        // Sort by priority (lowest first)
        var best: ?*ServerState = null;
        var best_priority: u8 = 255;

        for (servers) |server| {
            if (server.config.priority < best_priority) {
                best_priority = server.config.priority;
                best = server;
            }
        }

        return best;
    }

    /// Record a successful request
    pub fn recordSuccess(self: *Self, server: *ServerState, latency_ms: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        server.recordSuccess(latency_ms, now);
        self.stats.total_queries += 1;
        self.stats.successful_queries += 1;
    }

    /// Record a failed request
    pub fn recordFailure(self: *Self, server: *ServerState) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        const was_healthy = server.status != .unhealthy;
        server.recordFailure(now, self.config.circuit_timeout_ms);

        if (was_healthy and server.status == .unhealthy) {
            self.stats.circuit_breaker_trips += 1;
        }
        self.stats.failover_events += 1;
    }

    /// Mark query as completely failed (all retries exhausted)
    pub fn recordQueryFailure(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.stats.total_queries += 1;
        self.stats.failed_queries += 1;
    }

    /// Get healthy server count
    pub fn healthyServerCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        var count: usize = 0;
        for (self.servers.items) |*server| {
            if (server.isAvailable(now) and server.status == .healthy) {
                count += 1;
            }
        }
        return count;
    }

    /// Get statistics
    pub fn getStats(self: *Self) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Get all server states (for monitoring)
    pub fn getServerStates(self: *Self) []const ServerState {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.servers.items;
    }

    /// Force health check on all servers
    pub fn checkHealth(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        for (self.servers.items) |*server| {
            // Reset servers that have been in circuit breaker timeout
            if (server.status == .unhealthy and now >= server.circuit_open_until) {
                server.status = .unknown;
                server.consecutive_failures = 0;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ServerConfig defaults" {
    const config = ServerConfig{
        .address = "8.8.8.8",
    };

    try std.testing.expectEqual(@as(u16, 53), config.port);
    try std.testing.expectEqual(@as(u8, 50), config.weight);
    try std.testing.expect(!config.is_backup);
}

test "ServerState record success" {
    var state = ServerState{
        .config = .{ .address = "test" },
    };

    const now = std.time.milliTimestamp();
    state.recordSuccess(100, now);

    try std.testing.expectEqual(@as(u64, 1), state.total_requests);
    try std.testing.expectEqual(@as(u64, 1), state.successful_responses);
    try std.testing.expectEqual(@as(u32, 0), state.consecutive_failures);
    try std.testing.expectEqual(ServerStatus.healthy, state.status);
}

test "ServerState record failure and circuit breaker" {
    var state = ServerState{
        .config = .{ .address = "test" },
    };

    const now = std.time.milliTimestamp();

    // First failure - degraded
    state.recordFailure(now, 30_000);
    try std.testing.expectEqual(ServerStatus.degraded, state.status);

    // Second failure - still degraded
    state.recordFailure(now, 30_000);
    try std.testing.expectEqual(ServerStatus.degraded, state.status);

    // Third failure - circuit breaker opens
    state.recordFailure(now, 30_000);
    try std.testing.expectEqual(ServerStatus.unhealthy, state.status);
    try std.testing.expect(state.circuit_open_until > now);
}

test "FailoverManager init/deinit" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{});
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 0), manager.servers.items.len);
}

test "FailoverManager add/remove server" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{});
    defer manager.deinit();

    try manager.addServer(.{ .address = "8.8.8.8" });
    try manager.addServer(.{ .address = "8.8.4.4" });

    try std.testing.expectEqual(@as(usize, 2), manager.servers.items.len);

    const removed = manager.removeServer("8.8.8.8");
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 1), manager.servers.items.len);
}

test "FailoverManager round robin selection" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{ .strategy = .round_robin });
    defer manager.deinit();

    try manager.addServer(.{ .address = "server1" });
    try manager.addServer(.{ .address = "server2" });

    // Mark servers as healthy
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }

    const s1 = manager.selectServer();
    const s2 = manager.selectServer();
    const s3 = manager.selectServer();

    try std.testing.expect(s1 != null);
    try std.testing.expect(s2 != null);
    try std.testing.expect(s3 != null);

    // Should cycle through servers
    try std.testing.expect(s1 != s2 or manager.servers.items.len == 1);
}

test "FailoverManager statistics" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{});
    defer manager.deinit();

    try manager.addServer(.{ .address = "test" });
    manager.servers.items[0].status = .healthy;

    if (manager.selectServer()) |server| {
        manager.recordSuccess(server, 50);
        manager.recordSuccess(server, 60);
        manager.recordFailure(server);
    }

    const stats = manager.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.total_queries);
    try std.testing.expectEqual(@as(u64, 2), stats.successful_queries);
    try std.testing.expectEqual(@as(u64, 1), stats.failover_events);
}

test "Strategy enum" {
    try std.testing.expectEqual(Strategy.round_robin, Strategy.round_robin);
    try std.testing.expectEqual(Strategy.weighted, Strategy.weighted);
    try std.testing.expectEqual(Strategy.least_connections, Strategy.least_connections);
}
