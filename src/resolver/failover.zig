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
const clock = @import("clock");
const random_util = @import("random");

inline fn timeMilli() i64 {
    return clock.milliTimestamp();
}

/// Shared SystemClock instance used as the default clock seam. SystemClock
/// holds no state (its vtable impls ignore the instance pointer), so a
/// single module-level instance is safe to share across managers.
var default_system_clock: clock.SystemClock = .{};

/// Zig 0.16.0-compatible mutex shim (shared, see src/util/sync.zig).
const Mutex = @import("sync").Mutex;

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
    /// Smooth weighted round-robin running weight (GAP-0885)
    current_weight: i64 = 0,

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
    /// Maximum retries before giving up.
    /// RESERVED — not yet wired: retry counting is handled by the caller
    /// (e.g. RecursiveConfig.max_server_attempts), not the failover manager,
    /// so setting this currently has no effect (REL-6).
    max_retries: u8 = 3,
    /// Retry delay (ms).
    /// RESERVED — not yet wired (see max_retries) (REL-6).
    retry_delay_ms: u32 = 100,
    /// Minimum healthy servers required
    min_healthy_servers: u8 = 1,
    /// Enable automatic health checks
    enable_health_checks: bool = true,
};

/// Opaque, copyable reference to a server in a `FailoverManager` pool.
///
/// Handles remain valid only as long as the server set is unchanged:
/// `addServer`/`removeServer` bump the manager's generation counter,
/// invalidating every previously issued handle. Stale handles are
/// rejected (no-op, `false` result) by `recordSuccess`/`recordFailure`
/// instead of dereferencing relocated `ServerState` memory (GAP-0876).
pub const ServerHandle = struct {
    /// Index into the manager's server list at issue time
    index: usize,
    /// Pool generation at issue time
    generation: u32,
};

/// Failover and load balancing manager
pub const FailoverManager = struct {
    /// Upper bound on servers considered per selection. Failover pools are
    /// tiny; this sizes the stack buffer in selectServer (PF-NEW-33).
    const max_tracked_servers: usize = 256;

    allocator: std.mem.Allocator,
    config: FailoverConfig,
    /// Server states
    servers: std.ArrayList(ServerState),
    /// Pool generation; bumped on every addServer/removeServer so that
    /// outstanding ServerHandles become stale instead of dangling
    generation: u32 = 0,
    /// Round-robin index
    rr_index: usize = 0,
    /// Random number generator
    rng: random_util.SystemRandom,
    /// Clock seam: real clock by default, mock clock injectable for
    /// deterministic circuit-breaker tests (GAP-0880)
    clk: clock.Clock,
    /// Statistics
    stats: Stats,
    /// Mutex for thread safety
    mutex: Mutex,

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
        return initWithClock(allocator, config, default_system_clock.clock());
    }

    /// Init with an injected clock (GAP-0880). Production callers use
    /// `init` (real clock); tests inject `clock.MockClock` to exercise
    /// circuit-breaker timing deterministically.
    pub fn initWithClock(
        allocator: std.mem.Allocator,
        config: FailoverConfig,
        clk: clock.Clock,
    ) InitError!Self {
        // Use secure random for server selection (GAP-0851: shared
        // fail-fast entropy helper, no hand-rolled seeding).
        const rng = random_util.SystemRandom.init() catch {
            return error.EntropyUnavailable;
        };
        return Self{
            .allocator = allocator,
            .config = config,
            .servers = .empty,
            .rr_index = 0,
            .rng = rng,
            .clk = clk,
            .stats = .{},
            .mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.servers.deinit(self.allocator);
    }

    /// Add a server to the pool. Invalidates all outstanding ServerHandles.
    pub fn addServer(self: *Self, config: ServerConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.servers.append(self.allocator, ServerState{
            .config = config,
        });
        self.generation +%= 1;
    }

    /// Remove a server from the pool. Invalidates all outstanding
    /// ServerHandles when a server is removed.
    pub fn removeServer(self: *Self, address: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.servers.items, 0..) |server, i| {
            if (std.mem.eql(u8, server.config.address, address)) {
                _ = self.servers.swapRemove(i);
                self.generation +%= 1;
                return true;
            }
        }
        return false;
    }

    /// Resolve a handle to the server's config (copied). Returns null if
    /// the handle is stale.
    pub fn serverConfig(self: *Self, handle: ServerHandle) ?ServerConfig {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (handle.generation != self.generation) return null;
        if (handle.index >= self.servers.items.len) return null;
        return self.servers.items[handle.index].config;
    }

    /// Select the next server based on strategy.
    ///
    /// Returns an opaque handle rather than a `*ServerState`: the backing
    /// ArrayList may realloc/relocate on addServer/removeServer, so raw
    /// pointers must never escape the manager (GAP-0876). The handle stays
    /// valid until the next addServer/removeServer call.
    pub fn selectServer(self: *Self) ?ServerHandle {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = self.clk.nowMs();

        // Collect available server indices into a stack buffer — failover
        // pools are tiny, so this avoids a heap allocation + free on every
        // selection, all of it under the mutex (PF-NEW-33, #218). Indices
        // (not pointers) so nothing aliasing servers.items escapes (GAP-0876).
        var stack: [max_tracked_servers]usize = undefined;
        var count: usize = 0;
        for (self.servers.items, 0..) |*server, i| {
            if (server.isAvailable(now)) {
                if (count >= stack.len) break;
                stack[count] = i;
                count += 1;
            }
        }
        const available = stack[0..count];

        if (available.len == 0) {
            // No healthy servers. As a last resort hand back *a* server so the
            // caller has something to try, but rotate (REL-6) instead of always
            // returning servers[0] so successive all-unhealthy calls don't hammer
            // the same primary.
            if (self.servers.items.len > 0) {
                const idx = self.rr_index % self.servers.items.len;
                self.rr_index +%= 1;
                return ServerHandle{ .index = idx, .generation = self.generation };
            }
            return null;
        }

        const selected = switch (self.config.strategy) {
            .round_robin => self.selectRoundRobin(available),
            .weighted => self.selectWeighted(available),
            .least_connections => self.selectLeastConnections(available),
            .latency_based => self.selectLatencyBased(available),
            .random => self.selectRandom(available),
            .primary_secondary => self.selectPrimarySecondary(available),
        } orelse return null;

        return ServerHandle{ .index = selected, .generation = self.generation };
    }

    fn selectRoundRobin(self: *Self, indices: []const usize) ?usize {
        if (indices.len == 0) return null;
        const idx = indices[self.rr_index % indices.len];
        self.rr_index = (self.rr_index + 1) % indices.len;
        return idx;
    }

    /// Smooth weighted round-robin (nginx algorithm, GAP-0885).
    ///
    /// Each call adds every healthy server's configured weight to its
    /// running `current_weight`, picks the server with the highest running
    /// weight, then subtracts the total weight from the pick. This
    /// interleaves selections proportionally (A,B,A,B for equal weights)
    /// instead of producing consecutive batches, and adapts naturally as
    /// the healthy set changes.
    fn selectWeighted(self: *Self, indices: []const usize) ?usize {
        if (indices.len == 0) return null;

        var total_weight: i64 = 0;
        for (indices) |i| {
            const server = &self.servers.items[i];
            const weight: i64 = server.config.weight;
            total_weight += weight;
            server.current_weight += weight;
        }

        if (total_weight == 0) return indices[0];

        var best = indices[0];
        var best_weight = self.servers.items[best].current_weight;
        for (indices[1..]) |i| {
            const cw = self.servers.items[i].current_weight;
            if (cw > best_weight) {
                best_weight = cw;
                best = i;
            }
        }

        self.servers.items[best].current_weight -= total_weight;
        return best;
    }

    fn selectLeastConnections(self: *Self, indices: []const usize) ?usize {
        if (indices.len == 0) return null;

        var min_conn: u32 = std.math.maxInt(u32);
        var selected: ?usize = null;

        for (indices) |i| {
            const server = &self.servers.items[i];
            if (server.active_connections < min_conn) {
                min_conn = server.active_connections;
                selected = i;
            }
        }

        return selected;
    }

    fn selectLatencyBased(self: *Self, indices: []const usize) ?usize {
        if (indices.len == 0) return null;

        var min_latency: u32 = std.math.maxInt(u32);
        var selected: ?usize = null;

        for (indices) |i| {
            const server = &self.servers.items[i];
            // Prefer servers with known latency
            const latency = if (server.avg_latency_ms > 0) server.avg_latency_ms else 1000;
            if (latency < min_latency) {
                min_latency = latency;
                selected = i;
            }
        }

        return selected;
    }

    fn selectRandom(self: *Self, indices: []const usize) ?usize {
        if (indices.len == 0) return null;
        const pick = self.rng.random().intRangeLessThan(usize, 0, indices.len);
        return indices[pick];
    }

    fn selectPrimarySecondary(self: *Self, indices: []const usize) ?usize {
        if (indices.len == 0) return null;

        // Sort by priority (lowest first)
        var best: ?usize = null;
        var best_priority: u8 = 255;

        for (indices) |i| {
            const server = &self.servers.items[i];
            if (server.config.priority < best_priority) {
                best_priority = server.config.priority;
                best = i;
            }
        }

        return best;
    }

    /// Record a successful request.
    ///
    /// Returns false (no-op) when the handle is stale, i.e. the server set
    /// changed since the handle was obtained (GAP-0876).
    pub fn recordSuccess(self: *Self, handle: ServerHandle, latency_ms: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (handle.generation != self.generation) return false;
        if (handle.index >= self.servers.items.len) return false;

        const now = self.clk.nowMs();
        self.servers.items[handle.index].recordSuccess(latency_ms, now);
        self.stats.total_queries += 1;
        self.stats.successful_queries += 1;
        return true;
    }

    /// Record a failed request.
    ///
    /// Returns false (no-op) when the handle is stale, i.e. the server set
    /// changed since the handle was obtained (GAP-0876).
    pub fn recordFailure(self: *Self, handle: ServerHandle) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (handle.generation != self.generation) return false;
        if (handle.index >= self.servers.items.len) return false;

        const now = self.clk.nowMs();
        const server = &self.servers.items[handle.index];
        const was_healthy = server.status != .unhealthy;
        server.recordFailure(now, self.config.circuit_timeout_ms);

        if (was_healthy and server.status == .unhealthy) {
            self.stats.circuit_breaker_trips += 1;
        }
        self.stats.failover_events += 1;
        return true;
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

        const now = self.clk.nowMs();
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

        const now = self.clk.nowMs();

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

    const now = timeMilli();
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

    const now = timeMilli();

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
    try std.testing.expect(s1.?.index != s2.?.index or manager.servers.items.len == 1);
}

test "FailoverManager rotates last-resort server when all unhealthy (REL-6)" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{ .strategy = .round_robin });
    defer manager.deinit();

    try manager.addServer(.{ .address = "server1" });
    try manager.addServer(.{ .address = "server2" });

    // Force both servers into an open-circuit (unavailable) state.
    const future = timeMilli() + 1_000_000;
    for (manager.servers.items) |*server| {
        server.status = .unhealthy;
        server.circuit_open_until = future;
    }

    const s1 = manager.selectServer();
    const s2 = manager.selectServer();

    try std.testing.expect(s1 != null);
    try std.testing.expect(s2 != null);
    // Before the fix this always returned servers[0]; now the last-resort
    // fallback rotates so it does not hammer a single known-down server.
    try std.testing.expect(s1.?.index != s2.?.index);
}

test "FailoverManager statistics" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{});
    defer manager.deinit();

    try manager.addServer(.{ .address = "test" });
    manager.servers.items[0].status = .healthy;

    if (manager.selectServer()) |handle| {
        try std.testing.expect(manager.recordSuccess(handle, 50));
        try std.testing.expect(manager.recordSuccess(handle, 60));
        try std.testing.expect(manager.recordFailure(handle));
    }

    const stats = manager.getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.total_queries);
    try std.testing.expectEqual(@as(u64, 2), stats.successful_queries);
    try std.testing.expectEqual(@as(u64, 1), stats.failover_events);
}

test "FailoverManager stale handle rejected after server set mutation (GAP-0876)" {
    const allocator = std.testing.allocator;
    var manager = try FailoverManager.init(allocator, .{});
    defer manager.deinit();

    try manager.addServer(.{ .address = "server1" });
    manager.servers.items[0].status = .healthy;

    const handle = manager.selectServer();
    try std.testing.expect(handle != null);

    // A handle obtained before the pool changes must be usable.
    try std.testing.expect(manager.recordSuccess(handle.?, 10));

    // Mutating the server set (append may realloc; swapRemove relocates)
    // invalidates all outstanding handles.
    try manager.addServer(.{ .address = "server2" });
    try std.testing.expect(!manager.recordSuccess(handle.?, 10));
    try std.testing.expect(!manager.recordFailure(handle.?));

    // Stale handles must not mutate statistics.
    const stats = manager.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.total_queries);
    try std.testing.expectEqual(@as(u64, 0), stats.failover_events);

    // A freshly obtained handle works again.
    const fresh = manager.selectServer();
    try std.testing.expect(fresh != null);
    try std.testing.expect(manager.recordSuccess(fresh.?, 10));

    // removeServer also bumps the generation.
    const fresh2 = manager.selectServer();
    try std.testing.expect(manager.removeServer("server2"));
    try std.testing.expect(!manager.recordFailure(fresh2.?));
}

test "FailoverManager circuit opens after 3 failures and recovers via mock clock (GAP-0880)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .circuit_timeout_ms = 30_000 },
        mock.clock(),
    );
    defer manager.deinit();

    try manager.addServer(.{ .address = "primary" });
    manager.servers.items[0].status = .healthy;

    // Three consecutive failures open the circuit breaker.
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const handle = manager.selectServer().?;
        try std.testing.expect(manager.recordFailure(handle));
    }
    try std.testing.expectEqual(ServerStatus.unhealthy, manager.servers.items[0].status);
    try std.testing.expect(!manager.servers.items[0].isAvailable(mock.clock().nowMs()));
    try std.testing.expectEqual(@as(u64, 1), manager.getStats().circuit_breaker_trips);

    // Just before the circuit timeout the server stays unavailable.
    mock.advanceMs(29_999);
    try std.testing.expect(!manager.servers.items[0].isAvailable(mock.clock().nowMs()));

    // After the timeout expires, checkHealth resets the breaker.
    mock.advanceMs(2);
    manager.checkHealth();
    try std.testing.expectEqual(ServerStatus.unknown, manager.servers.items[0].status);
    try std.testing.expect(manager.servers.items[0].isAvailable(mock.clock().nowMs()));
    try std.testing.expectEqual(@as(usize, 0), manager.servers.items[0].consecutive_failures);
}

test "FailoverManager weighted selection proportions over 1000 draws (GAP-0880)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .strategy = .weighted },
        mock.clock(),
    );
    defer manager.deinit();

    try manager.addServer(.{ .address = "light", .weight = 25 });
    try manager.addServer(.{ .address = "heavy", .weight = 75 });
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }

    var counts = [_]usize{ 0, 0 };
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const handle = manager.selectServer().?;
        counts[handle.index] += 1;
    }

    // Expected proportions: 25% / 75% of 1000 draws, +/-10 percentage
    // points tolerance (the algorithm is deterministic, so this is loose).
    try std.testing.expect(counts[0] >= 150 and counts[0] <= 350);
    try std.testing.expect(counts[1] >= 650 and counts[1] <= 850);
    try std.testing.expectEqual(@as(usize, 1000), counts[0] + counts[1]);
}

test "FailoverManager least-connections picks lowest active count (GAP-0880)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .strategy = .least_connections },
        mock.clock(),
    );
    defer manager.deinit();

    try manager.addServer(.{ .address = "busy" });
    try manager.addServer(.{ .address = "idle" });
    try manager.addServer(.{ .address = "medium" });
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }
    manager.servers.items[0].active_connections = 5;
    manager.servers.items[1].active_connections = 1;
    manager.servers.items[2].active_connections = 3;

    const handle = manager.selectServer().?;
    try std.testing.expectEqual(@as(usize, 1), handle.index);
}

test "FailoverManager latency strategy picks fastest recorded (GAP-0880)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .strategy = .latency_based },
        mock.clock(),
    );
    defer manager.deinit();

    try manager.addServer(.{ .address = "slow" });
    try manager.addServer(.{ .address = "fast" });
    try manager.addServer(.{ .address = "unknown-latency" });
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }
    manager.servers.items[0].avg_latency_ms = 200;
    manager.servers.items[1].avg_latency_ms = 50;
    // servers.items[2] has no recorded latency: treated as 1000ms.

    const handle = manager.selectServer().?;
    try std.testing.expectEqual(@as(usize, 1), handle.index);
}

test "FailoverManager primary-secondary fails over and returns (GAP-0880)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .strategy = .primary_secondary, .circuit_timeout_ms = 30_000 },
        mock.clock(),
    );
    defer manager.deinit();

    try manager.addServer(.{ .address = "primary", .priority = 0 });
    try manager.addServer(.{ .address = "secondary", .priority = 1, .is_backup = true });
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }

    // Both healthy: primary wins.
    try std.testing.expectEqual(@as(usize, 0), manager.selectServer().?.index);

    // Trip the primary's circuit breaker.
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const handle = ServerHandle{ .index = 0, .generation = manager.generation };
        try std.testing.expect(manager.recordFailure(handle));
    }
    try std.testing.expectEqual(ServerStatus.unhealthy, manager.servers.items[0].status);

    // Primary unavailable: secondary is selected.
    try std.testing.expectEqual(@as(usize, 1), manager.selectServer().?.index);

    // Recover the primary after the circuit timeout.
    mock.advanceMs(30_001);
    manager.checkHealth();
    try std.testing.expectEqual(@as(usize, 0), manager.selectServer().?.index);
}

// GAP-0880 (f): the InitError.EntropyUnavailable path of FailoverManager.init
// is intentionally NOT covered by a unit test. SystemRandom.init() fails only
// when the OS entropy source (getrandom/posix fillSecure) fails, and the
// random module deliberately exposes no injection seam for that source: the
// fail-fast-on-weak-entropy behavior is a security requirement (GAP-0851,
// DNS transaction-ID prediction), and adding a fake-entropy seam to the
// production path would weaken it. The error mapping is a single catch.

test "FailoverManager smooth weighted round-robin interleaves equal weights (GAP-0885)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .strategy = .weighted },
        mock.clock(),
    );
    defer manager.deinit();

    try manager.addServer(.{ .address = "a", .weight = 1 });
    try manager.addServer(.{ .address = "b", .weight = 1 });
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }

    // Smooth WRR (nginx algorithm) must interleave equal weights strictly:
    // A,B,A,B,... -- never batches like the old cumulative-accumulator walk.
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const handle = manager.selectServer().?;
        try std.testing.expectEqual(i % 2, handle.index);
    }
}

test "FailoverManager smooth weighted round-robin avoids batching at weight 50 (GAP-0885)" {
    const allocator = std.testing.allocator;
    var mock = clock.MockClock.init();
    var manager = try FailoverManager.initWithClock(
        allocator,
        .{ .strategy = .weighted },
        mock.clock(),
    );
    defer manager.deinit();

    // Default weight is 50: the old algorithm produced 50 consecutive
    // picks of A followed by 50 of B. Smooth WRR must never repeat a
    // server twice in a row when weights are equal.
    try manager.addServer(.{ .address = "a" });
    try manager.addServer(.{ .address = "b" });
    for (manager.servers.items) |*server| {
        server.status = .healthy;
    }

    var prev = manager.selectServer().?.index;
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        const next = manager.selectServer().?.index;
        try std.testing.expect(next != prev);
        prev = next;
    }
}

test "Strategy enum" {
    try std.testing.expectEqual(Strategy.round_robin, Strategy.round_robin);
    try std.testing.expectEqual(Strategy.weighted, Strategy.weighted);
    try std.testing.expectEqual(Strategy.least_connections, Strategy.least_connections);
}
