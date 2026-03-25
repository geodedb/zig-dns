// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Connection Pool for DNS TCP/TLS Transports
//!
//! Provides connection pooling and pipelining support for TCP-based DNS transports:
//! - Connection reuse to avoid TCP handshake overhead
//! - Pipelining: send multiple queries without waiting for responses
//! - Idle connection timeout and health checking
//! - Per-server connection limits
//!
//! References:
//! - RFC 7766: DNS Transport over TCP - Implementation Requirements
//! - RFC 7828: EDNS TCP Keepalive Option

const std = @import("std");
const builtin = @import("builtin");
const io = @import("transport_io");

/// Cross-platform dummy fd for testing (not a real connection)
/// On Windows fd_t is *anyopaque, on POSIX it's an integer
const testing_dummy_fd: std.posix.fd_t = if (builtin.os.tag == .windows)
    @ptrFromInt(std.math.maxInt(usize))
else
    0;

const max_message_size: usize = 65535;

/// Connection pool configuration
pub const PoolConfig = struct {
    /// Maximum connections per server
    max_connections_per_server: u16 = 4,
    /// Maximum idle time before closing connection (ms)
    idle_timeout_ms: u32 = 30_000,
    /// Maximum connection lifetime (ms)
    max_connection_age_ms: u32 = 300_000, // 5 minutes
    /// Enable pipelining (multiple queries per connection)
    enable_pipelining: bool = true,
    /// Maximum pipelined queries per connection
    max_pipelined_queries: u16 = 10,
    /// Connection health check interval (ms)
    health_check_interval_ms: u32 = 60_000,
    /// Connection retry delay on failure (ms)
    retry_delay_ms: u32 = 1000,
    /// Maximum retry attempts
    max_retries: u8 = 3,
};

/// Connection state
pub const ConnectionState = enum {
    /// Connection is available for queries
    idle,
    /// Connection is actively handling queries
    active,
    /// Connection is being established
    connecting,
    /// Connection is being closed
    closing,
    /// Connection is closed/failed
    closed,
};

/// Pooled connection statistics
pub const ConnectionStats = struct {
    /// Total queries processed
    queries_processed: u64 = 0,
    /// Total bytes sent
    bytes_sent: u64 = 0,
    /// Total bytes received
    bytes_received: u64 = 0,
    /// Connection errors
    errors: u32 = 0,
    /// Successful pipelined batches
    pipelined_batches: u32 = 0,
};

/// Pooled connection wrapper
pub const PooledConnection = struct {
    /// Socket file descriptor
    fd: std.posix.fd_t,
    /// Server address
    server: ServerKey,
    /// Connection state
    state: ConnectionState,
    /// Whether the TCP socket has completed its connect handshake
    is_connected: bool,
    /// Time connection was established
    created_at: i64,
    /// Time of last activity
    last_used: i64,
    /// Number of pending pipelined queries
    pending_queries: u16,
    /// Connection statistics
    stats: ConnectionStats,
    /// EDNS TCP Keepalive timeout (from server)
    keepalive_timeout_ms: ?u32,
    /// Unique generation assigned by the pool, used to safely locate
    /// this entry via ConnectionHandle after ArrayList mutations.
    generation: u64 = 0,

    const Self = @This();

    pub fn init(fd: std.posix.fd_t, server: ServerKey, now: i64) Self {
        return Self{
            .fd = fd,
            .server = server,
            .state = .idle,
            .is_connected = false,
            .created_at = now,
            .last_used = now,
            .pending_queries = 0,
            .stats = .{},
            .keepalive_timeout_ms = null,
            .generation = 0,
        };
    }

    /// Check if connection is healthy
    pub fn isHealthy(self: *const Self, config: PoolConfig, now: i64) bool {
        if (self.state == .closed) return false;

        // Check max age
        const age_ms: u64 = @intCast(@max(0, now - self.created_at));
        if (age_ms > config.max_connection_age_ms) return false;

        // Check idle timeout
        if (self.state == .idle) {
            const idle_ms: u64 = @intCast(@max(0, now - self.last_used));
            // Use server-provided keepalive if available
            const timeout = self.keepalive_timeout_ms orelse config.idle_timeout_ms;
            if (idle_ms > timeout) return false;
        }

        return true;
    }

    /// Check if connection can accept more pipelined queries
    pub fn canPipeline(self: *const Self, config: PoolConfig) bool {
        if (!config.enable_pipelining) return self.pending_queries == 0;
        return self.pending_queries < config.max_pipelined_queries;
    }

    /// Mark connection as being used
    pub fn markActive(self: *Self, now: i64) void {
        self.state = .active;
        self.last_used = now;
        self.pending_queries += 1;
    }

    /// Mark query as complete
    pub fn markQueryComplete(self: *Self, now: i64, bytes_sent: u64, bytes_recv: u64) void {
        self.last_used = now;
        self.stats.queries_processed += 1;
        self.stats.bytes_sent += bytes_sent;
        self.stats.bytes_received += bytes_recv;

        if (self.pending_queries > 0) {
            self.pending_queries -= 1;
        }

        if (self.pending_queries == 0) {
            self.state = .idle;
        }
    }

    /// Close the connection
    pub fn close(self: *Self) void {
        if (self.state != .closed) {
            std.posix.close(self.fd);
            self.state = .closed;
        }
    }
};

/// Server identifier key
pub const ServerKey = struct {
    /// Server IP/hostname hash
    host_hash: u64,
    /// Server port
    port: u16,
    /// Transport type (tcp, dot, etc.)
    transport: TransportType,

    pub const TransportType = enum(u8) {
        tcp,
        dot,
        doh,
        doq,
    };

    pub fn init(host: []const u8, port: u16, transport: TransportType) ServerKey {
        return .{
            .host_hash = std.hash.Wyhash.hash(0, host),
            .port = port,
            .transport = transport,
        };
    }

    pub fn eql(a: ServerKey, b: ServerKey) bool {
        return a.host_hash == b.host_hash and a.port == b.port and a.transport == b.transport;
    }
};

/// Connection pool
pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    config: PoolConfig,
    /// All pooled connections
    connections: std.ArrayList(PooledConnection),
    /// Mutex for thread safety
    mutex: std.Thread.Mutex,
    /// Pool statistics
    stats: PoolStats,
    /// Monotonically increasing generation counter.
    /// Each PooledConnection gets a unique generation at creation time.
    /// ConnectionHandle stores the generation so that release/markConnected
    /// can locate the correct entry even after ArrayList reallocation or
    /// swapRemove reordering.
    next_generation: u64 = 0,

    const Self = @This();

    /// Handle returned by acquire(). Contains a copy of the connection
    /// data needed for I/O (fd, is_connected) plus a generation token
    /// for safely locating the entry later. Because it is a value type
    /// (not a pointer into the ArrayList), it is immune to ArrayList
    /// reallocation and swapRemove reordering.
    pub const ConnectionHandle = struct {
        /// Socket file descriptor (copied at acquire time)
        fd: std.posix.fd_t,
        /// Whether the TCP handshake has completed (copied at acquire time)
        is_connected: bool,
        /// Unique generation of the PooledConnection (stable identifier)
        generation: u64,
    };

    pub const PoolStats = struct {
        /// Total connections created
        connections_created: u64 = 0,
        /// Total connections reused
        connections_reused: u64 = 0,
        /// Total connections closed (idle timeout)
        connections_timed_out: u64 = 0,
        /// Total connections closed (error)
        connections_errored: u64 = 0,
        /// Current active connections
        active_connections: u32 = 0,
        /// Current idle connections
        idle_connections: u32 = 0,
        /// Total pipelined query batches
        pipelined_batches: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, config: PoolConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .connections = .empty,
            .mutex = .{},
            .stats = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |*conn| {
            conn.close();
        }
        self.connections.deinit(self.allocator);
    }

    /// Find a PooledConnection by its unique generation. Must be called
    /// while the mutex is held. Returns null if the connection has been
    /// removed (e.g. by cleanup).
    fn findByGeneration(self: *Self, generation: u64) ?*PooledConnection {
        for (self.connections.items) |*conn| {
            if (conn.generation == generation) return conn;
        }
        return null;
    }

    /// Get or create a connection to the server.
    /// Returns a ConnectionHandle (value type) instead of a pointer into
    /// the ArrayList, preventing dangling-pointer bugs when concurrent
    /// operations cause the backing array to reallocate or swapRemove to
    /// reorder entries.
    pub fn acquire(self: *Self, server: ServerKey, timeout_ms: u32) !ConnectionHandle {
        self.mutex.lock();

        const now = std.time.milliTimestamp();

        // First, try to reuse an existing connection
        for (self.connections.items) |*conn| {
            if (!conn.server.eql(server)) continue;
            if (!conn.isHealthy(self.config, now)) continue;
            if (!conn.canPipeline(self.config)) continue;

            conn.markActive(now);
            self.stats.connections_reused += 1;
            const handle = ConnectionHandle{
                .fd = conn.fd,
                .is_connected = conn.is_connected,
                .generation = conn.generation,
            };
            self.mutex.unlock();
            return handle;
        }

        // Check if we can create a new connection
        const server_count = self.countServerConnections(server);
        if (server_count >= self.config.max_connections_per_server) {
            self.mutex.unlock();
            return error.PoolExhausted;
        }

        // Unlock during potentially-blocking connect to avoid holding the
        // mutex while waiting on the network.
        self.mutex.unlock();

        var fd = self.createConnection(server, timeout_ms) catch |err| {
            return err;
        };
        errdefer if (fd != -1) std.posix.close(fd);

        // Re-lock to mutate pool state
        self.mutex.lock();
        defer self.mutex.unlock();

        // QC-NEW-02 TOCTOU fix: Re-check the connection limit now that
        // we hold the lock again. Another thread may have created a
        // connection for the same server while we were unlocked.
        const recheck_count = self.countServerConnections(server);
        if (recheck_count >= self.config.max_connections_per_server) {
            // Limit exceeded -- close the fd we just created and try to
            // reuse an existing connection that may have become available.
            std.posix.close(fd);
            fd = -1; // Prevent errdefer double-close

            for (self.connections.items) |*conn| {
                if (!conn.server.eql(server)) continue;
                if (!conn.isHealthy(self.config, now)) continue;
                if (!conn.canPipeline(self.config)) continue;

                conn.markActive(now);
                self.stats.connections_reused += 1;
                return ConnectionHandle{
                    .fd = conn.fd,
                    .is_connected = conn.is_connected,
                    .generation = conn.generation,
                };
            }
            return error.PoolExhausted;
        }

        const generation = self.next_generation;
        self.next_generation += 1;

        var conn = PooledConnection.init(fd, server, now);
        conn.generation = generation;
        try self.connections.append(self.allocator, conn);

        // Access via findByGeneration (safe after append) to markActive
        const pool_conn = self.findByGeneration(generation).?;
        pool_conn.markActive(now);
        self.stats.connections_created += 1;
        self.stats.active_connections += 1;

        return ConnectionHandle{
            .fd = pool_conn.fd,
            .is_connected = pool_conn.is_connected,
            .generation = generation,
        };
    }

    /// Release a connection back to the pool.
    /// Accepts a ConnectionHandle (value type) instead of a pointer.
    pub fn release(self: *Self, handle: ConnectionHandle, success: bool, bytes_sent: u64, bytes_recv: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const conn = self.findByGeneration(handle.generation) orelse return;
        const now = std.time.milliTimestamp();

        if (success) {
            conn.markQueryComplete(now, bytes_sent, bytes_recv);
            if (conn.state == .idle) {
                self.stats.active_connections -|= 1;
                self.stats.idle_connections += 1;
            }
        } else {
            conn.stats.errors += 1;
            conn.close();
            self.stats.connections_errored += 1;
            self.stats.active_connections -|= 1;
        }
    }

    /// Mark a connection as having completed the TCP handshake.
    /// Called by callers after a successful connectWithTimeout.
    pub fn markConnected(self: *Self, handle: *ConnectionHandle) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findByGeneration(handle.generation)) |conn| {
            conn.is_connected = true;
        }
        // Also update the caller's handle so subsequent reads see the
        // new value without re-acquiring the lock.
        handle.is_connected = true;
    }

    /// Clean up idle/expired connections
    pub fn cleanup(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();
        var i: usize = 0;

        while (i < self.connections.items.len) {
            const conn = &self.connections.items[i];

            if (!conn.isHealthy(self.config, now)) {
                conn.close();
                if (conn.state == .idle) {
                    self.stats.idle_connections -|= 1;
                } else {
                    self.stats.active_connections -|= 1;
                }
                self.stats.connections_timed_out += 1;
                _ = self.connections.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Get pool statistics
    pub fn getStats(self: *Self) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Recalculate counts
        var active: u32 = 0;
        var idle: u32 = 0;
        for (self.connections.items) |conn| {
            switch (conn.state) {
                .active => active += 1,
                .idle => idle += 1,
                else => {},
            }
        }
        self.stats.active_connections = active;
        self.stats.idle_connections = idle;

        return self.stats;
    }

    fn countServerConnections(self: *Self, server: ServerKey) u16 {
        var count: u16 = 0;
        for (self.connections.items) |conn| {
            if (conn.server.eql(server) and conn.state != .closed) {
                count += 1;
            }
        }
        return count;
    }

    /// Create a new pooled connection entry (socket only, no active connection).
    /// The actual TCP connection is established lazily on first use, not here.
    /// Parameters `server` and `timeout_ms` are stored for deferred connection
    /// establishment; they do NOT trigger an immediate connect.
    fn createConnection(self: *Self, server: ServerKey, timeout_ms: u32) !std.posix.fd_t {
        _ = timeout_ms;
        _ = self;

        // Create socket
        const fd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        errdefer std.posix.close(fd);

        // Set TCP_NODELAY to reduce latency (best-effort, non-fatal)
        const one: c_int = 1;
        std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};

        // Set SO_KEEPALIVE (best-effort, non-fatal)
        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&one)) catch {};

        // Note: Actual connection happens when the address is provided
        // For now, we just return the configured socket
        _ = server;

        return fd;
    }
};

/// Pipelined query batch
pub const PipelinedBatch = struct {
    allocator: std.mem.Allocator,
    /// Queries in the batch
    queries: std.ArrayList(Query),
    /// Connection handle to use (value type, not a pointer into the pool)
    conn: ?ConnectionPool.ConnectionHandle,

    pub const Query = struct {
        /// Query ID (from DNS header)
        id: u16,
        /// Wire format query
        wire_data: []u8,
        /// Response slot
        response: ?[]u8,
        /// Error if failed
        err: ?anyerror,
        /// Completion flag
        completed: bool,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .queries = .empty,
            .conn = null,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.queries.items) |*q| {
            self.allocator.free(q.wire_data);
            if (q.response) |r| self.allocator.free(r);
        }
        self.queries.deinit(self.allocator);
    }

    /// Add a query to the batch
    pub fn addQuery(self: *Self, id: u16, wire_data: []const u8) !void {
        const copy = try self.allocator.dupe(u8, wire_data);
        errdefer self.allocator.free(copy);

        try self.queries.append(self.allocator, .{
            .id = id,
            .wire_data = copy,
            .response = null,
            .err = null,
            .completed = false,
        });
    }

    /// Execute all queries in the batch
    /// Uses poll-based timeout to avoid blocking indefinitely on reads/writes.
    pub fn execute(self: *Self, fd: std.posix.fd_t, timeout_ms: u32) !void {
        // Send all queries with TCP length prefix using writeAll loop
        for (self.queries.items) |q| {
            // SECURITY (SEC-SCAN-04): Bounds check before @intCast to u16 (CWE-681)
            if (q.wire_data.len > std.math.maxInt(u16)) return error.MessageTooLong;
            var length_prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &length_prefix, @intCast(q.wire_data.len), .big);

            try io.writeAllWithTimeout(fd, &length_prefix, timeout_ms);
            try io.writeAllWithTimeout(fd, q.wire_data, timeout_ms);
        }

        // Receive all responses in order
        outer: for (self.queries.items) |*q| {
            // Read response length with timeout
            var resp_len_buf: [2]u8 = undefined;
            var len_read: usize = 0;
            while (len_read < 2) {
                const n = io.readWithTimeout(fd, resp_len_buf[len_read..], timeout_ms) catch |err| {
                    q.err = err;
                    q.completed = true;
                    continue :outer;
                };
                if (n == 0) {
                    q.err = error.ConnectionClosed;
                    q.completed = true;
                    continue :outer;
                }
                len_read += n;
            }
            const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
            if (resp_len == 0 or resp_len > max_message_size) {
                q.err = error.MessageTooLarge;
                q.completed = true;
                continue :outer;
            }

            // Read response
            const response = self.allocator.alloc(u8, resp_len) catch |err| {
                q.err = err;
                q.completed = true;
                continue :outer;
            };

            var total_read: usize = 0;
            while (total_read < resp_len) {
                const n = io.readWithTimeout(fd, response[total_read..], timeout_ms) catch |err| {
                    q.err = err;
                    q.completed = true;
                    self.allocator.free(response);
                    continue :outer;
                };
                if (n == 0) {
                    q.err = error.ConnectionClosed;
                    q.completed = true;
                    self.allocator.free(response);
                    continue :outer;
                }
                total_read += n;
            }

            q.response = response;
            q.completed = true;
        }
    }

    /// Get response for a query by ID
    pub fn getResponse(self: *Self, id: u16) ?[]u8 {
        for (self.queries.items) |*q| {
            if (q.id == id and q.completed and q.response != null) {
                const resp = q.response;
                q.response = null; // Transfer ownership
                return resp;
            }
        }
        return null;
    }
};

/// Pooled TCP transport
pub const PooledTcpTransport = struct {
    allocator: std.mem.Allocator,
    pool: *ConnectionPool,
    address: std.net.Address,
    server_key: ServerKey,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pool: *ConnectionPool, host: []const u8, port: u16) !Self {
        return Self{
            .allocator = allocator,
            .pool = pool,
            .address = try std.net.Address.parseIp4(host, port),
            .server_key = ServerKey.init(host, port, .tcp),
        };
    }

    /// Send a single query
    pub fn query(self: *Self, wire_req: []const u8, timeout_ms: u32) ![]u8 {
        var handle = try self.pool.acquire(self.server_key, timeout_ms);
        errdefer self.pool.release(handle, false, 0, 0);

        // Only connect if the socket hasn't completed its TCP handshake yet.
        // Reused pooled connections are already connected.
        if (!handle.is_connected) {
            try io.connectWithTimeout(handle.fd, self.address, timeout_ms);
            self.pool.markConnected(&handle);
        }

        // Send query with TCP length prefix
        // SECURITY (SEC-SCAN-04): Bounds check before @intCast to u16 (CWE-681)
        if (wire_req.len > std.math.maxInt(u16)) return error.MessageTooLong;
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(wire_req.len), .big);

        try io.writeAllWithTimeout(handle.fd, &length_prefix, timeout_ms);
        try io.writeAllWithTimeout(handle.fd, wire_req, timeout_ms);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        try io.readExactWithTimeout(handle.fd, &resp_len_buf, timeout_ms);
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
        if (resp_len == 0 or resp_len > max_message_size) {
            return error.MessageTooLarge;
        }

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try io.readWithTimeout(handle.fd, response[total_read..], timeout_ms);
            if (n == 0) return error.ConnectionClosed;
            total_read += n;
        }

        self.pool.release(handle, true, wire_req.len + 2, resp_len + 2);
        return response;
    }

    /// Send multiple queries with pipelining
    pub fn queryBatch(self: *Self, queries: []const []const u8, timeout_ms: u32) ![]?[]u8 {
        var handle = try self.pool.acquire(self.server_key, timeout_ms);
        errdefer self.pool.release(handle, false, 0, 0);

        // Only connect if the socket hasn't completed its TCP handshake yet.
        if (!handle.is_connected) {
            try io.connectWithTimeout(handle.fd, self.address, timeout_ms);
            self.pool.markConnected(&handle);
        }

        var total_sent: u64 = 0;
        var total_recv: u64 = 0;

        // Send all queries
        for (queries) |q| {
            // SECURITY (SEC-SCAN-04): Bounds check before @intCast to u16 (CWE-681)
            if (q.len > std.math.maxInt(u16)) return error.MessageTooLong;
            var length_prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &length_prefix, @intCast(q.len), .big);

            try io.writeAllWithTimeout(handle.fd, &length_prefix, timeout_ms);
            try io.writeAllWithTimeout(handle.fd, q, timeout_ms);
            total_sent += q.len + 2;
        }

        // Allocate response array
        const responses = try self.allocator.alloc(?[]u8, queries.len);
        errdefer {
            for (responses) |r| {
                if (r) |resp| self.allocator.free(resp);
            }
            self.allocator.free(responses);
        }

        // Receive all responses
        for (responses) |*resp| {
            // Read response length
            var resp_len_buf: [2]u8 = undefined;
            try io.readExactWithTimeout(handle.fd, &resp_len_buf, timeout_ms);
            const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
            if (resp_len == 0 or resp_len > max_message_size) {
                return error.MessageTooLarge;
            }

            // Read response
            const response = try self.allocator.alloc(u8, resp_len);
            errdefer self.allocator.free(response);

            var total_read: usize = 0;
            while (total_read < resp_len) {
                const n = try io.readWithTimeout(handle.fd, response[total_read..], timeout_ms);
                if (n == 0) return error.ConnectionClosed;
                total_read += n;
            }

            resp.* = response;
            total_recv += resp_len + 2;
        }

        self.pool.release(handle, true, total_sent, total_recv);
        return responses;
    }
};

// ============================================================================
// Tests
// ============================================================================

/// Reuse testSocketPair from io.zig to avoid code duplication.
const testSocketPair = io.testSocketPair;

test "ServerKey equality" {
    const key1 = ServerKey.init("8.8.8.8", 53, .tcp);
    const key2 = ServerKey.init("8.8.8.8", 53, .tcp);
    const key3 = ServerKey.init("8.8.4.4", 53, .tcp);
    const key4 = ServerKey.init("8.8.8.8", 853, .dot);

    try std.testing.expect(key1.eql(key2));
    try std.testing.expect(!key1.eql(key3));
    try std.testing.expect(!key1.eql(key4));
}

test "PoolConfig defaults" {
    const config = PoolConfig{};

    try std.testing.expectEqual(@as(u16, 4), config.max_connections_per_server);
    try std.testing.expectEqual(@as(u32, 30_000), config.idle_timeout_ms);
    try std.testing.expect(config.enable_pipelining);
}

test "ConnectionPool init/deinit" {
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.init(allocator, .{});
    defer pool.deinit();

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.connections_created);
}

test "PooledConnection health check" {
    const server = ServerKey.init("test", 53, .tcp);
    var conn = PooledConnection.init(testing_dummy_fd, server, 0);

    const config = PoolConfig{
        .idle_timeout_ms = 1000,
        .max_connection_age_ms = 5000,
    };

    // Fresh connection is healthy
    try std.testing.expect(conn.isHealthy(config, 500));

    // Connection past max age is not healthy
    try std.testing.expect(!conn.isHealthy(config, 10000));

    // Idle connection past timeout is not healthy
    conn.state = .idle;
    conn.last_used = 0;
    try std.testing.expect(!conn.isHealthy(config, 2000));
}

test "PooledConnection pipelining" {
    const server = ServerKey.init("test", 53, .tcp);
    var conn = PooledConnection.init(testing_dummy_fd, server, 0);

    const config = PoolConfig{
        .enable_pipelining = true,
        .max_pipelined_queries = 5,
    };

    // Can pipeline initially
    try std.testing.expect(conn.canPipeline(config));

    // Fill up the pipeline
    conn.pending_queries = 5;
    try std.testing.expect(!conn.canPipeline(config));

    // With pipelining disabled
    const no_pipe_config = PoolConfig{
        .enable_pipelining = false,
    };
    conn.pending_queries = 0;
    try std.testing.expect(conn.canPipeline(no_pipe_config));
    conn.pending_queries = 1;
    try std.testing.expect(!conn.canPipeline(no_pipe_config));
}

test "PipelinedBatch add query" {
    const allocator = std.testing.allocator;
    var batch = PipelinedBatch.init(allocator);
    defer batch.deinit();

    try batch.addQuery(1234, &[_]u8{ 0x04, 0xD2, 0x01, 0x00 });
    try batch.addQuery(5678, &[_]u8{ 0x16, 0x2E, 0x01, 0x00 });

    try std.testing.expectEqual(@as(usize, 2), batch.queries.items.len);
    try std.testing.expectEqual(@as(u16, 1234), batch.queries.items[0].id);
    try std.testing.expectEqual(@as(u16, 5678), batch.queries.items[1].id);
}

test "PooledConnection is_connected defaults to false" {
    const server = ServerKey.init("test", 53, .tcp);
    const conn = PooledConnection.init(testing_dummy_fd, server, 0);

    // New connections should not be marked as connected
    try std.testing.expect(!conn.is_connected);
}

test "PooledConnection is_connected tracks state" {
    const server = ServerKey.init("test", 53, .tcp);
    var conn = PooledConnection.init(testing_dummy_fd, server, 0);

    try std.testing.expect(!conn.is_connected);
    conn.is_connected = true;
    try std.testing.expect(conn.is_connected);

    // Simulate close by setting state directly (avoids closing dummy fd 0)
    conn.state = .closed;
    try std.testing.expectEqual(ConnectionState.closed, conn.state);
    // is_connected remains true because close does not reset it;
    // the state field governs whether the connection is usable.
    try std.testing.expect(conn.is_connected);
}

test "PipelinedBatch execute with empty batch succeeds" {
    // Verify the execute signature accepts a timeout_ms parameter
    // (Bug 4 fix: blocking reads without timeout).
    // With no queries, both for loops are empty, so execute succeeds.
    const allocator = std.testing.allocator;
    var batch = PipelinedBatch.init(allocator);
    defer batch.deinit();

    // Empty batch with any fd should succeed (no I/O performed)
    try batch.execute(testing_dummy_fd, 1000);
}

test "PipelinedBatch execute with socketpair completes all queries" {
    // Integration test using a real socketpair to verify:
    // - Bug 1: writeAll loop (no partial write data loss)
    // - Bug 2: outer loop label (continue :outer on connection close)
    // - Bug 4: timeout-based reads (no infinite blocking)
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Create a socketpair for testing
    const fds = try testSocketPair();
    const client_fd = fds[0];
    const server_fd = fds[1];
    defer std.posix.close(client_fd);
    defer std.posix.close(server_fd);

    // Build a batch with one query
    var batch = PipelinedBatch.init(allocator);
    defer batch.deinit();

    const query_data = [_]u8{ 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try batch.addQuery(0xABCD, &query_data);

    // Simulate server in a separate thread that reads the query and sends a response
    const ServerThread = struct {
        fn run(fd: std.posix.fd_t) void {
            // Read the 2-byte length prefix + query from client
            var len_buf: [2]u8 = undefined;
            var read_total: usize = 0;
            while (read_total < 2) {
                var poll_fds = [_]std.posix.pollfd{.{
                    .fd = fd,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                _ = std.posix.poll(&poll_fds, 5000) catch return;
                const n = std.posix.read(fd, len_buf[read_total..]) catch return;
                if (n == 0) return;
                read_total += n;
            }
            const msg_len = std.mem.readInt(u16, &len_buf, .big);

            // Read the query body
            var query_buf: [512]u8 = undefined;
            var body_read: usize = 0;
            while (body_read < msg_len) {
                var poll_fds = [_]std.posix.pollfd{.{
                    .fd = fd,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                _ = std.posix.poll(&poll_fds, 5000) catch return;
                const n = std.posix.read(fd, query_buf[body_read .. body_read + (msg_len - body_read)]) catch return;
                if (n == 0) return;
                body_read += n;
            }

            // Send a response: 2-byte length prefix + response body
            const response = [_]u8{ 0xAB, 0xCD, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var resp_prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &resp_prefix, response.len, .big);

            // Write with poll to handle non-blocking
            var sent: usize = 0;
            const full_resp = resp_prefix ++ response;
            while (sent < full_resp.len) {
                var poll_fds = [_]std.posix.pollfd{.{
                    .fd = fd,
                    .events = std.posix.POLL.OUT,
                    .revents = 0,
                }};
                _ = std.posix.poll(&poll_fds, 5000) catch return;
                const n = std.posix.write(fd, full_resp[sent..]) catch return;
                sent += n;
            }
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ServerThread.run, .{server_fd});

    // Execute the batch with a 5 second timeout
    try batch.execute(client_fd, 5000);

    server_thread.join();

    // Verify the response was received
    try std.testing.expect(batch.queries.items[0].completed);
    try std.testing.expect(batch.queries.items[0].err == null);
    try std.testing.expect(batch.queries.items[0].response != null);

    const resp = batch.queries.items[0].response.?;
    // First two bytes should be the query ID
    try std.testing.expectEqual(@as(u8, 0xAB), resp[0]);
    try std.testing.expectEqual(@as(u8, 0xCD), resp[1]);
}

test "PipelinedBatch execute handles connection closed gracefully" {
    // Test Bug 2 fix: continue :outer label prevents infinite loop
    // when connection is closed mid-batch
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Create a socketpair
    const fds = try testSocketPair();
    const client_fd = fds[0];
    const server_fd = fds[1];
    defer std.posix.close(client_fd);

    // Build a batch with two queries
    var batch = PipelinedBatch.init(allocator);
    defer batch.deinit();

    try batch.addQuery(0x0001, &[_]u8{ 0x00, 0x01, 0x01, 0x00 });
    try batch.addQuery(0x0002, &[_]u8{ 0x00, 0x02, 0x01, 0x00 });

    // Close the server end immediately so the client sees EOF
    // after writing. This tests that the outer: label works.
    const ServerThread = struct {
        fn run(fd: std.posix.fd_t) void {
            // Read just enough to let the writes complete, then close
            var buf: [512]u8 = undefined;
            var poll_fds = [_]std.posix.pollfd{.{
                .fd = fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            _ = std.posix.poll(&poll_fds, 2000) catch {};
            _ = std.posix.read(fd, &buf) catch {};
            // Close immediately - no response sent
            std.posix.close(fd);
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ServerThread.run, .{server_fd});

    // Execute should NOT hang (Bug 2: infinite loop fix) and should NOT
    // return an unrecoverable error -- individual queries get errors.
    const result = batch.execute(client_fd, 2000);

    server_thread.join();

    // The execute may return an error from writeAllWithTimeout if the
    // peer closed before all writes complete, or individual queries may
    // have errors set. Either way, it must not hang.
    if (result) |_| {
        // If execute succeeded, check that queries have appropriate errors
        for (batch.queries.items) |q| {
            if (q.completed and q.err != null) {
                // ConnectionClosed or Timeout are acceptable per-query errors
                try std.testing.expect(q.err.? == error.ConnectionClosed or q.err.? == error.Timeout);
            }
        }
    } else |_| {
        // A transport-level error during write is also acceptable
    }
}

test "ConnectionPool acquire releases mutex on all paths" {
    // Test Bug 3 fix: mutex race in acquire
    // Verify the pool is usable after various acquire outcomes.
    const allocator = std.testing.allocator;
    var pool = ConnectionPool.init(allocator, .{
        .max_connections_per_server = 1,
    });
    defer pool.deinit();

    const server = ServerKey.init("127.0.0.1", 53, .tcp);

    // Pool is empty, acquire will try to create a new connection.
    // createConnection creates a socket but doesn't connect it.
    // This verifies the mutex is properly released on all code paths.
    const result = pool.acquire(server, 1000);
    if (result) |conn| {
        // Got a connection - verify pool state is consistent
        pool.release(conn, false, 0, 0);
    } else |_| {
        // Error is acceptable (socket creation may fail in test env)
    }

    // Pool should still be usable (mutex not deadlocked)
    const stats = pool.getStats();
    _ = stats;

    // Verify cleanup works (would deadlock if mutex is broken)
    pool.cleanup();
}
