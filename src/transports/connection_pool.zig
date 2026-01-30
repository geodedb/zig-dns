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

    const Self = @This();

    pub fn init(fd: std.posix.fd_t, server: ServerKey, now: i64) Self {
        return Self{
            .fd = fd,
            .server = server,
            .state = .idle,
            .created_at = now,
            .last_used = now,
            .pending_queries = 0,
            .stats = .{},
            .keepalive_timeout_ms = null,
        };
    }

    /// Check if connection is healthy
    pub fn isHealthy(self: *const Self, config: PoolConfig, now: i64) bool {
        if (self.state == .closed) return false;

        // Check max age
        const age_ms: u64 = @intCast(now - self.created_at);
        if (age_ms > config.max_connection_age_ms) return false;

        // Check idle timeout
        if (self.state == .idle) {
            const idle_ms: u64 = @intCast(now - self.last_used);
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

    const Self = @This();

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

    /// Get or create a connection to the server
    pub fn acquire(self: *Self, server: ServerKey, timeout_ms: u32) !*PooledConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // First, try to reuse an existing connection
        for (self.connections.items) |*conn| {
            if (!conn.server.eql(server)) continue;
            if (!conn.isHealthy(self.config, now)) continue;
            if (!conn.canPipeline(self.config)) continue;

            conn.markActive(now);
            self.stats.connections_reused += 1;
            return conn;
        }

        // Check if we can create a new connection
        const server_count = self.countServerConnections(server);
        if (server_count >= self.config.max_connections_per_server) {
            // Wait for a connection to become available
            return error.PoolExhausted;
        }

        // Create new connection (unlock during connect)
        self.mutex.unlock();
        defer self.mutex.lock();

        const fd = try self.createConnection(server, timeout_ms);

        // Re-lock and add to pool
        const conn = PooledConnection.init(fd, server, now);
        try self.connections.append(self.allocator, conn);

        const ptr = &self.connections.items[self.connections.items.len - 1];
        ptr.markActive(now);
        self.stats.connections_created += 1;
        self.stats.active_connections += 1;

        return ptr;
    }

    /// Release a connection back to the pool
    pub fn release(self: *Self, conn: *PooledConnection, success: bool, bytes_sent: u64, bytes_recv: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

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

        // Set TCP_NODELAY to reduce latency
        const one: c_int = 1;
        _ = std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one));

        // Set SO_KEEPALIVE
        _ = std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, std.mem.asBytes(&one));

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
    /// Connection to use
    conn: ?*PooledConnection,

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
    pub fn execute(self: *Self, fd: std.posix.fd_t) !void {
        // Send all queries with TCP length prefix
        for (self.queries.items) |q| {
            var length_prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &length_prefix, @intCast(q.wire_data.len), .big);

            _ = try std.posix.write(fd, &length_prefix);
            _ = try std.posix.write(fd, q.wire_data);
        }

        // Receive all responses in order
        for (self.queries.items) |*q| {
            // Read response length
            var resp_len_buf: [2]u8 = undefined;
            var len_read: usize = 0;
            while (len_read < 2) {
                const n = try std.posix.read(fd, resp_len_buf[len_read..]);
                if (n == 0) {
                    q.err = error.ConnectionClosed;
                    q.completed = true;
                    continue;
                }
                len_read += n;
            }
            const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
            if (resp_len == 0 or resp_len > max_message_size) {
                q.err = error.MessageTooLarge;
                q.completed = true;
                continue;
            }

            // Read response
            const response = try self.allocator.alloc(u8, resp_len);
            errdefer self.allocator.free(response);

            var total_read: usize = 0;
            while (total_read < resp_len) {
                const n = try std.posix.read(fd, response[total_read..]);
                if (n == 0) {
                    q.err = error.ConnectionClosed;
                    q.completed = true;
                    self.allocator.free(response);
                    continue;
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
        const conn = try self.pool.acquire(self.server_key, timeout_ms);
        errdefer self.pool.release(conn, false, 0, 0);

        // Connect if needed (socket was created non-blocking)
        try connectWithTimeout(conn.fd, self.address, timeout_ms);

        // Send query with TCP length prefix
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(wire_req.len), .big);

        try writeAllWithTimeout(conn.fd, &length_prefix, timeout_ms);
        try writeAllWithTimeout(conn.fd, wire_req, timeout_ms);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        try readExactWithTimeout(conn.fd, &resp_len_buf, timeout_ms);
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
        if (resp_len == 0 or resp_len > max_message_size) {
            return error.MessageTooLarge;
        }

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try readWithTimeout(conn.fd, response[total_read..], timeout_ms);
            if (n == 0) return error.ConnectionClosed;
            total_read += n;
        }

        self.pool.release(conn, true, wire_req.len + 2, resp_len + 2);
        return response;
    }

    /// Send multiple queries with pipelining
    pub fn queryBatch(self: *Self, queries: []const []const u8, timeout_ms: u32) ![]?[]u8 {
        const conn = try self.pool.acquire(self.server_key, timeout_ms);
        errdefer self.pool.release(conn, false, 0, 0);

        // Connect if needed
        try connectWithTimeout(conn.fd, self.address, timeout_ms);

        var total_sent: u64 = 0;
        var total_recv: u64 = 0;

        // Send all queries
        for (queries) |q| {
            var length_prefix: [2]u8 = undefined;
            std.mem.writeInt(u16, &length_prefix, @intCast(q.len), .big);

            try writeAllWithTimeout(conn.fd, &length_prefix, timeout_ms);
            try writeAllWithTimeout(conn.fd, q, timeout_ms);
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
            try readExactWithTimeout(conn.fd, &resp_len_buf, timeout_ms);
            const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
            if (resp_len == 0 or resp_len > max_message_size) {
                return error.MessageTooLarge;
            }

            // Read response
            const response = try self.allocator.alloc(u8, resp_len);
            errdefer self.allocator.free(response);

            var total_read: usize = 0;
            while (total_read < resp_len) {
                const n = try readWithTimeout(conn.fd, response[total_read..], timeout_ms);
                if (n == 0) return error.ConnectionClosed;
                total_read += n;
            }

            resp.* = response;
            total_recv += resp_len + 2;
        }

        self.pool.release(conn, true, total_sent, total_recv);
        return responses;
    }
};

fn connectWithTimeout(sock: std.posix.socket_t, address: std.net.Address, timeout_ms: u32) !void {
    std.posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.InProgress => {},
        error.IsConnected => return,
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

// ============================================================================
// Tests
// ============================================================================

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
