// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS over TLS (DoT) Transport
//!
//! RFC 7858: DNS over Transport Layer Security (TLS)
//! RFC 8310: Usage Profiles for DNS over TLS (Strict Profile)
//!
//! This module provides DoT transport with pluggable TLS backends.
//! Since Zig's standard library doesn't include TLS, implementations
//! must provide their own TLS backend (e.g., BoringSSL, mbedTLS, bearssl).
//!
//! ## Security Requirements for TLS Backends (SEC-011)
//!
//! Implementers of `TlsBackend` MUST ensure the following security properties:
//!
//! ### TLS Version Requirements
//! - **Minimum**: TLS 1.2 (RFC 8310 compliance)
//! - **Recommended**: TLS 1.3 for improved security and performance
//! - MUST NOT support SSL 3.0, TLS 1.0, or TLS 1.1
//!
//! ### Certificate Validation (RFC 8310 Strict Profile)
//! - MUST validate server certificate against trusted CA bundle
//! - MUST verify Subject Alternative Name (SAN) matches server hostname
//! - MUST check certificate expiration
//! - SHOULD check certificate revocation (OCSP stapling preferred)
//! - MUST fail connection if certificate validation fails
//!
//! ### SPKI Pinning (Optional, Recommended)
//! For high-security deployments, implement SPKI (Subject Public Key Info) pinning:
//! - Pin the server's public key or intermediate CA public key
//! - Reject connections if pin doesn't match
//! - Support pin backup keys for rotation
//!
//! ### Cipher Suite Requirements
//! **Required (MUST support at least one):**
//! - TLS_AES_256_GCM_SHA384 (TLS 1.3)
//! - TLS_AES_128_GCM_SHA256 (TLS 1.3)
//! - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
//! - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
//!
//! **Prohibited (MUST NOT support):**
//! - Any cipher suite using RC4, 3DES, MD5, or SHA1 for MAC
//! - Export cipher suites
//! - NULL cipher suites
//! - Anonymous key exchange
//!
//! ### SNI (Server Name Indication)
//! - MUST send SNI extension with server hostname
//! - SNI enables servers to select correct certificate
//!
//! ### Example Backend Configuration
//!
//! **BoringSSL Example:**
//! ```c
//! SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
//! SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
//! SSL_CTX_set_default_verify_paths(ctx);
//! SSL_set_tlsext_host_name(ssl, hostname);
//! ```
//!
//! **mbedTLS Example:**
//! ```c
//! mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
//! mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3,
//!                                      MBEDTLS_SSL_MINOR_VERSION_3);
//! mbedtls_ssl_set_hostname(&ssl, hostname);
//! ```
//!
//! **WARNING**: Backends that disable certificate validation, use
//! opportunistic encryption, or permit downgrade attacks will
//! compromise the confidentiality of DNS queries and may enable
//! man-in-the-middle attacks, defeating the purpose of DoT.

const std = @import("std");
const channel = @import("channel");

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;
pub const DoTOptions = channel.DoTOptions;
pub const SocketAddress = channel.SocketAddress;

/// TLS backend interface
/// Implementations must provide all these functions for a complete DoT transport
pub const TlsBackend = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Establish TLS connection with the given options
        connect: *const fn (ctx: *anyopaque, options: TlsConnectOptions) anyerror!TlsConnection,
        /// Close and cleanup the backend
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn connect(self: TlsBackend, options: TlsConnectOptions) !TlsConnection {
        return self.vtable.connect(self.ctx, options);
    }

    pub fn deinit(self: TlsBackend) void {
        self.vtable.deinit(self.ctx);
    }
};

/// TLS connection options
pub const TlsConnectOptions = struct {
    /// Server hostname for SNI
    server_name: []const u8,
    /// Server IP address
    host: []const u8,
    /// Server port (default 853 for DoT)
    port: u16 = 853,
    /// CA certificate in PEM format for verification
    ca_pem: ?[]const u8 = null,
    /// ALPN protocol (must be "dot" for RFC 7858)
    alpn: []const u8 = "dot",
    /// TLS version (1.2 or 1.3)
    tls_version: TlsVersion = .tls_1_3,
    /// Connection timeout in milliseconds
    timeout_ms: u32 = 5000,
    /// Explicitly use system CA trust store (SEC-GAP-057: CWE-295)
    use_system_ca: bool = false,
};

/// TLS version
pub const TlsVersion = enum {
    tls_1_2,
    tls_1_3,
};

/// TLS connection handle
pub const TlsConnection = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Write data to TLS connection
        write: *const fn (ctx: *anyopaque, data: []const u8) anyerror!usize,
        /// Read data from TLS connection
        read: *const fn (ctx: *anyopaque, buffer: []u8) anyerror!usize,
        /// Close connection
        close: *const fn (ctx: *anyopaque) void,
        /// Check if connection is open
        isOpen: *const fn (ctx: *anyopaque) bool,
        /// Get negotiated ALPN protocol
        getAlpn: *const fn (ctx: *anyopaque) ?[]const u8,
        /// Get negotiated TLS version
        getTlsVersion: *const fn (ctx: *anyopaque) TlsVersion,
    };

    pub fn write(self: TlsConnection, data: []const u8) !usize {
        return self.vtable.write(self.ctx, data);
    }

    pub fn read(self: TlsConnection, buffer: []u8) !usize {
        return self.vtable.read(self.ctx, buffer);
    }

    pub fn close(self: TlsConnection) void {
        self.vtable.close(self.ctx);
    }

    pub fn isOpen(self: TlsConnection) bool {
        return self.vtable.isOpen(self.ctx);
    }

    pub fn getAlpn(self: TlsConnection) ?[]const u8 {
        return self.vtable.getAlpn(self.ctx);
    }

    pub fn getTlsVersion(self: TlsConnection) TlsVersion {
        return self.vtable.getTlsVersion(self.ctx);
    }
};

/// DoT Transport (RFC 7858 Strict Profile)
/// - ALPN: "dot" (MUST)
/// - TLS 1.3 preferred, 1.2 minimum
/// - Certificate verification against authentication domain name
/// - SNI = authentication domain name
pub const DoTTransport = struct {
    allocator: std.mem.Allocator,
    options: DoTOptions,
    tls_backend: ?TlsBackend,
    connection: ?TlsConnection,
    /// Connection pool settings
    keepalive: bool,
    max_idle_ms: u32,
    last_used: i64,

    const Self = @This();

    /// ALPN protocol identifier for DoT (RFC 7858)
    pub const alpn_dot = "dot";
    /// Default DoT port
    pub const default_port: u16 = 853;
    /// Maximum DNS message size
    pub const max_message_size: usize = 65535;

    pub fn init(allocator: std.mem.Allocator, options: DoTOptions) !Self {
        return initWithBackend(allocator, options, null);
    }

    /// Initialize with a TLS backend
    pub fn initWithBackend(allocator: std.mem.Allocator, options: DoTOptions, backend: ?TlsBackend) !Self {
        // Validate ALPN
        if (!std.mem.eql(u8, options.alpn_dot, alpn_dot)) {
            return error.InvalidAlpn;
        }

        // Validate CA trust configuration (SEC-GAP-057: CWE-295)
        // Either ca_pem must be provided OR use_system_ca must be explicitly true
        if (options.ca_pem.len == 0 and !options.use_system_ca) {
            return error.NoCaTrustConfigured;
        }

        return Self{
            .allocator = allocator,
            .options = options,
            .tls_backend = backend,
            .connection = null,
            .keepalive = true,
            .max_idle_ms = 30000,
            .last_used = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.connection) |conn| {
            conn.close();
            self.connection = null;
        }
        if (self.tls_backend) |backend| {
            backend.deinit();
            self.tls_backend = null;
        }
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = .dot,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    /// Ensure we have an active TLS connection
    fn ensureConnection(self: *Self, timeout_ms: u32) !void {
        // Check if existing connection is still valid
        if (self.connection) |conn| {
            if (conn.isOpen()) {
                // Check idle timeout
                const now = std.time.milliTimestamp();
                if (now - self.last_used < self.max_idle_ms) {
                    return; // Connection still good
                }
            }
            // Close stale connection
            conn.close();
            self.connection = null;
        }

        // Need a TLS backend to establish connection
        const backend = self.tls_backend orelse return error.NoTlsBackend;

        // Establish new connection
        self.connection = try backend.connect(.{
            .server_name = self.options.server_name,
            .host = self.options.addr.host,
            .port = self.options.addr.port,
            .ca_pem = if (self.options.ca_pem.len > 0) self.options.ca_pem else null,
            .alpn = self.options.alpn_dot,
            .tls_version = .tls_1_3,
            .timeout_ms = timeout_ms,
            .use_system_ca = self.options.use_system_ca,
        });

        // Verify ALPN was negotiated correctly
        if (self.connection) |conn| {
            if (conn.getAlpn()) |alpn| {
                if (!std.mem.eql(u8, alpn, alpn_dot)) {
                    conn.close();
                    self.connection = null;
                    return error.AlpnNegotiationFailed;
                }
            }
        }

        self.last_used = std.time.milliTimestamp();
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        // Ensure we have a connection
        try self.ensureConnection(timeout_ms);

        const conn = self.connection orelse return error.NoConnection;

        // RFC 7858: Use same framing as TCP (2-byte length prefix)
        // SECURITY (SEC-SCAN-04): Bounds check before @intCast to u16 (CWE-681)
        if (wire_req.len > std.math.maxInt(u16)) return error.MessageTooLong;
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(wire_req.len), .big);

        // Write length prefix + message (writeAll loop to handle partial writes)
        try tlsWriteAll(conn, &length_prefix);
        try tlsWriteAll(conn, wire_req);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        var len_read: usize = 0;
        while (len_read < 2) {
            const n = try conn.read(resp_len_buf[len_read..]);
            if (n == 0) return error.ConnectionClosed;
            len_read += n;
        }
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);

        if (resp_len > max_message_size) {
            return error.MessageTooLarge;
        }

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try conn.read(response[total_read..]);
            if (n == 0) return error.ConnectionClosed;
            total_read += n;
        }

        self.last_used = std.time.milliTimestamp();
        return response;
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (self.connection) |conn| {
            conn.close();
            self.connection = null;
        }
    }

    const vtable = Channel.VTable{
        .query = queryImpl,
        .close = closeImpl,
    };
};

/// Write all bytes through a TLS connection, looping on partial writes.
/// Prevents silent data truncation when TLS write returns fewer bytes than requested.
fn tlsWriteAll(conn: TlsConnection, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = try conn.write(data[sent..]);
        if (n == 0) return error.ConnectionClosed;
        sent += n;
    }
}

/// Mock TLS backend for testing
pub const MockTlsBackend = struct {
    allocator: std.mem.Allocator,
    responses: std.ArrayList([]const u8),
    response_index: usize,
    alpn: []const u8,
    tls_version: TlsVersion,
    connect_should_fail: bool,
    is_connected: bool,
    /// Per-instance write buffer for mock connection (moved from mutable statics
    /// to per-instance state for thread safety -- QL-05).
    write_buffer: [65535]u8,
    write_len: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .responses = .empty,
            .response_index = 0,
            .alpn = "dot",
            .tls_version = .tls_1_3,
            .connect_should_fail = false,
            .is_connected = false,
            .write_buffer = undefined,
            .write_len = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.responses.items) |r| {
            self.allocator.free(r);
        }
        self.responses.deinit(self.allocator);
    }

    pub fn addResponse(self: *Self, response: []const u8) !void {
        const copy = try self.allocator.dupe(u8, response);
        try self.responses.append(self.allocator, copy);
    }

    pub fn setAlpn(self: *Self, alpn: []const u8) void {
        self.alpn = alpn;
    }

    pub fn setConnectFailure(self: *Self, should_fail: bool) void {
        self.connect_should_fail = should_fail;
    }

    pub fn backend(self: *Self) TlsBackend {
        return TlsBackend{
            .ctx = self,
            .vtable = &backend_vtable,
        };
    }

    fn connectImpl(ctx: *anyopaque, options: TlsConnectOptions) anyerror!TlsConnection {
        _ = options;
        const self: *Self = @ptrCast(@alignCast(ctx));

        if (self.connect_should_fail) {
            return error.TlsHandshakeFailed;
        }

        self.is_connected = true;

        return TlsConnection{
            .ctx = self,
            .vtable = &connection_vtable,
        };
    }

    fn deinitImpl(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.is_connected = false;
    }

    const backend_vtable = TlsBackend.VTable{
        .connect = connectImpl,
        .deinit = deinitImpl,
    };

    // Mock connection vtable -- write_buffer and write_len are per-instance
    // fields (see struct definition above) rather than mutable statics.

    fn writeImpl(ctx: *anyopaque, data: []const u8) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (self.write_len + data.len > self.write_buffer.len) {
            return error.BufferOverflow;
        }
        @memcpy(self.write_buffer[self.write_len..][0..data.len], data);
        self.write_len += data.len;
        return data.len;
    }

    fn readImpl(ctx: *anyopaque, buffer: []u8) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ctx));

        if (self.response_index >= self.responses.items.len) {
            return error.NoMoreResponses;
        }

        // First call returns length prefix, second call returns data
        const response = self.responses.items[self.response_index];

        // Check if we need to send length prefix
        if (buffer.len >= 2 and self.write_len > 0) {
            // Reset write buffer for next query
            self.write_len = 0;

            // Send length prefix
            var len_buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_buf, @intCast(response.len), .big);
            @memcpy(buffer[0..2], &len_buf);
            return 2;
        }

        // Send actual response
        const to_copy = @min(buffer.len, response.len);
        @memcpy(buffer[0..to_copy], response[0..to_copy]);
        self.response_index += 1;
        return to_copy;
    }

    fn closeConnectionImpl(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.is_connected = false;
    }

    fn isOpenImpl(ctx: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.is_connected;
    }

    fn getAlpnImpl(ctx: *anyopaque) ?[]const u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.alpn;
    }

    fn getTlsVersionImpl(ctx: *anyopaque) TlsVersion {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.tls_version;
    }

    const connection_vtable = TlsConnection.VTable{
        .write = writeImpl,
        .read = readImpl,
        .close = closeConnectionImpl,
        .isOpen = isOpenImpl,
        .getAlpn = getAlpnImpl,
        .getTlsVersion = getTlsVersionImpl,
    };
};

/// Mock DoT for simpler testing (pre-existing compatibility)
pub const MockDoT = struct {
    allocator: std.mem.Allocator,
    options: DoTOptions,
    handshake_info: HandshakeInfo,
    responses: std.ArrayList([]const u8),
    response_index: usize,

    pub const HandshakeInfo = struct {
        alpn: []const u8,
        sni: []const u8,
        tls_version: []const u8,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: DoTOptions) Self {
        return Self{
            .allocator = allocator,
            .options = options,
            .handshake_info = .{
                .alpn = options.alpn_dot,
                .sni = options.server_name,
                .tls_version = "1.3",
            },
            .responses = .empty,
            .response_index = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.responses.items) |r| {
            self.allocator.free(r);
        }
        self.responses.deinit(self.allocator);
    }

    pub fn addResponse(self: *Self, response: []const u8) !void {
        const copy = try self.allocator.dupe(u8, response);
        try self.responses.append(self.allocator, copy);
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = .dot,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    /// Get handshake info as JSON
    pub fn handshakeInfoJson(self: *Self) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"alpn":["{s}"],"sni":"{s}","tls_version":"{s}"}}
        , .{
            self.handshake_info.alpn,
            self.handshake_info.sni,
            self.handshake_info.tls_version,
        });
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        _ = wire_req;
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        if (self.response_index >= self.responses.items.len) {
            return error.Timeout;
        }

        const response = self.responses.items[self.response_index];
        self.response_index += 1;

        return try self.allocator.dupe(u8, response);
    }

    fn closeImpl(_: *anyopaque) void {}

    const vtable = Channel.VTable{
        .query = queryImpl,
        .close = closeImpl,
    };
};

test "DoTTransport ALPN validation" {
    const allocator = std.testing.allocator;

    // Valid ALPN
    _ = try DoTTransport.init(allocator, .{
        .server_name = "dns.example.com",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_dot = "dot",
    });

    // Invalid ALPN
    try std.testing.expectError(error.InvalidAlpn, DoTTransport.init(allocator, .{
        .server_name = "dns.example.com",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_dot = "wrong",
    }));
}

test "MockDoT handshake info" {
    const allocator = std.testing.allocator;

    var mock = MockDoT.init(allocator, .{
        .server_name = "dns.example",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_dot = "dot",
    });
    defer mock.deinit();

    const info = try mock.handshakeInfoJson();
    defer allocator.free(info);

    try std.testing.expect(std.mem.indexOf(u8, info, "\"alpn\":[\"dot\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, info, "\"sni\":\"dns.example\"") != null);
}

test "MockTlsBackend basic" {
    const allocator = std.testing.allocator;

    var mock = MockTlsBackend.init(allocator);
    defer mock.deinit();

    // Add test response
    const response = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    try mock.addResponse(&response);

    const backend = mock.backend();

    // Connect
    const conn = try backend.connect(.{
        .server_name = "dns.example.com",
        .host = "1.2.3.4",
        .port = 853,
    });

    try std.testing.expect(conn.isOpen());
    try std.testing.expectEqualStrings("dot", conn.getAlpn().?);
    try std.testing.expectEqual(TlsVersion.tls_1_3, conn.getTlsVersion());
}

test "TlsBackend connect failure" {
    const allocator = std.testing.allocator;

    var mock = MockTlsBackend.init(allocator);
    defer mock.deinit();

    mock.setConnectFailure(true);

    const backend = mock.backend();

    try std.testing.expectError(error.TlsHandshakeFailed, backend.connect(.{
        .server_name = "dns.example.com",
        .host = "1.2.3.4",
        .port = 853,
    }));
}

test "DoTTransport without backend" {
    const allocator = std.testing.allocator;

    var transport = try DoTTransport.init(allocator, .{
        .server_name = "dns.example.com",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_dot = "dot",
    });
    defer transport.deinit();

    // Query should fail without TLS backend
    const ch = transport.channel();
    try std.testing.expectError(error.NoTlsBackend, ch.query(&[_]u8{ 0x00, 0x01 }, 1000));
}
