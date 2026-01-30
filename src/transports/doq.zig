// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS over QUIC (DoQ) Transport
//!
//! RFC 9250: DNS over Dedicated QUIC Connections
//!
//! This module provides DoQ transport with a pluggable QUIC backend interface.
//! Since Zig's standard library doesn't include QUIC support, implementations
//! must provide their own QUIC backend (e.g., quiche, ngtcp2, msquic).

const std = @import("std");
const builtin = @import("builtin");
const channel = @import("channel");

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;
pub const DoQOptions = channel.DoQOptions;

// Feature gate
const build_options = @import("build_options");
const feature_doq = if (@hasDecl(build_options, "feature_doq")) build_options.feature_doq else false;

/// QUIC Backend Interface
///
/// Implementations must provide this interface to enable DoQ transport.
/// The backend handles QUIC connection and stream management.
pub const QuicBackend = struct {
    /// Opaque context for the backend implementation
    ctx: *anyopaque,
    /// Backend function table
    vtable: *const VTable,

    pub const VTable = struct {
        /// Connect to QUIC server
        connect: *const fn (
            ctx: *anyopaque,
            host: []const u8,
            port: u16,
            alpn: []const u8,
            timeout_ms: u32,
        ) anyerror!void,

        /// Open a new bidirectional stream and send data
        /// Returns stream ID
        openStream: *const fn (
            ctx: *anyopaque,
            data: []const u8,
        ) anyerror!u64,

        /// Read from stream until FIN
        readStream: *const fn (
            ctx: *anyopaque,
            stream_id: u64,
            allocator: std.mem.Allocator,
            timeout_ms: u32,
        ) anyerror![]u8,

        /// Close stream
        closeStream: *const fn (
            ctx: *anyopaque,
            stream_id: u64,
        ) void,

        /// Close connection
        close: *const fn (ctx: *anyopaque) void,

        /// Check if connected
        isConnected: *const fn (ctx: *anyopaque) bool,
    };

    pub fn connect(
        self: QuicBackend,
        host: []const u8,
        port: u16,
        alpn: []const u8,
        timeout_ms: u32,
    ) !void {
        return self.vtable.connect(self.ctx, host, port, alpn, timeout_ms);
    }

    pub fn openStream(self: QuicBackend, data: []const u8) !u64 {
        return self.vtable.openStream(self.ctx, data);
    }

    pub fn readStream(
        self: QuicBackend,
        stream_id: u64,
        allocator: std.mem.Allocator,
        timeout_ms: u32,
    ) ![]u8 {
        return self.vtable.readStream(self.ctx, stream_id, allocator, timeout_ms);
    }

    pub fn closeStream(self: QuicBackend, stream_id: u64) void {
        self.vtable.closeStream(self.ctx, stream_id);
    }

    pub fn close(self: QuicBackend) void {
        self.vtable.close(self.ctx);
    }

    pub fn isConnected(self: QuicBackend) bool {
        return self.vtable.isConnected(self.ctx);
    }
};

/// DoQ Transport with pluggable QUIC backend
///
/// RFC 9250 Requirements:
/// - ALPN: "doq" (MUST)
/// - UDP port 853 (default)
/// - One query per bidirectional stream
/// - 2-octet length prefix on each message
/// - Message ID MUST be 0
///
/// Usage:
/// ```zig
/// var quic_backend = MyQuicBackend.init(...);
/// var doq = try DoQTransport.init(allocator, options, quic_backend.backend());
/// defer doq.deinit();
///
/// var ch = doq.channel();
/// const response = try ch.query(wire_request, 5000);
/// ```
pub const DoQTransport = struct {
    allocator: std.mem.Allocator,
    options: DoQOptions,
    quic_backend: ?QuicBackend,
    connected: bool,

    const Self = @This();

    /// ALPN protocol identifier for DoQ (RFC 9250)
    pub const alpn_doq = "doq";
    /// Default DoQ port
    pub const default_port: u16 = 853;
    /// Maximum message size
    pub const max_message_size: usize = 65535;

    pub fn init(allocator: std.mem.Allocator, options: DoQOptions, quic_backend: ?QuicBackend) !Self {
        if (!feature_doq and quic_backend != null) {
            return error.FeatureDisabled;
        }

        // Validate ALPN
        if (!std.mem.eql(u8, options.alpn_doq, alpn_doq)) {
            return error.InvalidAlpn;
        }

        return Self{
            .allocator = allocator,
            .options = options,
            .quic_backend = quic_backend,
            .connected = false,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.quic_backend) |backend| {
            backend.close();
        }
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = .doq,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const backend = self.quic_backend orelse return error.NoQuicBackend;

        // Ensure connected
        if (!self.connected) {
            try backend.connect(
                self.options.server_name,
                self.options.addr.port,
                self.options.alpn_doq,
                timeout_ms,
            );
            self.connected = true;
        }

        // Prepare DoQ message: 2-byte length prefix + DNS message with ID=0
        const doq_msg = try prepareDoQMessage(self.allocator, wire_req);
        defer self.allocator.free(doq_msg);

        // Open stream and send
        const stream_id = try backend.openStream(doq_msg);
        defer backend.closeStream(stream_id);

        // Read response
        const response_with_prefix = try backend.readStream(stream_id, self.allocator, timeout_ms);
        defer self.allocator.free(response_with_prefix);

        // Strip 2-byte length prefix
        if (response_with_prefix.len < 2) {
            return error.InvalidResponse;
        }

        const msg_len = std.mem.readInt(u16, response_with_prefix[0..2], .big);
        if (msg_len == 0) {
            return error.InvalidResponse;
        }
        if (msg_len > max_message_size or response_with_prefix.len > max_message_size + 2) {
            return error.MessageTooLarge;
        }
        if (msg_len + 2 > response_with_prefix.len) {
            return error.InvalidResponse;
        }

        return try self.allocator.dupe(u8, response_with_prefix[2..][0..msg_len]);
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.deinit();
    }

    const vtable = Channel.VTable{
        .query = queryImpl,
        .close = closeImpl,
    };
};

/// Prepare DoQ wire message (set ID=0, add length prefix)
/// Per RFC 9250: Message ID MUST be 0, 2-byte length prefix
pub fn prepareDoQMessage(allocator: std.mem.Allocator, wire_req: []const u8) ![]u8 {
    if (wire_req.len < 2) {
        return error.InvalidMessage;
    }
    if (wire_req.len > DoQTransport.max_message_size) {
        return error.MessageTooLarge;
    }

    const result = try allocator.alloc(u8, 2 + wire_req.len);
    errdefer allocator.free(result);

    // 2-byte length prefix
    std.mem.writeInt(u16, result[0..2], @intCast(wire_req.len), .big);

    // Copy message with ID=0
    @memcpy(result[2..], wire_req);
    result[2] = 0;
    result[3] = 0;

    return result;
}

/// Parse DoQ response (strip length prefix, verify ID=0)
pub fn parseDoQResponse(data: []const u8) ![]const u8 {
    if (data.len < 4) {
        return error.InvalidResponse;
    }

    const msg_len = std.mem.readInt(u16, data[0..2], .big);
    if (msg_len == 0) {
        return error.InvalidResponse;
    }
    if (msg_len > DoQTransport.max_message_size or data.len > DoQTransport.max_message_size + 2) {
        return error.MessageTooLarge;
    }
    if (msg_len + 2 > data.len) {
        return error.InvalidResponse;
    }

    // Verify ID is 0 (RFC 9250)
    if (data[2] != 0 or data[3] != 0) {
        return error.InvalidMessageId;
    }

    return data[2..][0..msg_len];
}

/// Mock QUIC Backend for testing
pub const MockQuicBackend = struct {
    allocator: std.mem.Allocator,
    connected: bool,
    streams: std.AutoHashMap(u64, StreamData),
    next_stream_id: u64,
    responses: std.ArrayList([]const u8),
    response_index: usize,
    connection_info: ConnectionInfo,

    pub const StreamData = struct {
        data_sent: []const u8,
        response: ?[]const u8,
    };

    pub const ConnectionInfo = struct {
        host: []const u8,
        port: u16,
        alpn: []const u8,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .connected = false,
            .streams = std.AutoHashMap(u64, StreamData).init(allocator),
            .next_stream_id = 0,
            .responses = .empty,
            .response_index = 0,
            .connection_info = .{ .host = "", .port = 0, .alpn = "" },
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.data_sent);
            if (entry.value_ptr.response) |r| {
                self.allocator.free(r);
            }
        }
        self.streams.deinit();

        for (self.responses.items) |r| {
            self.allocator.free(r);
        }
        self.responses.deinit(self.allocator);
    }

    pub fn addResponse(self: *Self, response: []const u8) !void {
        const copy = try self.allocator.dupe(u8, response);
        try self.responses.append(self.allocator, copy);
    }

    pub fn backend(self: *Self) QuicBackend {
        return QuicBackend{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    /// Get last stream data for verification
    pub fn getLastStreamData(self: *Self) ?[]const u8 {
        if (self.next_stream_id == 0) return null;
        const entry = self.streams.get(self.next_stream_id - 4) orelse return null;
        return entry.data_sent;
    }

    fn connectImpl(ctx: *anyopaque, host: []const u8, port: u16, alpn: []const u8, timeout_ms: u32) anyerror!void {
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        self.connection_info = .{
            .host = host,
            .port = port,
            .alpn = alpn,
        };
        self.connected = true;
    }

    fn openStreamImpl(ctx: *anyopaque, data: []const u8) anyerror!u64 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        if (!self.connected) {
            return error.NotConnected;
        }

        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // QUIC bidirectional streams increment by 4

        const data_copy = try self.allocator.dupe(u8, data);
        try self.streams.put(stream_id, .{
            .data_sent = data_copy,
            .response = null,
        });

        return stream_id;
    }

    fn readStreamImpl(ctx: *anyopaque, stream_id: u64, allocator: std.mem.Allocator, timeout_ms: u32) anyerror![]u8 {
        _ = stream_id;
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        if (self.response_index >= self.responses.items.len) {
            return error.Timeout;
        }

        const response = self.responses.items[self.response_index];
        self.response_index += 1;

        // Add 2-byte length prefix to response
        const result = try allocator.alloc(u8, 2 + response.len);
        std.mem.writeInt(u16, result[0..2], @intCast(response.len), .big);
        @memcpy(result[2..], response);

        return result;
    }

    fn closeStreamImpl(_: *anyopaque, _: u64) void {}

    fn closeImpl(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.connected = false;
    }

    fn isConnectedImpl(ctx: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.connected;
    }

    const vtable = QuicBackend.VTable{
        .connect = connectImpl,
        .openStream = openStreamImpl,
        .readStream = readStreamImpl,
        .closeStream = closeStreamImpl,
        .close = closeImpl,
        .isConnected = isConnectedImpl,
    };
};

/// Legacy MockDoQ for backward compatibility
pub const MockDoQ = struct {
    allocator: std.mem.Allocator,
    options: DoQOptions,
    quic_mock: MockQuicBackend,
    handshake_info: HandshakeInfo,
    responses: std.ArrayList([]const u8),
    response_index: usize,
    stream_frames: std.ArrayList([]const u8),

    pub const HandshakeInfo = struct {
        alpn: []const u8,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: DoQOptions) Self {
        return Self{
            .allocator = allocator,
            .options = options,
            .quic_mock = MockQuicBackend.init(allocator),
            .handshake_info = .{ .alpn = options.alpn_doq },
            .responses = .empty,
            .response_index = 0,
            .stream_frames = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.quic_mock.deinit();

        for (self.responses.items) |r| {
            self.allocator.free(r);
        }
        self.responses.deinit(self.allocator);

        for (self.stream_frames.items) |f| {
            self.allocator.free(f);
        }
        self.stream_frames.deinit(self.allocator);
    }

    pub fn addResponse(self: *Self, response: []const u8) !void {
        const copy = try self.allocator.dupe(u8, response);
        try self.responses.append(self.allocator, copy);
        try self.quic_mock.addResponse(response);
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = .doq,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    /// Get handshake info
    pub fn handshakeInfoJson(self: *Self) ![]u8 {
        return std.fmt.allocPrint(self.allocator,
            \\{{"alpn":["{s}"]}}
        , .{self.handshake_info.alpn});
    }

    /// Verify stream frame has correct format
    pub fn verifyLastStreamFrame(self: *Self) !bool {
        if (self.stream_frames.items.len == 0) return false;

        const frame = self.stream_frames.items[self.stream_frames.items.len - 1];
        if (frame.len < 4) return false;

        // Check 2-byte length prefix
        const length = std.mem.readInt(u16, frame[0..2], .big);
        if (length + 2 != frame.len) return false;

        // Check Message ID = 0
        if (frame[2] != 0 or frame[3] != 0) return false;

        return true;
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        // Record the stream frame
        const doq_msg = try prepareDoQMessage(self.allocator, wire_req);
        try self.stream_frames.append(self.allocator, doq_msg);

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

// =========================================================================
// Tests
// =========================================================================

test "DoQTransport feature gate" {
    const allocator = std.testing.allocator;

    if (!feature_doq) {
        var mock = MockQuicBackend.init(allocator);
        defer mock.deinit();

        try std.testing.expectError(error.FeatureDisabled, DoQTransport.init(allocator, .{
            .server_name = "dns.example.com",
            .addr = .{ .host = "1.2.3.4", .port = 853 },
            .ca_pem = "",
            .alpn_doq = "doq",
        }, mock.backend()));
    }
}

test "DoQTransport invalid ALPN" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidAlpn, DoQTransport.init(allocator, .{
        .server_name = "dns.example.com",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_doq = "wrong",
    }, null));
}

test "prepareDoQMessage" {
    const allocator = std.testing.allocator;

    const wire = [_]u8{ 0x12, 0x34, 0x01, 0x00 }; // ID=0x1234
    const doq_msg = try prepareDoQMessage(allocator, &wire);
    defer allocator.free(doq_msg);

    // Check length prefix
    try std.testing.expectEqual(@as(u16, 4), std.mem.readInt(u16, doq_msg[0..2], .big));

    // Check ID is zeroed
    try std.testing.expectEqual(@as(u8, 0), doq_msg[2]);
    try std.testing.expectEqual(@as(u8, 0), doq_msg[3]);
}

test "prepareDoQMessage rejects short input" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidMessage, prepareDoQMessage(allocator, &[_]u8{0x01}));
}

test "prepareDoQMessage rejects oversized input" {
    const allocator = std.testing.allocator;
    const oversized = try allocator.alloc(u8, DoQTransport.max_message_size + 1);
    defer allocator.free(oversized);
    @memset(oversized, 0xAA);
    try std.testing.expectError(error.MessageTooLarge, prepareDoQMessage(allocator, oversized));
}

test "parseDoQResponse" {
    // Valid response with ID=0
    const data = [_]u8{ 0x00, 0x04, 0x00, 0x00, 0x81, 0x80 };
    const parsed = try parseDoQResponse(&data);
    try std.testing.expectEqual(@as(usize, 4), parsed.len);
    try std.testing.expectEqual(@as(u8, 0), parsed[0]);
    try std.testing.expectEqual(@as(u8, 0), parsed[1]);
}

test "parseDoQResponse invalid ID" {
    // Response with non-zero ID
    const data = [_]u8{ 0x00, 0x04, 0x12, 0x34, 0x81, 0x80 };
    try std.testing.expectError(error.InvalidMessageId, parseDoQResponse(&data));
}

test "parseDoQResponse rejects oversized response" {
    const allocator = std.testing.allocator;
    const oversized = try allocator.alloc(u8, DoQTransport.max_message_size + 3);
    defer allocator.free(oversized);
    @memset(oversized, 0);
    std.mem.writeInt(u16, oversized[0..2], @intCast(DoQTransport.max_message_size + 1), .big);
    oversized[2] = 0;
    oversized[3] = 0;
    try std.testing.expectError(error.MessageTooLarge, parseDoQResponse(oversized));
}

test "MockQuicBackend basic" {
    const allocator = std.testing.allocator;

    var mock = MockQuicBackend.init(allocator);
    defer mock.deinit();

    const dns_response = [_]u8{ 0x00, 0x00, 0x81, 0x80 };
    try mock.addResponse(&dns_response);

    const backend = mock.backend();

    // Connect
    try backend.connect("dns.example.com", 853, "doq", 5000);
    try std.testing.expect(backend.isConnected());

    // Open stream
    const stream_id = try backend.openStream("test data");
    try std.testing.expectEqual(@as(u64, 0), stream_id);

    // Read response
    const response = try backend.readStream(stream_id, allocator, 1000);
    defer allocator.free(response);

    // Verify length prefix was added
    try std.testing.expectEqual(@as(u16, 4), std.mem.readInt(u16, response[0..2], .big));

    // Close
    backend.closeStream(stream_id);
    backend.close();
    try std.testing.expect(!backend.isConnected());
}

test "MockDoQ stream frame verification" {
    const allocator = std.testing.allocator;

    var mock = MockDoQ.init(allocator, .{
        .server_name = "dns.example.com",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_doq = "doq",
    });
    defer mock.deinit();

    try mock.addResponse(&[_]u8{ 0, 0, 0x81, 0x80 });

    const ch = mock.channel();
    const resp = ch.query(&[_]u8{ 0x12, 0x34, 0x01, 0x00 }, 1000) catch return;
    defer allocator.free(resp);

    try std.testing.expect(try mock.verifyLastStreamFrame());
}
