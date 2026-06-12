// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS over HTTPS (DoH) Transport
//!
//! RFC 8484: DNS Queries over HTTPS (DoH)
//!
//! This module provides DoH transport with a pluggable HTTP backend interface.
//! Since Zig's standard library doesn't include HTTP/2 support, implementations
//! must provide their own HTTP backend (e.g., curl, nghttp2, or custom HTTP/2).
//!
//! ## Security Requirements for HTTP Backends (SEC-011)
//!
//! Implementers of `HttpBackend` MUST ensure the following security properties:
//!
//! ### TLS Requirements
//! - **Minimum TLS Version**: TLS 1.2 required, TLS 1.3 strongly recommended
//! - **Certificate Validation**: MUST validate server certificates against trusted CAs
//! - **Hostname Verification**: MUST verify server hostname matches certificate
//! - **Certificate Pinning**: RECOMMENDED for high-security deployments
//!
//! ### Cipher Suite Requirements
//! - MUST support AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)
//! - SHOULD disable weak/legacy ciphers (RC4, 3DES, MD5-based MACs)
//! - RECOMMENDED cipher suites:
//!   - TLS_AES_256_GCM_SHA384 (TLS 1.3)
//!   - TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
//!   - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
//!
//! ### HTTP/2 Security
//! - MUST implement HTTP/2 per RFC 7540
//! - SHOULD implement HSTS validation
//! - MUST NOT follow redirects to non-HTTPS URLs
//!
//! ### Example Backend Configuration (curl)
//! ```c
//! curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
//! curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
//! curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
//! curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
//! ```
//!
//! ### Security Validation
//! Backend implementations should validate:
//! - Certificate chain up to trusted root
//! - Certificate revocation (OCSP/CRL when available)
//! - Certificate expiration dates
//! - Subject Alternative Name (SAN) matches
//!
//! **WARNING**: Backends that disable certificate validation or use
//! insecure TLS configurations will compromise the security benefits
//! of DoH and may enable man-in-the-middle attacks.

const std = @import("std");
const channel = @import("channel");

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;
pub const DoHOptions = channel.DoHOptions;

/// HTTP Backend Interface
///
/// Implementations must provide this interface to enable DoH transport.
/// The backend handles HTTP/2 communication with the DoH server.
pub const HttpBackend = struct {
    /// Opaque context for the backend implementation
    ctx: *anyopaque,
    /// Backend function table
    vtable: *const VTable,

    pub const VTable = struct {
        /// Perform HTTP GET request
        /// Returns response body or error
        get: *const fn (
            ctx: *anyopaque,
            url: []const u8,
            headers: []const Header,
            timeout_ms: u32,
            tls: TlsConfig,
        ) anyerror!Response,

        /// Perform HTTP POST request
        /// Returns response body or error
        post: *const fn (
            ctx: *anyopaque,
            url: []const u8,
            headers: []const Header,
            body: []const u8,
            timeout_ms: u32,
            tls: TlsConfig,
        ) anyerror!Response,

        /// Close/cleanup the backend
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };

    pub const TlsConfig = struct {
        ca_pem: []const u8,
        bootstrap_ip: ?channel.SocketAddress,
        /// Hostname the server certificate must be verified against (SNI +
        /// cert validation). Derived from the request URL authority. Without
        /// this an IP-bootstrapped backend has no name to verify against and
        /// could accept any cert for the dialed IP — MITM (A4, #293).
        server_name: []const u8 = "",
    };

    pub const Response = struct {
        status_code: u16,
        body: []u8,
        allocator: std.mem.Allocator,
        /// Content-Type header value (SEC-GAP-056: CWE-319)
        content_type: ?[]const u8 = null,

        pub fn deinit(self: *Response) void {
            self.allocator.free(self.body);
        }
    };

    pub fn get(
        self: HttpBackend,
        url: []const u8,
        headers: []const Header,
        timeout_ms: u32,
        tls: TlsConfig,
    ) !Response {
        return self.vtable.get(self.ctx, url, headers, timeout_ms, tls);
    }

    pub fn post(
        self: HttpBackend,
        url: []const u8,
        headers: []const Header,
        body: []const u8,
        timeout_ms: u32,
        tls: TlsConfig,
    ) !Response {
        return self.vtable.post(self.ctx, url, headers, body, timeout_ms, tls);
    }

    pub fn deinit(self: HttpBackend) void {
        self.vtable.deinit(self.ctx);
    }
};

/// DoH Transport with pluggable HTTP backend
///
/// Usage:
/// ```zig
/// var http_backend = MyHttpBackend.init(...);
/// var doh = try DoHTransport.init(allocator, options, http_backend.backend());
/// defer doh.deinit();
///
/// var ch = doh.channel();
/// const response = try ch.query(wire_request, 5000);
/// ```
pub const DoHTransport = struct {
    allocator: std.mem.Allocator,
    options: DoHOptions,
    http_backend: ?HttpBackend,

    const Self = @This();

    /// Media type for DNS wire format (RFC 8484)
    pub const media_type = "application/dns-message";
    /// Default DoH port
    pub const default_port: u16 = 443;
    /// Maximum response size (RFC 8484 recommends at least 64KB)
    pub const max_response_size: usize = 65535;

    /// Initialize DoH transport with HTTP backend
    pub fn init(allocator: std.mem.Allocator, options: DoHOptions, http_backend: ?HttpBackend) !Self {
        // Validate HTTPS scheme (SEC-GAP-056: CWE-319)
        if (!std.mem.startsWith(u8, options.uri, "https://")) {
            return error.HttpsRequired;
        }

        // Fail closed if no CA trust is configured, mirroring DoT (A6, #295).
        if (options.ca_pem.len == 0 and !options.use_system_ca) {
            return error.NoCaTrustConfigured;
        }

        return Self{
            .allocator = allocator,
            .options = options,
            .http_backend = http_backend,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.http_backend) |backend| {
            backend.deinit();
        }
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = .doh,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const backend = self.http_backend orelse return error.NoHttpBackend;

        const tls = HttpBackend.TlsConfig{
            .ca_pem = self.options.ca_pem,
            .bootstrap_ip = self.options.bootstrap_ip,
            .server_name = uriHost(self.options.uri),
        };

        // Build URL and headers
        const headers = [_]HttpBackend.Header{
            .{ .name = "Accept", .value = media_type },
            .{ .name = "Content-Type", .value = media_type },
        };

        if (self.options.prefer_get) {
            // GET method: encode as base64url in query parameter
            const encoded = try base64urlEncode(self.allocator, wire_req);
            defer self.allocator.free(encoded);

            // Build URL with query parameter
            const url = try std.fmt.allocPrint(
                self.allocator,
                "{s}?dns={s}",
                .{ self.options.uri, encoded },
            );
            defer self.allocator.free(url);

            var response = try backend.get(url, &headers, timeout_ms, tls);
            defer response.deinit();

            if (response.status_code != 200) {
                return error.HttpError;
            }

            // Validate Content-Type (SEC-GAP-056: CWE-319; A12, #301).
            // RFC 8484 mandates application/dns-message; a missing header must
            // be rejected, not silently accepted.
            const ct = response.content_type orelse return error.InvalidContentType;
            if (!std.mem.eql(u8, ct, media_type)) {
                return error.InvalidContentType;
            }

            if (response.body.len > max_response_size) {
                return error.MessageTooLarge;
            }

            return try self.allocator.dupe(u8, response.body);
        } else {
            // POST method: send wire format in body
            var response = try backend.post(self.options.uri, &headers, wire_req, timeout_ms, tls);
            defer response.deinit();

            if (response.status_code != 200) {
                return error.HttpError;
            }

            // Validate Content-Type (SEC-GAP-056: CWE-319; A12, #301).
            // RFC 8484 mandates application/dns-message; a missing header must
            // be rejected, not silently accepted.
            const ct = response.content_type orelse return error.InvalidContentType;
            if (!std.mem.eql(u8, ct, media_type)) {
                return error.InvalidContentType;
            }

            if (response.body.len > max_response_size) {
                return error.MessageTooLarge;
            }

            return try self.allocator.dupe(u8, response.body);
        }
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

/// Extract the host (authority without userinfo or port) from an http(s) URL,
/// for use as the TLS verification name (A4, #293). Returns the whole input if
/// it has no scheme separator.
pub fn uriHost(uri: []const u8) []const u8 {
    const after_scheme = if (std.mem.indexOf(u8, uri, "://")) |i| uri[i + 3 ..] else uri;
    // Authority ends at the first '/', '?' or '#'.
    var authority = after_scheme;
    for (after_scheme, 0..) |c, i| {
        if (c == '/' or c == '?' or c == '#') {
            authority = after_scheme[0..i];
            break;
        }
    }
    // Strip userinfo ("user@host").
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
        authority = authority[at + 1 ..];
    }
    // Strip the port. For a bracketed IPv6 literal the host is "[...]" and the
    // port (if any) follows the ']'; otherwise the port follows the last ':'.
    if (authority.len > 0 and authority[0] == '[') {
        if (std.mem.indexOfScalar(u8, authority, ']')) |close| {
            authority = authority[0 .. close + 1];
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        authority = authority[0..colon];
    }
    return authority;
}

/// Base64url encoding for DoH GET requests (RFC 4648, no padding)
pub fn base64urlEncode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    // Exact unpadded base64url length. The previous formula over-allocated
    // (padded length), and the function returns a sub-slice of exactly the
    // encoded length — so freeing the returned slice freed fewer bytes than
    // were allocated, a free-size mismatch on the DoH GET path. Sizing the
    // allocation to the returned length keeps allocate/free symmetric.
    const output_len = (data.len * 4 + 2) / 3;
    var output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    var out_idx: usize = 0;
    var i: usize = 0;

    while (i + 3 <= data.len) : (i += 3) {
        const b0 = data[i];
        const b1 = data[i + 1];
        const b2 = data[i + 2];

        output[out_idx] = alphabet[b0 >> 2];
        output[out_idx + 1] = alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        output[out_idx + 2] = alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
        output[out_idx + 3] = alphabet[b2 & 0x3F];
        out_idx += 4;
    }

    const remaining = data.len - i;
    if (remaining == 1) {
        const b0 = data[i];
        output[out_idx] = alphabet[b0 >> 2];
        output[out_idx + 1] = alphabet[(b0 & 0x03) << 4];
        return output[0 .. out_idx + 2]; // No padding
    } else if (remaining == 2) {
        const b0 = data[i];
        const b1 = data[i + 1];
        output[out_idx] = alphabet[b0 >> 2];
        output[out_idx + 1] = alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        output[out_idx + 2] = alphabet[(b1 & 0x0F) << 2];
        return output[0 .. out_idx + 3]; // No padding
    }

    return output[0..out_idx];
}

/// Base64url decoding for DoH responses
pub fn base64urlDecode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    if (data.len == 0) return try allocator.alloc(u8, 0);

    // Calculate output length (accounting for no padding)
    const output_len = (data.len * 3) / 4;
    var output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);

    const decode_table = comptime blk: {
        var table: [256]u8 = [_]u8{0xFF} ** 256;
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for (alphabet, 0..) |c, i| {
            table[c] = @intCast(i);
        }
        break :blk table;
    };

    var out_idx: usize = 0;
    var i: usize = 0;

    while (i + 4 <= data.len) : (i += 4) {
        const v0 = decode_table[data[i]];
        const v1 = decode_table[data[i + 1]];
        const v2 = decode_table[data[i + 2]];
        const v3 = decode_table[data[i + 3]];

        if (v0 == 0xFF or v1 == 0xFF or v2 == 0xFF or v3 == 0xFF) {
            return error.InvalidBase64;
        }

        output[out_idx] = (v0 << 2) | (v1 >> 4);
        output[out_idx + 1] = (v1 << 4) | (v2 >> 2);
        output[out_idx + 2] = (v2 << 6) | v3;
        out_idx += 3;
    }

    // Handle remaining bytes (no padding in base64url)
    const remaining = data.len - i;
    if (remaining == 2) {
        const v0 = decode_table[data[i]];
        const v1 = decode_table[data[i + 1]];
        if (v0 == 0xFF or v1 == 0xFF) return error.InvalidBase64;
        output[out_idx] = (v0 << 2) | (v1 >> 4);
        return output[0 .. out_idx + 1];
    } else if (remaining == 3) {
        const v0 = decode_table[data[i]];
        const v1 = decode_table[data[i + 1]];
        const v2 = decode_table[data[i + 2]];
        if (v0 == 0xFF or v1 == 0xFF or v2 == 0xFF) return error.InvalidBase64;
        output[out_idx] = (v0 << 2) | (v1 >> 4);
        output[out_idx + 1] = (v1 << 4) | (v2 >> 2);
        return output[0 .. out_idx + 2];
    }

    return output[0..out_idx];
}

/// Mock HTTP Backend for testing
pub const MockHttpBackend = struct {
    allocator: std.mem.Allocator,
    responses: std.ArrayList(MockResponse),
    response_index: usize,
    requests: std.ArrayList(RequestRecord),

    pub const MockResponse = struct {
        status_code: u16,
        body: []const u8,
        /// Defaults to the RFC 8484 media type so the common case passes the
        /// Content-Type check; set null to exercise the missing-header path.
        content_type: ?[]const u8 = DoHTransport.media_type,
    };

    pub const RequestRecord = struct {
        method: []const u8,
        url: []const u8,
        body: []const u8,
        ca_pem: []const u8,
        bootstrap_ip: ?channel.SocketAddress,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .responses = .empty,
            .response_index = 0,
            .requests = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.responses.items) |r| {
            self.allocator.free(r.body);
        }
        self.responses.deinit(self.allocator);

        for (self.requests.items) |r| {
            self.allocator.free(r.method);
            self.allocator.free(r.url);
            self.allocator.free(r.body);
            self.allocator.free(r.ca_pem);
            if (r.bootstrap_ip) |addr| {
                self.allocator.free(addr.host);
            }
        }
        self.requests.deinit(self.allocator);
    }

    pub fn addResponse(self: *Self, status_code: u16, body: []const u8) !void {
        const body_copy = try self.allocator.dupe(u8, body);
        try self.responses.append(self.allocator, .{
            .status_code = status_code,
            .body = body_copy,
        });
    }

    /// Queue a response with an explicit Content-Type (null = header absent).
    pub fn addResponseWithContentType(self: *Self, status_code: u16, body: []const u8, content_type: ?[]const u8) !void {
        const body_copy = try self.allocator.dupe(u8, body);
        try self.responses.append(self.allocator, .{
            .status_code = status_code,
            .body = body_copy,
            .content_type = content_type,
        });
    }

    pub fn backend(self: *Self) HttpBackend {
        return HttpBackend{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn getImpl(
        ctx: *anyopaque,
        url: []const u8,
        headers: []const HttpBackend.Header,
        timeout_ms: u32,
        tls: HttpBackend.TlsConfig,
    ) anyerror!HttpBackend.Response {
        _ = headers;
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const ca_copy = try self.allocator.dupe(u8, tls.ca_pem);
        errdefer self.allocator.free(ca_copy);
        const bootstrap_copy = if (tls.bootstrap_ip) |addr|
            channel.SocketAddress{
                .host = try self.allocator.dupe(u8, addr.host),
                .port = addr.port,
            }
        else
            null;
        errdefer if (bootstrap_copy) |addr| self.allocator.free(addr.host);

        // Record request
        try self.requests.append(self.allocator, .{
            .method = try self.allocator.dupe(u8, "GET"),
            .url = try self.allocator.dupe(u8, url),
            .body = try self.allocator.dupe(u8, ""),
            .ca_pem = ca_copy,
            .bootstrap_ip = bootstrap_copy,
        });

        if (self.response_index >= self.responses.items.len) {
            return error.Timeout;
        }

        const resp = self.responses.items[self.response_index];
        self.response_index += 1;

        return HttpBackend.Response{
            .status_code = resp.status_code,
            .body = try self.allocator.dupe(u8, resp.body),
            .allocator = self.allocator,
            .content_type = resp.content_type,
        };
    }

    fn postImpl(
        ctx: *anyopaque,
        url: []const u8,
        headers: []const HttpBackend.Header,
        body: []const u8,
        timeout_ms: u32,
        tls: HttpBackend.TlsConfig,
    ) anyerror!HttpBackend.Response {
        _ = headers;
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const ca_copy = try self.allocator.dupe(u8, tls.ca_pem);
        errdefer self.allocator.free(ca_copy);
        const bootstrap_copy = if (tls.bootstrap_ip) |addr|
            channel.SocketAddress{
                .host = try self.allocator.dupe(u8, addr.host),
                .port = addr.port,
            }
        else
            null;
        errdefer if (bootstrap_copy) |addr| self.allocator.free(addr.host);

        // Record request
        try self.requests.append(self.allocator, .{
            .method = try self.allocator.dupe(u8, "POST"),
            .url = try self.allocator.dupe(u8, url),
            .body = try self.allocator.dupe(u8, body),
            .ca_pem = ca_copy,
            .bootstrap_ip = bootstrap_copy,
        });

        if (self.response_index >= self.responses.items.len) {
            return error.Timeout;
        }

        const resp = self.responses.items[self.response_index];
        self.response_index += 1;

        return HttpBackend.Response{
            .status_code = resp.status_code,
            .body = try self.allocator.dupe(u8, resp.body),
            .allocator = self.allocator,
            .content_type = resp.content_type,
        };
    }

    fn deinitImpl(_: *anyopaque) void {}

    const vtable = HttpBackend.VTable{
        .get = getImpl,
        .post = postImpl,
        .deinit = deinitImpl,
    };
};

/// Legacy MockDoH for backward compatibility
pub const MockDoH = struct {
    allocator: std.mem.Allocator,
    options: DoHOptions,
    http_mock: MockHttpBackend,
    transport: ?DoHTransport,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: DoHOptions) Self {
        return Self{
            .allocator = allocator,
            .options = options,
            .http_mock = MockHttpBackend.init(allocator),
            .transport = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.transport) |*t| {
            t.deinit();
        }
        self.http_mock.deinit();
    }

    pub fn addResponse(self: *Self, response: []const u8) !void {
        try self.http_mock.addResponse(200, response);
    }

    pub fn channel(self: *Self) Channel {
        if (self.transport == null) {
            self.transport = DoHTransport.init(
                self.allocator,
                self.options,
                self.http_mock.backend(),
            ) catch return Channel{
                .kind = .doh,
                .ctx = self,
                .vtable = &fallback_vtable,
            };
        }
        return self.transport.?.channel();
    }

    fn fallbackQuery(_: *anyopaque, _: []const u8, _: u32) anyerror![]u8 {
        return error.NotInitialized;
    }

    fn fallbackClose(_: *anyopaque) void {}

    const fallback_vtable = Channel.VTable{
        .query = fallbackQuery,
        .close = fallbackClose,
    };
};

// =========================================================================
// Tests
// =========================================================================

test "base64urlEncode" {
    const allocator = std.testing.allocator;

    // Test vector
    const input = [_]u8{ 0x00, 0x00, 0x01 };
    const encoded = try base64urlEncode(allocator, &input);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings("AAAB", encoded);
}

test "base64urlEncode longer input" {
    const allocator = std.testing.allocator;

    // "Hello, World!" in base64url (no padding)
    const input = "Hello, World!";
    const encoded = try base64urlEncode(allocator, input);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings("SGVsbG8sIFdvcmxkIQ", encoded);
}

test "base64urlDecode" {
    const allocator = std.testing.allocator;

    const encoded = "AAAB";
    const decoded = try base64urlDecode(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x01 }, decoded);
}

test "base64url round trip" {
    const allocator = std.testing.allocator;

    const original = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    const encoded = try base64urlEncode(allocator, &original);
    defer allocator.free(encoded);

    const decoded = try base64urlDecode(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, &original, decoded);
}

test "DoHTransport media type" {
    try std.testing.expectEqualStrings("application/dns-message", DoHTransport.media_type);
}

test "A6 (#295): DoH init fails closed with no CA trust configured" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NoCaTrustConfigured, DoHTransport.init(allocator, .{
        .uri = "https://dns.example.com/dns-query",
        .ca_pem = "",
    }, null));
}

test "A4 (#293): uriHost extracts the TLS verification name" {
    try std.testing.expectEqualStrings("dns.example.com", uriHost("https://dns.example.com/dns-query"));
    try std.testing.expectEqualStrings("dns.example.com", uriHost("https://dns.example.com:8443/dns-query"));
    try std.testing.expectEqualStrings("dns.example.com", uriHost("https://user@dns.example.com/dns-query"));
    try std.testing.expectEqualStrings("dns.example.com", uriHost("https://dns.example.com"));
    try std.testing.expectEqualStrings("[2001:db8::1]", uriHost("https://[2001:db8::1]:443/dns-query"));
}

test "MockHttpBackend basic" {
    const allocator = std.testing.allocator;

    var mock = MockHttpBackend.init(allocator);
    defer mock.deinit();

    try mock.addResponse(200, "test response");

    const backend = mock.backend();
    var response = try backend.get(
        "https://example.com",
        &.{},
        1000,
        .{ .ca_pem = "", .bootstrap_ip = null },
    );
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("test response", response.body);
}

test "DoHTransport with MockHttpBackend GET" {
    const allocator = std.testing.allocator;

    var http_mock = MockHttpBackend.init(allocator);
    defer http_mock.deinit();

    // Add a mock DNS response
    const dns_response = [_]u8{ 0x00, 0x01, 0x81, 0x80 };
    try http_mock.addResponse(200, &dns_response);

    var doh = try DoHTransport.init(allocator, .{
        .uri = "https://dns.example.com/dns-query",
        .ca_pem = "test-ca",
        .bootstrap_ip = .{ .host = "9.9.9.9", .port = 443 },
        .prefer_get = true,
    }, http_mock.backend());
    defer doh.deinit();

    var ch = doh.channel();
    const wire_req = [_]u8{ 0x00, 0x01, 0x01, 0x00 };
    const response = try ch.query(&wire_req, 1000);
    defer allocator.free(response);

    try std.testing.expectEqualSlices(u8, &dns_response, response);

    // Verify request was recorded
    try std.testing.expectEqual(@as(usize, 1), http_mock.requests.items.len);
    try std.testing.expectEqualStrings("GET", http_mock.requests.items[0].method);
}

test "A12 (#301): DoH rejects a response with no Content-Type" {
    const allocator = std.testing.allocator;

    var http_mock = MockHttpBackend.init(allocator);
    defer http_mock.deinit();

    const dns_response = [_]u8{ 0x00, 0x01, 0x81, 0x80 };
    try http_mock.addResponseWithContentType(200, &dns_response, null);

    var doh = try DoHTransport.init(allocator, .{
        .uri = "https://dns.example.com/dns-query",
        .ca_pem = "test-ca",
        .prefer_get = true,
    }, http_mock.backend());
    defer doh.deinit();

    var ch = doh.channel();
    const wire_req = [_]u8{ 0x00, 0x01, 0x01, 0x00 };
    // RFC 8484 mandates application/dns-message; a missing header is rejected.
    try std.testing.expectError(error.InvalidContentType, ch.query(&wire_req, 1000));
}

test "DoHTransport with MockHttpBackend POST" {
    const allocator = std.testing.allocator;

    var http_mock = MockHttpBackend.init(allocator);
    defer http_mock.deinit();

    const dns_response = [_]u8{ 0x00, 0x01, 0x81, 0x80 };
    try http_mock.addResponse(200, &dns_response);

    var doh = try DoHTransport.init(allocator, .{
        .uri = "https://dns.example.com/dns-query",
        .ca_pem = "",
        .use_system_ca = true,
        .prefer_get = false,
    }, http_mock.backend());
    defer doh.deinit();

    var ch = doh.channel();
    const wire_req = [_]u8{ 0x00, 0x01, 0x01, 0x00 };
    const response = try ch.query(&wire_req, 1000);
    defer allocator.free(response);

    try std.testing.expectEqualSlices(u8, &dns_response, response);

    // Verify POST was used
    try std.testing.expectEqual(@as(usize, 1), http_mock.requests.items.len);
    try std.testing.expectEqualStrings("POST", http_mock.requests.items[0].method);
}

test "DoHTransport response size cap" {
    const allocator = std.testing.allocator;

    var http_mock = MockHttpBackend.init(allocator);
    defer http_mock.deinit();

    const oversized = try allocator.alloc(u8, DoHTransport.max_response_size + 1);
    defer allocator.free(oversized);
    @memset(oversized, 0xAB);

    try http_mock.addResponse(200, oversized);

    var doh = try DoHTransport.init(allocator, .{
        .uri = "https://dns.example.com/dns-query",
        .ca_pem = "",
        .use_system_ca = true,
        .prefer_get = true,
    }, http_mock.backend());
    defer doh.deinit();

    var ch = doh.channel();
    const wire_req = [_]u8{ 0x00, 0x01, 0x01, 0x00 };
    try std.testing.expectError(error.MessageTooLarge, ch.query(&wire_req, 1000));
}
