// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Remote Configuration Module
//!
//! Provides integration with remote configuration stores:
//! - etcd (v3 API)
//! - HashiCorp Consul (KV store)
//!
//! Example usage:
//! ```zig
//! const remote = @import("remote");
//!
//! // Using etcd
//! var etcd = try remote.Etcd.init(allocator, .{
//!     .endpoints = &.{"http://localhost:2379"},
//! });
//! defer etcd.deinit();
//!
//! const value = try etcd.get("config/database/host");
//!
//! // Using Consul
//! var consul = try remote.Consul.init(allocator, .{
//!     .address = "http://localhost:8500",
//! });
//! defer consul.deinit();
//!
//! const kv = try consul.get("config/app/settings");
//! ```

const std = @import("std");
const mem = std.mem;
const http = std.http;
const Uri = std.Uri;
const Allocator = mem.Allocator;

/// Remote configuration errors
pub const RemoteError = error{
    ConnectionFailed,
    RequestFailed,
    KeyNotFound,
    InvalidResponse,
    Unauthorized,
    Timeout,
    OutOfMemory,
};

// ============================================================================
// etcd Client
// ============================================================================

/// etcd client options
pub const EtcdOptions = struct {
    /// etcd endpoints (e.g., "http://localhost:2379")
    endpoints: []const []const u8 = &.{"http://localhost:2379"},
    /// Request timeout in milliseconds
    timeout_ms: u32 = 5000,
    /// Username for authentication (optional)
    username: ?[]const u8 = null,
    /// Password for authentication (optional)
    password: ?[]const u8 = null,
};

/// etcd v3 API client
pub const Etcd = struct {
    allocator: Allocator,
    options: EtcdOptions,
    client: http.Client,
    /// Arena for response storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator, options: EtcdOptions) Etcd {
        return .{
            .allocator = allocator,
            .options = options,
            .client = http.Client{ .allocator = allocator },
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Etcd) void {
        self.client.deinit();
        self.arena.deinit();
    }

    /// Get a value by key from etcd
    pub fn get(self: *Etcd, key: []const u8) RemoteError!?[]const u8 {
        // etcd v3 uses gRPC-gateway REST API
        // POST /v3/kv/range with JSON body
        const endpoint = self.options.endpoints[0];
        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/range", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        // Base64 encode the key (etcd v3 requirement)
        const encoder = std.base64.standard;
        const encoded_len = encoder.calcSize(key.len);
        const encoded_key = self.allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, key);

        // Build JSON request body
        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        // Make HTTP request
        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        // Parse response
        return self.parseEtcdResponse(response);
    }

    /// Put a value by key to etcd
    pub fn put(self: *Etcd, key: []const u8, value: []const u8) RemoteError!void {
        const endpoint = self.options.endpoints[0];
        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/put", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        // Base64 encode key and value
        const encoder = std.base64.standard;

        const encoded_key_len = encoder.calcSize(key.len);
        const encoded_key = self.allocator.alloc(u8, encoded_key_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, key);

        const encoded_value_len = encoder.calcSize(value.len);
        const encoded_value = self.allocator.alloc(u8, encoded_value_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_value);
        _ = encoder.encode(encoded_value, value);

        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\",\"value\":\"{s}\"}}", .{ encoded_key, encoded_value }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);
    }

    /// Delete a key from etcd
    pub fn delete(self: *Etcd, key: []const u8) RemoteError!void {
        const endpoint = self.options.endpoints[0];
        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/deleterange", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const encoder = std.base64.standard;
        const encoded_len = encoder.calcSize(key.len);
        const encoded_key = self.allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, key);

        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\"}}", .{encoded_key}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);
    }

    /// Get all keys with a prefix
    pub fn getPrefix(self: *Etcd, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        const endpoint = self.options.endpoints[0];
        const url = std.fmt.allocPrint(self.allocator, "{s}/v3/kv/range", .{endpoint}) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const encoder = std.base64.standard;
        const encoded_len = encoder.calcSize(prefix.len);
        const encoded_key = self.allocator.alloc(u8, encoded_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_key);
        _ = encoder.encode(encoded_key, prefix);

        // Range end for prefix query (increment last byte)
        var range_end = self.allocator.dupe(u8, prefix) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(range_end);
        if (range_end.len > 0) {
            range_end[range_end.len - 1] += 1;
        }
        const encoded_end_len = encoder.calcSize(range_end.len);
        const encoded_end = self.allocator.alloc(u8, encoded_end_len) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(encoded_end);
        _ = encoder.encode(encoded_end, range_end);

        const body = std.fmt.allocPrint(self.allocator, "{{\"key\":\"{s}\",\"range_end\":\"{s}\"}}", .{ encoded_key, encoded_end }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(body);

        const response = self.makeRequest(url, body) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        return self.parseEtcdRangeResponse(response);
    }

    fn makeRequest(self: *Etcd, url: []const u8, body: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.headers.content_type = http.Client.Request.Headers.Value{ .override = "application/json" };

        request.send() catch return error.RequestFailed;
        request.writer().writeAll(body) catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        const response_body = request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
        return response_body;
    }

    fn parseEtcdResponse(self: *Etcd, response: []const u8) ?[]const u8 {
        // Simple JSON parsing for etcd response
        // Response format: {"header":{...},"kvs":[{"key":"...","value":"..."}]}
        const value_start = mem.indexOf(u8, response, "\"value\":\"") orelse return null;
        const value_content_start = value_start + 9;
        const value_end = mem.indexOfPos(u8, response, value_content_start, "\"") orelse return null;
        const encoded_value = response[value_content_start..value_end];

        // Decode base64 value
        const decoder = std.base64.standard;
        const decoded_len = decoder.calcSizeForSlice(encoded_value) catch return null;
        const decoded = self.arena.allocator().alloc(u8, decoded_len) catch return null;
        _ = decoder.decode(decoded, encoded_value) catch return null;

        return decoded;
    }

    fn parseEtcdRangeResponse(self: *Etcd, response: []const u8) RemoteError!std.StringHashMap([]const u8) {
        var result = std.StringHashMap([]const u8).init(self.allocator);
        errdefer result.deinit();

        // Simple parsing - find all key-value pairs in response
        var pos: usize = 0;
        while (mem.indexOfPos(u8, response, pos, "\"key\":\"")) |key_start| {
            const key_content_start = key_start + 7;
            const key_end = mem.indexOfPos(u8, response, key_content_start, "\"") orelse break;
            const encoded_key = response[key_content_start..key_end];

            const value_start = mem.indexOfPos(u8, response, key_end, "\"value\":\"") orelse break;
            const value_content_start = value_start + 9;
            const value_end = mem.indexOfPos(u8, response, value_content_start, "\"") orelse break;
            const encoded_value = response[value_content_start..value_end];

            // Decode key and value
            const decoder = std.base64.standard;

            const key_decoded_len = decoder.calcSizeForSlice(encoded_key) catch break;
            const decoded_key = self.arena.allocator().alloc(u8, key_decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.decode(decoded_key, encoded_key) catch break;

            const value_decoded_len = decoder.calcSizeForSlice(encoded_value) catch break;
            const decoded_value = self.arena.allocator().alloc(u8, value_decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.decode(decoded_value, encoded_value) catch break;

            result.put(decoded_key, decoded_value) catch return RemoteError.OutOfMemory;
            pos = value_end;
        }

        return result;
    }
};

// ============================================================================
// Consul Client
// ============================================================================

/// Consul client options
pub const ConsulOptions = struct {
    /// Consul HTTP address
    address: []const u8 = "http://localhost:8500",
    /// Datacenter (optional)
    datacenter: ?[]const u8 = null,
    /// ACL token (optional)
    token: ?[]const u8 = null,
    /// Request timeout in milliseconds
    timeout_ms: u32 = 5000,
};

/// HashiCorp Consul KV client
pub const Consul = struct {
    allocator: Allocator,
    options: ConsulOptions,
    client: http.Client,
    /// Arena for response storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator, options: ConsulOptions) Consul {
        return .{
            .allocator = allocator,
            .options = options,
            .client = http.Client{ .allocator = allocator },
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Consul) void {
        self.client.deinit();
        self.arena.deinit();
    }

    /// Get a value by key from Consul KV store
    pub fn get(self: *Consul, key: []const u8) RemoteError!?[]const u8 {
        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?raw", .{ self.options.address, key }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const response = self.makeGetRequest(url) catch |err| {
            if (err == error.NotFound) return null;
            return RemoteError.RequestFailed;
        };

        // Copy to arena for persistent storage
        const result = self.arena.allocator().dupe(u8, response) catch return RemoteError.OutOfMemory;
        self.allocator.free(response);

        return result;
    }

    /// Put a value by key to Consul KV store
    pub fn put(self: *Consul, key: []const u8, value: []const u8) RemoteError!void {
        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}", .{ self.options.address, key }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        _ = self.makePutRequest(url, value) catch return RemoteError.RequestFailed;
    }

    /// Delete a key from Consul KV store
    pub fn delete(self: *Consul, key: []const u8) RemoteError!void {
        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}", .{ self.options.address, key }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        _ = self.makeDeleteRequest(url) catch return RemoteError.RequestFailed;
    }

    /// Get all keys with a prefix
    pub fn getPrefix(self: *Consul, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?recurse", .{ self.options.address, prefix }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const response = self.makeGetRequest(url) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        return self.parseConsulKVList(response, prefix);
    }

    /// List all keys with a prefix (keys only, no values)
    pub fn listKeys(self: *Consul, prefix: []const u8) RemoteError![]const []const u8 {
        const url = std.fmt.allocPrint(self.allocator, "{s}/v1/kv/{s}?keys", .{ self.options.address, prefix }) catch return RemoteError.OutOfMemory;
        defer self.allocator.free(url);

        const response = self.makeGetRequest(url) catch return RemoteError.RequestFailed;
        defer self.allocator.free(response);

        return self.parseKeysList(response);
    }

    fn makeGetRequest(self: *Consul, url: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        // Add token header if configured
        if (self.options.token) |token| {
            request.headers = .{
                .content_type = .{ .override = "application/json" },
            };
            _ = token;
            // Note: Custom headers would be added here in a full implementation
        }

        request.send() catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        if (request.status == .not_found) {
            return error.NotFound;
        }

        return request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
    }

    fn makePutRequest(self: *Consul, url: []const u8, body: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.PUT, uri, .{
            .server_header_buffer = &server_header_buffer,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.send() catch return error.RequestFailed;
        request.writer().writeAll(body) catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        return request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
    }

    fn makeDeleteRequest(self: *Consul, url: []const u8) ![]u8 {
        const uri = Uri.parse(url) catch return error.InvalidUri;

        var server_header_buffer: [4096]u8 = undefined;
        var request = self.client.open(.DELETE, uri, .{
            .server_header_buffer = &server_header_buffer,
        }) catch return error.ConnectionFailed;
        defer request.deinit();

        request.send() catch return error.RequestFailed;
        request.finish() catch return error.RequestFailed;
        request.wait() catch return error.RequestFailed;

        return request.reader().readAllAlloc(self.allocator, 1024 * 1024) catch return error.RequestFailed;
    }

    fn parseConsulKVList(self: *Consul, response: []const u8, prefix: []const u8) RemoteError!std.StringHashMap([]const u8) {
        _ = prefix;
        var result = std.StringHashMap([]const u8).init(self.allocator);
        errdefer result.deinit();

        // Consul returns JSON array: [{"Key":"...","Value":"base64..."},...]
        var pos: usize = 0;
        while (mem.indexOfPos(u8, response, pos, "\"Key\":\"")) |key_start| {
            const key_content_start = key_start + 7;
            const key_end = mem.indexOfPos(u8, response, key_content_start, "\"") orelse break;
            const key_value = response[key_content_start..key_end];

            const value_start = mem.indexOfPos(u8, response, key_end, "\"Value\":\"") orelse break;
            const value_content_start = value_start + 9;
            const value_end = mem.indexOfPos(u8, response, value_content_start, "\"") orelse break;
            const encoded_value = response[value_content_start..value_end];

            // Decode base64 value
            const decoder = std.base64.standard;
            const decoded_len = decoder.calcSizeForSlice(encoded_value) catch break;
            const decoded_value = self.arena.allocator().alloc(u8, decoded_len) catch return RemoteError.OutOfMemory;
            _ = decoder.decode(decoded_value, encoded_value) catch break;

            const owned_key = self.arena.allocator().dupe(u8, key_value) catch return RemoteError.OutOfMemory;
            result.put(owned_key, decoded_value) catch return RemoteError.OutOfMemory;

            pos = value_end;
        }

        return result;
    }

    fn parseKeysList(self: *Consul, response: []const u8) RemoteError![]const []const u8 {
        var keys: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer keys.deinit(self.allocator);

        // Response is JSON array: ["key1","key2",...]
        var pos: usize = 0;
        while (mem.indexOfPos(u8, response, pos, "\"")) |start| {
            const content_start = start + 1;
            const end = mem.indexOfPos(u8, response, content_start, "\"") orelse break;
            const key = response[content_start..end];

            const owned_key = self.arena.allocator().dupe(u8, key) catch return RemoteError.OutOfMemory;
            keys.append(self.allocator, owned_key) catch return RemoteError.OutOfMemory;

            pos = end + 1;
        }

        return keys.toOwnedSlice(self.allocator) catch return RemoteError.OutOfMemory;
    }
};

// ============================================================================
// Remote Provider Interface
// ============================================================================

/// Abstract remote config provider interface
pub const RemoteProvider = union(enum) {
    etcd: *Etcd,
    consul: *Consul,

    pub fn get(self: RemoteProvider, key: []const u8) RemoteError!?[]const u8 {
        return switch (self) {
            .etcd => |e| e.get(key),
            .consul => |c| c.get(key),
        };
    }

    pub fn put(self: RemoteProvider, key: []const u8, value: []const u8) RemoteError!void {
        return switch (self) {
            .etcd => |e| e.put(key, value),
            .consul => |c| c.put(key, value),
        };
    }

    pub fn delete(self: RemoteProvider, key: []const u8) RemoteError!void {
        return switch (self) {
            .etcd => |e| e.delete(key),
            .consul => |c| c.delete(key),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Etcd initialization" {
    var etcd = Etcd.init(std.testing.allocator, .{});
    defer etcd.deinit();

    try std.testing.expectEqualStrings("http://localhost:2379", etcd.options.endpoints[0]);
}

test "Consul initialization" {
    var consul = Consul.init(std.testing.allocator, .{});
    defer consul.deinit();

    try std.testing.expectEqualStrings("http://localhost:8500", consul.options.address);
}

test "Etcd custom endpoints" {
    const endpoints = [_][]const u8{ "http://etcd1:2379", "http://etcd2:2379" };
    var etcd = Etcd.init(std.testing.allocator, .{
        .endpoints = &endpoints,
    });
    defer etcd.deinit();

    try std.testing.expectEqual(@as(usize, 2), etcd.options.endpoints.len);
}

test "Consul with token" {
    var consul = Consul.init(std.testing.allocator, .{
        .token = "my-secret-token",
        .datacenter = "dc1",
    });
    defer consul.deinit();

    try std.testing.expectEqualStrings("my-secret-token", consul.options.token.?);
    try std.testing.expectEqualStrings("dc1", consul.options.datacenter.?);
}

test "RemoteProvider union" {
    var etcd = Etcd.init(std.testing.allocator, .{});
    defer etcd.deinit();

    const provider = RemoteProvider{ .etcd = &etcd };
    _ = provider;
}
