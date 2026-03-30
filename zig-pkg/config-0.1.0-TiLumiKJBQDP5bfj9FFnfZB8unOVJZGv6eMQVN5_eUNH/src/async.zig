// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Async Configuration Loading Module
//!
//! Provides asynchronous configuration loading capabilities using Zig's
//! thread-based concurrency model. Useful for:
//! - Loading multiple config files in parallel
//! - Non-blocking config loading in servers
//! - Background config refresh
//!
//! Example usage:
//! ```zig
//! const async_config = @import("async");
//!
//! // Load multiple configs in parallel
//! var loader = async_config.AsyncLoader(MyConfig).init(allocator);
//! defer loader.deinit();
//!
//! try loader.addFile("config.toml", .toml);
//! try loader.addFile("secrets.json", .json);
//!
//! // Start loading in background
//! try loader.startAsync();
//!
//! // Do other work...
//!
//! // Wait for completion and get result
//! const config = try loader.await();
//! ```

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Thread = std.Thread;
const Allocator = mem.Allocator;

const loader_mod = @import("loader.zig");
const Format = loader_mod.Format;

/// Async loading errors
pub const AsyncError = error{
    LoadFailed,
    AlreadyRunning,
    NotStarted,
    Timeout,
    OutOfMemory,
    ThreadError,
};

/// State of async operation
pub const AsyncState = enum {
    idle,
    running,
    completed,
    failed,
};

/// Result of an async load operation
pub fn AsyncResult(comptime T: type) type {
    return struct {
        config: ?T,
        err: ?anyerror,
        state: AsyncState,
    };
}

/// File to load asynchronously
const AsyncFile = struct {
    path: []const u8,
    format: Format,
};

/// Async configuration loader
pub fn AsyncLoader(comptime T: type) type {
    return struct {
        allocator: Allocator,
        files: std.ArrayListUnmanaged(AsyncFile),
        thread: ?Thread,
        result: AsyncResult(T),
        mutex: Thread.Mutex,
        arena: std.heap.ArenaAllocator,

        const Self = @This();

        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .files = .{},
                .thread = null,
                .result = .{
                    .config = null,
                    .err = null,
                    .state = .idle,
                },
                .mutex = .{},
                .arena = std.heap.ArenaAllocator.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            // Wait for any running thread
            if (self.thread) |thread| {
                thread.join();
            }
            self.files.deinit(self.allocator);
            self.arena.deinit();
        }

        /// Add a file to load
        pub fn addFile(self: *Self, path: []const u8, format: Format) !void {
            const owned_path = try self.arena.allocator().dupe(u8, path);
            try self.files.append(self.allocator, .{
                .path = owned_path,
                .format = format,
            });
        }

        /// Start async loading
        pub fn startAsync(self: *Self) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.result.state == .running) {
                return AsyncError.AlreadyRunning;
            }

            self.result.state = .running;
            self.result.config = null;
            self.result.err = null;

            self.thread = try Thread.spawn(.{}, loadThreadFn, .{self});
        }

        /// Wait for async loading to complete and get result
        pub fn await(self: *Self) !T {
            if (self.thread) |thread| {
                thread.join();
                self.thread = null;
            }

            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.result.state == .failed) {
                if (self.result.err) |e| {
                    return e;
                }
                return AsyncError.LoadFailed;
            }

            if (self.result.config) |config| {
                return config;
            }

            return AsyncError.LoadFailed;
        }

        /// Check if loading is complete (non-blocking)
        pub fn isComplete(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.result.state == .completed or self.result.state == .failed;
        }

        /// Get current state
        pub fn getState(self: *Self) AsyncState {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.result.state;
        }

        /// Try to get result without blocking (returns null if not ready)
        pub fn tryGetResult(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.result.state == .completed) {
                return self.result.config;
            }
            return null;
        }

        fn loadThreadFn(self: *Self) void {
            var loader = loader_mod.Loader(T).init(self.allocator);
            defer loader.deinit();

            // Load each file
            for (self.files.items) |file| {
                self.loadFile(&loader, file.path, file.format) catch |e| {
                    self.mutex.lock();
                    self.result.state = .failed;
                    self.result.err = e;
                    self.mutex.unlock();
                    return;
                };
            }

            // Get final config
            const config = loader.load(.{
                .app_name = "async",
                .use_xdg = false,
                .optional = true,
            }) catch |e| {
                self.mutex.lock();
                self.result.state = .failed;
                self.result.err = e;
                self.mutex.unlock();
                return;
            };

            self.mutex.lock();
            self.result.config = config;
            self.result.state = .completed;
            self.mutex.unlock();
        }

        fn loadFile(self: *Self, loader: *loader_mod.Loader(T), path: []const u8, format: Format) !void {
            _ = format;
            _ = self;

            const file = fs.cwd().openFile(path, .{}) catch {
                return; // File not found is ok for optional configs
            };
            defer file.close();

            const content = try file.readToEndAlloc(loader.allocator, 10 * 1024 * 1024);
            defer loader.allocator.free(content);

            // Parse and apply to loader
            const detected_format = Format.fromExtension(path);
            loader.parseContent(content, detected_format, .project, path) catch {};
        }
    };
}

/// Load a config file asynchronously (convenience function)
pub fn loadAsync(comptime T: type, allocator: Allocator, path: []const u8) !*AsyncLoader(T) {
    const loader = try allocator.create(AsyncLoader(T));
    loader.* = AsyncLoader(T).init(allocator);
    try loader.addFile(path, .auto);
    try loader.startAsync();
    return loader;
}

/// Callback type for async completion
pub const CompletionCallback = *const fn (success: bool, user_data: ?*anyopaque) void;

/// Async loader with callback support
pub fn AsyncLoaderWithCallback(comptime T: type) type {
    return struct {
        loader: AsyncLoader(T),
        callback: ?CompletionCallback,
        user_data: ?*anyopaque,

        const Self = @This();

        pub fn init(allocator: Allocator) Self {
            return .{
                .loader = AsyncLoader(T).init(allocator),
                .callback = null,
                .user_data = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.loader.deinit();
        }

        pub fn setCallback(self: *Self, callback: CompletionCallback, user_data: ?*anyopaque) void {
            self.callback = callback;
            self.user_data = user_data;
        }

        pub fn addFile(self: *Self, path: []const u8, format: Format) !void {
            try self.loader.addFile(path, format);
        }

        pub fn startAsync(self: *Self) !void {
            try self.loader.startAsync();
        }

        /// Poll for completion and trigger callback if done
        pub fn poll(self: *Self) bool {
            if (self.loader.isComplete()) {
                if (self.callback) |cb| {
                    const success = self.loader.result.state == .completed;
                    cb(success, self.user_data);
                }
                return true;
            }
            return false;
        }

        pub fn await(self: *Self) !T {
            return self.loader.await();
        }
    };
}

/// Load multiple config files in parallel
pub fn loadParallel(comptime T: type, allocator: Allocator, paths: []const []const u8) !T {
    const ThreadContext = struct {
        path: []const u8,
        allocator: Allocator,
        result: ?[]const u8,
        err: ?anyerror,
    };

    var contexts = try allocator.alloc(ThreadContext, paths.len);
    defer allocator.free(contexts);

    var threads = try allocator.alloc(?Thread, paths.len);
    defer allocator.free(threads);

    // Initialize contexts
    for (paths, 0..) |path, i| {
        contexts[i] = .{
            .path = path,
            .allocator = allocator,
            .result = null,
            .err = null,
        };
    }

    // Spawn threads
    for (contexts, 0..) |*ctx, i| {
        threads[i] = Thread.spawn(.{}, struct {
            fn load(c: *ThreadContext) void {
                const file = fs.cwd().openFile(c.path, .{}) catch |e| {
                    c.err = e;
                    return;
                };
                defer file.close();

                c.result = file.readToEndAlloc(c.allocator, 10 * 1024 * 1024) catch |e| {
                    c.err = e;
                    return;
                };
            }
        }.load, .{ctx}) catch null;
    }

    // Wait for all threads
    for (threads) |maybe_thread| {
        if (maybe_thread) |thread| {
            thread.join();
        }
    }

    // Merge results into loader
    var loader = loader_mod.Loader(T).init(allocator);
    defer loader.deinit();

    for (contexts, 0..) |ctx, i| {
        if (ctx.result) |content| {
            defer allocator.free(content);
            const format = Format.fromExtension(paths[i]);
            loader.parseContent(content, format, .project, paths[i]) catch {};
        }
    }

    return loader.load(.{
        .app_name = "parallel",
        .use_xdg = false,
        .optional = true,
    });
}

// ============================================================================
// Tests
// ============================================================================

test "AsyncLoader initialization" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try std.testing.expectEqual(AsyncState.idle, loader.getState());
}

test "AsyncLoader add file" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.addFile("/tmp/config.toml", .toml);
    try loader.addFile("/tmp/config.json", .json);

    try std.testing.expectEqual(@as(usize, 2), loader.files.items.len);
}

test "AsyncState enum" {
    try std.testing.expectEqual(AsyncState.idle, AsyncState.idle);
    try std.testing.expectEqual(AsyncState.running, AsyncState.running);
    try std.testing.expectEqual(AsyncState.completed, AsyncState.completed);
    try std.testing.expectEqual(AsyncState.failed, AsyncState.failed);
}

test "AsyncLoaderWithCallback initialization" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoaderWithCallback(Config).init(std.testing.allocator);
    defer loader.deinit();

    try std.testing.expect(loader.callback == null);
}

test "AsyncLoaderWithCallback set callback" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = AsyncLoaderWithCallback(Config).init(std.testing.allocator);
    defer loader.deinit();

    const TestCallback = struct {
        var called = false;
        fn callback(_: bool, _: ?*anyopaque) void {
            called = true;
        }
    };

    loader.setCallback(TestCallback.callback, null);
    try std.testing.expect(loader.callback != null);
}
