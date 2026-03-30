// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Watch/Hot-Reload Module
//!
//! Provides file watching and hot-reload capabilities for configuration files.
//! Supports polling-based watching for cross-platform compatibility.
//!
//! Example usage:
//! ```zig
//! const watch = @import("watch");
//!
//! var watcher = watch.Watcher.init(allocator, .{
//!     .poll_interval_ms = 1000,
//! });
//! defer watcher.deinit();
//!
//! try watcher.addPath("config.toml", onConfigChanged);
//! try watcher.start();
//!
//! // Later...
//! watcher.stop();
//! ```

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;
const Thread = std.Thread;

/// Watch errors
pub const WatchError = error{
    FileNotFound,
    AccessDenied,
    WatcherAlreadyRunning,
    WatcherNotRunning,
    TooManyWatches,
    OutOfMemory,
};

/// Type of file change event
pub const ChangeEvent = enum {
    modified,
    deleted,
    created,
};

/// Callback function type for file changes
pub const ChangeCallback = *const fn (path: []const u8, event: ChangeEvent, user_data: ?*anyopaque) void;

/// Watch options
pub const WatchOptions = struct {
    /// Polling interval in milliseconds (for polling mode)
    poll_interval_ms: u32 = 1000,
    /// Whether to trigger callback on initial add
    trigger_on_add: bool = false,
    /// Maximum number of paths to watch
    max_watches: usize = 100,
};

/// Information about a watched file
const WatchedFile = struct {
    path: []const u8,
    callback: ChangeCallback,
    user_data: ?*anyopaque,
    last_mtime: i128,
    last_size: u64,
    exists: bool,
};

/// File watcher with hot-reload support
pub const Watcher = struct {
    allocator: Allocator,
    options: WatchOptions,
    watches: std.ArrayListUnmanaged(WatchedFile),
    running: std.atomic.Value(bool),
    thread: ?Thread,
    /// Arena for path storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator, options: WatchOptions) Watcher {
        return .{
            .allocator = allocator,
            .options = options,
            .watches = .{},
            .running = std.atomic.Value(bool).init(false),
            .thread = null,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Watcher) void {
        self.stop();
        self.watches.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Add a file to watch
    pub fn addPath(self: *Watcher, path: []const u8, callback: ChangeCallback) !void {
        try self.addPathWithData(path, callback, null);
    }

    /// Add a file to watch with user data
    pub fn addPathWithData(self: *Watcher, path: []const u8, callback: ChangeCallback, user_data: ?*anyopaque) !void {
        if (self.watches.items.len >= self.options.max_watches) {
            return WatchError.TooManyWatches;
        }

        const owned_path = try self.arena.allocator().dupe(u8, path);

        // Get initial file state
        const stat = getFileStat(path);
        const exists = stat != null;

        try self.watches.append(self.allocator, .{
            .path = owned_path,
            .callback = callback,
            .user_data = user_data,
            .last_mtime = if (stat) |s| s.mtime else 0,
            .last_size = if (stat) |s| s.size else 0,
            .exists = exists,
        });

        // Trigger callback on add if requested
        if (self.options.trigger_on_add and exists) {
            callback(owned_path, .modified, user_data);
        }
    }

    /// Remove a watched path
    pub fn removePath(self: *Watcher, path: []const u8) bool {
        for (self.watches.items, 0..) |watch, i| {
            if (mem.eql(u8, watch.path, path)) {
                _ = self.watches.orderedRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Start watching (spawns background thread)
    pub fn start(self: *Watcher) !void {
        if (self.running.load(.acquire)) {
            return WatchError.WatcherAlreadyRunning;
        }

        self.running.store(true, .release);
        self.thread = try Thread.spawn(.{}, watchLoop, .{self});
    }

    /// Stop watching
    pub fn stop(self: *Watcher) void {
        if (!self.running.load(.acquire)) {
            return;
        }

        self.running.store(false, .release);

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    /// Check if watcher is running
    pub fn isRunning(self: *const Watcher) bool {
        return self.running.load(.acquire);
    }

    /// Get number of watched paths
    pub fn watchCount(self: *const Watcher) usize {
        return self.watches.items.len;
    }

    /// Manually trigger a check (for testing or immediate updates)
    pub fn checkNow(self: *Watcher) void {
        self.checkForChanges();
    }

    fn watchLoop(self: *Watcher) void {
        while (self.running.load(.acquire)) {
            self.checkForChanges();
            std.Thread.sleep(self.options.poll_interval_ms * std.time.ns_per_ms);
        }
    }

    fn checkForChanges(self: *Watcher) void {
        for (self.watches.items) |*watch| {
            const current_stat = getFileStat(watch.path);
            const currently_exists = current_stat != null;

            if (watch.exists and !currently_exists) {
                // File was deleted
                watch.exists = false;
                watch.callback(watch.path, .deleted, watch.user_data);
            } else if (!watch.exists and currently_exists) {
                // File was created
                watch.exists = true;
                if (current_stat) |stat| {
                    watch.last_mtime = stat.mtime;
                    watch.last_size = stat.size;
                }
                watch.callback(watch.path, .created, watch.user_data);
            } else if (currently_exists) {
                // Check for modification
                if (current_stat) |stat| {
                    if (stat.mtime != watch.last_mtime or stat.size != watch.last_size) {
                        watch.last_mtime = stat.mtime;
                        watch.last_size = stat.size;
                        watch.callback(watch.path, .modified, watch.user_data);
                    }
                }
            }
        }
    }
};

/// File stat information
const FileStat = struct {
    mtime: i128,
    size: u64,
};

fn getFileStat(path: []const u8) ?FileStat {
    const file = fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    const stat = file.stat() catch return null;
    return .{
        .mtime = stat.mtime,
        .size = stat.size,
    };
}

/// Simple config reloader that wraps a Loader
pub fn ConfigReloader(comptime T: type) type {
    const loader_mod = @import("loader.zig");

    return struct {
        loader: *loader_mod.Loader(T),
        watcher: Watcher,
        on_reload: ?*const fn (*loader_mod.Loader(T)) void,

        const Self = @This();

        pub fn init(allocator: Allocator, loader: *loader_mod.Loader(T), options: WatchOptions) Self {
            return .{
                .loader = loader,
                .watcher = Watcher.init(allocator, options),
                .on_reload = null,
            };
        }

        pub fn deinit(self: *Self) void {
            self.watcher.deinit();
        }

        /// Set callback for after reload
        pub fn onReload(self: *Self, callback: *const fn (*loader_mod.Loader(T)) void) void {
            self.on_reload = callback;
        }

        /// Watch a config file and auto-reload on changes
        pub fn watchConfig(self: *Self, path: []const u8) !void {
            try self.watcher.addPathWithData(path, reloadCallback, self);
        }

        /// Start watching
        pub fn start(self: *Self) !void {
            try self.watcher.start();
        }

        /// Stop watching
        pub fn stop(self: *Self) void {
            self.watcher.stop();
        }

        fn reloadCallback(path: []const u8, event: ChangeEvent, user_data: ?*anyopaque) void {
            _ = path;
            if (event == .deleted) return;

            if (user_data) |ptr| {
                const self: *Self = @ptrCast(@alignCast(ptr));
                self.loader.reset();

                if (self.on_reload) |callback| {
                    callback(self.loader);
                }
            }
        }
    };
}

/// Watch a single file and call callback on changes (convenience function)
pub fn watchFile(
    allocator: Allocator,
    path: []const u8,
    callback: ChangeCallback,
    options: WatchOptions,
) !Watcher {
    var watcher = Watcher.init(allocator, options);
    errdefer watcher.deinit();

    try watcher.addPath(path, callback);
    try watcher.start();

    return watcher;
}

// ============================================================================
// Tests
// ============================================================================

test "Watcher initialization" {
    var watcher = Watcher.init(std.testing.allocator, .{});
    defer watcher.deinit();

    try std.testing.expect(!watcher.isRunning());
    try std.testing.expectEqual(@as(usize, 0), watcher.watchCount());
}

test "Watcher add and remove path" {
    var watcher = Watcher.init(std.testing.allocator, .{});
    defer watcher.deinit();

    const dummy_callback = struct {
        fn cb(_: []const u8, _: ChangeEvent, _: ?*anyopaque) void {}
    }.cb;

    // Add a path (doesn't need to exist for adding)
    try watcher.addPath("/tmp/test_config.toml", dummy_callback);
    try std.testing.expectEqual(@as(usize, 1), watcher.watchCount());

    // Remove the path
    try std.testing.expect(watcher.removePath("/tmp/test_config.toml"));
    try std.testing.expectEqual(@as(usize, 0), watcher.watchCount());

    // Remove non-existent path
    try std.testing.expect(!watcher.removePath("/tmp/nonexistent"));
}

test "Watcher max watches limit" {
    var watcher = Watcher.init(std.testing.allocator, .{ .max_watches = 2 });
    defer watcher.deinit();

    const dummy_callback = struct {
        fn cb(_: []const u8, _: ChangeEvent, _: ?*anyopaque) void {}
    }.cb;

    try watcher.addPath("/tmp/file1", dummy_callback);
    try watcher.addPath("/tmp/file2", dummy_callback);

    // Third should fail
    try std.testing.expectError(WatchError.TooManyWatches, watcher.addPath("/tmp/file3", dummy_callback));
}

test "Watcher double start error" {
    var watcher = Watcher.init(std.testing.allocator, .{ .poll_interval_ms = 100 });
    defer watcher.deinit();

    try watcher.start();
    defer watcher.stop();

    try std.testing.expectError(WatchError.WatcherAlreadyRunning, watcher.start());
}

test "Watcher stop when not running" {
    var watcher = Watcher.init(std.testing.allocator, .{});
    defer watcher.deinit();

    // Should not panic or error
    watcher.stop();
}

test "getFileStat returns null for nonexistent" {
    const stat = getFileStat("/nonexistent/path/to/file");
    try std.testing.expect(stat == null);
}
