// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! LRU Cache Implementation
//!
//! Generic Least Recently Used cache with O(1) operations.

const std = @import("std");

/// LRU Cache with string keys
pub fn LruCache(comptime V: type) type {
    return struct {
        allocator: std.mem.Allocator,
        map: std.StringHashMap(Node),
        head: ?*Node,
        tail: ?*Node,
        capacity: usize,
        count: usize,
        /// Optional callback invoked when a value is evicted or overwritten.
        /// The caller can use this to free any owned memory inside the value.
        on_evict: ?*const fn (std.mem.Allocator, V) void,

        const Self = @This();

        const Node = struct {
            key: []const u8,
            value: V,
            prev: ?*Node,
            next: ?*Node,
        };

        pub fn init(allocator: std.mem.Allocator, capacity: usize) Self {
            return Self{
                .allocator = allocator,
                .map = std.StringHashMap(Node).init(allocator),
                .head = null,
                .tail = null,
                .capacity = capacity,
                .count = 0,
                .on_evict = null,
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                if (self.on_evict) |cb| {
                    cb(self.allocator, entry.value_ptr.value);
                }
                self.allocator.free(entry.key_ptr.*);
            }
            self.map.deinit();
        }

        pub fn get(self: *Self, key: []const u8) ?V {
            if (self.map.getPtr(key)) |node| {
                self.moveToFront(node);
                return node.value;
            }
            return null;
        }

        /// Handle returned by getWithHandle() that allows O(1) removal
        /// without re-hashing the key.
        pub const EntryHandle = struct {
            value: V,
            key_ptr: *[]const u8,
            node_ptr: *Node,
        };

        /// Like get(), but returns an EntryHandle containing the value
        /// plus internal pointers.  The caller can pass the handle to
        /// removeByHandle() to delete the entry without a second hash.
        /// The handle is invalidated by any mutation to the cache.
        pub fn getWithHandle(self: *Self, key: []const u8) ?EntryHandle {
            if (self.map.getEntry(key)) |entry| {
                self.moveToFront(entry.value_ptr);
                return .{
                    .value = entry.value_ptr.value,
                    .key_ptr = entry.key_ptr,
                    .node_ptr = entry.value_ptr,
                };
            }
            return null;
        }

        /// Remove an entry using its handle (obtained from getWithHandle).
        /// This avoids re-hashing the key because we already have the
        /// internal pointers from the initial lookup.
        /// The handle MUST have been obtained from a prior getWithHandle
        /// call with no intervening map mutations.
        pub fn removeByHandle(self: *Self, handle: EntryHandle) void {
            if (self.on_evict) |cb| {
                cb(self.allocator, handle.node_ptr.value);
            }
            self.removeFromList(handle.node_ptr);
            const key_slice = handle.key_ptr.*;
            self.map.removeByPtr(handle.key_ptr);
            self.allocator.free(key_slice);
            self.count -= 1;
        }

        pub fn put(self: *Self, key: []const u8, value: V) !void {
            if (self.map.getPtr(key)) |node| {
                if (self.on_evict) |cb| {
                    cb(self.allocator, node.value);
                }
                node.value = value;
                self.moveToFront(node);
                return;
            }

            if (self.count >= self.capacity) {
                self.evictLru();
            }

            const key_copy = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(key_copy);

            try self.map.put(key_copy, Node{
                .key = key_copy,
                .value = value,
                .prev = null,
                .next = self.head,
            });

            const node = self.map.getPtr(key_copy).?;

            if (self.head) |head| {
                head.prev = node;
            }
            self.head = node;

            if (self.tail == null) {
                self.tail = node;
            }

            self.count += 1;
        }

        pub fn remove(self: *Self, key: []const u8) bool {
            if (self.map.fetchRemove(key)) |kv| {
                const node = &kv.value;
                if (self.on_evict) |cb| {
                    cb(self.allocator, node.value);
                }
                self.removeFromList(node);
                self.allocator.free(kv.key);
                self.count -= 1;
                return true;
            }
            return false;
        }

        pub fn clear(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
                if (self.on_evict) |cb| {
                    cb(self.allocator, entry.value_ptr.value);
                }
                self.allocator.free(entry.key_ptr.*);
            }
            self.map.clearRetainingCapacity();
            self.head = null;
            self.tail = null;
            self.count = 0;
        }

        pub fn len(self: *Self) usize {
            return self.count;
        }

        fn moveToFront(self: *Self, node: *Node) void {
            if (self.head == node) return;

            if (node.prev) |prev| {
                prev.next = node.next;
            }
            if (node.next) |next| {
                next.prev = node.prev;
            }
            if (self.tail == node) {
                self.tail = node.prev;
            }

            node.prev = null;
            node.next = self.head;
            if (self.head) |head| {
                head.prev = node;
            }
            self.head = node;
        }

        fn removeFromList(self: *Self, node: *const Node) void {
            if (node.prev) |prev| {
                prev.next = node.next;
            } else {
                self.head = node.next;
            }

            if (node.next) |next| {
                next.prev = node.prev;
            } else {
                self.tail = node.prev;
            }
        }

        fn evictLru(self: *Self) void {
            if (self.tail) |tail| {
                const key = tail.key;
                if (self.on_evict) |cb| {
                    cb(self.allocator, tail.value);
                }
                self.removeFromList(tail);
                _ = self.map.remove(key);
                self.allocator.free(key);
                self.count -= 1;
            }
        }
    };
}

test "LruCache basic" {
    const allocator = std.testing.allocator;
    var cache = LruCache(i32).init(allocator, 3);
    defer cache.deinit();

    try cache.put("a", 1);
    try cache.put("b", 2);

    try std.testing.expectEqual(@as(?i32, 1), cache.get("a"));
    try std.testing.expectEqual(@as(?i32, 2), cache.get("b"));
}

test "LruCache getWithHandle returns value and handle" {
    const allocator = std.testing.allocator;
    var cache = LruCache(i32).init(allocator, 3);
    defer cache.deinit();

    try cache.put("x", 42);
    try cache.put("y", 99);

    // getWithHandle should return the value
    if (cache.getWithHandle("x")) |handle| {
        try std.testing.expectEqual(@as(i32, 42), handle.value);
    } else {
        return error.TestUnexpectedResult;
    }

    // Non-existent key returns null
    try std.testing.expect(cache.getWithHandle("z") == null);
}

test "LruCache removeByHandle removes without re-hashing" {
    const allocator = std.testing.allocator;
    var cache = LruCache(i32).init(allocator, 3);
    defer cache.deinit();

    try cache.put("a", 1);
    try cache.put("b", 2);
    try cache.put("c", 3);

    // Get handle for "b"
    const handle = cache.getWithHandle("b") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i32, 2), handle.value);

    // Remove using the handle
    cache.removeByHandle(handle);

    // "b" should be gone
    try std.testing.expect(cache.get("b") == null);
    try std.testing.expectEqual(@as(usize, 2), cache.len());

    // Other entries should still be present
    try std.testing.expectEqual(@as(?i32, 1), cache.get("a"));
    try std.testing.expectEqual(@as(?i32, 3), cache.get("c"));
}

test "LruCache removeByHandle calls on_evict" {
    const allocator = std.testing.allocator;

    // Track eviction via a simple counter using a struct with a static var
    const Tracker = struct {
        var evict_count: usize = 0;

        fn onEvict(_: std.mem.Allocator, _: i32) void {
            evict_count += 1;
        }
    };
    Tracker.evict_count = 0;

    var cache = LruCache(i32).init(allocator, 3);
    cache.on_evict = &Tracker.onEvict;
    defer cache.deinit();

    try cache.put("a", 10);
    try cache.put("b", 20);

    const handle = cache.getWithHandle("a") orelse return error.TestUnexpectedResult;
    cache.removeByHandle(handle);

    // on_evict should have been called once (for removeByHandle)
    try std.testing.expectEqual(@as(usize, 1), Tracker.evict_count);
}

test "LruCache eviction" {
    const allocator = std.testing.allocator;
    var cache = LruCache(i32).init(allocator, 2);
    defer cache.deinit();

    try cache.put("a", 1);
    try cache.put("b", 2);
    try cache.put("c", 3);

    try std.testing.expectEqual(@as(?i32, null), cache.get("a"));
    try std.testing.expectEqual(@as(?i32, 2), cache.get("b"));
    try std.testing.expectEqual(@as(?i32, 3), cache.get("c"));
}
