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
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.map.iterator();
            while (it.next()) |entry| {
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

        pub fn put(self: *Self, key: []const u8, value: V) !void {
            if (self.map.getPtr(key)) |node| {
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
