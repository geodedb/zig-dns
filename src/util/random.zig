// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Random Number Generator Abstraction
//!
//! Provides a mockable PRNG interface for deterministic testing.

const std = @import("std");

/// Mock PRNG with fixed seed for deterministic testing
pub const MockRandom = struct {
    prng: std.Random.DefaultPrng,

    const Self = @This();

    /// Fixed seed for reproducible tests
    pub const default_seed: u64 = 0x123456789ABCDEF0;

    pub fn init() Self {
        return initWithSeed(default_seed);
    }

    pub fn initWithSeed(seed: u64) Self {
        return Self{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    /// Get underlying std.Random for compatibility
    pub fn random(self: *Self) std.Random {
        return self.prng.random();
    }
};

/// System PRNG using OS entropy
pub const SystemRandom = struct {
    prng: std.Random.DefaultPrng,

    const Self = @This();

    pub fn init() Self {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
            seed = @bitCast(std.time.milliTimestamp());
        };
        return Self{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn random(self: *Self) std.Random {
        return self.prng.random();
    }
};

test "MockRandom deterministic" {
    var rng1 = MockRandom.init();
    var rng2 = MockRandom.init();

    const v1 = rng1.random().int(u32);
    const v2 = rng2.random().int(u32);
    try std.testing.expectEqual(v1, v2);
}
