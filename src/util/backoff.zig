// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Exponential Backoff with Jitter
//!
//! Implements various backoff strategies for retry logic:
//! - Exponential backoff
//! - Exponential backoff with full jitter
//! - Exponential backoff with equal jitter
//! - Exponential backoff with decorrelated jitter
//! - Linear backoff
//! - Constant backoff
//!
//! References:
//! - AWS Architecture Blog: Exponential Backoff And Jitter
//! - Google Cloud Best Practices

const std = @import("std");

/// Backoff strategy type
pub const Strategy = enum {
    /// Fixed delay between retries
    constant,
    /// Linear increase: delay = base * attempt
    linear,
    /// Exponential increase: delay = base * 2^attempt
    exponential,
    /// Exponential with full jitter: delay = random(0, base * 2^attempt)
    exponential_full_jitter,
    /// Exponential with equal jitter: delay = base * 2^attempt / 2 + random(0, base * 2^attempt / 2)
    exponential_equal_jitter,
    /// Decorrelated jitter: delay = random(base, prev_delay * 3)
    exponential_decorrelated_jitter,
};

/// Backoff configuration
pub const Config = struct {
    /// Backoff strategy
    strategy: Strategy = .exponential_full_jitter,
    /// Base delay in milliseconds
    base_delay_ms: u64 = 100,
    /// Maximum delay in milliseconds
    max_delay_ms: u64 = 30_000,
    /// Maximum number of retries (0 = unlimited)
    max_retries: u32 = 10,
    /// Multiplier for exponential backoff (default 2.0)
    multiplier: f64 = 2.0,

    pub fn withStrategy(self: Config, strategy: Strategy) Config {
        var config = self;
        config.strategy = strategy;
        return config;
    }

    pub fn withBaseDelay(self: Config, ms: u64) Config {
        var config = self;
        config.base_delay_ms = ms;
        return config;
    }

    pub fn withMaxDelay(self: Config, ms: u64) Config {
        var config = self;
        config.max_delay_ms = ms;
        return config;
    }

    pub fn withMaxRetries(self: Config, retries: u32) Config {
        var config = self;
        config.max_retries = retries;
        return config;
    }
};

/// Exponential backoff state machine
pub const Backoff = struct {
    config: Config,
    /// Current attempt number (0-indexed)
    attempt: u32,
    /// Last delay used (for decorrelated jitter)
    last_delay_ms: u64,
    /// Pseudo-random number generator
    prng: std.Random.DefaultPrng,

    const Self = @This();

    /// Error returned when secure entropy is unavailable
    pub const InitError = error{EntropyUnavailable};

    pub fn init(config: Config) InitError!Self {
        // Use secure random for jitter calculations
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
            return error.EntropyUnavailable;
        };
        return Self{
            .config = config,
            .attempt = 0,
            .last_delay_ms = config.base_delay_ms,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn initWithSeed(config: Config, seed: u64) Self {
        return Self{
            .config = config,
            .attempt = 0,
            .last_delay_ms = config.base_delay_ms,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    fn random(self: *Self) std.Random {
        return self.prng.random();
    }

    /// Reset the backoff state
    pub fn reset(self: *Self) void {
        self.attempt = 0;
        self.last_delay_ms = self.config.base_delay_ms;
    }

    /// Check if we should retry
    pub fn shouldRetry(self: *const Self) bool {
        if (self.config.max_retries == 0) return true;
        return self.attempt < self.config.max_retries;
    }

    /// Get the next delay and advance the attempt counter
    /// Returns null if max retries exceeded
    pub fn nextDelay(self: *Self) ?u64 {
        if (!self.shouldRetry()) return null;

        const delay = self.calculateDelay();
        self.attempt += 1;
        self.last_delay_ms = delay;

        return delay;
    }

    /// Peek at what the next delay would be without advancing
    pub fn peekDelay(self: *const Self) u64 {
        return self.calculateDelay();
    }

    fn calculateDelay(self: *Self) u64 {
        const base = self.config.base_delay_ms;
        const max = self.config.max_delay_ms;

        const delay = switch (self.config.strategy) {
            .constant => base,
            .linear => self.calculateLinear(base, max),
            .exponential => self.calculateExponential(base, max),
            .exponential_full_jitter => self.calculateFullJitter(base, max),
            .exponential_equal_jitter => self.calculateEqualJitter(base, max),
            .exponential_decorrelated_jitter => self.calculateDecorrelatedJitter(base, max),
        };

        return @min(delay, max);
    }

    fn calculateLinear(self: *const Self, base: u64, max: u64) u64 {
        const delay = base *| (self.attempt + 1);
        return @min(delay, max);
    }

    fn calculateExponential(self: *const Self, base: u64, max: u64) u64 {
        if (self.attempt >= 63) return max;
        const shift: u6 = @intCast(@min(self.attempt, 63));
        const delay = base *| (@as(u64, 1) << shift);
        return @min(delay, max);
    }

    fn calculateFullJitter(self: *Self, base: u64, max: u64) u64 {
        const exp_delay = self.calculateExponential(base, max);
        if (exp_delay == 0) return 0;
        return self.random().uintLessThan(u64, exp_delay + 1);
    }

    fn calculateEqualJitter(self: *Self, base: u64, max: u64) u64 {
        const exp_delay = self.calculateExponential(base, max);
        const half = exp_delay / 2;
        if (half == 0) return exp_delay;
        return half + self.random().uintLessThan(u64, half + 1);
    }

    fn calculateDecorrelatedJitter(self: *Self, base: u64, max: u64) u64 {
        const upper_bound = @min(self.last_delay_ms *| 3, max);
        if (upper_bound <= base) return base;
        return base + self.random().uintLessThan(u64, upper_bound - base + 1);
    }

    /// Get current attempt number
    pub fn getAttempt(self: *const Self) u32 {
        return self.attempt;
    }

    /// Get remaining retries (returns max value for unlimited)
    pub fn remainingRetries(self: *const Self) u32 {
        if (self.config.max_retries == 0) return std.math.maxInt(u32);
        if (self.attempt >= self.config.max_retries) return 0;
        return self.config.max_retries - self.attempt;
    }
};

/// Retry executor that handles the backoff loop
pub fn RetryExecutor(comptime Context: type, comptime ErrorSet: type) type {
    return struct {
        backoff: Backoff,
        on_retry: ?*const fn (ctx: Context, attempt: u32, err: ErrorSet) void,
        context: Context,

        const Self = @This();

        pub fn init(config: Config, context: Context) Backoff.InitError!Self {
            return Self{
                .backoff = try Backoff.init(config),
                .on_retry = null,
                .context = context,
            };
        }

        pub fn setRetryCallback(self: *Self, callback: *const fn (Context, u32, ErrorSet) void) void {
            self.on_retry = callback;
        }

        /// Execute a function with retries
        pub fn execute(
            self: *Self,
            comptime func: fn (Context) ErrorSet!void,
        ) ErrorSet!void {
            while (true) {
                func(self.context) catch |err| {
                    if (self.on_retry) |callback| {
                        callback(self.context, self.backoff.getAttempt(), err);
                    }

                    if (self.backoff.nextDelay()) |delay_ms| {
                        std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                        continue;
                    }

                    return err;
                };

                return;
            }
        }

        /// Execute with a result type
        pub fn executeWithResult(
            self: *Self,
            comptime ResultType: type,
            comptime func: fn (Context) ErrorSet!ResultType,
        ) ErrorSet!ResultType {
            while (true) {
                return func(self.context) catch |err| {
                    if (self.on_retry) |callback| {
                        callback(self.context, self.backoff.getAttempt(), err);
                    }

                    if (self.backoff.nextDelay()) |delay_ms| {
                        std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                        continue;
                    }

                    return err;
                };
            }
        }

        pub fn reset(self: *Self) void {
            self.backoff.reset();
        }
    };
}

/// Simple retry function for one-off retries
/// Returns error.EntropyUnavailable if secure random is not available
pub fn retry(
    comptime func: anytype,
    args: anytype,
    config: Config,
) Backoff.InitError!@typeInfo(@TypeOf(func)).@"fn".return_type.? {
    var backoff = try Backoff.init(config);

    while (true) {
        return @call(.auto, func, args) catch |err| {
            if (backoff.nextDelay()) |delay_ms| {
                std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
    }
}

/// Calculate delay without creating a full Backoff instance
pub fn calculateDelay(
    strategy: Strategy,
    attempt: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
) u64 {
    return switch (strategy) {
        .constant => @min(base_delay_ms, max_delay_ms),
        .linear => @min(base_delay_ms *| (attempt + 1), max_delay_ms),
        .exponential, .exponential_full_jitter, .exponential_equal_jitter, .exponential_decorrelated_jitter => blk: {
            if (attempt >= 63) break :blk max_delay_ms;
            const shift: u6 = @intCast(@min(attempt, 63));
            break :blk @min(base_delay_ms *| (@as(u64, 1) << shift), max_delay_ms);
        },
    };
}

/// Predefined configurations
pub const Presets = struct {
    /// Aggressive retry for fast-failing operations
    pub const aggressive = Config{
        .strategy = .exponential_full_jitter,
        .base_delay_ms = 10,
        .max_delay_ms = 1_000,
        .max_retries = 5,
    };

    /// Standard retry for typical network operations
    pub const standard = Config{
        .strategy = .exponential_full_jitter,
        .base_delay_ms = 100,
        .max_delay_ms = 30_000,
        .max_retries = 10,
    };

    /// Patient retry for slow operations
    pub const patient = Config{
        .strategy = .exponential_equal_jitter,
        .base_delay_ms = 500,
        .max_delay_ms = 60_000,
        .max_retries = 15,
    };

    /// DNS-specific retry preset
    pub const dns = Config{
        .strategy = .exponential_full_jitter,
        .base_delay_ms = 100,
        .max_delay_ms = 5_000,
        .max_retries = 3,
    };

    /// DNS recursive resolution preset
    pub const dns_recursive = Config{
        .strategy = .exponential_decorrelated_jitter,
        .base_delay_ms = 200,
        .max_delay_ms = 10_000,
        .max_retries = 5,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "Backoff constant strategy" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .constant, .base_delay_ms = 100, .max_retries = 3 },
        12345,
    );

    try std.testing.expectEqual(@as(u64, 100), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 100), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 100), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(?u64, null), backoff.nextDelay());
}

test "Backoff linear strategy" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .linear, .base_delay_ms = 100, .max_delay_ms = 1000, .max_retries = 5 },
        12345,
    );

    try std.testing.expectEqual(@as(u64, 100), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 200), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 300), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 400), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 500), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(?u64, null), backoff.nextDelay());
}

test "Backoff exponential strategy" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .exponential, .base_delay_ms = 100, .max_delay_ms = 10000, .max_retries = 5 },
        12345,
    );

    try std.testing.expectEqual(@as(u64, 100), backoff.nextDelay().?); // 100 * 2^0
    try std.testing.expectEqual(@as(u64, 200), backoff.nextDelay().?); // 100 * 2^1
    try std.testing.expectEqual(@as(u64, 400), backoff.nextDelay().?); // 100 * 2^2
    try std.testing.expectEqual(@as(u64, 800), backoff.nextDelay().?); // 100 * 2^3
    try std.testing.expectEqual(@as(u64, 1600), backoff.nextDelay().?); // 100 * 2^4
}

test "Backoff exponential with max delay cap" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .exponential, .base_delay_ms = 1000, .max_delay_ms = 5000, .max_retries = 10 },
        12345,
    );

    try std.testing.expectEqual(@as(u64, 1000), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 2000), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 4000), backoff.nextDelay().?);
    try std.testing.expectEqual(@as(u64, 5000), backoff.nextDelay().?); // capped
    try std.testing.expectEqual(@as(u64, 5000), backoff.nextDelay().?); // still capped
}

test "Backoff full jitter produces values in range" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .exponential_full_jitter, .base_delay_ms = 100, .max_delay_ms = 10000, .max_retries = 100 },
        12345,
    );

    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const delay = backoff.nextDelay().?;
        const max_expected = calculateDelay(.exponential, i, 100, 10000);
        try std.testing.expect(delay <= max_expected);
    }
}

test "Backoff equal jitter produces values in range" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .exponential_equal_jitter, .base_delay_ms = 100, .max_delay_ms = 10000, .max_retries = 100 },
        12345,
    );

    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        const delay = backoff.nextDelay().?;
        const exp_delay = calculateDelay(.exponential, i, 100, 10000);
        try std.testing.expect(delay >= exp_delay / 2);
        try std.testing.expect(delay <= exp_delay);
    }
}

test "Backoff reset" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .exponential, .base_delay_ms = 100, .max_retries = 3 },
        12345,
    );

    _ = backoff.nextDelay();
    _ = backoff.nextDelay();
    try std.testing.expectEqual(@as(u32, 2), backoff.getAttempt());

    backoff.reset();
    try std.testing.expectEqual(@as(u32, 0), backoff.getAttempt());
    try std.testing.expectEqual(@as(u64, 100), backoff.nextDelay().?);
}

test "Backoff shouldRetry" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .constant, .base_delay_ms = 100, .max_retries = 2 },
        12345,
    );

    try std.testing.expect(backoff.shouldRetry());
    _ = backoff.nextDelay();
    try std.testing.expect(backoff.shouldRetry());
    _ = backoff.nextDelay();
    try std.testing.expect(!backoff.shouldRetry());
}

test "Backoff unlimited retries" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .constant, .base_delay_ms = 100, .max_retries = 0 },
        12345,
    );

    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expect(backoff.shouldRetry());
        try std.testing.expect(backoff.nextDelay() != null);
    }
}

test "Backoff remainingRetries" {
    var backoff = Backoff.initWithSeed(
        Config{ .strategy = .constant, .base_delay_ms = 100, .max_retries = 5 },
        12345,
    );

    try std.testing.expectEqual(@as(u32, 5), backoff.remainingRetries());
    _ = backoff.nextDelay();
    try std.testing.expectEqual(@as(u32, 4), backoff.remainingRetries());
}

test "Config builder pattern" {
    const base = Config{};
    const config = base
        .withStrategy(.exponential_full_jitter)
        .withBaseDelay(200)
        .withMaxDelay(10000)
        .withMaxRetries(5);

    try std.testing.expectEqual(Strategy.exponential_full_jitter, config.strategy);
    try std.testing.expectEqual(@as(u64, 200), config.base_delay_ms);
    try std.testing.expectEqual(@as(u64, 10000), config.max_delay_ms);
    try std.testing.expectEqual(@as(u32, 5), config.max_retries);
}

test "Presets are valid" {
    var aggressive = Backoff.initWithSeed(Presets.aggressive, 12345);
    try std.testing.expect(aggressive.nextDelay() != null);

    var standard = Backoff.initWithSeed(Presets.standard, 12345);
    try std.testing.expect(standard.nextDelay() != null);

    var patient = Backoff.initWithSeed(Presets.patient, 12345);
    try std.testing.expect(patient.nextDelay() != null);

    var dns = Backoff.initWithSeed(Presets.dns, 12345);
    try std.testing.expect(dns.nextDelay() != null);
}

test "calculateDelay utility function" {
    try std.testing.expectEqual(@as(u64, 100), calculateDelay(.constant, 0, 100, 1000));
    try std.testing.expectEqual(@as(u64, 100), calculateDelay(.constant, 5, 100, 1000));

    try std.testing.expectEqual(@as(u64, 100), calculateDelay(.linear, 0, 100, 1000));
    try std.testing.expectEqual(@as(u64, 500), calculateDelay(.linear, 4, 100, 1000));
    try std.testing.expectEqual(@as(u64, 1000), calculateDelay(.linear, 10, 100, 1000)); // capped

    try std.testing.expectEqual(@as(u64, 100), calculateDelay(.exponential, 0, 100, 10000));
    try std.testing.expectEqual(@as(u64, 800), calculateDelay(.exponential, 3, 100, 10000));
    try std.testing.expectEqual(@as(u64, 10000), calculateDelay(.exponential, 10, 100, 10000)); // capped
}
