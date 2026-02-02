// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ========================================================================
    // Build Options
    // ========================================================================

    const feature_doq = b.option(bool, "feature_doq", "Enable DNS over QUIC support") orelse false;
    const enable_spice = b.option(bool, "spice", "Enable spice-based parallelism") orelse true;

    const build_options = b.addOptions();
    build_options.addOption(bool, "feature_doq", feature_doq);
    build_options.addOption(bool, "enable_spice", enable_spice);

    // Get spice dependency if enabled
    const spice_mod: ?*std.Build.Module = if (enable_spice) blk: {
        const spice_dep = b.dependency("spice", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk spice_dep.module("spice");
    } else null;

    // ========================================================================
    // Define all DNS modules
    // ========================================================================
    //
    // Module organization follows RFC structure:
    // - Core protocol (name, header, question, record, message)
    // - Record types (types, rdata)
    // - Resolution (resolver, stub, recursive, cache)
    // - Transport (client, server)
    // - Utilities (compression, edns)

    // RFC 1035 Section 3.1: Name Space Definitions
    // DNS name handling (labels, compression, encoding)
    const name_mod = b.addModule("name", .{
        .root_source_file = b.path("src/name.zig"),
        .target = target,
    });

    // RFC 1035 Section 4.1.1: Header Section Format
    // DNS message header structure
    const header_mod = b.addModule("header", .{
        .root_source_file = b.path("src/header.zig"),
        .target = target,
    });

    // RFC 1035 Section 3.2: RR Definitions
    // DNS resource record types (A, AAAA, CNAME, MX, etc.)
    const types_mod = b.addModule("types", .{
        .root_source_file = b.path("src/types.zig"),
        .target = target,
    });

    // RFC 1035 Section 4.1.2: Question Section Format
    // DNS question section handling
    const question_mod = b.addModule("question", .{
        .root_source_file = b.path("src/question.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
        },
    });

    // RFC 1035 Section 4.1.3: Resource Record Format
    // DNS resource record parsing and encoding
    const record_mod = b.addModule("record", .{
        .root_source_file = b.path("src/record.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
        },
    });

    // RFC 1035 Section 4: Messages
    // Complete DNS message handling
    const message_mod = b.addModule("message", .{
        .root_source_file = b.path("src/message.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "name", .module = name_mod },
            .{ .name = "header", .module = header_mod },
            .{ .name = "question", .module = question_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "types", .module = types_mod },
        },
    });

    // RFC 6891: Extension Mechanisms for DNS (EDNS0)
    // Extended DNS options and OPT record handling
    const edns_mod = b.addModule("edns", .{
        .root_source_file = b.path("src/edns.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "types", .module = types_mod },
        },
    });

    // Cache Poisoning Protection (RFC 5452)
    const cache_protection_mod = b.addModule("cache_protection", .{
        .root_source_file = b.path("src/resolver/cache_protection.zig"),
        .target = target,
    });

    // DNS caching (RFC 1035 Section 7.4)
    // TTL-based response caching
    const cache_mod = b.addModule("cache", .{
        .root_source_file = b.path("src/cache.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "cache_protection", .module = cache_protection_mod },
        },
    });

    // RFC 1034 Section 5.3.3: Stub Resolver
    // Simple forwarding resolver
    const stub_mod = b.addModule("stub", .{
        .root_source_file = b.path("src/stub.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "message", .module = message_mod },
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
            .{ .name = "header", .module = header_mod },
            .{ .name = "question", .module = question_mod },
            .{ .name = "record", .module = record_mod },
        },
    });

    // RFC 1034 Section 5.3: Recursive Resolver
    // Full recursive name resolution
    const recursive_mod = b.addModule("recursive", .{
        .root_source_file = b.path("src/recursive.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "message", .module = message_mod },
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
            .{ .name = "header", .module = header_mod },
            .{ .name = "question", .module = question_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "cache", .module = cache_mod },
            .{ .name = "stub", .module = stub_mod },
        },
    });

    // DNS Client - High-level resolution interface
    // Combines stub and recursive resolution
    const client_mod = b.addModule("client", .{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "message", .module = message_mod },
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
            .{ .name = "header", .module = header_mod },
            .{ .name = "question", .module = question_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "stub", .module = stub_mod },
            .{ .name = "recursive", .module = recursive_mod },
            .{ .name = "cache", .module = cache_mod },
            .{ .name = "edns", .module = edns_mod },
        },
    });

    // ========================================================================
    // Utility Modules (for deterministic testing)
    // ========================================================================

    // Clock abstraction for deterministic testing
    const clock_mod = b.addModule("util_clock", .{
        .root_source_file = b.path("src/util/clock.zig"),
        .target = target,
    });

    // Random abstraction for deterministic testing
    const random_mod = b.addModule("util_random", .{
        .root_source_file = b.path("src/util/random.zig"),
        .target = target,
    });

    // LRU Cache implementation
    const lru_mod = b.addModule("util_lru", .{
        .root_source_file = b.path("src/util/lru.zig"),
        .target = target,
    });

    // Prometheus-style metrics
    const metrics_mod = b.addModule("util_metrics", .{
        .root_source_file = b.path("src/util/metrics.zig"),
        .target = target,
    });

    // Enhanced metrics (histograms, gauges, per-server stats)
    const enhanced_metrics_mod = b.addModule("util_enhanced_metrics", .{
        .root_source_file = b.path("src/util/enhanced_metrics.zig"),
        .target = target,
    });

    // Exponential backoff with jitter
    const backoff_mod = b.addModule("util_backoff", .{
        .root_source_file = b.path("src/util/backoff.zig"),
        .target = target,
    });

    // ========================================================================
    // Resolver Channel Abstraction
    // ========================================================================

    // Channel interface for all transports
    const channel_mod = b.addModule("resolver_channel", .{
        .root_source_file = b.path("src/resolver/channel.zig"),
        .target = target,
    });

    // EDNS(0) handling for resolver
    const resolver_edns_mod = b.addModule("resolver_edns", .{
        .root_source_file = b.path("src/resolver/edns.zig"),
        .target = target,
    });

    // DNS Cache with TTL clamping (RFC 2308 negative caching)
    const dns_cache_mod = b.addModule("dns_cache", .{
        .root_source_file = b.path("src/resolver/dns_cache.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "types", .module = types_mod },
            .{ .name = "lru", .module = lru_mod },
            .{ .name = "clock", .module = clock_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "message", .module = message_mod },
            .{ .name = "name", .module = name_mod },
        },
    });

    // Zone Transfer (RFC 5936 AXFR, RFC 1995 IXFR)
    const zone_transfer_mod = b.addModule("zone_transfer", .{
        .root_source_file = b.path("src/resolver/zone_transfer.zig"),
        .target = target,
    });

    // DNSSEC Validation (RFC 4033/4034/4035)
    const dnssec_mod = b.addModule("dnssec", .{
        .root_source_file = b.path("src/resolver/dnssec.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "record", .module = record_mod },
            .{ .name = "name", .module = name_mod },
            .{ .name = "types", .module = types_mod },
        },
    });

    // ========================================================================
    // Security Modules
    // ========================================================================

    // TSIG - Transaction Signature (RFC 2845)
    const tsig_mod = b.addModule("tsig", .{
        .root_source_file = b.path("src/security/tsig.zig"),
        .target = target,
    });

    // SIG(0) - DNS Request and Transaction Signatures (RFC 2931)
    const sig0_mod = b.addModule("sig0", .{
        .root_source_file = b.path("src/security/sig0.zig"),
        .target = target,
    });

    // Zone File Parser (RFC 1035 Section 5)
    const zone_file_mod = b.addModule("zone_file", .{
        .root_source_file = b.path("src/zone_file.zig"),
        .target = target,
    });
    _ = zone_file_mod;

    // Cache Prefetching
    const cache_prefetch_mod = b.addModule("cache_prefetch", .{
        .root_source_file = b.path("src/resolver/cache_prefetch.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "types", .module = types_mod },
            .{ .name = "dns_cache", .module = dns_cache_mod },
            .{ .name = "clock", .module = clock_mod },
        },
    });
    _ = cache_prefetch_mod; // Module available for external use

    // Server Failover and Load Balancing
    const failover_mod = b.addModule("failover", .{
        .root_source_file = b.path("src/resolver/failover.zig"),
        .target = target,
    });

    // Split DNS / Policy Routing
    const split_dns_mod = b.addModule("split_dns", .{
        .root_source_file = b.path("src/resolver/split_dns.zig"),
        .target = target,
    });

    // Response Policy Zones (RFC 8646)
    const rpz_mod = b.addModule("rpz", .{
        .root_source_file = b.path("src/resolver/rpz.zig"),
        .target = target,
    });

    // Query/Response Logging
    const logging_mod = b.addModule("logging", .{
        .root_source_file = b.path("src/resolver/logging.zig"),
        .target = target,
    });

    // Configuration File Support
    const config_mod = b.addModule("config", .{
        .root_source_file = b.path("src/resolver/config.zig"),
        .target = target,
    });

    // High-Level Convenience APIs
    const convenience_mod = b.addModule("convenience", .{
        .root_source_file = b.path("src/resolver/convenience.zig"),
        .target = target,
    });

    // ========================================================================
    // Transport Modules
    // ========================================================================

    // UDP Transport
    const udp_mod = b.addModule("transport_udp", .{
        .root_source_file = b.path("src/transports/udp.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "channel", .module = channel_mod },
        },
    });

    // TCP Transport
    const tcp_mod = b.addModule("transport_tcp", .{
        .root_source_file = b.path("src/transports/tcp.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "channel", .module = channel_mod },
        },
    });

    // DoT Transport (RFC 7858)
    const dot_mod = b.addModule("transport_dot", .{
        .root_source_file = b.path("src/transports/dot.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "channel", .module = channel_mod },
        },
    });

    // DoH Transport (RFC 8484)
    const doh_mod = b.addModule("transport_doh", .{
        .root_source_file = b.path("src/transports/doh.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "channel", .module = channel_mod },
        },
    });

    // DoQ Transport (RFC 9250) - Feature gated
    const doq_mod = b.addModule("transport_doq", .{
        .root_source_file = b.path("src/transports/doq.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "channel", .module = channel_mod },
            .{ .name = "build_options", .module = build_options.createModule() },
        },
    });

    // Connection Pool (RFC 7766/7828 - TCP Implementation Requirements)
    const connection_pool_mod = b.addModule("connection_pool", .{
        .root_source_file = b.path("src/transports/connection_pool.zig"),
        .target = target,
    });

    // Happy Eyeballs (RFC 8305 - Dual-Stack Connection Racing)
    const happy_eyeballs_mod = b.addModule("happy_eyeballs", .{
        .root_source_file = b.path("src/transports/happy_eyeballs.zig"),
        .target = target,
    });

    // Mark unused modules as used (used indirectly or for future expansion)
    _ = udp_mod;
    _ = tcp_mod;
    _ = doh_mod;
    _ = dnssec_mod;
    _ = tsig_mod;
    _ = sig0_mod;
    _ = connection_pool_mod;
    _ = happy_eyeballs_mod;
    _ = enhanced_metrics_mod;
    _ = backoff_mod;
    _ = failover_mod;
    _ = split_dns_mod;
    _ = rpz_mod;
    _ = logging_mod;
    _ = config_mod;
    _ = convenience_mod;

    // ========================================================================
    // Public API Module - Main Entry Point
    // ========================================================================
    //
    // The "dns" module provides the stable public API surface.
    // All other modules are re-exported through src/lib.zig for
    // backward compatibility and ease of use.
    //
    // Usage: const dns = @import("dns");
    //        const message = dns.message;
    //        const resolver = dns.client;

    // Parallel module for spice-based parallelism
    const parallel_mod = b.addModule("parallel", .{
        .root_source_file = b.path("src/parallel.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options.createModule() },
            .{ .name = "record", .module = record_mod },
            .{ .name = "message", .module = message_mod },
        },
    });
    if (spice_mod) |sm| {
        parallel_mod.addImport("spice", sm);
    }

    const dns_mod = b.addModule("dns", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "name", .module = name_mod },
            .{ .name = "header", .module = header_mod },
            .{ .name = "types", .module = types_mod },
            .{ .name = "question", .module = question_mod },
            .{ .name = "record", .module = record_mod },
            .{ .name = "message", .module = message_mod },
            .{ .name = "edns", .module = edns_mod },
            .{ .name = "cache", .module = cache_mod },
            .{ .name = "stub", .module = stub_mod },
            .{ .name = "recursive", .module = recursive_mod },
            .{ .name = "client", .module = client_mod },
            .{ .name = "parallel", .module = parallel_mod },
        },
    });

    // ========================================================================
    // zdig CLI - dig-like DNS query tool
    // ========================================================================
    //
    // A command-line DNS query tool similar to dig, built on this library.
    // Usage: zig build zdig -- example.com
    //        zig build run-zdig -- @8.8.8.8 example.com MX
    //
    // Note: zdig uses POSIX socket APIs and is not available on Windows.

    const target_info = target.result;
    const is_windows = target_info.os.tag == .windows;

    // CLI Module (from external zig-cli library via dependency)
    const cli_dep = b.dependency("cli", .{
        .target = target,
        .optimize = optimize,
    });
    const cli_mod = cli_dep.module("cli");

    if (!is_windows) {
        const zdig_exe = b.addExecutable(.{
            .name = "zdig",
            .root_module = b.createModule(.{
                .root_source_file = b.path("cmd/zdig.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dns", .module = dns_mod },
                    .{ .name = "cli", .module = cli_mod },
                },
            }),
        });

        // Install the executable
        b.installArtifact(zdig_exe);

        // Create a run step for the CLI
        const run_zdig = b.addRunArtifact(zdig_exe);
        run_zdig.step.dependOn(b.getInstallStep());

        // Pass command line arguments to zdig
        if (b.args) |args| {
            run_zdig.addArgs(args);
        }

        const run_zdig_step = b.step("run-zdig", "Run the zdig DNS query tool");
        run_zdig_step.dependOn(&run_zdig.step);

        // Also create a "zdig" build step that just builds (no run)
        const zdig_step = b.step("zdig", "Build the zdig DNS query tool");
        zdig_step.dependOn(&zdig_exe.step);
    }

    // ========================================================================
    // Unit Tests - Test each module independently
    // ========================================================================

    const test_step = b.step("test", "Run all unit tests");

    // Helper to create test with imports
    const TestInfo = struct {
        name: []const u8,
        source: []const u8,
        imports: []const std.Build.Module.Import,
    };

    const tests = [_]TestInfo{
        .{ .name = "name", .source = "src/name.zig", .imports = &.{} },
        .{ .name = "header", .source = "src/header.zig", .imports = &.{} },
        .{ .name = "types", .source = "src/types.zig", .imports = &.{} },
        .{
            .name = "question",
            .source = "src/question.zig",
            .imports = &.{
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
            },
        },
        .{
            .name = "record",
            .source = "src/record.zig",
            .imports = &.{
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
            },
        },
        .{
            .name = "message",
            .source = "src/message.zig",
            .imports = &.{
                .{ .name = "name", .module = name_mod },
                .{ .name = "header", .module = header_mod },
                .{ .name = "question", .module = question_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "types", .module = types_mod },
            },
        },
        .{
            .name = "edns",
            .source = "src/edns.zig",
            .imports = &.{
                .{ .name = "types", .module = types_mod },
            },
        },
        .{
            .name = "cache",
            .source = "src/cache.zig",
            .imports = &.{
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "cache_protection", .module = cache_protection_mod },
            },
        },
        .{
            .name = "stub",
            .source = "src/stub.zig",
            .imports = &.{
                .{ .name = "message", .module = message_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
                .{ .name = "header", .module = header_mod },
                .{ .name = "question", .module = question_mod },
                .{ .name = "record", .module = record_mod },
            },
        },
        .{
            .name = "recursive",
            .source = "src/recursive.zig",
            .imports = &.{
                .{ .name = "message", .module = message_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
                .{ .name = "header", .module = header_mod },
                .{ .name = "question", .module = question_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "cache", .module = cache_mod },
                .{ .name = "stub", .module = stub_mod },
            },
        },
        .{
            .name = "client",
            .source = "src/client.zig",
            .imports = &.{
                .{ .name = "message", .module = message_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
                .{ .name = "header", .module = header_mod },
                .{ .name = "question", .module = question_mod },
                .{ .name = "record", .module = record_mod },
                .{ .name = "stub", .module = stub_mod },
                .{ .name = "recursive", .module = recursive_mod },
                .{ .name = "cache", .module = cache_mod },
                .{ .name = "edns", .module = edns_mod },
            },
        },
    };

    for (tests) |test_info| {
        const unit_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_info.source),
                .target = target,
                .optimize = optimize,
                .imports = test_info.imports,
            }),
        });

        const run_test = b.addRunArtifact(unit_test);
        test_step.dependOn(&run_test.step);
    }

    // Lib tests
    const lib_test = b.addTest(.{
        .root_module = dns_mod,
    });
    const run_lib_test = b.addRunArtifact(lib_test);
    test_step.dependOn(&run_lib_test.step);

    // ========================================================================
    // RFC Test Vectors
    // ========================================================================

    const test_vectors_step = b.step("test-vectors", "Run RFC 1035/8484/8499 test vector validation");

    const vectors_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc1035_vectors.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dns", .module = dns_mod },
                .{ .name = "message", .module = message_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "header", .module = header_mod },
                .{ .name = "types", .module = types_mod },
            },
        }),
    });

    const run_vectors_test = b.addRunArtifact(vectors_test);
    test_vectors_step.dependOn(&run_vectors_test.step);

    // Add to main test step
    test_step.dependOn(test_vectors_step);

    // ========================================================================
    // RFC-Specific Test Suites - Organized by RFC section
    // ========================================================================

    // RFC 1035: Domain Names - Implementation and Specification
    const test_rfc1035_step = b.step("test-rfc1035", "Run RFC 1035 (DNS) test suite");

    const rfc1035_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc1035/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dns", .module = dns_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "header", .module = header_mod },
                .{ .name = "message", .module = message_mod },
                .{ .name = "types", .module = types_mod },
                .{ .name = "question", .module = question_mod },
                .{ .name = "record", .module = record_mod },
            },
        }),
    });

    const run_rfc1035_test = b.addRunArtifact(rfc1035_test);
    test_rfc1035_step.dependOn(&run_rfc1035_test.step);

    // Add RFC 1035 tests to main test suite
    test_step.dependOn(test_rfc1035_step);

    // RFC 3596: DNS Extensions to Support IPv6 (AAAA records)
    const test_rfc3596_step = b.step("test-rfc3596", "Run RFC 3596 (AAAA) test suite");

    const rfc3596_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc3596/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dns", .module = dns_mod },
                .{ .name = "types", .module = types_mod },
                .{ .name = "record", .module = record_mod },
            },
        }),
    });

    const run_rfc3596_test = b.addRunArtifact(rfc3596_test);
    test_rfc3596_step.dependOn(&run_rfc3596_test.step);

    test_step.dependOn(test_rfc3596_step);

    // RFC 6891: Extension Mechanisms for DNS (EDNS0)
    const test_rfc6891_step = b.step("test-rfc6891", "Run RFC 6891 (EDNS0) test suite");

    const rfc6891_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/rfc6891/mod.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "dns", .module = dns_mod },
                .{ .name = "edns", .module = edns_mod },
                .{ .name = "message", .module = message_mod },
                .{ .name = "types", .module = types_mod },
            },
        }),
    });

    const run_rfc6891_test = b.addRunArtifact(rfc6891_test);
    test_rfc6891_step.dependOn(&run_rfc6891_test.step);

    test_step.dependOn(test_rfc6891_step);

    // ========================================================================
    // Acceptance Tests - Mock I/O deterministic tests
    // ========================================================================

    const test_accept_step = b.step("test-accept", "Run acceptance tests with mocked I/O");

    const accept_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/accept.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "types", .module = types_mod },
                .{ .name = "message", .module = message_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "channel", .module = channel_mod },
                .{ .name = "dns_cache", .module = dns_cache_mod },
                .{ .name = "edns", .module = resolver_edns_mod },
                .{ .name = "clock", .module = clock_mod },
                .{ .name = "random", .module = random_mod },
                .{ .name = "metrics", .module = metrics_mod },
                .{ .name = "dot", .module = dot_mod },
                .{ .name = "doq", .module = doq_mod },
                .{ .name = "cache_protection", .module = cache_protection_mod },
                .{ .name = "zone_transfer", .module = zone_transfer_mod },
            },
        }),
    });

    const run_accept_test = b.addRunArtifact(accept_test);
    test_accept_step.dependOn(&run_accept_test.step);

    test_step.dependOn(test_accept_step);

    // ========================================================================
    // Utility Module Tests
    // ========================================================================

    const test_util_step = b.step("test-util", "Run utility module tests");

    const util_tests = [_][]const u8{
        "src/util/clock.zig",
        "src/util/random.zig",
        "src/util/lru.zig",
        "src/util/metrics.zig",
        "src/util/enhanced_metrics.zig",
        "src/util/backoff.zig",
    };

    for (util_tests) |test_source| {
        const util_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_source),
                .target = target,
                .optimize = optimize,
            }),
        });
        const run_util_test = b.addRunArtifact(util_test);
        test_util_step.dependOn(&run_util_test.step);
    }

    test_step.dependOn(test_util_step);

    // ========================================================================
    // Transport Module Tests
    // ========================================================================
    //
    // Note: Transport modules use relative imports for channel.zig.
    // Individual module tests are run through acceptance tests which
    // properly set up the import paths. Channel tests run standalone.

    const test_transport_step = b.step("test-transport", "Run transport module tests");

    // Channel tests (standalone, no external imports needed)
    const channel_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/channel.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_channel_test = b.addRunArtifact(channel_test);
    test_transport_step.dependOn(&run_channel_test.step);

    // Connection Pool tests (RFC 7766/7828)
    const connection_pool_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transports/connection_pool.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_connection_pool_test = b.addRunArtifact(connection_pool_test);
    test_transport_step.dependOn(&run_connection_pool_test.step);

    // Happy Eyeballs tests (RFC 8305)
    const happy_eyeballs_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transports/happy_eyeballs.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_happy_eyeballs_test = b.addRunArtifact(happy_eyeballs_test);
    test_transport_step.dependOn(&run_happy_eyeballs_test.step);

    test_step.dependOn(test_transport_step);

    // ========================================================================
    // Resolver Module Tests
    // ========================================================================
    //
    // Note: DNS cache uses relative imports for types/lru/clock.
    // Full integration tests run through acceptance tests.
    // EDNS tests run standalone since they have no dependencies.

    const test_resolver_step = b.step("test-resolver", "Run resolver module tests");

    // EDNS tests (standalone, no external imports)
    const resolver_edns_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/edns.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_resolver_edns_test = b.addRunArtifact(resolver_edns_test);
    test_resolver_step.dependOn(&run_resolver_edns_test.step);

    // Cache protection tests (standalone, no external imports)
    const cache_protection_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/cache_protection.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_cache_protection_test = b.addRunArtifact(cache_protection_test);
    test_resolver_step.dependOn(&run_cache_protection_test.step);

    // Zone transfer tests (standalone, no external imports)
    const zone_transfer_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/zone_transfer.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_zone_transfer_test = b.addRunArtifact(zone_transfer_test);
    test_resolver_step.dependOn(&run_zone_transfer_test.step);

    // DNSSEC tests (RFC 4033/4034/4035)
    const dnssec_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/dnssec.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "record", .module = record_mod },
                .{ .name = "name", .module = name_mod },
                .{ .name = "types", .module = types_mod },
            },
        }),
    });
    const run_dnssec_test = b.addRunArtifact(dnssec_test);
    test_resolver_step.dependOn(&run_dnssec_test.step);

    // Cache prefetching tests
    const cache_prefetch_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/cache_prefetch.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "types", .module = types_mod },
                .{ .name = "dns_cache", .module = dns_cache_mod },
                .{ .name = "clock", .module = clock_mod },
            },
        }),
    });
    const run_cache_prefetch_test = b.addRunArtifact(cache_prefetch_test);
    test_resolver_step.dependOn(&run_cache_prefetch_test.step);

    // Failover and load balancing tests
    const failover_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/failover.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_failover_test = b.addRunArtifact(failover_test);
    test_resolver_step.dependOn(&run_failover_test.step);

    // Split DNS tests
    const split_dns_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/split_dns.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_split_dns_test = b.addRunArtifact(split_dns_test);
    test_resolver_step.dependOn(&run_split_dns_test.step);

    // RPZ tests (RFC 8646)
    const rpz_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/rpz.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_rpz_test = b.addRunArtifact(rpz_test);
    test_resolver_step.dependOn(&run_rpz_test.step);

    // Logging tests
    const logging_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/logging.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_logging_test = b.addRunArtifact(logging_test);
    test_resolver_step.dependOn(&run_logging_test.step);

    // Config tests
    const config_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/config.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_config_test = b.addRunArtifact(config_test);
    test_resolver_step.dependOn(&run_config_test.step);

    // Convenience API tests
    const convenience_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver/convenience.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_convenience_test = b.addRunArtifact(convenience_test);
    test_resolver_step.dependOn(&run_convenience_test.step);

    test_step.dependOn(test_resolver_step);

    // ========================================================================
    // Security Module Tests
    // ========================================================================

    const test_security_step = b.step("test-security", "Run security module tests");

    // TSIG tests (RFC 2845)
    const tsig_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/security/tsig.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tsig_test = b.addRunArtifact(tsig_test);
    test_security_step.dependOn(&run_tsig_test.step);

    // SIG(0) tests (RFC 2931)
    const sig0_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/security/sig0.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_sig0_test = b.addRunArtifact(sig0_test);
    test_security_step.dependOn(&run_sig0_test.step);

    // Zone file tests
    const zone_file_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zone_file.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_zone_file_test = b.addRunArtifact(zone_file_test);
    test_security_step.dependOn(&run_zone_file_test.step);

    test_step.dependOn(test_security_step);

    // ========================================================================
    // Examples
    // ========================================================================
    //
    // Practical example programs demonstrating library usage.
    // Build all examples: zig build examples
    // Run individual examples: zig build run-basic-query

    const examples_step = b.step("examples", "Build all examples");

    // Helper struct for example configuration
    const ExampleInfo = struct {
        name: []const u8,
        description: []const u8,
        source: []const u8,
    };

    const examples = [_]ExampleInfo{
        .{
            .name = "basic_query",
            .description = "Basic DNS query using stub resolver",
            .source = "examples/basic_query.zig",
        },
        .{
            .name = "recursive_resolution",
            .description = "Full recursive resolution from root servers",
            .source = "examples/recursive_resolution.zig",
        },
        .{
            .name = "message_parsing",
            .description = "Low-level DNS message building and parsing",
            .source = "examples/message_parsing.zig",
        },
        .{
            .name = "custom_transport",
            .description = "Understanding DNS transport protocols",
            .source = "examples/custom_transport.zig",
        },
    };

    for (examples) |example| {
        // Create executable for each example
        const exe = b.addExecutable(.{
            .name = example.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(example.source),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "dns", .module = dns_mod },
                },
            }),
        });

        // Install the executable
        b.installArtifact(exe);
        examples_step.dependOn(&exe.step);

        // Create run step for this example
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());

        // Pass command line arguments if any
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        // Create named run step (e.g., "run-basic-query")
        const run_name = b.fmt("run-{s}", .{example.name});
        const run_step = b.step(run_name, example.description);
        run_step.dependOn(&run_cmd.step);
    }
}
