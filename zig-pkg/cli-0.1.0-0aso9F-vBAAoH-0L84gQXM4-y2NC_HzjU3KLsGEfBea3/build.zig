// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ========================================================================
    // External Dependencies
    // ========================================================================

    const config_dep = b.dependency("config", .{
        .target = target,
        .optimize = optimize,
    });
    const ext_config_mod = config_dep.module("config");

    // ========================================================================
    // Define Library Modules
    // ========================================================================
    //
    // Module organization follows Cobra/Viper patterns:
    // - cli: Command-line parsing, help, completions
    // - config: Configuration loading with XDG, precedence, secrets (from external lib)
    // - term: Terminal utilities (TTY, color, pager, progress)
    // - util: Common utilities (errors, suggestions, text, fs)

    // CLI Module
    const cli_mod = b.addModule("cli", .{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Config Module (wrapper around external config library)
    const config_mod = b.addModule("config", .{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "config", .module = ext_config_mod },
        },
    });

    // Terminal Module
    const term_mod = b.addModule("term", .{
        .root_source_file = b.path("src/term.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Utility Module
    const util_mod = b.addModule("util", .{
        .root_source_file = b.path("src/util.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Root Module: Public API
    _ = b.addModule("zig_cli", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ========================================================================
    // Unit Tests
    // ========================================================================

    // CLI module tests
    const cli_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    // Config module tests
    const config_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "config", .module = ext_config_mod },
            },
        }),
    });
    const run_config_tests = b.addRunArtifact(config_tests);

    // Term module tests
    const term_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/term.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_term_tests = b.addRunArtifact(term_tests);

    // Util module tests
    const util_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/util.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_util_tests = b.addRunArtifact(util_tests);

    // Root module tests
    const root_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_root_tests = b.addRunArtifact(root_tests);

    // Test step: runs all unit tests
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_config_tests.step);
    test_step.dependOn(&run_term_tests.step);
    test_step.dependOn(&run_util_tests.step);
    test_step.dependOn(&run_root_tests.step);

    // ========================================================================
    // Integration Tests
    // ========================================================================

    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "cli", .module = cli_mod },
                .{ .name = "config", .module = config_mod },
                .{ .name = "term", .module = term_mod },
                .{ .name = "util", .module = util_mod },
            },
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_integration_step = b.step("test-integration", "Run integration tests");
    test_integration_step.dependOn(&run_integration_tests.step);

    // ========================================================================
    // All Tests
    // ========================================================================

    const test_all_step = b.step("test-all", "Run all tests (unit + integration)");
    test_all_step.dependOn(test_step);
    test_all_step.dependOn(test_integration_step);

    // ========================================================================
    // Check Step (for IDE integration)
    // ========================================================================

    const check_cli = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const check_config = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "config", .module = ext_config_mod },
            },
        }),
    });
    const check_term = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/term.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const check_util = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/util.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const check_root = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const check_step = b.step("check", "Check for compilation errors (for IDE integration)");
    check_step.dependOn(&check_cli.step);
    check_step.dependOn(&check_config.step);
    check_step.dependOn(&check_term.step);
    check_step.dependOn(&check_util.step);
    check_step.dependOn(&check_root.step);

    // ========================================================================
    // Demo Executable
    // ========================================================================

    const demo = b.addExecutable(.{
        .name = "demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "cli", .module = cli_mod },
                .{ .name = "config", .module = config_mod },
                .{ .name = "term", .module = term_mod },
                .{ .name = "util", .module = util_mod },
            },
        }),
    });

    b.installArtifact(demo);

    const run_demo = b.addRunArtifact(demo);
    if (b.args) |args| {
        run_demo.addArgs(args);
    }

    const run_step = b.step("run", "Build and run the demo");
    run_step.dependOn(&run_demo.step);
}
