// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Zig CLI Library
//!
//! A comprehensive command-line interface and configuration management library
//! for Zig applications, providing Cobra/Viper-class features.
//!
//! ## Features
//!
//! ### CLI Features
//! - Nested command trees with subcommands
//! - Type-safe flag parsing (bool, int, float, string, path, arrays)
//! - Automatic help generation with examples-first approach
//! - Shell completion generation (bash, zsh, fish)
//! - Man page generation
//! - Error messages with typo suggestions
//!
//! ### Config Features
//! - Multiple format support (TOML, JSON, YAML)
//! - XDG Base Directory compliance
//! - Precedence: flags > env > project > user > system > defaults
//! - Secret handling (file/stdin only, never flags/env)
//! - Provenance tracking
//!
//! ### Terminal Features
//! - TTY detection
//! - ANSI color with NO_COLOR compliance
//! - Pager integration
//! - Progress indicators (spinners, bars)
//!
//! ## Quick Start
//!
//! ```zig
//! const zig_cli = @import("zig_cli");
//! const cli = zig_cli.cli;
//!
//! const root_cmd = cli.Command{
//!     .name = "myapp",
//!     .summary = "My application",
//!     .run = myRun,
//! };
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     defer _ = gpa.deinit();
//!
//!     const args = try std.process.argsAlloc(gpa.allocator());
//!     defer std.process.argsFree(gpa.allocator(), args);
//!
//!     const exit_code = try cli.run(&root_cmd, args, gpa.allocator());
//!     std.process.exit(exit_code);
//! }
//! ```

const std = @import("std");

pub const cli = @import("cli.zig");
pub const config = @import("config.zig");
pub const term = @import("term.zig");
pub const util = @import("util.zig");
pub const signal = @import("signal.zig");
pub const prompt = @import("prompt.zig");

/// Library version
pub const version = "0.0.0";

// ============================================================================
// Convenience Re-exports
// ============================================================================

// CLI types
pub const Command = cli.Command;
pub const Context = cli.Context;
pub const FlagSpec = cli.FlagSpec;
pub const FlagType = cli.FlagType;
pub const SecretPolicy = cli.SecretPolicy;
pub const ParseError = cli.ParseError;
pub const run = cli.run;
pub const generateCompletions = cli.generateCompletions;
pub const generateMan = cli.generateMan;

// Config types
pub const Loader = config.Loader;
pub const LoadOptions = config.LoadOptions;
pub const Source = config.Source;
pub const load = config.load;

// Terminal types
pub const Color = term.Color;
pub const Progress = term.Progress;
pub const ProgressBar = term.ProgressBar;

// Utility types
pub const suggestClosest = util.suggestClosest;
pub const ExitCode = util.ExitCode;

// Signal handling
pub const Signal = signal.Signal;
pub const installSignalHandlers = signal.install;
pub const wasInterrupted = signal.wasInterrupted;
pub const shouldShutdown = signal.shouldShutdown;
pub const onCleanup = signal.onCleanup;

// Interactive prompts
pub const PromptError = prompt.PromptError;
pub const InputConfig = prompt.InputConfig;
pub const promptInput = prompt.input;
pub const promptPassword = prompt.password;
pub const promptConfirm = prompt.confirm;
pub const promptSelect = prompt.select;
pub const promptMultiSelect = prompt.multiSelect;

// ============================================================================
// Tests
// ============================================================================

test {
    _ = cli;
    _ = config;
    _ = term;
    _ = util;
    _ = signal;
    _ = prompt;
}
