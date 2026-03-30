// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Utility Module
//!
//! Common utilities:
//! - Error formatting
//! - Text manipulation
//! - Suggestion/typo correction
//! - Filesystem helpers

const std = @import("std");

pub const errors = @import("util/errors.zig");
pub const suggest = @import("util/suggest.zig");
pub const text = @import("util/text.zig");
pub const fs = @import("util/fs.zig");

// Re-export commonly used types
pub const Severity = errors.Severity;
pub const FormattedError = errors.FormattedError;
pub const ExitCode = errors.ExitCode;
pub const printError = errors.printError;
pub const printWarning = errors.printWarning;
pub const printErrorWithSuggestion = errors.printErrorWithSuggestion;

pub const levenshteinDistance = suggest.levenshteinDistance;
pub const suggestClosest = suggest.suggestClosest;
pub const suggestAll = suggest.suggestAll;

pub const wordWrap = text.wordWrap;
pub const indent = text.indent;
pub const padRight = text.padRight;
pub const padLeft = text.padLeft;
pub const truncate = text.truncate;

pub const FsError = fs.FsError;
pub const exists = fs.exists;
pub const isDirectory = fs.isDirectory;
pub const isFile = fs.isFile;
pub const readFile = fs.readFile;
pub const ensureDir = fs.ensureDir;
pub const redactPath = fs.redactPath;

// ============================================================================
// Tests
// ============================================================================

test {
    _ = errors;
    _ = suggest;
    _ = text;
    _ = fs;
}
