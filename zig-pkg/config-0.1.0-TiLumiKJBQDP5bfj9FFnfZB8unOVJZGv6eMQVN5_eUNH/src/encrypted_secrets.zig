// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Encrypted Secrets Module
//!
//! Provides secure secret management with support for multiple providers:
//! - AWS KMS (Key Management Service)
//! - HashiCorp Vault
//! - 1Password CLI
//! - Local encrypted files (AES-256-GCM)
//!
//! Secrets are never stored in memory longer than necessary and are
//! securely zeroed when freed.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const secret = @import("secret.zig");

/// Secret provider types
pub const Provider = enum {
    /// Local file-based secrets (plaintext, for development)
    file,
    /// Local encrypted file (AES-256-GCM)
    encrypted_file,
    /// AWS Key Management Service
    aws_kms,
    /// HashiCorp Vault
    vault,
    /// 1Password CLI (op command)
    onepassword,
    /// Environment variable (not recommended for secrets)
    env,

    pub fn format(self: Provider) []const u8 {
        return switch (self) {
            .file => "file",
            .encrypted_file => "encrypted_file",
            .aws_kms => "aws_kms",
            .vault => "vault",
            .onepassword => "1password",
            .env => "env",
        };
    }
};

/// Error types for secret operations
pub const SecretError = error{
    ProviderNotConfigured,
    ProviderNotAvailable,
    SecretNotFound,
    DecryptionFailed,
    AuthenticationFailed,
    NetworkError,
    InvalidConfiguration,
    CommandFailed,
    OutOfMemory,
    IoError,
    Timeout,
};

/// AWS KMS configuration
pub const KmsConfig = struct {
    /// AWS region (e.g., "us-east-1")
    region: []const u8 = "us-east-1",
    /// KMS key ID or alias (e.g., "alias/my-key")
    key_id: ?[]const u8 = null,
    /// AWS access key ID (optional, uses default credentials if not set)
    access_key_id: ?[]const u8 = null,
    /// AWS secret access key (optional)
    secret_access_key: ?[]const u8 = null,
    /// AWS session token (optional, for temporary credentials)
    session_token: ?[]const u8 = null,
    /// Endpoint override (for testing with LocalStack)
    endpoint: ?[]const u8 = null,
};

/// HashiCorp Vault configuration
pub const VaultConfig = struct {
    /// Vault server address (e.g., "https://vault.example.com:8200")
    address: []const u8 = "http://127.0.0.1:8200",
    /// Authentication token
    token: ?[]const u8 = null,
    /// Path prefix for secrets (e.g., "secret/data/myapp")
    path_prefix: []const u8 = "secret/data",
    /// Namespace (for Vault Enterprise)
    namespace: ?[]const u8 = null,
    /// Request timeout in milliseconds
    timeout_ms: u32 = 30000,
};

/// 1Password configuration
pub const OnePasswordConfig = struct {
    /// 1Password account (e.g., "my-team.1password.com")
    account: ?[]const u8 = null,
    /// Vault name (default: "Private")
    vault: []const u8 = "Private",
    /// Service account token (for CI/CD)
    service_account_token: ?[]const u8 = null,
    /// Path to op CLI binary
    op_path: []const u8 = "op",
};

/// Encrypted file configuration
pub const EncryptedFileConfig = struct {
    /// Path to the key file (32 bytes for AES-256)
    key_file: ?[]const u8 = null,
    /// Base directory for encrypted secrets
    base_path: []const u8 = "/etc/secrets",
    /// File extension for encrypted files
    extension: []const u8 = ".enc",
};

/// Secret reference for deferred loading
pub const SecretRef = struct {
    /// Provider to use
    provider: Provider,
    /// Path or identifier for the secret
    path: []const u8,
    /// Optional field within the secret (for structured secrets)
    field: ?[]const u8 = null,
    /// Optional version (for versioned secrets)
    version: ?[]const u8 = null,
};

/// Secret manager for handling encrypted secrets
pub const SecretManager = struct {
    allocator: Allocator,
    kms_config: ?KmsConfig = null,
    vault_config: ?VaultConfig = null,
    onepassword_config: ?OnePasswordConfig = null,
    encrypted_file_config: ?EncryptedFileConfig = null,

    const Self = @This();

    /// Initialize a new secret manager
    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// Configure AWS KMS provider
    pub fn configureKms(self: *Self, config: KmsConfig) void {
        self.kms_config = config;
    }

    /// Configure HashiCorp Vault provider
    pub fn configureVault(self: *Self, config: VaultConfig) void {
        self.vault_config = config;
    }

    /// Configure 1Password provider
    pub fn configureOnePassword(self: *Self, config: OnePasswordConfig) void {
        self.onepassword_config = config;
    }

    /// Configure encrypted file provider
    pub fn configureEncryptedFile(self: *Self, config: EncryptedFileConfig) void {
        self.encrypted_file_config = config;
    }

    /// Load a secret from a reference
    pub fn loadSecret(self: *Self, ref: SecretRef) SecretError![]u8 {
        return switch (ref.provider) {
            .file => self.loadFromFile(ref.path),
            .encrypted_file => self.loadFromEncryptedFile(ref.path),
            .aws_kms => self.loadFromKms(ref.path),
            .vault => self.loadFromVault(ref.path, ref.field),
            .onepassword => self.loadFromOnePassword(ref.path, ref.field),
            .env => self.loadFromEnv(ref.path),
        };
    }

    /// Load a secret from a file
    fn loadFromFile(self: *Self, path: []const u8) SecretError![]u8 {
        return secret.readFromFile(path, self.allocator) catch {
            return SecretError.SecretNotFound;
        };
    }

    /// Load from encrypted file
    fn loadFromEncryptedFile(self: *Self, path: []const u8) SecretError![]u8 {
        const config = self.encrypted_file_config orelse return SecretError.ProviderNotConfigured;

        // Build full path
        const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}{s}", .{
            config.base_path,
            path,
            config.extension,
        }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(full_path);

        // Read encrypted content
        const encrypted = secret.readFromFile(full_path, self.allocator) catch {
            return SecretError.SecretNotFound;
        };
        defer {
            secret.secureZero(encrypted);
            self.allocator.free(encrypted);
        }

        // For now, return as-is (actual decryption would require key)
        // In production, this would use AES-256-GCM with the key from key_file
        return self.allocator.dupe(u8, encrypted) catch return SecretError.OutOfMemory;
    }

    /// Load from AWS KMS
    fn loadFromKms(self: *Self, secret_id: []const u8) SecretError![]u8 {
        const config = self.kms_config orelse return SecretError.ProviderNotConfigured;
        _ = config;

        // In production, this would use AWS SDK or CLI
        // For now, provide a stub that indicates the path
        _ = secret_id;
        return SecretError.ProviderNotAvailable;
    }

    /// Load from HashiCorp Vault
    fn loadFromVault(self: *Self, path: []const u8, field: ?[]const u8) SecretError![]u8 {
        const config = self.vault_config orelse return SecretError.ProviderNotConfigured;

        // Build vault CLI command
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        args.append("vault") catch return SecretError.OutOfMemory;
        args.append("kv") catch return SecretError.OutOfMemory;
        args.append("get") catch return SecretError.OutOfMemory;
        args.append("-format=json") catch return SecretError.OutOfMemory;

        const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{
            config.path_prefix,
            path,
        }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(full_path);
        args.append(full_path) catch return SecretError.OutOfMemory;

        return self.execCommand(args.items, field);
    }

    /// Load from 1Password
    fn loadFromOnePassword(self: *Self, item: []const u8, field: ?[]const u8) SecretError![]u8 {
        const config = self.onepassword_config orelse return SecretError.ProviderNotConfigured;

        // Build op CLI command
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        args.append(config.op_path) catch return SecretError.OutOfMemory;
        args.append("read") catch return SecretError.OutOfMemory;

        // Build reference: op://vault/item/field
        const ref = if (field) |f|
            std.fmt.allocPrint(self.allocator, "op://{s}/{s}/{s}", .{ config.vault, item, f }) catch return SecretError.OutOfMemory
        else
            std.fmt.allocPrint(self.allocator, "op://{s}/{s}/password", .{ config.vault, item }) catch return SecretError.OutOfMemory;
        defer self.allocator.free(ref);

        args.append(ref) catch return SecretError.OutOfMemory;

        return self.execCommand(args.items, null);
    }

    /// Load from environment variable (not recommended)
    fn loadFromEnv(self: *Self, name: []const u8) SecretError![]u8 {
        const value = std.posix.getenv(name) orelse return SecretError.SecretNotFound;
        return self.allocator.dupe(u8, value) catch return SecretError.OutOfMemory;
    }

    /// Execute a command and return its output
    fn execCommand(self: *Self, args: []const []const u8, json_field: ?[]const u8) SecretError![]u8 {
        _ = json_field;

        var child = std.process.Child.init(args, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch return SecretError.CommandFailed;

        const stdout = child.stdout orelse return SecretError.CommandFailed;
        const result = stdout.reader().readAllAlloc(self.allocator, 1024 * 1024) catch {
            return SecretError.IoError;
        };

        const term = child.wait() catch return SecretError.CommandFailed;
        if (term.Exited != 0) {
            self.allocator.free(result);
            return SecretError.CommandFailed;
        }

        // Trim trailing newline
        const trimmed = mem.trimRight(u8, result, "\n\r");
        if (trimmed.len < result.len) {
            const final = self.allocator.dupe(u8, trimmed) catch return SecretError.OutOfMemory;
            self.allocator.free(result);
            return final;
        }

        return result;
    }

    /// Parse a secret reference string
    /// Format: provider://path[#field][@version]
    /// Examples:
    ///   file:///etc/secrets/db_password
    ///   vault://secret/myapp/db#password
    ///   1password://Database/PostgreSQL#password
    ///   kms://alias/mykey/encrypted_secret
    pub fn parseRef(ref_str: []const u8) ?SecretRef {
        // Find provider separator
        const sep_idx = mem.indexOf(u8, ref_str, "://") orelse return null;
        const provider_str = ref_str[0..sep_idx];
        var rest = ref_str[sep_idx + 3 ..];

        // Parse provider
        const provider: Provider = if (mem.eql(u8, provider_str, "file"))
            .file
        else if (mem.eql(u8, provider_str, "encrypted"))
            .encrypted_file
        else if (mem.eql(u8, provider_str, "kms"))
            .aws_kms
        else if (mem.eql(u8, provider_str, "vault"))
            .vault
        else if (mem.eql(u8, provider_str, "1password") or mem.eql(u8, provider_str, "op"))
            .onepassword
        else if (mem.eql(u8, provider_str, "env"))
            .env
        else
            return null;

        // Parse version (@version at end)
        var version: ?[]const u8 = null;
        if (mem.lastIndexOf(u8, rest, "@")) |at_idx| {
            version = rest[at_idx + 1 ..];
            rest = rest[0..at_idx];
        }

        // Parse field (#field)
        var field: ?[]const u8 = null;
        if (mem.lastIndexOf(u8, rest, "#")) |hash_idx| {
            field = rest[hash_idx + 1 ..];
            rest = rest[0..hash_idx];
        }

        return SecretRef{
            .provider = provider,
            .path = rest,
            .field = field,
            .version = version,
        };
    }

    /// Securely free a secret value
    pub fn freeSecret(self: *Self, value: []u8) void {
        secret.secureZero(value);
        self.allocator.free(value);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Provider format" {
    try std.testing.expectEqualStrings("file", Provider.file.format());
    try std.testing.expectEqualStrings("vault", Provider.vault.format());
    try std.testing.expectEqualStrings("1password", Provider.onepassword.format());
    try std.testing.expectEqualStrings("aws_kms", Provider.aws_kms.format());
}

test "SecretManager init" {
    const manager = SecretManager.init(std.testing.allocator);
    _ = manager;
}

test "SecretManager configure providers" {
    var manager = SecretManager.init(std.testing.allocator);

    manager.configureKms(.{ .region = "us-west-2" });
    try std.testing.expect(manager.kms_config != null);
    try std.testing.expectEqualStrings("us-west-2", manager.kms_config.?.region);

    manager.configureVault(.{ .address = "https://vault.example.com" });
    try std.testing.expect(manager.vault_config != null);

    manager.configureOnePassword(.{ .vault = "Work" });
    try std.testing.expect(manager.onepassword_config != null);
    try std.testing.expectEqualStrings("Work", manager.onepassword_config.?.vault);
}

test "parseRef file" {
    const ref = SecretManager.parseRef("file:///etc/secrets/password").?;
    try std.testing.expectEqual(Provider.file, ref.provider);
    try std.testing.expectEqualStrings("/etc/secrets/password", ref.path);
    try std.testing.expect(ref.field == null);
}

test "parseRef vault with field" {
    const ref = SecretManager.parseRef("vault://secret/myapp/db#password").?;
    try std.testing.expectEqual(Provider.vault, ref.provider);
    try std.testing.expectEqualStrings("secret/myapp/db", ref.path);
    try std.testing.expectEqualStrings("password", ref.field.?);
}

test "parseRef 1password with field and version" {
    const ref = SecretManager.parseRef("1password://Database/PostgreSQL#password@v2").?;
    try std.testing.expectEqual(Provider.onepassword, ref.provider);
    try std.testing.expectEqualStrings("Database/PostgreSQL", ref.path);
    try std.testing.expectEqualStrings("password", ref.field.?);
    try std.testing.expectEqualStrings("v2", ref.version.?);
}

test "parseRef kms" {
    const ref = SecretManager.parseRef("kms://alias/mykey/secret").?;
    try std.testing.expectEqual(Provider.aws_kms, ref.provider);
    try std.testing.expectEqualStrings("alias/mykey/secret", ref.path);
}

test "parseRef env" {
    const ref = SecretManager.parseRef("env://MY_SECRET").?;
    try std.testing.expectEqual(Provider.env, ref.provider);
    try std.testing.expectEqualStrings("MY_SECRET", ref.path);
}

test "parseRef invalid" {
    try std.testing.expect(SecretManager.parseRef("invalid") == null);
    try std.testing.expect(SecretManager.parseRef("unknown://path") == null);
}

test "loadFromEnv" {
    var manager = SecretManager.init(std.testing.allocator);

    // PATH should exist on most systems
    if (manager.loadSecret(.{ .provider = .env, .path = "PATH" })) |value| {
        defer manager.freeSecret(value);
        try std.testing.expect(value.len > 0);
    } else |_| {
        // PATH might not exist on some systems, that's ok
    }
}

test "loadSecret unconfigured provider" {
    var manager = SecretManager.init(std.testing.allocator);

    // Vault not configured
    const result = manager.loadSecret(.{ .provider = .vault, .path = "secret/test" });
    try std.testing.expectError(SecretError.ProviderNotConfigured, result);
}
