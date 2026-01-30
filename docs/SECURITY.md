# Security Guide

**Last Updated:** 2026-01-30

This document describes security considerations, hardening options, and best practices for using the zigdns library.

## Build Hardening (SEC-012)

### Recommended Build Configuration

For production deployments, use the following build options:

```bash
# Production build with safety checks
zig build -Doptimize=ReleaseSafe

# Or with explicit safety options
zig build -Doptimize=ReleaseFast -Dsafety=true
```

### Optimization Levels and Security

| Mode | Runtime Checks | Performance | Recommended For |
|------|---------------|-------------|-----------------|
| `Debug` | Full | Slow | Development, debugging |
| `ReleaseSafe` | Full | Good | **Production (recommended)** |
| `ReleaseFast` | Minimal | Best | Benchmarks, trusted inputs |
| `ReleaseSmall` | Minimal | Good | Embedded, size-constrained |

**Recommendation:** Use `ReleaseSafe` for production DNS servers. The overhead is minimal (~5-10%) compared to `ReleaseFast`, but you retain:
- Bounds checking on array accesses
- Integer overflow detection
- Null pointer checks
- Stack protection

### Security-Relevant Compiler Options

When building the library or applications using it:

```zig
// In build.zig, for the executable/library step:
const exe = b.addExecutable(.{
    .name = "my-dns-app",
    .root_source_file = b.path("src/main.zig"),
    .target = target,
    .optimize = .ReleaseSafe,  // Recommended
});

// Enable stack protection (default in ReleaseSafe)
exe.link_gc_sections = true;  // Remove unused code

// For additional hardening on Linux:
exe.link_libc();  // May be needed for PIE support
```

### Position-Independent Code (PIE/PIC)

For shared libraries or executables that benefit from ASLR:

```bash
# Build as position-independent executable
zig build -Dtarget=x86_64-linux -Dpic=true
```

### Memory Safety Features

Zig provides these safety features by default in safe builds:
- **Bounds Checking**: Array and slice access validated
- **Use-After-Free Detection**: Pointer validity checking
- **Integer Overflow**: Arithmetic overflow detection
- **Null Safety**: Optional type enforcement

To explicitly disable (NOT RECOMMENDED for production):
```bash
zig build -Doptimize=ReleaseFast  # Disables most runtime checks
```

## Transport Security

### DNS over TLS (DoT) Configuration

When implementing a TLS backend for DoT transport:

```
Minimum Requirements:
- TLS 1.2 or higher (TLS 1.3 preferred)
- Certificate validation enabled
- Hostname verification enabled
- AEAD cipher suites only
```

See `src/transports/dot.zig` for detailed backend requirements.

### DNS over HTTPS (DoH) Configuration

When implementing an HTTP backend for DoH transport:

```
Minimum Requirements:
- HTTP/2 support
- TLS 1.2+ (same requirements as DoT)
- Certificate validation enabled
- No HTTP-to-HTTPS redirects followed
```

See `src/transports/doh.zig` for detailed backend requirements.

## Authentication

### TSIG Authentication

For zone transfers and authenticated queries:

```zig
const tsig = @import("security/tsig");

// Use strong algorithms (NOT hmac_md5 or hmac_sha1)
const key = tsig.TsigKey.init(
    "transfer-key.example.com",
    .hmac_sha256,  // Recommended
    secret_bytes,
);
```

**Algorithm Recommendations:**
| Algorithm | Recommendation |
|-----------|---------------|
| `hmac_sha256` | **Recommended** |
| `hmac_sha384` | Good |
| `hmac_sha512` | Good |
| `hmac_sha1` | **Deprecated** - collision vulnerabilities |
| `hmac_md5` | **Deprecated** - known weaknesses |

### Zone Transfer Security

Always enable authentication for zone transfers:

```zig
const zt = @import("resolver/zone_transfer");

const config = zt.ZoneTransferConfig{
    .tsig_key = my_tsig_key,
    .require_auth = true,         // Enforce authentication
    .warn_unauthenticated = true, // Log warnings
};
```

## Entropy and Randomness

### Transaction ID Generation

The library requires cryptographically secure entropy for:
- DNS transaction ID generation (cache poisoning protection)
- 0x20 case randomization (spoofing protection)

The library will **fail initialization** if secure entropy is unavailable:

```zig
// This may return error.EntropyUnavailable
var resolver = try RecursiveResolver.init(allocator, config);
```

**Do NOT** fall back to timestamp-based seeding in production - this enables transaction ID prediction attacks (see RFC 5452).

## DNSSEC Considerations

### Algorithm Support

| Algorithm | Status | Notes |
|-----------|--------|-------|
| Ed25519 (15) | Supported | Recommended |
| ECDSA P-256 (13) | Supported | Widely compatible |
| ECDSA P-384 (14) | Supported | High security |
| RSA-SHA256 (8) | **NOT SUPPORTED** | Most common, limitation |
| RSA-SHA512 (10) | **NOT SUPPORTED** | Limitation |

**Note:** RSA algorithms are not implemented. See `src/resolver/dnssec.zig` for details. For full DNSSEC validation, consider using an external resolver.

## Input Validation

The library enforces these limits per RFC 1035:
- Maximum name length: 255 bytes
- Maximum label length: 63 bytes
- Maximum compression pointer hops: 16

These limits prevent:
- Buffer overflows from oversized names
- Infinite loops from malicious compression pointers
- Resource exhaustion attacks

## Deployment Checklist

- [ ] Build with `ReleaseSafe` optimization
- [ ] Enable TSIG authentication for zone transfers
- [ ] Use TLS 1.2+ for DoT/DoH transports
- [ ] Validate TLS certificates (no self-signed in production)
- [ ] Monitor for deprecation warnings (weak algorithms)
- [ ] Review transport backend security configuration
- [ ] Test entropy availability on target platform
- [ ] Configure rate limiting at network layer
- [ ] Enable logging for security events

## Reporting Security Issues

For security vulnerabilities, please report via:
- GitLab Security Advisory (preferred)
- Email: security@devnw.com

Do NOT report security issues in public issue trackers until coordinated disclosure is complete.
