# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-11

First release. Targets `net10.0` with no third-party dependencies.

### Added

- **DPAPI secret protection**
  - `ISecretProtector` — the substitutable contract: `Protect` / `Unprotect` / `TryUnprotect` for both strings and bytes,
    plus an `IsSupported` platform check.
  - `DpapiSecretProtector` — Windows DPAPI implementation. Output is Base64 with an `OZDP` envelope (magic, format
    version, protection scope) so malformed payloads, unknown versions and scope mismatches are detected before
    decryption is attempted. Throws `PlatformNotSupportedException` with actionable guidance on non-Windows platforms.
  - `DpapiProtectionOptions` — immutable options for the protection scope and optional additional entropy.
  - `SecretProtectionScope` — `CurrentUser` (default) and `LocalMachine`, kept platform-neutral so the public API stays
    usable off Windows.
- **Log masking**
  - `SecretMasker` — masks plain strings (`abcd****wxyz`), sensitive URL query parameters, and JSON fields.
    Values too short to keep both ends visible are masked entirely, and the mask segment has a fixed length so the
    output never leaks the original length. `TryMaskJson` keeps logging paths from throwing on invalid JSON.
  - `SecretMaskOptions` — visible prefix/suffix lengths, mask character and length, the minimum number of hidden
    characters, and an extensible list of sensitive field names. Name matching is always case-insensitive.
- **Configuration encryption**
  - `ConfigurationProtector` — AES-GCM encryption with a fresh nonce per call and an `OZCF` versioned envelope that
    doubles as the authenticated associated data. `IsProtectedValue` tells encrypted values from plain ones without the
    key.
  - `KeyDerivation` — PBKDF2 (HMAC-SHA256) key derivation with a 600,000 iteration default and a 100,000 minimum, plus
    cryptographically secure salt and key generation. No built-in key and no hard-coded salt.
- `SecretProtectionException` and `SecretProtectionFailureReason` — a single classified failure model shared by both
  protection paths.

[Unreleased]: https://github.com/ozakboy/Ozakboy.Security/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ozakboy/Ozakboy.Security/releases/tag/v0.1.0
