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
  - `DpapiProtectionOptions.Entropy` is documented for what it actually does: additional entropy keeps out other
    programs that hold the file without knowing the entropy (generic DPAPI tools, restored backups). It does **not**
    keep out code running as the same user — an application constant is compiled into the assembly and can be
    decompiled back out. Stopping same-account code requires a passphrase typed in at start-up that never touches disk.
- **Log masking**
  - `SecretMasker` — masks plain strings (`abcd****wxyz`), sensitive URL query parameters, and JSON fields.
    Values too short to keep both ends visible are masked entirely, and the mask segment has a fixed length so the
    output never leaks the original length. `TryMaskJson` keeps logging paths from throwing on invalid JSON.
  - `SecretMasker.RegisterKnownSecret` / `MaskText` / `ClearKnownSecrets` / `KnownSecretCount` — a registry of known
    secret literals and a global replacement over free-form text, for the leak paths the other three APIs cannot see:
    formatted log messages (`logger.LogError("… key={Key}", apiKey)`) and credentials embedded in exception text.
    Registration is thread-safe through an immutable-snapshot swap, so `MaskText` reads without a lock and allocates
    nothing when there is no match. Values below `MinimumKnownSecretLength` (8) are rejected, and the rejection message
    never echoes the value. Matching is ordinal and case-sensitive; hexadecimal values are additionally registered in
    both casings. `MaskJson` and `MaskQueryString` run their output through the registry as well.
  - `SecretMasker.MaximumRevealedLengthDivisor` — an unconditional floor: no configuration can reveal more than a
    third of a value. Both ends shrink proportionally when the configured lengths would exceed it, so a 12-character
    value reveals 2 + 2 rather than 4 + 4.
  - `SecretMaskOptions.UseSubstringMatching` (default `true`) with `DefaultSensitiveNameFragments` and
    `AdditionalSensitiveNameFragments` — a name containing `key`, `secret`, `token`, `password`, `credential` and
    similar fragments counts as sensitive, which is what catches `binanceApiKey`, `api_key_1` and `Api-Key-Secret`.
  - `SecretMaskOptions.DefaultFullMaskNames` / `DefaultFullMaskNameFragments` and
    `SecretMasker.IsAlwaysFullyMaskedName` — password-like fields (`password`, `passwd`, `pwd`, `passphrase`,
    `mnemonic`, `privateKey`, `pin`, `seed`) are always masked in full, because human passwords carry too little
    entropy for the keep-both-ends rule.
  - `MinimumHiddenLength` now has a floor of 1. Zero used to be accepted, which let an eight-character secret render
    as `abcd****efgh` — every original character intact while looking masked.
  - The built-in name list now covers the exchange headers and credential kinds it was missing: `x-mbx-apikey`,
    `x-mbx-api-key`, `bearer`, `jwt`, `otp`, `totp`, `mnemonic`, `seed`, `sessionId`, `sessionKey`, `webhookSecret`,
    `recoveryCode`, `proxy-authorization` and more.
  - `MaskQueryString` percent-decodes parameter names before matching them, so `?api%4Bey=…` no longer slips past,
    while the original spelling is preserved in the output — the query path now matches on the same basis as the JSON
    path. It also masks the password in `//user:password@host` style targets, which previously reached the log intact
    because such a target has no `?` at all.
  - `SecretMaskOptions` — visible prefix/suffix lengths, mask character and length, the minimum number of hidden
    characters, and extensible lists of sensitive names, sensitive fragments and always-fully-masked names. Name
    matching is always case-insensitive.
- **Configuration encryption**
  - `ConfigurationProtector` — AES-GCM encryption with a fresh nonce per call and an `OZCF` versioned envelope that
    doubles as the authenticated associated data. `IsProtectedValue` tells encrypted values from plain ones without the
    key; `IsSupported` reports whether the platform offers AES-GCM at all, and `TryDecrypt` returns `false` instead of
    letting `PlatformNotSupportedException` escape.
  - The associated-data claim is stated precisely: with only format version 1 in existence, a tampered magic or version
    is rejected by the format check before AES-GCM is reached. The test suite proves the associated data is genuinely
    enforced by decrypting an envelope whose header is a valid v1 but whose ciphertext was authenticated under
    different associated data.
  - `KeyDerivation` — PBKDF2 (HMAC-SHA256) key derivation with a 600,000 iteration default and a 100,000 minimum, plus
    cryptographically secure salt and key generation. No built-in key and no hard-coded salt.
  - `KeyDerivation.DeriveKey(ReadOnlySpan<byte>, …)` — a password overload the caller can zero with
    `CryptographicOperations.ZeroMemory`, since a password that arrives as a `string` can never be scrubbed.
  - `KeyDerivation.MinimumSaltLengthInBytes` is 16 bytes (128 bits), following NIST SP 800-132.
- `SecretProtectionException` and `SecretProtectionFailureReason` — a single classified failure model shared by both
  protection paths.

[Unreleased]: https://github.com/ozakboy/Ozakboy.Security/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ozakboy/Ozakboy.Security/releases/tag/v0.1.0
