# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

建置期變更,消費者不受影響:套件內容與公開 API 均未改動。

- **測試專案改走 Microsoft.Testing.Platform(MTP)**,不再經由 VSTest。原本引用 `MSTest` 整合套件會帶進
  `Microsoft.NET.Test.Sdk`,而那條路徑會遞移帶進第三方的 Newtonsoft.Json,違反本專案「只允許 BCL 與 Microsoft
  官方套件、判定看遞移相依而非套件名稱」的相依政策。現在改為直接點名 `MSTest.TestAdapter` / `MSTest.TestFramework`
  並開啟 `EnableMSTestRunner`,trx 報告與覆蓋率分別由 `Microsoft.Testing.Extensions.TrxReport` /
  `Microsoft.Testing.Extensions.CodeCoverage` 提供;repo 根目錄新增 `global.json`(`test.runner`),
  .NET 10 的 `dotnet test` 才會走 MTP。`dotnet list package --include-transitive` 已確認不再出現 Newtonsoft.Json,
  與 `Ozakboy.Http` 的測試專案寫法一致。
- **CI 改用 MTP 的旗標**:`--logger "trx;…"` 改為 `--report-trx --report-trx-filename …`,trx 落在測試專案的
  `bin/Release/net10.0/TestResults/` 底下。Windows 上「DPAPI 測試必須真的執行且通過」的驗證意圖不變:
  仍以 `--filter "TestCategory=Windows"` 單獨跑一輪並讀 trx 的 `ResultSummary/Counters` 逐項核對;
  差別只在 MTP 把 `Inconclusive` 計進 `notExecuted`,而該檢查本來就兩者一起看。
- 核心 csproj 補上 `PackageReleaseNotes`(摘要 0.1.0 與 0.1.1),nuget.org 的套件頁面才看得到版本重點。

Build-time changes only; consumers are unaffected: neither the package contents nor the public API changed.

- **The test project now runs on Microsoft.Testing.Platform (MTP)** instead of VSTest. Referencing the `MSTest`
  metapackage pulled in `Microsoft.NET.Test.Sdk`, and that path transitively drags in the third-party Newtonsoft.Json,
  which violates this project's dependency policy (BCL and official Microsoft packages only, judged by the transitive
  graph rather than by package name). The project now names `MSTest.TestAdapter` / `MSTest.TestFramework` directly
  with `EnableMSTestRunner`, trx reports and coverage come from `Microsoft.Testing.Extensions.TrxReport` /
  `Microsoft.Testing.Extensions.CodeCoverage`, and a repo-level `global.json` (`test.runner`) makes `dotnet test` on
  .NET 10 pick MTP. `dotnet list package --include-transitive` confirms Newtonsoft.Json is gone, matching the
  `Ozakboy.Http` test project.
- **CI uses the MTP flags**: `--logger "trx;…"` became `--report-trx --report-trx-filename …`, with the trx written
  under the test project's `bin/Release/net10.0/TestResults/`. The intent that DPAPI tests must actually run and pass
  on Windows is unchanged: the category is still run on its own with `--filter "TestCategory=Windows"` and the trx
  `ResultSummary/Counters` are still checked item by item; the only difference is that MTP counts `Inconclusive`
  under `notExecuted`, and the check already looked at both.
- The core csproj gains `PackageReleaseNotes` (summarising 0.1.0 and 0.1.1) so the nuget.org package page shows the
  release highlights.

## [0.1.1] - 2026-09-11

### Added

- Package icon. The shared ozakboy brand mark now shows on nuget.org and in IDE package managers.

No code changed in this release. NuGet package metadata cannot be altered on an already-published
version, so refreshing the icon requires publishing a new one.

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

[Unreleased]: https://github.com/ozakboy/Ozakboy.Security/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ozakboy/Ozakboy.Security/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ozakboy/Ozakboy.Security/releases/tag/v0.1.0
