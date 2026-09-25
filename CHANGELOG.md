# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-25

這一版的主題是「離開 Windows」:`ISecretProtector` 在 Linux EC2 與 Docker 上有了內建實作,
而 ASP.NET Core 宿主從設定解密、DI 註冊到日誌遮罩都有了現成的掛法。既有公開 API 沒有破壞性變更
(`Ozakboy.Http` 使用的 `SecretMasker` 完全不受影響);`SecretProtectionFailureReason` 只新增值。

The theme of this release is "leaving Windows": `ISecretProtector` gains a built-in implementation for Linux EC2 and
Docker, and ASP.NET Core hosts get ready-made wiring for configuration decryption, DI registration and log masking.
No breaking change to the existing public API (the `SecretMasker` that `Ozakboy.Http` uses is untouched);
`SecretProtectionFailureReason` only gains a value.

### Added

- **跨平台的金鑰式保護器 `KeyedSecretProtector`**(`Ozakboy.Security.Protection`):AES-256-GCM 的 `ISecretProtector`,
  主金鑰由可插拔的 `ISecretKeySource` 提供,Windows 上也能用(多台機器要共用同一把金鑰時,DPAPI 做不到,這個可以)。
  - **輸出格式就是既有的 `OZCF` 封裝**(魔術字 4 + 版本 1 + 隨機 nonce 12 + 驗證標籤 16 + 密文),沒有另立格式。
    同一把金鑰下,用 `ConfigurationProtector.Encrypt` 在 CLI 加密的值部署後由這個保護器解得開,反之亦然;
    設定整合層也只需認得一種格式。`KeyedSecretProtector.IsProtectedValue` 直接轉呼叫 `ConfigurationProtector.IsProtectedValue`。
  - **金鑰不常駐**:每次 Protect / Unprotect 向來源要一份、用完立刻 `CryptographicOperations.ZeroMemory`;
    物件不持有金鑰,不需要 Dispose。來源回傳長度錯誤的金鑰會再被擋一次(第三方實作不一定自己驗)。
  - `KeyLengthInBytes` = 32,刻意只接受 AES-256。
  - `TryUnprotect` 在金鑰取不到與平台不支援時都回 `false`,與 `ConfigurationProtector.TryDecrypt` 一致。
- **`ISecretKeySource`** 與兩個內建來源:
  - `EnvironmentVariableKeySource(variableName)`(容器場景):變數內容是 32 位元組金鑰的 Base64,
    未設定、不是 Base64、長度不對都以 `KeyUnavailable` 拒絕,訊息不回述變數內容。
  - `KeyFileKeySource(path)`(EC2 / VM 場景):檔案內容可以是 32 個原始位元組,或 32 位元組金鑰的 Base64 文字。
    **Unix 上每次讀取都檢查權限**,對群組或其他人開放任何位元(`r` / `w` / `x`)一律拒絕,訊息附實際權限(八進位)與
    `chmod 600` 指引;這條檢查刻意不可關閉。Windows 上不檢查(NTFS ACL 與 mode bits 不是同一套模型,不假裝能翻譯;
    Windows 請用 DPAPI)。長度恰為 32 位元組但全是 Base64 字母表字元的檔案視為 Base64 文字 ——
    24 位元組金鑰的 Base64 恰好也是 32 個字元,不加這條會把它當成一把弱金鑰照收。
- **`SecretProtectionFailureReason.KeyUnavailable`(= 6)**:主金鑰取不到 —— 環境變數未設定、金鑰檔不存在、長度不對、權限太開。
  把「這台機器沒配好金鑰」與「資料解不開」分開,`SecretProtectionException.Reason` 一看就知道要去修部署還是修資料。
- **設定值自動解密**(`Ozakboy.Security.Configuration`):`IConfigurationBuilder.DecryptProtectedValues(protector, isProtectedValue?)`
  把目前已加入的每個 `IConfigurationSource` 包一層,提供者在 `TryGet` 讀到受保護的值時解密後交出,
  其餘值與 `Set` / `Load` / `GetReloadToken` / `GetChildKeys` 原樣轉交。`WebApplicationBuilder.Configuration`
  (`ConfigurationManager`)直接可用。
  - 預設述詞 `IsAnyProtectedValue` 同時認 `OZCF` 與 `OZDP`;金鑰式保護器遇到 `OZDP` 會失敗而不是放行密文。
  - 解密失敗擲 `SecretProtectionException`,訊息指出**是哪個設定鍵**,但不含密文也不含明文;`Reason` 沿用保護器回報的原因。
    失敗發生在第一次讀到那個值時(通常是啟動綁定選項的當下),所以配錯金鑰的服務起不來,而不是帶著密文跑下去。
  - 每個密文只解密一次,以密文為鍵快取;重新載入後值沒變直接命中。
  - 呼叫之後才加的來源不會被包到(請在所有來源加完之後呼叫);重複呼叫不會重複包。
- **DI 註冊**(`Ozakboy.Security`):`IServiceCollection.AddOzakboySecurity()` / `AddOzakboySecurity(builder => …)`。
  - `SecretMasker` 以 `TryAddSingleton` 註冊,依新的 Options 類別 `SecretMaskingOptions`(`MaskOptions`、`KnownSecrets`、
    `AlsoRegisterOnDefaultMasker`、`MaskLogPropertiesByName`)建立並登記已知祕密;宿主可在設定綁定之後
    `services.Configure<SecretMaskingOptions>` 補登記。`KnownSecrets` 由 `IValidateOptions` 驗證(非空白、至少 8 字元),
    訊息只指出索引不回述值。`AlsoRegisterOnDefaultMasker` 預設 `true`,因為 `Ozakboy.Http` 有些關口會退回 `SecretMasker.Default`。
  - `OzakboySecurityBuilder`:`UseDpapiProtector(options?)`、`UseKeyedProtector(keySource)`、`UseKeyFromEnvironmentVariable(name)`、
    `UseKeyFromFile(path)`、`UseProtector(factory)`、`ConfigureMasking(…)`、`RegisterKnownSecret(secret)`。
    **保護器必須明確選**,沒選就沒有 `ISecretProtector` 註冊;唯一依作業系統決定的是
    `UseDpapiOnWindowsOtherwiseKeyed(keySource, dpapiOptions?)`,把「猜」寫在名字上,而且在解析當下才判斷。
- **日誌遮罩**(`Ozakboy.Security.Logging`):`MaskingLogger`(包一個 `ILogger`)、`MaskingLoggerFactory`(包一個 `ILoggerFactory`)、
  `MaskedException`(例外替身)與 `ILoggingBuilder.AddOzakboySecretMasking()` / `AddOzakboySecretMasking(masker, maskPropertiesByName)`。
  這是回應 `Ozakboy.TradeKit.Binance` 的抱怨「本套件自己寫出去的日誌不經過遮罩器」:遮罩下沉到 `ILogger` 這一層,
  不管是哪個套件、哪條路徑寫的都會過。
  - 遮三層:格式化後的訊息(`MaskText`)、結構化狀態裡的**字串**屬性(先字面替換、再依屬性名稱 —— `"token={Token}"` 沒登記也會被遮,
    可用 `MaskLogPropertiesByName = false` 關掉)、例外文字(訊息 / 堆疊 / `ToString()` 找到祕密時換成 `MaskedException` 替身,
    保留原型別名稱於 `OriginalTypeName`,內層例外遞迴處理;沒祕密的例外原封不動)。
  - 掛法是取代容器裡的 `ILoggerFactory` 註冊(型別 / 工廠 / 實例三種都支援,以 `ActivatorUtilities` 建內層再包),
    所以 `ILogger<T>` 與之後才加的提供者都涵蓋,順序無所謂;主函式庫因此不需要引用 `Microsoft.Extensions.Logging` 本體。
  - 效能:層級沒開直接返回;訊息只格式化一次;沒東西要遮時原狀態、原例外、原格式化委派原封往下傳,零配置。
  - **限制**(XML doc 與 README 都寫了):只有字串屬性逐個遮,非字串物件原樣通過;依名稱遮到的值短於 3 字元不在訊息裡替換;
    `Exception.Data` 與自訂屬性不遮;接收端以型別分派時看到的是替身。

- **Cross-platform keyed protector `KeyedSecretProtector`** (`Ozakboy.Security.Protection`): an AES-256-GCM `ISecretProtector`
  whose master key comes from a pluggable `ISecretKeySource`. It works on Windows too (several machines sharing one key
  is something DPAPI cannot do and this can).
  - **The output format is the existing `OZCF` envelope** (magic 4 + version 1 + random nonce 12 + tag 16 + ciphertext);
    no second format. Under the same key, a value encrypted from a CLI with `ConfigurationProtector.Encrypt` is readable
    by this protector after deployment and vice versa, and the configuration integration only has to recognise one
    format. `KeyedSecretProtector.IsProtectedValue` forwards to `ConfigurationProtector.IsProtectedValue`.
  - **The key is not kept resident**: every Protect / Unprotect asks the source for a copy and
    `CryptographicOperations.ZeroMemory`s it immediately; the object holds no key and needs no Dispose. A wrong-length
    key from a source is refused again by the protector (a third-party source might not validate).
  - `KeyLengthInBytes` = 32; only AES-256 is accepted, deliberately.
  - `TryUnprotect` returns `false` for an unobtainable key and for an unsupported platform, matching
    `ConfigurationProtector.TryDecrypt`.
- **`ISecretKeySource`** and two built-in sources:
  - `EnvironmentVariableKeySource(variableName)` (containers): the variable holds the Base64 of a 32-byte key; unset,
    not Base64 and wrong length are all refused as `KeyUnavailable`, and the message never echoes the value.
  - `KeyFileKeySource(path)` (EC2 / VM hosts): the file holds 32 raw bytes or the Base64 text of a 32-byte key.
    **On Unix the permissions are checked on every read**: any group or other bit (`r` / `w` / `x`) is refused, with the
    actual mode (octal) and a `chmod 600` hint in the message; the check deliberately cannot be switched off. No check
    on Windows (NTFS ACLs and mode bits are different models and the library does not pretend to translate; use DPAPI
    there). A file of exactly 32 bytes made entirely of Base64-alphabet characters is treated as Base64 text, because
    the Base64 of a 24-byte key is also exactly 32 characters and would otherwise be accepted as a weak raw key.
- **`SecretProtectionFailureReason.KeyUnavailable` (= 6)**: the master key could not be obtained — variable unset, key
  file missing, wrong length, permissions too open. It separates "this host is not provisioned" from "the data cannot be
  decrypted", so `SecretProtectionException.Reason` says whether to fix the deployment or the data.
- **Configuration decryption** (`Ozakboy.Security.Configuration`):
  `IConfigurationBuilder.DecryptProtectedValues(protector, isProtectedValue?)` wraps every `IConfigurationSource` added so
  far; the provider decrypts a protected value in `TryGet` and forwards everything else (`Set` / `Load` /
  `GetReloadToken` / `GetChildKeys`) untouched. `WebApplicationBuilder.Configuration` (`ConfigurationManager`) works directly.
  - The default predicate `IsAnyProtectedValue` recognises both `OZCF` and `OZDP`; a keyed protector meeting `OZDP` fails
    instead of passing the ciphertext through.
  - A failed decryption throws `SecretProtectionException` naming **the configuration key** but containing neither the
    ciphertext nor the plain text; `Reason` is whatever the protector reported. It surfaces the first time the value is
    read (usually while options bind at start-up), so a misprovisioned service fails to start rather than running on with ciphertext.
  - Each ciphertext is decrypted once and cached by ciphertext; an unchanged value after a reload hits the cache.
  - Sources added after the call are not wrapped (call it after every source has been added); calling twice does not double-wrap.
- **DI registration** (`Ozakboy.Security`): `IServiceCollection.AddOzakboySecurity()` / `AddOzakboySecurity(builder => …)`.
  - `SecretMasker` is registered with `TryAddSingleton`, built from the new Options class `SecretMaskingOptions`
    (`MaskOptions`, `KnownSecrets`, `AlsoRegisterOnDefaultMasker`, `MaskLogPropertiesByName`) with its known secrets
    registered; a host can add more with `services.Configure<SecretMaskingOptions>` after configuration is bound.
    `KnownSecrets` is validated by an `IValidateOptions` (non-blank, at least 8 characters) whose message names the index,
    never the value. `AlsoRegisterOnDefaultMasker` defaults to `true` because some `Ozakboy.Http` checkpoints fall back to
    `SecretMasker.Default`.
  - `OzakboySecurityBuilder`: `UseDpapiProtector(options?)`, `UseKeyedProtector(keySource)`,
    `UseKeyFromEnvironmentVariable(name)`, `UseKeyFromFile(path)`, `UseProtector(factory)`, `ConfigureMasking(…)`,
    `RegisterKnownSecret(secret)`. **The protector is chosen explicitly**; without a choice there is no `ISecretProtector`
    registration. The single OS-dependent method is `UseDpapiOnWindowsOtherwiseKeyed(keySource, dpapiOptions?)`, which
    spells the guess out in its name and decides at resolution time.
- **Log masking** (`Ozakboy.Security.Logging`): `MaskingLogger` (wraps an `ILogger`), `MaskingLoggerFactory` (wraps an
  `ILoggerFactory`), `MaskedException` (the exception stand-in) and `ILoggingBuilder.AddOzakboySecretMasking()` /
  `AddOzakboySecretMasking(masker, maskPropertiesByName)`. This answers the `Ozakboy.TradeKit.Binance` complaint that
  "what this package logs itself does not pass through the masker": masking now sits at the `ILogger` layer, so every
  package and every path goes through it.
  - Three layers are masked: the formatted message (`MaskText`), **string** properties in the structured state (literal
    replacement first, then by property name — `"token={Token}"` is masked even when unregistered; switch off with
    `MaskLogPropertiesByName = false`), and exception text (when a secret is found in the message / stack trace /
    `ToString()`, the exception is replaced by a `MaskedException` stand-in that keeps the original type name in
    `OriginalTypeName` and handles inner exceptions recursively; an exception without secrets passes through untouched).
  - It attaches by replacing the container's `ILoggerFactory` registration (type, factory and instance descriptors are all
    supported; the inner factory is built with `ActivatorUtilities` and wrapped), so `ILogger<T>` and providers added later
    are covered regardless of order, and the library never needs a reference to the concrete `Microsoft.Extensions.Logging`.
  - Performance: a disabled level returns at once; the message is formatted once; with nothing to mask the original state,
    exception and formatter are forwarded with zero allocation.
  - **Limits** (stated in the XML docs and the README): only string properties are masked individually and non-string
    objects pass through; a value masked by name that is shorter than 3 characters is not replaced in the message;
    `Exception.Data` and custom properties are not masked; a sink dispatching on exception type sees the stand-in.

### Changed

- **相依**:主函式庫新增 `Microsoft.Extensions.Configuration.Abstractions`、`Microsoft.Extensions.DependencyInjection.Abstractions`、
  `Microsoft.Extensions.Logging.Abstractions`、`Microsoft.Extensions.Options`(10.0.12)。四個都是 Microsoft 官方套件,
  遞移相依只有 `Microsoft.Extensions.Primitives`,沒有第三方;刻意不引用 `Microsoft.Extensions.Logging` / `.Configuration` 本體。
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
- 核心 csproj 補上 `PackageReleaseNotes`,nuget.org 的套件頁面才看得到版本重點。
- 測試:新增 97 個離線測試(金鑰式保護器 19、環境變數來源 9、金鑰檔來源 15 —— 其中 5 個用真實檔案與 Unix 權限位元,
  標記 `Unix` 分類、在 Windows 上略過 —— 設定整合 14、DI 14、日誌遮罩 17 + 9),總數 258。

- **Dependencies**: the library now references `Microsoft.Extensions.Configuration.Abstractions`,
  `Microsoft.Extensions.DependencyInjection.Abstractions`, `Microsoft.Extensions.Logging.Abstractions` and
  `Microsoft.Extensions.Options` (10.0.12). All four are official Microsoft packages whose only transitive dependency is
  `Microsoft.Extensions.Primitives`; no third-party package. The concrete `Microsoft.Extensions.Logging` /
  `.Configuration` packages are deliberately not referenced.
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
- The core csproj gains `PackageReleaseNotes` so the nuget.org package page shows the release highlights.
- Tests: 97 new offline tests (keyed protector 19, environment-variable source 9, key-file source 15 — five of them use
  real files and Unix permission bits, tagged `Unix` and skipped on Windows — configuration integration 14, DI 14,
  log masking 17 + 9), 258 in total.

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

[0.2.0]: https://github.com/ozakboy/Ozakboy.Security/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ozakboy/Ozakboy.Security/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ozakboy/Ozakboy.Security/releases/tag/v0.1.0
