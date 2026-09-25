# Ozakboy.Security

Credential and sensitive-data protection for .NET 10. Four things, nothing more:

1. **Secret protection** — encrypt credentials so they never sit on disk in plain text: Windows DPAPI on Windows, an AES-256-GCM keyed protector everywhere else (key from an environment variable or a permission-checked key file), both behind one interface you can replace.
2. **Log masking** — mask secrets before they reach a log: plain strings, URL query parameters, JSON fields, free-form text where the caller never gets to hand the value over, and an `ILogger` wrapper that does it for every log line in the process.
3. **Configuration encryption** — AES-GCM encryption for a configuration file or a section of it, plus PBKDF2 key derivation, and automatic decryption of encrypted `IConfiguration` values.
4. **ASP.NET Core wiring** — `DecryptProtectedValues`, `AddOzakboySecurity` and `AddOzakboySecretMasking`: three calls in `Program.cs`.

繁體中文說明請見 [README_zh-TW.md](README_zh-TW.md)。

## Design notes

- **No third-party dependencies.** Everything is built on the BCL and official Microsoft packages:
  `System.Security.Cryptography.ProtectedData` (the only way to reach DPAPI from .NET) and the
  `Microsoft.Extensions.*` abstractions for configuration, dependency injection, logging and options. Nothing in the
  transitive graph comes from anywhere else.
- **Failures are classified, not guessed.** Both payload formats carry a magic header and a version byte, so a corrupted
  value, an unknown format version and a scope mismatch are told apart *before* decryption is attempted. Whatever is left
  is reported as `DecryptionFailed`.
- **Expected failures do not throw.** A configuration file copied from another machine, edited by hand, or encrypted under
  a rotated key is normal. Every restore path has a `Try…` counterpart that returns `false`.
- **No built-in key, no hard-coded salt.** Where key material comes from is the caller's decision.

## Install

```bash
dotnet add package Ozakboy.Security
```

Target framework: `net10.0`.

## 1. DPAPI secret protection

```csharp
using Ozakboy.Security.Protection;

ISecretProtector protector = new DpapiSecretProtector();

// Encrypt once, then write the result into your configuration file.
string stored = protector.Protect("my-api-key-value");
Console.WriteLine(stored);            // Base64, starts with the OZDP envelope

// Read it back. TryUnprotect never throws for bad data.
if (protector.TryUnprotect(stored, out string? apiKey))
{
    Console.WriteLine(apiKey);        // my-api-key-value
}
else
{
    Console.WriteLine("Cannot restore this value on this machine or user account.");
}
```

Scope and additional entropy:

```csharp
using Ozakboy.Security.Protection;

var options = new DpapiProtectionOptions
{
    // CurrentUser (default): only the account that encrypted it can read it back.
    // LocalMachine: any account on this machine can, which is what a Windows service usually needs.
    Scope = SecretProtectionScope.LocalMachine,
}.WithEntropyText("MyApp/credentials/v1");

var protector = new DpapiSecretProtector(options);
string stored = protector.Protect("my-api-key-value");
```

### What the additional entropy actually buys you

Be precise about this one, because it is easy to over-read.

- **It protects against** other programs that end up holding the file but do not know the entropy: a generic
  DPAPI decryption tool, or whoever restores a backup and starts opening files. Without the entropy they get
  nothing, even running under the same account.
- **It does not protect against** code running as the same user. Passing an application constant — as in the
  snippet above — means the entropy is compiled into the assembly, and anything able to run as that user can
  decompile it straight back out. At that point DPAPI is stopping nothing extra.
- **If you need to stop same-account code**, the entropy has to come from a passphrase the operator types in at
  start-up and it must never be written to disk. The price is unattended start-up: with nobody there to type,
  the service does not come up.

When you need the reason a value could not be restored, use `Unprotect` and catch:

```csharp
using Ozakboy.Security;
using Ozakboy.Security.Protection;

try
{
    string apiKey = new DpapiSecretProtector().Unprotect(stored);
}
catch (SecretProtectionException ex) when (ex.Reason == SecretProtectionFailureReason.ScopeMismatch)
{
    // Encrypted with LocalMachine, being read with CurrentUser (or the other way round).
}
catch (SecretProtectionException ex) when (ex.Reason == SecretProtectionFailureReason.MalformedPayload)
{
    // The configuration file was truncated or hand-edited.
}
catch (SecretProtectionException)
{
    // DecryptionFailed: tampered data, or protected by another user account or machine.
}
```

DPAPI is a Windows facility. On any other platform `IsSupported` is `false` and the protect/unprotect calls throw
`PlatformNotSupportedException` with an explicit message. That is exactly why `ISecretProtector` exists — and for
Linux hosts and containers the package ships the other implementation itself: see [Running on Linux](#4-running-on-linux-and-in-containers).

## 2. Log masking

```csharp
using Ozakboy.Security.Masking;

SecretMasker masker = SecretMasker.Default;

Console.WriteLine(masker.Mask("abcdefghijklmnopqrstuvwxyz"));
// abcd****wxyz

Console.WriteLine(masker.Mask("short"));
// **** — values too short to keep both ends visible are masked entirely

Console.WriteLine(masker.MaskQueryString("/api/v3/order?symbol=BTCUSDT&apiKey=abcdefghijklmnopqrst"));
// /api/v3/order?symbol=BTCUSDT&apiKey=abc****rst

Console.WriteLine(masker.MaskJson("""{"apiKey":"abcdefghijklmnopqrst","symbol":"BTCUSDT","quantity":1.5}"""));
// {"apiKey":"abc****rst","symbol":"BTCUSDT","quantity":1.5}
```

The endpoint and the harmless parameters survive on purpose: a log that hides which call was made is not much use when
you are debugging.

### How much is ever revealed

Two limits apply, and the second one cannot be configured away:

1. The configured prefix and suffix lengths (4 and 4 by default), and a minimum number of hidden characters
   (4 by default, never below 1) before either end is shown at all.
2. **At most one third of the value is ever revealed.** Whatever the options say, a 12-character value shows
   2 + 2, not 4 + 4; a 64-character exchange API key shows the configured 4 + 4, which is well under the cap.
   This exists so a loose configuration cannot produce output that looks masked while reproducing the original.

Password-like fields — `password`, `passwd`, `pwd`, `passphrase`, `mnemonic`, `privateKey` and their variants — are
**always masked in full**, with no characters at either end. Human passwords carry far too little entropy for the
keep-both-ends rule to be safe on them.

### Which field names count as sensitive

Names are matched case-insensitively, in two passes:

- **Exact match** against the built-in list, which covers `apiKey`, `api_key`, `x-api-key`, `x-mbx-apikey`
  (the header Binance uses for API keys), `secret`, `secretKey`, `signature`, `token`, `bearer`, `jwt`, `otp`,
  `mnemonic`, `seed`, `sessionId`, `webhookSecret`, `privateKey`, `password`, `authorization` and several dozen more.
- **Substring match** — enabled by default (`UseSubstringMatching`) — against fragments such as `key`, `secret`,
  `token`, `password`, `credential`, `passphrase`, `signature`, `session` and `cookie`. This is what catches
  `binanceApiKey`, `api_key_1` and `Api-Key-Secret`, none of which an exact-match list would ever see coming.

Substring matching over-masks by design: a field named `keyword` or `publicKey` gets masked too. For a log masker
that is the right trade — an unreadable field costs less than a leaked key — but you can turn it off with
`UseSubstringMatching = false`, or supply your own fragments.

Query-parameter names are percent-decoded before they are matched, so `?api%4Bey=…` (`%4B` is `K`) does not slip
through; the original spelling is written back out. The JSON path decodes names the same way, so both entry points
match on the same basis.

Adjust how much stays visible, or extend the lists:

```csharp
using Ozakboy.Security.Masking;

var masker = new SecretMasker(new SecretMaskOptions
{
    VisiblePrefixLength = 2,
    VisibleSuffixLength = 2,
    MaskLength = 6,
    MaskCharacter = '#',
    AdditionalSensitiveNames = ["listenKey"],
    AdditionalSensitiveNameFragments = ["venue"],
    AdditionalFullMaskNames = ["withdrawWhitelistAddress"],
});

Console.WriteLine(masker.Mask("abcdefghijklmnop"));              // ab######op
Console.WriteLine(masker.MaskNamedValue("symbol", "BTCUSDT"));   // BTCUSDT (not sensitive, untouched)
```

The mask segment has a fixed length, so the output never reveals how long the original value was. On a logging path use
`TryMaskJson`, which returns `false` for invalid JSON instead of throwing:

```csharp
if (SecretMasker.Default.TryMaskJson(responseBody, out string? safeToLog))
{
    logger.LogInformation("response: {Body}", safeToLog);
}
```

> **Never write the fallback.** `try { log(MaskJson(x)) } catch { log(x) }` throws away the whole fail-closed design:
> the moment masking fails is usually the moment the content least belongs in a log. If `TryMaskJson` returns `false`,
> log the fact that it failed — not the payload.

### The values you never got to hand over

The three calls above all need the caller to produce the value. In practice that is not where credentials leak:

```csharp
logger.LogError("order failed key={Key}", apiKey);        // nothing above can see this
catch (Exception ex) { logger.LogError(ex.ToString()); }  // nor a key embedded in exception text
```

Register the secret once at start-up, and run free-form text through `MaskText`:

```csharp
using Ozakboy.Security.Masking;

// At start-up, right after the credentials are decrypted.
SecretMasker.Default.RegisterKnownSecret(apiKey);
SecretMasker.Default.RegisterKnownSecret(apiSecret);

// Anywhere text is about to be logged.
logger.LogError("order failed: {Message}", SecretMasker.Default.MaskText(ex.ToString()));
```

- Values shorter than `SecretMasker.MinimumKnownSecretLength` (8 characters) are rejected: registering a short
  string would mask swathes of ordinary log text. The rejection message never echoes the value.
- Matching is **ordinal and case-sensitive**, because credentials are. The one exception is hexadecimal values
  (signatures, digests), which are registered in both casings since libraries disagree about which to emit.
- Registration is thread-safe and lock-free on the reading side: `MaskText` reads an immutable snapshot, so it is
  safe to call from every thread of a trading loop. With nothing registered it returns the input string as-is and
  allocates nothing.
- `MaskJson` and `MaskQueryString` also run registered secrets over their output, so a key smuggled inside an
  innocently named field is still caught.

`MaskText` is a net under the other three, not a replacement for them: it only knows the values you registered.

## 3. Configuration encryption

```csharp
using System.Security.Cryptography;
using Ozakboy.Security.Configuration;

// The salt is stored next to the ciphertext and is not a secret. It is at least 16 bytes (128 bits).
byte[] salt = KeyDerivation.CreateSalt();
byte[] key = KeyDerivation.DeriveKey("the user's passphrase", salt);
try
{
    string encrypted = ConfigurationProtector.Encrypt(File.ReadAllText("appsettings.json"), key);
    File.WriteAllText("appsettings.protected", encrypted);
    File.WriteAllText("appsettings.salt", Convert.ToBase64String(salt));

    if (ConfigurationProtector.TryDecrypt(encrypted, key, out string? json))
    {
        Console.WriteLine(json);
    }
}
finally
{
    // Derived keys are ordinary byte arrays: zero them as soon as you are done, do not wait for the GC.
    CryptographicOperations.ZeroMemory(key);
}
```

A password that arrives as a `string` can never be scrubbed — strings are immutable, and the GC leaves copies
behind as it moves them, which is how passwords reach memory dumps and page files. When you control where the
password comes from, use the byte overload and clear the buffer yourself:

```csharp
using System.Security.Cryptography;
using System.Text;
using Ozakboy.Security.Configuration;

byte[] password = Encoding.UTF8.GetBytes(ReadPassphraseFromOperator());
byte[] salt = KeyDerivation.CreateSalt();
byte[] key = KeyDerivation.DeriveKey(password, salt);   // identical result to the string overload
try
{
    string encrypted = ConfigurationProtector.Encrypt("""{"apiKey":"…"}""", key);
}
finally
{
    CryptographicOperations.ZeroMemory(password);
    CryptographicOperations.ZeroMemory(key);
}
```

Or generate a random key and keep the key itself under DPAPI:

```csharp
using System.Security.Cryptography;
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Protection;

byte[] key = KeyDerivation.CreateKey();                 // 32 bytes, AES-256
var protector = new DpapiSecretProtector();
try
{
    // What lands in the configuration file is the DPAPI-protected key, never the key itself.
    string storedKey = protector.Protect(Convert.ToBase64String(key));
    string encrypted = ConfigurationProtector.Encrypt("""{"apiKey":"…"}""", key);
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}
```

A fresh nonce is generated for every encryption, so encrypting the same content twice never produces the same ciphertext.
AES-GCM authenticates as well as encrypts: change one byte of the payload and decryption fails instead of quietly
returning something wrong. The nonce is 96 random bits, so by the birthday bound a single key should not encrypt more
than 2^32 times (about 4.3 billion) before it is rotated — configuration encryption sits nowhere near that volume.

`ConfigurationProtector.IsProtectedValue(value)` tells an already-encrypted configuration value apart from one still in
plain text, without needing the key — handy when migrating an existing file. `ConfigurationProtector.IsSupported`
reports whether the platform offers AES-GCM at all; check it at start-up rather than discovering the answer the first
time you write a configuration file.

## 4. Running on Linux and in containers

DPAPI does not exist off Windows. `KeyedSecretProtector` is the cross-platform `ISecretProtector`: AES-256-GCM with a
master key the application owns, supplied by an `ISecretKeySource`. Two sources are built in, one per deployment shape.

**Containers (Docker / ECS / Kubernetes): the key in an environment variable**, injected by the orchestrator's secret
mechanism so it never lands in the image or in a configuration file.

```bash
openssl rand -base64 32        # generate once, store it in your secret manager as APP_MASTER_KEY
```

```csharp
using Ozakboy.Security.Protection;

ISecretProtector protector = new KeyedSecretProtector(new EnvironmentVariableKeySource("APP_MASTER_KEY"));

string stored = protector.Protect("line-channel-secret");      // Base64, OZCF envelope
if (protector.TryUnprotect(stored, out string? channelSecret))
{
    // …
}
```

**EC2 / VM hosts: the key in a file** that only the service account can read.

```bash
sudo install -m 600 -o myapp -g myapp /dev/null /etc/myapp/master.key
sudo sh -c 'head -c 32 /dev/urandom > /etc/myapp/master.key'   # 32 raw bytes; Base64 text (openssl rand -base64 32) works too
```

```csharp
ISecretProtector protector = new KeyedSecretProtector(new KeyFileKeySource("/etc/myapp/master.key"));
```

What the key-file source enforces, **on every read**, not only at start-up:

- The file must exist and hold exactly 32 bytes (raw), or Base64 text that decodes to 32 bytes. A 32-byte file made
  entirely of Base64 characters is read as Base64 text — the Base64 of a 24-byte key is also 32 characters, and
  without that rule it would be accepted as a weak raw key.
- On Unix, **any permission bit for group or others (`r`, `w` or `x`) makes the read fail** with the actual mode and
  `chmod 600` in the message. A file loosened after the process came up is caught the next time the key is needed. The
  check cannot be switched off: a security check that can be disabled eventually is.
- On Windows there is no permission check. NTFS ACLs and Unix mode bits are different models and the library does not
  pretend to translate between them; on Windows, DPAPI is the native answer. The source still works there (a developer
  machine, say), only without that line of defence.

Things worth knowing about `KeyedSecretProtector`:

- **Its output is the `OZCF` envelope of `ConfigurationProtector`**, not a third format. Under the same key, a value
  encrypted on a build machine with `ConfigurationProtector.Encrypt(value, key)` is readable by the protector after
  deployment, and the other way round. A one-off tool for encrypting values looks like this:

  ```csharp
  using System.Security.Cryptography;
  using Ozakboy.Security.Configuration;
  using Ozakboy.Security.Protection;

  byte[] key = new KeyFileKeySource("/etc/myapp/master.key").ReadKey();   // or EnvironmentVariableKeySource
  try
  {
      Console.WriteLine(ConfigurationProtector.Encrypt(args[0], key));  // paste the output into appsettings.json
  }
  finally
  {
      CryptographicOperations.ZeroMemory(key);
  }
  ```

- **The key is never resident.** Every protect / unprotect asks the source for a fresh copy and zeroes it immediately
  afterwards; the protector holds no key, needs no `Dispose`, and leaves no long-lived key in a memory dump. The price
  is one source read per operation (one file read plus the permission check for a key file). Secret protection is not a
  hot path, and the configuration integration below decrypts each value once.
- **`KeyUnavailable` tells a provisioning problem from a data problem.** An unset variable, a missing file, a wrong
  length or open permissions all surface as `SecretProtectionException` with
  `Reason == SecretProtectionFailureReason.KeyUnavailable`; the message names the variable or path and never the
  content. `TryUnprotect` returns `false` for it, like every other failure.
- **It works on Windows too.** It is not "the Linux one": when several Windows machines must share one key — which
  DPAPI, bound to a machine or a user, cannot do — this is the protector to use.
- **Your own key source** (a cloud KMS, an OS keychain) is one interface: `ISecretKeySource` has a `Description` for
  error messages and `ReadKey()`, which must return a freshly allocated 32-byte array every call, because the caller
  zeroes it.

## 5. ASP.NET Core integration

Three calls in `Program.cs`, each independent of the others:

```csharp
using Ozakboy.Security;
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Logging;
using Ozakboy.Security.Protection;

var builder = WebApplication.CreateBuilder(args);

// 1. Encrypted values in appsettings.json, environment variables or user secrets are decrypted on read.
//    Call it after every configuration source has been added — sources added later are not covered.
var protector = new KeyedSecretProtector(new KeyFileKeySource("/etc/myapp/master.key"));
builder.Configuration.DecryptProtectedValues(protector);

// 2. SecretMasker and ISecretProtector in the container. The protector is chosen explicitly, never guessed.
builder.Services.AddOzakboySecurity(security => security
    .UseProtector(_ => protector)
    .RegisterKnownSecret(builder.Configuration["Line:ChannelSecret"]!)
    .RegisterKnownSecret(builder.Configuration.GetConnectionString("Default")!));

// 3. Every ILogger<T> masks the message, the structured properties and the exception text before any provider sees them.
builder.Logging.AddOzakboySecretMasking();
```

```json
{
  "Line": {
    "ChannelId": "1234567890",
    "ChannelSecret": "T1pDRgE…"
  }
}
```

The `ChannelSecret` above is what `ConfigurationProtector.Encrypt` (or `KeyedSecretProtector.Protect`) printed; the
`ChannelId` is plain and stays plain. Your options classes and `IOptions<T>` bindings do not know the difference.

### Configuration decryption

- Values that are not protected pass through untouched, including empty and `null`. Which values count as protected is
  decided by `ProtectedValueConfigurationBuilderExtensions.IsAnyProtectedValue` by default — both the `OZCF` and the
  `OZDP` envelope — and you can pass your own predicate. A keyed protector meeting an `OZDP` value fails loudly rather
  than passing the ciphertext through: ciphertext used as plain text is worse than a failed start-up.
- A failed decryption throws `SecretProtectionException` whose message names **the configuration key** (`Line:ChannelSecret`)
  and contains neither the ciphertext nor the plain text; `Reason` is whatever the protector reported, so `KeyUnavailable`
  means "fix the deployment" and `DecryptionFailed` means "wrong key or edited value". It surfaces the first time the
  value is read, which is usually while options bind at start-up.
- Each ciphertext is decrypted once and cached by ciphertext, so repeated binding and `IOptionsSnapshot` do not hit the
  key file again. An unchanged value after a reload hits the cache; a changed one misses it naturally.
- `WebApplicationBuilder.Configuration` is a `ConfigurationManager`, which is also an `IConfigurationBuilder`; replacing
  its sources reloads immediately. Calling the method twice does not double-wrap.

### DI registration

- `SecretMasker` is registered as a singleton (`TryAddSingleton`, so one you registered yourself is kept), built from
  `SecretMaskingOptions`: `MaskOptions`, `KnownSecrets`, `AlsoRegisterOnDefaultMasker` and `MaskLogPropertiesByName`.
  Because it is the Options pattern, secrets can be added after configuration is bound:

  ```csharp
  builder.Services.Configure<SecretMaskingOptions>(options =>
      options.KnownSecrets.Add(builder.Configuration["Binance:ApiSecret"]!));
  ```

  Every known secret is validated (non-blank, at least 8 characters) when the masker is first resolved; the validation
  message names the index, never the value. `RegisterKnownSecret(...)` on the builder checks immediately instead.
- `AlsoRegisterOnDefaultMasker` (default `true`) mirrors the known secrets onto `SecretMasker.Default`, because some
  `Ozakboy.Http` checkpoints fall back to it when no named masker reaches them. One registration too many costs nothing;
  one too few is a leak. Switch it off when the shared static masker must stay untouched.
- The protector is a choice: `UseDpapiProtector(options?)`, `UseKeyedProtector(keySource)`,
  `UseKeyFromEnvironmentVariable(name)`, `UseKeyFromFile(path)` or `UseProtector(factory)`. Without one there is no
  `ISecretProtector` registration. The single method that looks at the operating system is
  `UseDpapiOnWindowsOtherwiseKeyed(keySource)`, for code that moves between a Windows development machine and Linux
  hosts; it spells the guess out in its name and decides when the protector is resolved.

### Log masking

`AddOzakboySecretMasking()` replaces the container's `ILoggerFactory` with a `MaskingLoggerFactory` that wraps every
logger it creates in a `MaskingLogger`. Because the factory rather than each provider is wrapped, `ILogger<T>` and
providers added later (`AddConsole()`, `AddProvider(...)`) are covered regardless of order. The masker comes from
`AddOzakboySecurity` (falling back to `SecretMasker.Default`); `AddOzakboySecretMasking(masker, maskPropertiesByName)`
takes an explicit one. Both types are public, so you can also wrap a single `ILogger` or `ILoggerFactory` by hand.

What is masked, in three layers:

1. **The formatted message**, through `MaskText` — every registered secret is replaced wherever it appears.
2. **String properties of the structured state** (`logger.LogError("order failed key={Key}", apiKey)`): a registered
   secret is replaced whole; an unregistered value is masked **by property name** through the same rules as
   `MaskNamedValue` — `{Token}`, `{Password}`, `{ApiKey}` are masked even when nobody registered the value, and the
   matching text in the formatted message is rewritten too. Substring matching applies, so `{CacheKey}` is masked as
   well; `MaskLogPropertiesByName = false` reduces the layer to registered secrets only.
3. **Exception text.** When the message, stack trace or `ToString()` of an exception contains a secret, the provider
   receives a `MaskedException` stand-in: masked message, masked stack trace, masked full text, the original type name
   in `OriginalTypeName`, inner exceptions handled recursively. An exception without secrets is passed through as-is.

What is **not** masked — read this before relying on it:

- Only **string** properties are masked individually. Objects, `Uri`s and numbers pass through, so a sink that
  `ToString()`s an object into a structured field is outside the wrapper's sight. The formatted message always goes
  through `MaskText`; objects inside structured fields do not.
- A value masked by name that is shorter than 3 characters is masked in the property but not replaced in the message,
  because replacing every `a` in a line would wreck it.
- `Exception.Data` and custom exception properties are not masked, and a sink that dispatches on the exception type
  sees `MaskedException`, not the original.
- Code that resolves an `ILoggerProvider` and creates loggers itself, and logging libraries that bypass
  `Microsoft.Extensions.Logging`, are not covered.

Performance: a disabled level returns before anything is formatted. Otherwise the message is formatted exactly once,
and when nothing turned out to need masking — the common case — the original state, exception and formatter are
forwarded untouched with no allocation. Only when something changed is one state object (plus one property array)
allocated.

## Payload formats

| | Magic | Layout |
| --- | --- | --- |
| `DpapiSecretProtector` | `OZDP` | magic (4) + version (1) + scope (1) + DPAPI blob |
| `ConfigurationProtector` | `OZCF` | magic (4) + version (1) + nonce (12) + tag (16) + ciphertext |
| `KeyedSecretProtector` | `OZCF` | the same envelope as `ConfigurationProtector` — the two interoperate under the same key |

Both are Base64-encoded in their string form. The `OZCF` header is also fed to AES-GCM as associated data, which binds
header and ciphertext together under the authentication tag. Note what actually happens when you tamper with the header
today: with only format version 1 in existence, the format check rejects a bad magic or version *before* AES-GCM is
reached, so that particular rejection comes from the format check, not from the tag. The associated data is what keeps
the binding sound once more than one format version is in circulation — and the test suite proves it is really enforced
by decrypting an envelope whose header is a valid v1 but whose ciphertext was authenticated under different associated
data.

## Failure reasons

`SecretProtectionException.Reason` is one of:

| Reason | Meaning |
| --- | --- |
| `MalformedPayload` | Not valid Base64, too short, or missing the format header. |
| `UnsupportedFormatVersion` | Written by a newer version of this library. |
| `ScopeMismatch` | Protected under `LocalMachine` but read as `CurrentUser`, or the reverse. |
| `DecryptionFailed` | Tampered data, a wrong key, or another user account or machine. |
| `PlatformNotSupported` | The mechanism is unavailable on this platform. `DpapiSecretProtector` throws `PlatformNotSupportedException` for this case; the value is here for substitute implementations that would rather report it as a failure reason. |
| `KeyUnavailable` | `KeyedSecretProtector` could not obtain its master key: variable unset, key file missing, wrong length, or permissions open to group or others. The data is fine; the host is not provisioned. |

## Requirements and limits

- .NET 10.
- Windows only for `DpapiSecretProtector`. Everything else — `KeyedSecretProtector`, masking, the `ILogger` wrapper,
  `ConfigurationProtector`, PBKDF2 and the ASP.NET Core integration — runs on Linux, macOS and Windows alike.
  AES-GCM needs support from the platform's cryptographic provider; `ConfigurationProtector.IsSupported` (equivalently
  `KeyedSecretProtector.IsSupported`) reports it, and it is available on every mainstream .NET 10 platform.
- The key-file permission check applies to Unix mode bits only; on Windows the key file is read without a check.
- The log-masking wrapper masks string properties, the formatted message and exception text; see
  [Log masking](#log-masking) for what it does not reach.

## License

MIT. See [LICENSE](LICENSE).
