# Ozakboy.Security

Credential and sensitive-data protection for .NET 10. Three things, nothing more:

1. **DPAPI secret protection** — encrypt credentials with Windows DPAPI so they never sit on disk in plain text, behind an interface you can replace.
2. **Log masking** — mask secrets before they reach a log: plain strings, URL query parameters, JSON fields, and free-form text where the caller never gets to hand the value over.
3. **Configuration encryption** — AES-GCM encryption for a configuration file or a section of it, plus PBKDF2 key derivation.

繁體中文說明請見 [README_zh-TW.md](README_zh-TW.md)。

## Design notes

- **No third-party dependencies.** Everything is built on the BCL. The single package reference,
  `System.Security.Cryptography.ProtectedData`, is published by Microsoft and is the only way to reach DPAPI from .NET.
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
`PlatformNotSupportedException` with an explicit message. That is exactly why `ISecretProtector` exists: inject a
different implementation (environment variables, an OS keychain, a cloud KMS) and the rest of your code does not change.

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

## Payload formats

| | Magic | Layout |
| --- | --- | --- |
| `DpapiSecretProtector` | `OZDP` | magic (4) + version (1) + scope (1) + DPAPI blob |
| `ConfigurationProtector` | `OZCF` | magic (4) + version (1) + nonce (12) + tag (16) + ciphertext |

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

## Requirements

- .NET 10
- Windows for the DPAPI parts; masking, AES-GCM and PBKDF2 run anywhere.

## License

MIT. See [LICENSE](LICENSE).
