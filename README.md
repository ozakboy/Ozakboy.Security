# Ozakboy.Security

Credential and sensitive-data protection for .NET 10. Three things, nothing more:

1. **DPAPI secret protection** — encrypt credentials with Windows DPAPI so they never sit on disk in plain text, behind an interface you can replace.
2. **Log masking** — mask secrets before they reach a log, for plain strings, URL query parameters and JSON fields.
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
// /api/v3/order?symbol=BTCUSDT&apiKey=abcd****qrst

Console.WriteLine(masker.MaskJson("""{"apiKey":"abcdefghijklmnopqrst","symbol":"BTCUSDT","quantity":1.5}"""));
// {"apiKey":"abcd****qrst","symbol":"BTCUSDT","quantity":1.5}
```

The endpoint and the harmless parameters survive on purpose: a log that hides which call was made is not much use when
you are debugging. Field names are matched case-insensitively, and the built-in list covers `apiKey`, `api_key`,
`secret`, `secretKey`, `signature`, `token`, `password`, `authorization` and a few dozen more.

Adjust how much stays visible, or extend the list of sensitive names:

```csharp
using Ozakboy.Security.Masking;

var masker = new SecretMasker(new SecretMaskOptions
{
    VisiblePrefixLength = 2,
    VisibleSuffixLength = 2,
    MaskLength = 6,
    MaskCharacter = '#',
    AdditionalSensitiveNames = ["listenKey", "x-mbx-apikey"],
});

Console.WriteLine(masker.Mask("abcdefghijklmnop"));   // ab######op
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

## 3. Configuration encryption

```csharp
using Ozakboy.Security.Configuration;

// The salt is stored next to the ciphertext and is not a secret.
byte[] salt = KeyDerivation.CreateSalt();
byte[] key = KeyDerivation.DeriveKey("the user's passphrase", salt);

string encrypted = ConfigurationProtector.Encrypt(File.ReadAllText("appsettings.json"), key);
File.WriteAllText("appsettings.protected", encrypted);
File.WriteAllText("appsettings.salt", Convert.ToBase64String(salt));

if (ConfigurationProtector.TryDecrypt(encrypted, key, out string? json))
{
    Console.WriteLine(json);
}
```

Or generate a random key and keep the key itself under DPAPI:

```csharp
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Protection;

byte[] key = KeyDerivation.CreateKey();                 // 32 bytes, AES-256
var protector = new DpapiSecretProtector();

// What lands in the configuration file is the DPAPI-protected key, never the key itself.
string storedKey = protector.Protect(Convert.ToBase64String(key));
string encrypted = ConfigurationProtector.Encrypt("""{"apiKey":"…"}""", key);
```

A fresh nonce is generated for every encryption, so encrypting the same content twice never produces the same ciphertext.
AES-GCM authenticates as well as encrypts: change one byte of the payload and decryption fails instead of quietly
returning something wrong.

`ConfigurationProtector.IsProtectedValue(value)` tells an already-encrypted configuration value apart from one still in
plain text, without needing the key — handy when migrating an existing file.

## Payload formats

| | Magic | Layout |
| --- | --- | --- |
| `DpapiSecretProtector` | `OZDP` | magic (4) + version (1) + scope (1) + DPAPI blob |
| `ConfigurationProtector` | `OZCF` | magic (4) + version (1) + nonce (12) + tag (16) + ciphertext |

Both are Base64-encoded in their string form. The `OZCF` header is also fed to AES-GCM as associated data, so tampering
with the header fails authentication too.

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
