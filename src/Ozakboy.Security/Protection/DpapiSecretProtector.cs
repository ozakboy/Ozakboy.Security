using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Ozakboy.Security.Protection;

/// <summary>
/// 以 Windows DPAPI 保護敏感資料的 <see cref="ISecretProtector"/> 實作。
/// 金鑰由作業系統依使用者帳戶或機器保管,程式不需要自己管理金鑰,適合把 API 金鑰這類憑證
/// 加密後寫進本機設定檔。
/// A <see cref="ISecretProtector"/> implementation backed by Windows DPAPI. The operating system
/// keeps the key material per user account or per machine, so the application never manages a key
/// itself; ideal for storing credentials such as API keys in a local configuration file.
/// </summary>
/// <remarks>
/// 輸出格式為 <c>OZDP</c> 標頭(4 位元組)+ 版本(1 位元組)+ 保護範圍(1 位元組)+ DPAPI 密文。
/// 標頭讓還原時能先分辨「資料損毀」與「範圍不符」,不必等到底層解密才發現。
/// The envelope is an <c>OZDP</c> magic header (4 bytes), a format version (1 byte), the protection
/// scope (1 byte) and the DPAPI blob. The header lets the unprotect path tell malformed data and a
/// scope mismatch apart before the underlying decryption is even attempted.
/// </remarks>
public sealed class DpapiSecretProtector : ISecretProtector
{
    /// <summary>
    /// 目前的封裝格式版本。
    /// The current envelope format version.
    /// </summary>
    private const byte FormatVersion = 1;

    /// <summary>
    /// 標頭長度:魔術字 4 + 版本 1 + 保護範圍 1。
    /// Header length: 4 magic bytes plus a version byte plus a scope byte.
    /// </summary>
    private const int HeaderLength = 6;

    /// <summary>
    /// 用來辨識本套件輸出的魔術字。
    /// Magic bytes identifying payloads written by this library.
    /// </summary>
    private static readonly byte[] MagicHeader = "OZDP"u8.ToArray();

    private readonly DpapiProtectionOptions _options;
    private readonly byte[]? _entropy;

    /// <summary>
    /// 以預設設定建立保護器(保護範圍為目前使用者、無額外熵值)。
    /// Creates a protector with the default options (current-user scope, no additional entropy).
    /// </summary>
    public DpapiSecretProtector()
        : this(new DpapiProtectionOptions())
    {
    }

    /// <summary>
    /// 以指定設定建立保護器。
    /// Creates a protector with the specified options.
    /// </summary>
    /// <param name="options">
    /// 保護設定,不可為 <see langword="null"/>。
    /// The protection options; must not be <see langword="null"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="options"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="options"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="options"/> 的保護範圍不是有效值時拋出。
    /// Thrown when the scope in <paramref name="options"/> is not a defined value.
    /// </exception>
    public DpapiSecretProtector(DpapiProtectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!Enum.IsDefined(options.Scope))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "保護範圍不是有效值。 The protection scope is not a defined value.");
        }

        _options = options;
        _entropy = options.Entropy.IsEmpty ? null : options.Entropy.ToArray();
    }

    /// <summary>
    /// 目前平台是否支援 DPAPI。DPAPI 是 Windows 專屬機制,其他作業系統一律為 <see langword="false"/>。
    /// Whether DPAPI is available on the current platform. DPAPI is Windows-only, so any other
    /// operating system reports <see langword="false"/>.
    /// </summary>
    public bool IsSupported => OperatingSystem.IsWindows();

    /// <summary>
    /// 這份保護器使用的保護範圍。
    /// The protection scope this protector uses.
    /// </summary>
    public SecretProtectionScope Scope => _options.Scope;

    /// <inheritdoc />
    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        try
        {
            return Convert.ToBase64String(Protect(plainBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    /// <inheritdoc />
    public byte[] Protect(byte[] plainBytes)
    {
        ArgumentNullException.ThrowIfNull(plainBytes);

        if (!OperatingSystem.IsWindows())
        {
            throw CreatePlatformNotSupportedException();
        }

        byte[] blob = ProtectedData.Protect(plainBytes, _entropy, MapScope(_options.Scope));

        byte[] envelope = new byte[HeaderLength + blob.Length];
        MagicHeader.CopyTo(envelope, 0);
        envelope[4] = FormatVersion;
        envelope[5] = (byte)_options.Scope;
        blob.CopyTo(envelope, HeaderLength);
        return envelope;
    }

    /// <inheritdoc />
    public string Unprotect(string protectedValue)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);

        byte[] payload = DecodeBase64(protectedValue);
        byte[] plainBytes = Unprotect(payload);
        try
        {
            return Encoding.UTF8.GetString(plainBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    /// <inheritdoc />
    public byte[] Unprotect(byte[] protectedBytes)
    {
        ArgumentNullException.ThrowIfNull(protectedBytes);

        ValidateEnvelope(protectedBytes);

        if (!OperatingSystem.IsWindows())
        {
            throw CreatePlatformNotSupportedException();
        }

        byte[] blob = protectedBytes[HeaderLength..];
        try
        {
            return ProtectedData.Unprotect(blob, _entropy, MapScope(_options.Scope));
        }
        catch (CryptographicException ex)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.DecryptionFailed,
                "無法還原這份資料:內容可能遭竄改,或它是由其他使用者帳戶、其他機器加密的(若有使用額外熵值,也請確認熵值一致)。 " +
                "The data could not be restored: it may have been tampered with, or it was protected by a different user account or machine (also verify the additional entropy matches).",
                ex);
        }
    }

    /// <inheritdoc />
    public bool TryUnprotect(string protectedValue, out string? plainText)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);

        try
        {
            plainText = Unprotect(protectedValue);
            return true;
        }
        catch (SecretProtectionException)
        {
            plainText = null;
            return false;
        }
    }

    /// <inheritdoc />
    public bool TryUnprotect(byte[] protectedBytes, out byte[]? plainBytes)
    {
        ArgumentNullException.ThrowIfNull(protectedBytes);

        try
        {
            plainBytes = Unprotect(protectedBytes);
            return true;
        }
        catch (SecretProtectionException)
        {
            plainBytes = null;
            return false;
        }
    }

    /// <summary>
    /// 判斷字串是否為本套件產生的保護資料(只看標頭,不做解密)。
    /// Checks whether a string is a payload written by this library, by inspecting the header only.
    /// </summary>
    /// <param name="value">
    /// 待檢查的字串,允許 <see langword="null"/>。
    /// The value to inspect; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 具備本套件標頭時回傳 <see langword="true"/>。
    /// <see langword="true"/> when the value carries this library's header.
    /// </returns>
    public static bool IsProtectedValue(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            return false;
        }

        return payload.Length > HeaderLength
            && payload.AsSpan(0, MagicHeader.Length).SequenceEqual(MagicHeader);
    }

    /// <summary>
    /// 把本套件的保護範圍對應到 DPAPI 的原生列舉。
    /// Maps this library's scope onto the native DPAPI enum.
    /// </summary>
    /// <param name="scope">
    /// 本套件的保護範圍。
    /// This library's protection scope.
    /// </param>
    /// <returns>
    /// 對應的 DPAPI 保護範圍。
    /// The matching DPAPI protection scope.
    /// </returns>
    [SupportedOSPlatform("windows")]
    private static DataProtectionScope MapScope(SecretProtectionScope scope)
        => scope == SecretProtectionScope.LocalMachine
            ? DataProtectionScope.LocalMachine
            : DataProtectionScope.CurrentUser;

    /// <summary>
    /// 取得保護範圍的顯示名稱(固定英文字面值,不受地區設定影響)。
    /// Gets a display name for a scope as a fixed literal, independent of culture settings.
    /// </summary>
    /// <param name="scope">
    /// 保護範圍。
    /// The protection scope.
    /// </param>
    /// <returns>
    /// 顯示名稱。
    /// The display name.
    /// </returns>
    private static string ScopeName(SecretProtectionScope scope) => scope switch
    {
        SecretProtectionScope.CurrentUser => "CurrentUser",
        SecretProtectionScope.LocalMachine => "LocalMachine",
        _ => "Unknown",
    };

    /// <summary>
    /// 建立平台不支援的例外,訊息說明原因與替代方案。
    /// Creates the platform-not-supported exception, explaining the cause and the alternative.
    /// </summary>
    /// <returns>
    /// 待拋出的例外。
    /// The exception to throw.
    /// </returns>
    private static PlatformNotSupportedException CreatePlatformNotSupportedException()
        => new(
            "DPAPI 是 Windows 作業系統提供的機制,目前平台無法使用。 " +
            "請改為注入其他 ISecretProtector 實作(例如以環境變數、作業系統金鑰鏈或雲端 KMS 保管憑證),本套件的介面即為此而設計。 " +
            "DPAPI is provided by the Windows operating system and is unavailable on the current platform. " +
            "Inject a different ISecretProtector implementation instead (for example one backed by environment variables, an OS keychain, or a cloud KMS); the interface exists exactly for this substitution.");

    /// <summary>
    /// 以 Base64 解碼保護資料,格式錯誤時轉為可判讀的失敗原因。
    /// Decodes a Base64 payload, converting format errors into a classified failure.
    /// </summary>
    /// <param name="protectedValue">
    /// 保護資料的 Base64 字串。
    /// The protected value as Base64 text.
    /// </param>
    /// <returns>
    /// 解碼後的位元組資料。
    /// The decoded bytes.
    /// </returns>
    private static byte[] DecodeBase64(string protectedValue)
    {
        try
        {
            return Convert.FromBase64String(protectedValue);
        }
        catch (FormatException ex)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.MalformedPayload,
                "保護資料不是有效的 Base64 內容,設定檔可能已損毀或被手動編輯。 " +
                "The protected value is not valid Base64; the configuration file may be corrupted or hand-edited.",
                ex);
        }
    }

    /// <summary>
    /// 檢查封裝標頭,並在不符時以對應的失敗原因拋出例外。
    /// Validates the envelope header and throws with the matching failure reason when it does not fit.
    /// </summary>
    /// <param name="payload">
    /// 完整的保護資料位元組。
    /// The full protected payload.
    /// </param>
    private void ValidateEnvelope(ReadOnlySpan<byte> payload)
    {
        if (payload.Length <= HeaderLength || !payload[..MagicHeader.Length].SequenceEqual(MagicHeader))
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.MalformedPayload,
                "保護資料缺少本套件的格式標頭,內容可能已損毀、被截斷,或根本不是本套件加密的資料。 " +
                "The payload is missing this library's format header; it may be corrupted, truncated, or not produced by this library at all.");
        }

        byte version = payload[MagicHeader.Length];
        if (version != FormatVersion)
        {
            string actualVersion = version.ToString(CultureInfo.InvariantCulture);
            string expectedVersion = FormatVersion.ToString(CultureInfo.InvariantCulture);
            throw new SecretProtectionException(
                SecretProtectionFailureReason.UnsupportedFormatVersion,
                "保護資料的格式版本為 " + actualVersion + ",本程式庫只支援版本 " + expectedVersion + ",資料可能由較新版本產生。 " +
                "The payload uses envelope version " + actualVersion + " but this library only supports version " +
                expectedVersion + "; it may have been written by a newer version.");
        }

        byte scopeValue = payload[MagicHeader.Length + 1];
        if (!Enum.IsDefined((SecretProtectionScope)scopeValue))
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.MalformedPayload,
                "保護資料標示的保護範圍不是有效值,內容可能已損毀。 " +
                "The payload declares an undefined protection scope; it may be corrupted.");
        }

        var payloadScope = (SecretProtectionScope)scopeValue;
        if (payloadScope != _options.Scope)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.ScopeMismatch,
                "保護資料是以 " + ScopeName(payloadScope) + " 範圍加密的,但目前以 " + ScopeName(_options.Scope) +
                " 範圍還原,兩者必須一致。 " +
                "The payload was protected with the " + ScopeName(payloadScope) + " scope but is being unprotected with the " +
                ScopeName(_options.Scope) + " scope; the two must match.");
        }
    }
}
