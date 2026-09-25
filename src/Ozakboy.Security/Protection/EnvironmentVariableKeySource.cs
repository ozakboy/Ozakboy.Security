using System.Globalization;
using System.Security.Cryptography;

namespace Ozakboy.Security.Protection;

/// <summary>
/// 從環境變數讀取主金鑰的 <see cref="ISecretKeySource"/>:變數內容是 32 位元組金鑰的 Base64 字串。
/// 這是容器(Docker / ECS / Kubernetes)場景的標準做法 —— 金鑰由編排系統的 secret 機制注入,
/// 不落在映像檔或設定檔裡。
/// An <see cref="ISecretKeySource"/> that reads the master key from an environment variable holding the
/// Base64 form of a 32-byte key. This is the standard arrangement for containers (Docker / ECS /
/// Kubernetes): the orchestrator's secret mechanism injects the key, and it never lands in the image or
/// a configuration file.
/// </summary>
/// <remarks>
/// 產生金鑰:<c>openssl rand -base64 32</c>,或在 .NET 裡
/// <c>Convert.ToBase64String(KeyDerivation.CreateKey())</c>。
/// 每次讀取都重新查環境變數,不快取:環境變數在程序啟動後幾乎不會變,而重讀的成本可以忽略;
/// 讀出的字串本身無法清零(字串不可變),這是環境變數這條路徑的固有限制,金鑰檔路徑沒有這個問題。
/// Generate a key with <c>openssl rand -base64 32</c>, or in .NET with
/// <c>Convert.ToBase64String(KeyDerivation.CreateKey())</c>. The variable is read afresh on every
/// call rather than cached: environment variables practically never change after start-up and re-reading
/// costs nothing. The string read cannot be zeroed (strings are immutable); that is an inherent limit of
/// the environment-variable route which the key-file route does not share.
/// </remarks>
public sealed class EnvironmentVariableKeySource : ISecretKeySource
{
    private readonly string _variableName;

    /// <summary>
    /// 建立以指定環境變數為來源的金鑰來源。
    /// Creates a key source backed by the named environment variable.
    /// </summary>
    /// <param name="variableName">
    /// 環境變數名稱,不可為空白。
    /// The environment variable name; must not be blank.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="variableName"/> 為 <see langword="null"/> 或空白時擲出。
    /// Thrown when <paramref name="variableName"/> is <see langword="null"/> or blank.
    /// </exception>
    public EnvironmentVariableKeySource(string variableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(variableName);
        _variableName = variableName;
    }

    /// <summary>
    /// 環境變數名稱。
    /// The environment variable name.
    /// </summary>
    public string VariableName => _variableName;

    /// <inheritdoc />
    public string Description => "環境變數 / environment variable '" + _variableName + "'";

    /// <inheritdoc />
    public byte[] ReadKey()
    {
        string? value = Environment.GetEnvironmentVariable(_variableName);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "環境變數 '" + _variableName + "' 未設定或為空,無法取得主金鑰。請以 32 位元組金鑰的 Base64 字串設定它(例如 openssl rand -base64 32)。 " +
                "Environment variable '" + _variableName + "' is unset or empty, so no master key is available. Set it to the Base64 form of a 32-byte key (for example openssl rand -base64 32).");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(value.Trim());
        }
        catch (FormatException ex)
        {
            // 訊息不回述變數內容:它可能是打錯了幾個字的真金鑰。
            // The message never echoes the value: it may be a real key with a typo in it.
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "環境變數 '" + _variableName + "' 的內容不是有效的 Base64,無法取得主金鑰。 " +
                "Environment variable '" + _variableName + "' does not hold valid Base64, so no master key is available.",
                ex);
        }

        if (key.Length != KeyedSecretProtector.KeyLengthInBytes)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "環境變數 '" + _variableName + "' 解碼後是 " + key.Length.ToString(CultureInfo.InvariantCulture) +
                " 位元組,主金鑰必須是 " + KeyedSecretProtector.KeyLengthInBytes.ToString(CultureInfo.InvariantCulture) + " 位元組(AES-256)。 " +
                "Environment variable '" + _variableName + "' decodes to " + key.Length.ToString(CultureInfo.InvariantCulture) +
                " bytes; the master key must be " + KeyedSecretProtector.KeyLengthInBytes.ToString(CultureInfo.InvariantCulture) + " bytes (AES-256).");
        }

        return key;
    }
}
