using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Configuration;

/// <summary>
/// 包住既有 <see cref="IConfigurationProvider"/> 的提供者:<see cref="TryGet"/> 讀到受保護的值就解密後回傳,
/// 其餘的值與所有其他操作原樣轉交給內層。
/// A provider wrapping an existing <see cref="IConfigurationProvider"/>: <see cref="TryGet"/> decrypts a
/// protected value before returning it; every other value and every other operation goes straight
/// through to the inner provider.
/// </summary>
/// <remarks>
/// 解密結果以密文為鍵快取:設定值在綁定與 <c>IOptionsSnapshot</c> 時會被讀很多次,而金鑰式保護器每次操作都會讀一次金鑰來源,
/// 沒有快取的話每次讀設定都在讀金鑰檔。以密文當鍵的好處是重新載入後值若沒變就直接命中、變了就自然失效,不必掛 reload token。
/// Decrypted results are cached by ciphertext: configuration values are read many times during binding and
/// through <c>IOptionsSnapshot</c>, and the keyed protector reads its key source on every operation, so
/// without the cache each configuration read would hit the key file. Keying by ciphertext means an unchanged
/// value after a reload hits the cache and a changed one misses it naturally, with no reload-token plumbing.
/// </remarks>
internal sealed class ProtectedValueConfigurationProvider : IConfigurationProvider, IDisposable
{
    private readonly IConfigurationProvider _inner;
    private readonly ISecretProtector _protector;
    private readonly Func<string?, bool> _isProtectedValue;
    private readonly ConcurrentDictionary<string, string> _decrypted = new(StringComparer.Ordinal);

    /// <summary>
    /// 建立包裝提供者。
    /// Creates the wrapping provider.
    /// </summary>
    /// <param name="inner">
    /// 被包住的原始提供者。
    /// The original provider being wrapped.
    /// </param>
    /// <param name="protector">
    /// 用來解密的保護器。
    /// The protector used to decrypt.
    /// </param>
    /// <param name="isProtectedValue">
    /// 判斷值是否受保護的述詞。
    /// The predicate deciding whether a value is protected.
    /// </param>
    public ProtectedValueConfigurationProvider(IConfigurationProvider inner, ISecretProtector protector, Func<string?, bool> isProtectedValue)
    {
        _inner = inner;
        _protector = protector;
        _isProtectedValue = isProtectedValue;
    }

    /// <inheritdoc />
    public bool TryGet(string key, out string? value)
    {
        if (!_inner.TryGet(key, out string? raw))
        {
            value = null;
            return false;
        }

        value = _isProtectedValue(raw) ? Decrypt(key, raw!) : raw;
        return true;
    }

    /// <inheritdoc />
    public void Set(string key, string? value) => _inner.Set(key, value);

    /// <inheritdoc />
    public IChangeToken GetReloadToken() => _inner.GetReloadToken();

    /// <inheritdoc />
    public void Load() => _inner.Load();

    /// <inheritdoc />
    public IEnumerable<string> GetChildKeys(IEnumerable<string> earlierKeys, string? parentPath)
        => _inner.GetChildKeys(earlierKeys, parentPath);

    /// <inheritdoc />
    public void Dispose() => (_inner as IDisposable)?.Dispose();

    /// <summary>
    /// 除錯檢視(<c>GetDebugView</c>)用內層提供者的名稱,讓宿主看到的還是原本的來源。
    /// The debug view (<c>GetDebugView</c>) shows the inner provider's name so the host still sees the original source.
    /// </summary>
    /// <returns>
    /// 內層提供者的字串表示。
    /// The inner provider's string form.
    /// </returns>
    public override string ToString() => _inner.ToString() ?? nameof(ProtectedValueConfigurationProvider);

    /// <summary>
    /// 解密一個受保護的值,失敗時擲出指明設定鍵的例外 —— 訊息裡只有鍵,沒有密文也沒有明文。
    /// Decrypts one protected value, throwing an exception that names the configuration key on failure —
    /// the message carries the key only, never the ciphertext or the plain text.
    /// </summary>
    /// <param name="key">
    /// 設定鍵(完整路徑)。
    /// The configuration key (full path).
    /// </param>
    /// <param name="protectedValue">
    /// 受保護的值。
    /// The protected value.
    /// </param>
    /// <returns>
    /// 解密後的明文。
    /// The decrypted plain text.
    /// </returns>
    private string Decrypt(string key, string protectedValue)
    {
        if (_decrypted.TryGetValue(protectedValue, out string? cached))
        {
            return cached;
        }

        string plainText;
        try
        {
            plainText = _protector.Unprotect(protectedValue);
        }
        catch (SecretProtectionException ex)
        {
            throw new SecretProtectionException(
                ex.Reason,
                "設定鍵 '" + key + "' 的值是受保護的密文,但無法解密(原因:" + ex.Reason + ")。" +
                "請確認這台主機配置的主金鑰與加密時用的是同一把,且值沒有被截斷或改動。 " +
                "The value of configuration key '" + key + "' is protected but could not be decrypted (reason: " + ex.Reason + "). " +
                "Check that this host is provisioned with the same master key the value was encrypted with, and that the value was not truncated or edited.",
                ex);
        }
        catch (PlatformNotSupportedException ex)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.PlatformNotSupported,
                "設定鍵 '" + key + "' 的值是受保護的密文,但目前平台不支援這個保護機制。 " +
                "The value of configuration key '" + key + "' is protected but the current platform does not support this protection mechanism.",
                ex);
        }

        return _decrypted.GetOrAdd(protectedValue, plainText);
    }
}
