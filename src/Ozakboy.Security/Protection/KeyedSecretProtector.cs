using System.Globalization;
using System.Security.Cryptography;
using Ozakboy.Security.Configuration;

namespace Ozakboy.Security.Protection;

/// <summary>
/// 以應用程式自己的主金鑰(AES-256-GCM)保護敏感資料的 <see cref="ISecretProtector"/>,跨平台可用。
/// 這是非 Windows 主機(Linux EC2、Docker 容器)上 <see cref="DpapiSecretProtector"/> 的替代品:
/// 金鑰不由作業系統保管,而是由 <see cref="ISecretKeySource"/> 提供 —— 環境變數、金鑰檔,或呼叫端自訂的來源。
/// An <see cref="ISecretProtector"/> that protects values with the application's own master key
/// (AES-256-GCM) and runs on every platform. It is the stand-in for <see cref="DpapiSecretProtector"/>
/// on non-Windows hosts (Linux EC2, Docker containers): the operating system does not hold the key;
/// an <see cref="ISecretKeySource"/> does — an environment variable, a key file, or a source of the
/// caller's own.
/// </summary>
/// <remarks>
/// <para>
/// <b>輸出格式就是 <see cref="ConfigurationProtector"/> 的 <c>OZCF</c> 封裝</b>(魔術字 4 + 版本 1 + 隨機 nonce 12 +
/// 驗證標籤 16 + 密文),沒有另立一種格式。這是刻意的:同一把金鑰下,用 <see cref="ConfigurationProtector.Encrypt(string, ReadOnlySpan{byte})"/>
/// 在建置機或 CLI 加密的值,部署後由這個保護器解得開,反之亦然;設定整合層也只需要認得一種格式
/// (<see cref="ConfigurationProtector.IsProtectedValue"/>)。代價是從密文本身看不出它是「整份設定檔」還是「單一值」,
/// 但兩者用的是同一把金鑰、同一套語意,分辨不出來也沒有任何後果。
/// <b>The output format is <see cref="ConfigurationProtector"/>'s <c>OZCF</c> envelope</b> (magic 4 + version 1 +
/// random nonce 12 + tag 16 + ciphertext); no second format is introduced. That is deliberate: under the
/// same key, a value encrypted on a build machine or from a CLI with
/// <see cref="ConfigurationProtector.Encrypt(string, ReadOnlySpan{byte})"/> is readable by this protector
/// after deployment, and the other way round, and the configuration integration only has to recognise one
/// format (<see cref="ConfigurationProtector.IsProtectedValue"/>). The cost is that the ciphertext alone
/// does not say whether it was "a whole file" or "a single value" — but both use the same key with the
/// same semantics, so nothing hinges on the difference.
/// </para>
/// <para>
/// <b>金鑰不常駐。</b>每次 Protect / Unprotect 都向 <see cref="ISecretKeySource"/> 要一份新的金鑰,用完立刻清零;
/// 這個物件本身不持有金鑰,所以不需要 Dispose,也不會在記憶體傾印裡留下一份長期存在的金鑰。
/// 代價是每次操作都讀一次來源(金鑰檔的話就是一次檔案讀取加權限檢查);憑證保護不是熱路徑,
/// 而設定整合層會快取解密結果,實際上每個值只解一次。
/// <b>The key is not kept resident.</b> Every Protect / Unprotect asks the <see cref="ISecretKeySource"/>
/// for a fresh copy and zeroes it immediately afterwards; the object holds no key, so it needs no Dispose
/// and leaves no long-lived key in a memory dump. The cost is one source read per operation (for a key
/// file: one file read plus the permission check). Secret protection is not a hot path, and the
/// configuration integration caches decrypted results, so in practice each value is decrypted once.
/// </para>
/// <para>
/// <b>Windows 上也能用。</b>它不是「只給 Linux 的」:在 Windows 上想讓多台機器共用同一把金鑰
/// (DPAPI 綁機器或使用者,做不到這件事)時,這個保護器就是答案。
/// <b>It works on Windows too.</b> It is not "the Linux one": on Windows, when several machines must
/// share one key (which DPAPI, bound to a machine or a user, cannot do), this protector is the answer.
/// </para>
/// </remarks>
public sealed class KeyedSecretProtector : ISecretProtector
{
    /// <summary>
    /// 主金鑰長度:32 位元組(AES-256)。刻意只接受這一種,不接受 16 / 24:主金鑰只有一把,沒有理由用較短的。
    /// The master-key length: 32 bytes (AES-256). Only this size is accepted, not 16 or 24: there is a
    /// single master key and no reason for it to be shorter.
    /// </summary>
    public const int KeyLengthInBytes = 32;

    private readonly ISecretKeySource _keySource;

    /// <summary>
    /// 以指定的金鑰來源建立保護器。建構時不讀金鑰。
    /// Creates a protector over the given key source. The key is not read at construction.
    /// </summary>
    /// <param name="keySource">
    /// 主金鑰來源,不可為 <see langword="null"/>。
    /// The master-key source; must not be <see langword="null"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="keySource"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="keySource"/> is <see langword="null"/>.
    /// </exception>
    public KeyedSecretProtector(ISecretKeySource keySource)
    {
        ArgumentNullException.ThrowIfNull(keySource);
        _keySource = keySource;
    }

    /// <summary>
    /// 目前平台是否支援 AES-GCM。與 <see cref="ConfigurationProtector.IsSupported"/> 相同;
    /// 不檢查金鑰來源是否可用,那要真的讀一次才知道。
    /// Whether AES-GCM is available on this platform; the same as
    /// <see cref="ConfigurationProtector.IsSupported"/>. It does not probe the key source — only an actual
    /// read can tell.
    /// </summary>
    public bool IsSupported => ConfigurationProtector.IsSupported;

    /// <summary>
    /// 這個保護器使用的金鑰來源。
    /// The key source this protector uses.
    /// </summary>
    public ISecretKeySource KeySource => _keySource;

    /// <summary>
    /// 判斷字串是否為本保護器(也就是 <see cref="ConfigurationProtector"/>)產生的密文,只看標頭,不需要金鑰。
    /// Checks whether a string is ciphertext produced by this protector (that is, by
    /// <see cref="ConfigurationProtector"/>), by header only and without the key.
    /// </summary>
    /// <param name="value">
    /// 待檢查的字串,允許 <see langword="null"/>。
    /// The value to inspect; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 具備 <c>OZCF</c> 標頭時回傳 <see langword="true"/>。
    /// <see langword="true"/> when the value carries the <c>OZCF</c> header.
    /// </returns>
    public static bool IsProtectedValue(string? value) => ConfigurationProtector.IsProtectedValue(value);

    /// <inheritdoc />
    public string Protect(string plainText)
    {
        ArgumentNullException.ThrowIfNull(plainText);

        byte[] key = ReadKey();
        try
        {
            return ConfigurationProtector.Encrypt(plainText, key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    public byte[] Protect(byte[] plainBytes)
    {
        ArgumentNullException.ThrowIfNull(plainBytes);

        byte[] key = ReadKey();
        try
        {
            return ConfigurationProtector.Encrypt(plainBytes, key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    public string Unprotect(string protectedValue)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);

        byte[] key = ReadKey();
        try
        {
            return ConfigurationProtector.Decrypt(protectedValue, key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    public byte[] Unprotect(byte[] protectedBytes)
    {
        ArgumentNullException.ThrowIfNull(protectedBytes);

        byte[] key = ReadKey();
        try
        {
            return ConfigurationProtector.Decrypt(protectedBytes, key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// 金鑰取不到(<see cref="SecretProtectionFailureReason.KeyUnavailable"/>)與平台不支援 AES-GCM 都回傳
    /// <see langword="false"/>,與 <see cref="ConfigurationProtector.TryDecrypt"/> 一致 —— 名字叫 <c>Try</c> 的方法不從側面漏例外。
    /// 要分辨「資料解不開」與「這台機器根本沒配金鑰」,請用 <see cref="Unprotect(string)"/> 並看 <see cref="SecretProtectionException.Reason"/>。
    /// An unobtainable key (<see cref="SecretProtectionFailureReason.KeyUnavailable"/>) and a platform
    /// without AES-GCM both yield <see langword="false"/>, matching
    /// <see cref="ConfigurationProtector.TryDecrypt"/>: a method named <c>Try</c> does not leak exceptions
    /// out the side. To tell "cannot decrypt" from "this host has no key", call
    /// <see cref="Unprotect(string)"/> and inspect <see cref="SecretProtectionException.Reason"/>.
    /// </remarks>
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
        catch (PlatformNotSupportedException)
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
        catch (PlatformNotSupportedException)
        {
            plainBytes = null;
            return false;
        }
    }

    /// <summary>
    /// 向金鑰來源讀一份金鑰,並再驗一次長度 —— 內建來源自己會驗,但第三方實作不一定。
    /// Reads a key from the source and re-checks its length: the built-in sources validate it themselves,
    /// a third-party implementation might not.
    /// </summary>
    /// <returns>
    /// 新配置的金鑰,呼叫端用完必須清零。
    /// A freshly allocated key the caller must zero after use.
    /// </returns>
    private byte[] ReadKey()
    {
        byte[]? key = _keySource.ReadKey();
        if (key is null || key.Length != KeyLengthInBytes)
        {
            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }

            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "金鑰來源(" + _keySource.Description + ")回傳的金鑰不是 " + KeyLengthInBytes.ToString(CultureInfo.InvariantCulture) + " 位元組,無法使用。 " +
                "The key source (" + _keySource.Description + ") returned a key that is not " + KeyLengthInBytes.ToString(CultureInfo.InvariantCulture) + " bytes long; it cannot be used.");
        }

        return key;
    }
}
