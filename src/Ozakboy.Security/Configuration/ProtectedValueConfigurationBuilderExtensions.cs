using Microsoft.Extensions.Configuration;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Configuration;

/// <summary>
/// <see cref="IConfigurationBuilder"/> 的擴充:讓設定值裡以本套件格式加密的字串在讀取時自動解密,
/// ASP.NET Core 的 <c>appsettings.json</c>、環境變數、User Secrets 都不用改寫法。
/// Extensions for <see cref="IConfigurationBuilder"/> that decrypt configuration values encrypted in this
/// library's formats on read, so ASP.NET Core's <c>appsettings.json</c>, environment variables and user
/// secrets all work unchanged.
/// </summary>
public static class ProtectedValueConfigurationBuilderExtensions
{
    /// <summary>
    /// 預設的「值是否受保護」判斷:認得 <c>OZCF</c>(<see cref="ConfigurationProtector"/> / <see cref="KeyedSecretProtector"/>)
    /// 與 <c>OZDP</c>(<see cref="DpapiSecretProtector"/>)兩種封裝。
    /// The default "is this value protected" test: recognises both the <c>OZCF</c>
    /// (<see cref="ConfigurationProtector"/> / <see cref="KeyedSecretProtector"/>) and the <c>OZDP</c>
    /// (<see cref="DpapiSecretProtector"/>) envelopes.
    /// </summary>
    /// <param name="value">
    /// 待檢查的設定值,允許 <see langword="null"/>。
    /// The configuration value to inspect; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 是任一種封裝時回傳 <see langword="true"/>。
    /// <see langword="true"/> when the value is either envelope.
    /// </returns>
    public static bool IsAnyProtectedValue(string? value)
        => ConfigurationProtector.IsProtectedValue(value) || DpapiSecretProtector.IsProtectedValue(value);

    /// <summary>
    /// 把目前已加入的每個設定來源包一層,讀到受保護的值時以 <paramref name="protector"/> 解密後再交出去;
    /// 不受保護的值原樣通過。<b>請在所有來源都加完之後呼叫</b>(在 ASP.NET Core 裡就是 <c>builder.Configuration</c> 上、
    /// 建 <c>Build()</c> 之前的最後一步):之後才加的來源不會被包到。
    /// Wraps every configuration source added so far so that protected values are decrypted with
    /// <paramref name="protector"/> when read; unprotected values pass through untouched. <b>Call it after
    /// every source has been added</b> (in ASP.NET Core: on <c>builder.Configuration</c>, as the last step
    /// before <c>Build()</c>): sources added afterwards are not wrapped.
    /// </summary>
    /// <param name="builder">
    /// 設定建構器;<c>WebApplicationBuilder.Configuration</c> 也可以(它同時是 <see cref="IConfigurationBuilder"/>,
    /// 替換來源會立即重新載入)。
    /// The configuration builder; <c>WebApplicationBuilder.Configuration</c> works too (it is also an
    /// <see cref="IConfigurationBuilder"/>, and replacing a source reloads immediately).
    /// </param>
    /// <param name="protector">
    /// 用來解密的保護器,通常是 <see cref="KeyedSecretProtector"/>(Linux / 容器)或 <see cref="DpapiSecretProtector"/>(Windows)。
    /// The protector used to decrypt, usually <see cref="KeyedSecretProtector"/> (Linux / containers) or
    /// <see cref="DpapiSecretProtector"/> (Windows).
    /// </param>
    /// <param name="isProtectedValue">
    /// 判斷值是否受保護的述詞,<see langword="null"/> 時用 <see cref="IsAnyProtectedValue"/>(認得 OZCF 與 OZDP)。
    /// 只想認其中一種,或有自訂格式時傳自己的。
    /// The predicate deciding whether a value is protected; <see langword="null"/> means
    /// <see cref="IsAnyProtectedValue"/> (both OZCF and OZDP). Pass your own to accept only one of them, or a
    /// custom format.
    /// </param>
    /// <returns>
    /// 同一個建構器,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <remarks>
    /// <para>
    /// 解密失敗會擲出 <see cref="SecretProtectionException"/>,訊息指出<b>是哪個設定鍵</b>,但不含密文也不含明文;
    /// <see cref="SecretProtectionException.Reason"/> 沿用保護器回報的原因(金鑰沒配好是 <see cref="SecretProtectionFailureReason.KeyUnavailable"/>、
    /// 金鑰不對是 <see cref="SecretProtectionFailureReason.DecryptionFailed"/>)。失敗發生在<b>第一次讀到那個值</b>的時候,
    /// 通常就是啟動時綁定選項的當下,所以配錯金鑰的服務起不來,而不是帶著密文跑下去。
    /// A failed decryption throws <see cref="SecretProtectionException"/> whose message names <b>the configuration
    /// key</b> but contains neither the ciphertext nor the plain text; <see cref="SecretProtectionException.Reason"/> is
    /// whatever the protector reported (<see cref="SecretProtectionFailureReason.KeyUnavailable"/> for a missing key,
    /// <see cref="SecretProtectionFailureReason.DecryptionFailed"/> for the wrong one). The failure surfaces the
    /// <b>first time that value is read</b>, usually while options are bound at start-up, so a misprovisioned service
    /// fails to start rather than running on with ciphertext.
    /// </para>
    /// <para>
    /// 每個密文只解密一次,結果快取在提供者裡;設定重新載入後值沒變就直接命中。
    /// Each ciphertext is decrypted once and cached in the provider; an unchanged value after a reload hits the cache.
    /// </para>
    /// <para>
    /// 已經包過的來源不會再包一次,重複呼叫是安全的。
    /// A source that is already wrapped is not wrapped again, so calling this twice is safe.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> 或 <paramref name="protector"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="builder"/> or <paramref name="protector"/> is <see langword="null"/>.
    /// </exception>
    public static IConfigurationBuilder DecryptProtectedValues(
        this IConfigurationBuilder builder,
        ISecretProtector protector,
        Func<string?, bool>? isProtectedValue = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(protector);

        Func<string?, bool> predicate = isProtectedValue ?? IsAnyProtectedValue;
        IList<IConfigurationSource> sources = builder.Sources;

        for (int i = 0; i < sources.Count; i++)
        {
            if (sources[i] is ProtectedValueConfigurationSource)
            {
                continue;
            }

            // 以索引替換而不是移除再插入:ConfigurationManager 的來源集合每動一次就重新載入一次,一次動作比兩次便宜,
            // 也不會出現「來源暫時消失」的中間狀態。
            // Replace by index rather than remove-and-insert: ConfigurationManager reloads on every mutation of its
            // source list, so one mutation is cheaper than two and there is no intermediate "source missing" state.
            sources[i] = new ProtectedValueConfigurationSource(sources[i], protector, predicate);
        }

        return builder;
    }
}
