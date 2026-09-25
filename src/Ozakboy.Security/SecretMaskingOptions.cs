using Ozakboy.Security.Masking;

namespace Ozakboy.Security;

/// <summary>
/// 由 <c>AddOzakboySecurity</c> 註冊的 <see cref="SecretMasker"/> 的 Options 設定:遮罩規則、啟動時要登記的已知祕密,
/// 以及日誌遮罩的行為開關。走 Options 模式是為了讓宿主能在設定綁定之後再補登記
/// (<c>services.Configure&lt;SecretMaskingOptions&gt;(o =&gt; o.KnownSecrets.Add(…))</c>),
/// 不必在呼叫 <c>AddOzakboySecurity</c> 的當下就把所有祕密拿在手上。
/// Options-pattern settings for the <see cref="SecretMasker"/> registered by <c>AddOzakboySecurity</c>: the
/// masking rules, the known secrets to register at start-up, and the log-masking behaviour switch. It uses the
/// Options pattern so a host can register more secrets after configuration has been bound
/// (<c>services.Configure&lt;SecretMaskingOptions&gt;(o =&gt; o.KnownSecrets.Add(…))</c>) instead of having every
/// secret in hand at the moment <c>AddOzakboySecurity</c> is called.
/// </summary>
/// <remarks>
/// 驗證:<see cref="KnownSecrets"/> 的每一項都必須非空白且長度至少 <see cref="SecretMasker.MinimumKnownSecretLength"/>,
/// 否則第一次解析 <see cref="SecretMasker"/> 時擲出 <see cref="Microsoft.Extensions.Options.OptionsValidationException"/>,
/// 訊息只指出第幾項,不回述值。
/// Validation: every entry in <see cref="KnownSecrets"/> must be non-blank and at least
/// <see cref="SecretMasker.MinimumKnownSecretLength"/> characters, otherwise the first resolution of
/// <see cref="SecretMasker"/> throws <see cref="Microsoft.Extensions.Options.OptionsValidationException"/>; the message
/// names the index only, never the value.
/// </remarks>
public sealed class SecretMaskingOptions
{
    /// <summary>
    /// 遮罩規則(露出幾碼、敏感欄位名清單等),預設 <see cref="SecretMaskOptions.Default"/>。
    /// The masking rules (how much to reveal, sensitive-name lists and so on); defaults to
    /// <see cref="SecretMaskOptions.Default"/>.
    /// </summary>
    public SecretMaskOptions MaskOptions { get; set; } = SecretMaskOptions.Default;

    /// <summary>
    /// 建立遮罩器時要登記的已知祕密字面值(API 金鑰、channel secret、資料庫密碼)。
    /// 通常從 <c>IConfiguration</c> 讀出來之後加進來;值只進遮罩器,不會從任何公開 API 流出去。
    /// Known secret literals to register when the masker is built (API keys, channel secrets, database passwords).
    /// Usually added after they are read from <c>IConfiguration</c>; the values go into the masker only and never leave
    /// through any public API.
    /// </summary>
    public IList<string> KnownSecrets { get; } = [];

    /// <summary>
    /// 是否把 <see cref="KnownSecrets"/> 也登記到 <see cref="SecretMasker.Default"/> 上,預設 <see langword="true"/>。
    /// <c>Ozakboy.Http</c> 有些關口在沒拿到具名遮罩器時會退回 <see cref="SecretMasker.Default"/>;
    /// 多登記一份不花什麼,少登記一份就是外洩。不想動到共用的靜態遮罩器(例如測試隔離)時關掉。
    /// Whether <see cref="KnownSecrets"/> are also registered on <see cref="SecretMasker.Default"/>; defaults to
    /// <see langword="true"/>. Some <c>Ozakboy.Http</c> checkpoints fall back to <see cref="SecretMasker.Default"/> when
    /// no named masker reaches them; one registration too many costs nothing, one too few is a leak. Turn it off when
    /// the shared static masker must stay untouched (test isolation, say).
    /// </summary>
    public bool AlsoRegisterOnDefaultMasker { get; set; } = true;

    /// <summary>
    /// 日誌遮罩是否依<b>屬性名稱</b>遮結構化日誌的字串值(<c>"token={Token}"</c> 的 <c>Token</c> 屬性即使沒登記也會被遮),
    /// 預設 <see langword="true"/>。名稱比對用 <see cref="SecretMasker.IsSensitiveName"/>,所以包含式比對的過度遮罩也適用
    /// (<c>{CacheKey}</c> 會被遮)。關掉之後日誌遮罩只剩已登記祕密的字面替換。
    /// Whether log masking masks string values of structured properties <b>by property name</b> (the <c>Token</c>
    /// property in <c>"token={Token}"</c> is masked even when unregistered); defaults to <see langword="true"/>. Name
    /// matching goes through <see cref="SecretMasker.IsSensitiveName"/>, so substring over-masking applies as well
    /// (<c>{CacheKey}</c> gets masked). With it off, log masking is reduced to literal replacement of registered secrets.
    /// </summary>
    public bool MaskLogPropertiesByName { get; set; } = true;
}
