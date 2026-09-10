using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;

namespace Ozakboy.Security.Masking;

/// <summary>
/// 敏感字串遮罩器:在寫入日誌前把憑證遮掉,只保留足以辨識的頭尾。
/// 支援四種入口:純字串(<see cref="Mask"/>)、URL query 參數(<see cref="MaskQueryString"/>)、
/// JSON 欄位(<see cref="MaskJson"/>),以及不需要呼叫端交出欄位名的自由文字
/// (<see cref="RegisterKnownSecret"/> 搭配 <see cref="MaskText"/>)。
/// 敏感欄位名比對一律忽略大小寫,並可另外啟用包含式比對。
/// Masks sensitive values before they reach a log, keeping only enough of each end to recognise which
/// credential it was. There are four entry points: plain strings (<see cref="Mask"/>), URL query
/// parameters (<see cref="MaskQueryString"/>), JSON fields (<see cref="MaskJson"/>), and free-form text
/// that the caller never had to hand over field by field (<see cref="RegisterKnownSecret"/> together
/// with <see cref="MaskText"/>). Field-name matching always ignores case and can additionally run as a
/// substring match.
/// </summary>
/// <remarks>
/// 執行緒安全:設定與名稱清單建立後不再變動;已登記祕密的清單是可變狀態,以「不可變快照 + 原子交換」
/// 維持執行緒安全 —— 登記時在鎖內建立新陣列並整個換掉,<see cref="MaskText"/> 只讀取快照,不需要鎖。
/// Thread safety: the options and the name sets never change after construction. The registry of known
/// secrets is mutable state kept safe by an immutable-snapshot swap: registration builds a fresh array
/// under a lock and swaps it in atomically, while <see cref="MaskText"/> only reads the current snapshot
/// and takes no lock at all.
/// </remarks>
public sealed class SecretMasker
{
    /// <summary>
    /// 露出字元數的無條件上限除數:不論設定怎麼調,露出的字元數都不得超過原值長度除以本值。
    /// 目前為 3,即最多露出三分之一。這是最後一道保險,擋住「設定被調鬆之後遮了等於沒遮」的情況。
    /// The unconditional cap on revealed characters: whatever the options say, at most
    /// <c>length / this</c> characters are ever revealed. It is 3, meaning a third of the value. This is
    /// the last line of defence against options loose enough to make masking meaningless.
    /// </summary>
    public const int MaximumRevealedLengthDivisor = 3;

    /// <summary>
    /// 可登記為已知祕密的最短長度。低於此長度的值會被拒絕:登記一個三、五個字元的字串,
    /// 會讓正常日誌內容被大量誤遮,反而把日誌變成不可讀。
    /// The shortest value accepted by <see cref="RegisterKnownSecret"/>. Anything shorter is rejected:
    /// registering a three- or five-character string would mask swathes of ordinary log text and turn the
    /// log into noise.
    /// </summary>
    public const int MinimumKnownSecretLength = 8;

    /// <summary>
    /// JSON 輸出用的編碼器:允許所有 Unicode 字元原樣輸出(中文不被轉成跳脫序列),
    /// 但仍保留 HTML 敏感字元的跳脫,避免遮罩後的日誌被貼進網頁時出事。
    /// The encoder used for JSON output: it lets every Unicode character through verbatim (so
    /// non-ASCII text stays readable) while still escaping HTML-sensitive characters, in case the
    /// masked log line ends up rendered in a web page.
    /// </summary>
    private static readonly JavaScriptEncoder JsonOutputEncoder = JavaScriptEncoder.Create(UnicodeRanges.All);

    private readonly HashSet<string> _sensitiveNames;
    private readonly string[] _sensitiveFragments;
    private readonly HashSet<string> _fullMaskNames;
    private readonly string[] _fullMaskFragments;
    private readonly string _maskSegment;

    /// <summary>
    /// 登記祕密時的互斥鎖。只保護「建立新快照並交換」這段,遮罩路徑不會走到這裡。
    /// The lock guarding registration. It only covers building and swapping the snapshot; the masking
    /// path never touches it.
    /// </summary>
    private readonly Lock _registrationLock = new();

    /// <summary>
    /// 已登記的祕密值快照,依長度由長到短排序,確保較長的祕密先被替換掉。
    /// 這個欄位只在鎖內以整個新陣列取代,讀取端一律以 <see cref="Volatile"/> 的方式讀取,確保取得的是完整快照。
    /// The snapshot of registered secret values, ordered longest first so a longer secret is replaced
    /// before any shorter one nested inside it. The field is only ever replaced wholesale under the lock;
    /// readers take a complete snapshot through a volatile read.
    /// </summary>
    private string[] _knownSecrets = [];

    /// <summary>
    /// 以預設設定建立遮罩器。
    /// Creates a masker with the default options.
    /// </summary>
    public SecretMasker()
        : this(SecretMaskOptions.Default)
    {
    }

    /// <summary>
    /// 以指定設定建立遮罩器。
    /// Creates a masker with the specified options.
    /// </summary>
    /// <param name="options">
    /// 遮罩設定,不可為 <see langword="null"/>。
    /// The masking options; must not be <see langword="null"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="options"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="options"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// 長度設定為負數、遮罩長度不是正數,或最少遮罩字元數小於 1 時拋出。
    /// Thrown when any length option is negative, the mask length is not positive, or the minimum hidden
    /// length is below 1.
    /// </exception>
    public SecretMasker(SecretMaskOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfNegative(options.VisiblePrefixLength, nameof(options));
        ArgumentOutOfRangeException.ThrowIfNegative(options.VisibleSuffixLength, nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.MinimumHiddenLength, 1, nameof(options));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaskLength, nameof(options));

        Options = options;
        _maskSegment = new string(options.MaskCharacter, options.MaskLength);

        _fullMaskNames = BuildNameSet(
            options.IncludeDefaultFullMaskNames ? SecretMaskOptions.DefaultFullMaskNames : null,
            options.AdditionalFullMaskNames);
        _fullMaskFragments = options.UseSubstringMatching
            ? BuildFragmentList(
                options.IncludeDefaultFullMaskNames ? SecretMaskOptions.DefaultFullMaskNameFragments : null,
                options.AdditionalFullMaskNameFragments)
            : [];

        // 全遮欄位本來就是敏感欄位,直接併入敏感清單,避免兩份清單各自維護時漏掉一邊。
        // A full-mask name is by definition sensitive, so it is folded into the sensitive sets; keeping
        // the two lists independent would eventually let one drift out of sync with the other.
        _sensitiveNames = BuildNameSet(
            options.IncludeDefaultSensitiveNames ? SecretMaskOptions.DefaultSensitiveNames : null,
            options.AdditionalSensitiveNames);
        _sensitiveNames.UnionWith(_fullMaskNames);

        _sensitiveFragments = options.UseSubstringMatching
            ? BuildFragmentList(
                options.IncludeDefaultSensitiveNames ? SecretMaskOptions.DefaultSensitiveNameFragments : null,
                options.AdditionalSensitiveNameFragments,
                _fullMaskFragments)
            : [];
    }

    /// <summary>
    /// 以預設設定建立的共用遮罩器,同時也是登記已知祕密的預設去處:
    /// 交易系統啟動時把金鑰登記到這裡,全程式的 <see cref="MaskText"/> 就共用同一份清單。
    /// A shared masker built from the default options, and the natural place to register known secrets:
    /// register the credentials here at start-up and every <see cref="MaskText"/> call in the process
    /// shares the same registry.
    /// </summary>
    public static SecretMasker Default { get; } = new();

    /// <summary>
    /// 這份遮罩器使用的設定。
    /// The options this masker uses.
    /// </summary>
    public SecretMaskOptions Options { get; }

    /// <summary>
    /// 全遮時輸出的遮罩字串(例如 <c>****</c>)。
    /// The mask segment emitted when a value is masked entirely (for example <c>****</c>).
    /// </summary>
    public string MaskSegment => _maskSegment;

    /// <summary>
    /// 目前已登記的祕密數量。刻意只公開數量而不公開內容 —— 已登記的值不會從任何 API 流出去。
    /// How many secrets are currently registered. Only the count is exposed, never the values: nothing
    /// that was registered ever leaves this object through a public API.
    /// </summary>
    public int KnownSecretCount => Volatile.Read(ref _knownSecrets).Length;

    /// <summary>
    /// 登記一個已知的祕密字面值,之後 <see cref="MaskText"/> 會把文字中出現的這個值換成遮罩字串。
    /// 適用於呼叫端根本沒機會逐欄位交出值的路徑:格式化字串的日誌、例外訊息、第三方函式庫吐出的內容。
    /// Registers a known secret literal; from then on <see cref="MaskText"/> replaces every occurrence of
    /// it with the mask segment. This is for paths where the caller never gets to hand values over field
    /// by field: formatted log messages, exception text, output from third-party libraries.
    /// </summary>
    /// <param name="value">
    /// 祕密的原始值,長度至少 <see cref="MinimumKnownSecretLength"/> 個字元。
    /// The raw secret value; at least <see cref="MinimumKnownSecretLength"/> characters long.
    /// </param>
    /// <returns>
    /// 這次呼叫確實新增了項目時回傳 <see langword="true"/>;值先前已登記過則回傳 <see langword="false"/>。
    /// <see langword="true"/> when this call actually added something; <see langword="false"/> when the
    /// value was already registered.
    /// </returns>
    /// <remarks>
    /// 替換一律採「區分大小寫的序數比對」:憑證本身區分大小寫,若改成忽略大小寫,只是大小寫碰巧相同的
    /// 一般文字也會被誤遮,而且遮掉之後無從得知遮的是什麼。
    /// 唯一的例外是十六進位表示(簽章、雜湊):同一個值可能以大寫或小寫出現,因此純十六進位且含字母的值
    /// 會自動連同全大寫與全小寫兩種寫法一起登記。Base64 這類大小寫本身帶有意義的表示法不做此處理。
    /// Replacement is always ordinal and case-sensitive: credentials are case-sensitive, a
    /// case-insensitive pass would mask ordinary text that merely differs in case, and once masked there
    /// is no way to tell what was hit. The single exception is hexadecimal (signatures, digests), where
    /// the same value legitimately appears in either case: a pure-hex value containing letters is
    /// registered in its all-lower and all-upper forms as well. Representations where case carries
    /// meaning, such as Base64, get no such treatment.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="value"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="value"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="value"/> 長度不足或只有空白字元時拋出。例外訊息刻意不含該值本身。
    /// Thrown when <paramref name="value"/> is too short or consists only of whitespace. The exception
    /// message deliberately never contains the value itself.
    /// </exception>
    public bool RegisterKnownSecret(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        // 例外訊息只說明規則,絕不回述被拒絕的值 —— 呼叫端多半會把例外寫進日誌,
        // 那正是這個型別存在要阻止的事。
        // The message states the rule and never echoes the rejected value: callers log exceptions, which
        // is precisely what this type exists to prevent.
        if (value.Length < MinimumKnownSecretLength || string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(
                "登記的祕密值長度至少需要 " + MinimumKnownSecretLength.ToString(CultureInfo.InvariantCulture) +
                " 個字元,且不得只有空白字元;過短的值會讓正常日誌內容被大量誤遮。 " +
                "A registered secret must be at least " + MinimumKnownSecretLength.ToString(CultureInfo.InvariantCulture) +
                " characters long and not whitespace only; shorter values would mask large amounts of ordinary log text.",
                nameof(value));
        }

        lock (_registrationLock)
        {
            List<string>? additions = null;
            CollectAddition(value, ref additions);

            if (IsHexWithLetters(value))
            {
                CollectAddition(value.ToLowerInvariant(), ref additions);
                CollectAddition(value.ToUpperInvariant(), ref additions);
            }

            if (additions is null)
            {
                return false;
            }

            string[] current = _knownSecrets;
            string[] updated = new string[current.Length + additions.Count];
            current.CopyTo(updated, 0);
            additions.CopyTo(updated, current.Length);

            // 由長到短:祕密 A 是祕密 B 的子字串時,必須先換掉較長的那個,否則會留下殘片。
            // Longest first: when one secret contains another, replacing the longer one first is what
            // stops a fragment of it surviving in the output.
            Array.Sort(updated, static (left, right) => right.Length.CompareTo(left.Length));

            Volatile.Write(ref _knownSecrets, updated);
            return true;
        }
    }

    /// <summary>
    /// 清空已登記的祕密清單。金鑰輪替後舊值不再需要保護時、或測試之間需要隔離狀態時使用。
    /// Clears the registry of known secrets. Use it after a key rotation, when the old value no longer
    /// needs protecting, or to isolate state between tests.
    /// </summary>
    public void ClearKnownSecrets()
    {
        lock (_registrationLock)
        {
            Volatile.Write(ref _knownSecrets, []);
        }
    }

    /// <summary>
    /// 對任意文字做全域替換,把所有已登記的祕密值換成遮罩字串。
    /// 這是最後一道防線:攔得到 <c>logger.LogError("下單失敗 key={Key}", apiKey)</c> 這種格式化日誌,
    /// 也攔得到 <c>ex.ToString()</c> 裡夾帶的憑證。
    /// Performs a global replacement over arbitrary text, swapping every registered secret for the mask
    /// segment. This is the last line of defence: it catches formatted log calls such as
    /// <c>logger.LogError("order failed key={Key}", apiKey)</c> as well as credentials embedded in
    /// <c>ex.ToString()</c>.
    /// </summary>
    /// <param name="text">
    /// 要遮罩的文字,允許 <see langword="null"/>。
    /// The text to mask; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 遮罩後的文字;沒有登記任何祕密,或文字中沒有出現已登記的值時,原字串實例會原樣回傳。
    /// The masked text. When nothing is registered, or no registered value occurs in the text, the very
    /// same string instance is returned.
    /// </returns>
    /// <remarks>
    /// 效能:這個方法可能在熱路徑上被呼叫。清單為空時直接回傳(絕大多數專案只會登記個位數個祕密),
    /// 每個祕密先以 <see cref="string.Contains(string, StringComparison)"/> 探測、命中才配置新字串,
    /// 因此「沒有命中」的常見情況完全不配置記憶體。
    /// Performance: this can sit on a hot path. An empty registry returns immediately (most applications
    /// register a single-digit number of secrets), and each secret is probed with
    /// <see cref="string.Contains(string, StringComparison)"/> before any string is allocated, so the
    /// common no-match case allocates nothing at all.
    /// </remarks>
    [return: NotNullIfNotNull(nameof(text))]
    public string? MaskText(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        string[] secrets = Volatile.Read(ref _knownSecrets);
        if (secrets.Length == 0)
        {
            return text;
        }

        string result = text;
        foreach (string secret in secrets)
        {
            if (result.Length >= secret.Length && result.Contains(secret, StringComparison.Ordinal))
            {
                result = result.Replace(secret, _maskSegment, StringComparison.Ordinal);
            }
        }

        return result;
    }

    /// <summary>
    /// 遮罩敏感字串:長度足夠時保留頭尾各數個字元(例如 <c>abcd****wxyz</c>),
    /// 太短則整串遮掉。<see langword="null"/> 與空字串原樣回傳(沒有內容就沒有東西會外洩)。
    /// Masks a sensitive string, keeping a few characters at each end when the value is long enough
    /// (for example <c>abcd****wxyz</c>) and masking it entirely when it is not. <see langword="null"/>
    /// and empty strings are returned as-is: there is nothing to leak.
    /// </summary>
    /// <param name="value">
    /// 要遮罩的值,允許 <see langword="null"/>。
    /// The value to mask; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 遮罩後的字串。
    /// The masked string.
    /// </returns>
    /// <remarks>
    /// 露出的字元數受兩層限制:設定的頭尾長度,以及
    /// 「露出字元數不得超過原值長度的 1/<see cref="MaximumRevealedLengthDivisor"/>」這條無條件底線。
    /// 後者不受任何設定影響,超過時會依原設定的頭尾比例自動縮減,例如預設設定下 12 個字元的值
    /// 只會露出 2 + 2 而不是 4 + 4。
    /// Two limits apply to how much is revealed: the configured prefix and suffix lengths, and the
    /// unconditional rule that no more than 1/<see cref="MaximumRevealedLengthDivisor"/> of the value is
    /// ever shown. The latter cannot be configured away; when it bites, both ends shrink in proportion,
    /// so under the default options a twelve-character value reveals 2 + 2 rather than 4 + 4.
    /// </remarks>
    [return: NotNullIfNotNull(nameof(value))]
    public string? Mask(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        int prefixLength = Options.VisiblePrefixLength;
        int suffixLength = Options.VisibleSuffixLength;
        long requiredLength = (long)prefixLength + suffixLength + Options.MinimumHiddenLength;

        if (value.Length < requiredLength)
        {
            return _maskSegment;
        }

        // 無條件底線:不論設定怎麼調,露出的字元數都不得超過原值長度的 1/3。
        // The unconditional floor: no configuration may reveal more than a third of the value.
        int allowedVisible = value.Length / MaximumRevealedLengthDivisor;
        int totalVisible = prefixLength + suffixLength;
        if (totalVisible > allowedVisible)
        {
            // 依原本的頭尾比例縮減,盡量維持呼叫端設定的形狀;除不盡的餘數給開頭,
            // 因為憑證的前綴通常比尾綴更能辨識這是哪一把金鑰。
            // Shrink both ends proportionally so the shape the caller asked for is preserved. The
            // remainder goes to the prefix: a credential's leading characters usually say more about
            // which key it is than its trailing ones.
            suffixLength = (int)((long)allowedVisible * suffixLength / totalVisible);
            prefixLength = allowedVisible - suffixLength;
        }

        if (prefixLength + suffixLength <= 0)
        {
            return _maskSegment;
        }

        return string.Concat(
            value.AsSpan(0, prefixLength),
            _maskSegment.AsSpan(),
            value.AsSpan(value.Length - suffixLength));
    }

    /// <summary>
    /// 判斷欄位名是否屬於敏感欄位(忽略大小寫)。
    /// 先做完全比對;<see cref="SecretMaskOptions.UseSubstringMatching"/> 開啟時,名稱含有任一敏感片段
    /// (<c>key</c>、<c>secret</c>、<c>token</c>、<c>password</c>、<c>credential</c> 等)也算敏感。
    /// Determines whether a field name is considered sensitive; matching ignores case. Exact matching
    /// runs first; with <see cref="SecretMaskOptions.UseSubstringMatching"/> enabled, a name that merely
    /// contains a sensitive fragment (<c>key</c>, <c>secret</c>, <c>token</c>, <c>password</c>,
    /// <c>credential</c> and friends) counts as sensitive too.
    /// </summary>
    /// <param name="name">
    /// 欄位名,允許 <see langword="null"/>。
    /// The field name; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 屬於敏感欄位時回傳 <see langword="true"/>。
    /// <see langword="true"/> when the name is sensitive.
    /// </returns>
    public bool IsSensitiveName(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        return _sensitiveNames.Contains(name) || ContainsAnyFragment(name, _sensitiveFragments);
    }

    /// <summary>
    /// 判斷欄位名是否屬於「一律全遮」欄位(忽略大小寫)。
    /// 這類欄位(<c>password</c>、<c>passphrase</c>、<c>mnemonic</c>、<c>privateKey</c> 等)不保留任何頭尾字元:
    /// 人類密碼的熵值太低,露出頭尾等於把它交出去。
    /// Determines whether a field name always has its value masked in full; matching ignores case. Such
    /// fields (<c>password</c>, <c>passphrase</c>, <c>mnemonic</c>, <c>privateKey</c> and friends) keep no
    /// characters at either end: human passwords carry too little entropy for that to be safe.
    /// </summary>
    /// <param name="name">
    /// 欄位名,允許 <see langword="null"/>。
    /// The field name; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 該欄位必須全遮時回傳 <see langword="true"/>。
    /// <see langword="true"/> when the field must be masked in full.
    /// </returns>
    public bool IsAlwaysFullyMaskedName(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        return _fullMaskNames.Contains(name) || ContainsAnyFragment(name, _fullMaskFragments);
    }

    /// <summary>
    /// 依欄位名決定要不要遮罩:敏感欄位遮掉,其餘原樣回傳。
    /// Masks a value only when its field name is sensitive; other values are returned unchanged.
    /// </summary>
    /// <param name="name">
    /// 欄位名。
    /// The field name.
    /// </param>
    /// <param name="value">
    /// 欄位值,允許 <see langword="null"/>。
    /// The field value; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 敏感欄位回傳遮罩後的值,其餘回傳原值。
    /// The masked value for sensitive names, otherwise the original value.
    /// </returns>
    [return: NotNullIfNotNull(nameof(value))]
    public string? MaskNamedValue(string? name, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        if (IsAlwaysFullyMaskedName(name))
        {
            return _maskSegment;
        }

        return IsSensitiveName(name) ? Mask(value) : value;
    }

    /// <summary>
    /// 遮罩請求位址中的敏感 query 參數值,其餘部分原樣保留。
    /// 保留路徑與非敏感參數是刻意的:除錯時必須看得出打了哪個端點、帶了什麼參數。
    /// 例如 <c>/api/order?symbol=BTCUSDT&amp;apiKey=abcd...</c> 只有 <c>apiKey</c> 的值會被遮掉。
    /// Masks the values of sensitive query parameters while leaving everything else intact. Keeping
    /// the path and the harmless parameters is deliberate: debugging needs to show which endpoint was
    /// called and with what. For example, in <c>/api/order?symbol=BTCUSDT&amp;apiKey=abcd...</c> only
    /// the <c>apiKey</c> value is masked.
    /// </summary>
    /// <param name="requestTarget">
    /// 完整或相對的請求位址,也接受單獨的 query 字串。
    /// An absolute or relative request target; a bare query string is accepted as well.
    /// </param>
    /// <returns>
    /// 遮罩後的請求位址。
    /// The request target with sensitive parameter values masked.
    /// </returns>
    /// <remarks>
    /// 參數名在比對前會先做百分號解碼(<see cref="Uri.UnescapeDataString(string)"/>),
    /// 否則 <c>?api%4Bey=…</c> 這種變形會因為字面上不等於 <c>apiKey</c> 而整個穿過去;
    /// 輸出仍寫回原始的參數名,不改寫日誌內容。
    /// 這讓 query 路徑與 JSON 路徑的行為一致 —— <see cref="MaskJson"/> 由
    /// <see cref="JsonDocument"/> 負責解碼,本來就是拿解碼後的名稱比對的。
    /// 位址中若帶有 <c>//使用者:密碼@主機</c> 形式的 basic 認證資訊,密碼部分也會被遮掉。
    /// Parameter names are percent-decoded with <see cref="Uri.UnescapeDataString(string)"/> before they
    /// are matched; otherwise a form such as <c>?api%4Bey=…</c> would slip through simply because it is
    /// not literally <c>apiKey</c>. The original spelling is written back out, so the log text itself is
    /// not rewritten. This makes the query path behave exactly like the JSON path, where
    /// <see cref="JsonDocument"/> already decodes names before they are compared. Basic-auth credentials
    /// carried as <c>//user:password@host</c> have their password masked as well.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="requestTarget"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="requestTarget"/> is <see langword="null"/>.
    /// </exception>
    public string MaskQueryString(string requestTarget)
    {
        ArgumentNullException.ThrowIfNull(requestTarget);

        if (requestTarget.Length == 0)
        {
            return requestTarget;
        }

        int queryStart = requestTarget.IndexOf('?');
        string head = queryStart >= 0 ? requestTarget[..(queryStart + 1)] : string.Empty;
        string query = queryStart >= 0 ? requestTarget[(queryStart + 1)..] : requestTarget;

        int fragmentStart = query.IndexOf('#');
        string fragment = string.Empty;
        if (fragmentStart >= 0)
        {
            fragment = query[fragmentStart..];
            query = query[..fragmentStart];
        }

        // basic 認證資訊只會出現在 authority(也就是 query 之前);位址沒有 '?' 時整串都被當成 query,
        // 所以兩邊都要處理。切分完再遮,遮罩符號本身若是 '?' 或 '#' 也不會影響切分結果。
        // Basic-auth credentials can only appear in the authority, which sits before the query; a target
        // without a '?' is treated as a bare query string, so both halves are handled. Masking after the
        // split keeps a '?' or '#' mask character from disturbing the split itself.
        head = MaskUserInfo(head);
        if (queryStart < 0)
        {
            query = MaskUserInfo(query);
        }

        if (query.Length == 0)
        {
            return MaskText(head + fragment);
        }

        string[] pairs = query.Split('&');
        for (int i = 0; i < pairs.Length; i++)
        {
            pairs[i] = MaskQueryPair(pairs[i]);
        }

        return MaskText(head + string.Join('&', pairs) + fragment);
    }

    /// <summary>
    /// 遮罩 JSON 內容中敏感欄位的值,結構與非敏感欄位保持不變。
    /// 敏感欄位若是物件或陣列,整個子結構會被換成遮罩字串。
    /// Masks the values of sensitive fields inside a JSON document, leaving the structure and the
    /// non-sensitive fields untouched. When a sensitive field holds an object or an array, the whole
    /// subtree is replaced by the mask segment.
    /// </summary>
    /// <param name="json">
    /// 有效的 JSON 內容。
    /// A valid JSON document.
    /// </param>
    /// <returns>
    /// 遮罩後的 JSON 字串(不含縮排)。
    /// The masked JSON text, without indentation.
    /// </returns>
    /// <remarks>
    /// 欄位名由 <see cref="JsonDocument"/> 解碼後才比對,因此 <c>Key</c> 這類跳脫寫法不會繞過遮罩;
    /// <see cref="MaskQueryString"/> 也已做等價的百分號解碼,兩條路徑的比對基準一致。
    /// 非敏感欄位的字串值仍會再過一次 <see cref="MaskText"/>,把夾帶在其中的已登記祕密攔下來。
    /// Field names are compared after <see cref="JsonDocument"/> has decoded them, so an escape such as
    /// <c>Key</c> cannot slip past; <see cref="MaskQueryString"/> performs the equivalent
    /// percent-decoding, which leaves both paths matching on the same basis. String values of
    /// non-sensitive fields are additionally passed through <see cref="MaskText"/>, catching registered
    /// secrets that were smuggled inside them.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="json"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="json"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="json"/> 不是有效 JSON 時拋出;日誌路徑請改用 <see cref="TryMaskJson"/>。
    /// Thrown when <paramref name="json"/> is not valid JSON; logging paths should use
    /// <see cref="TryMaskJson"/> instead.
    /// </exception>
    public string MaskJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        try
        {
            return MaskJsonCore(json);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException(
                "內容不是有效的 JSON,無法逐欄位遮罩。 The value is not valid JSON and cannot be masked field by field.",
                nameof(json),
                ex);
        }
    }

    /// <summary>
    /// 嘗試遮罩 JSON 內容,內容不是有效 JSON 時回傳 <see langword="false"/> 而不拋例外。
    /// 日誌路徑應該用這個版本:記錄失敗不該讓主流程掛掉。
    /// Attempts to mask a JSON document, returning <see langword="false"/> instead of throwing when
    /// the input is not valid JSON. Logging paths should prefer this overload: a logging failure must
    /// never take the main flow down with it.
    /// </summary>
    /// <param name="json">
    /// 待遮罩的內容。
    /// The content to mask.
    /// </param>
    /// <param name="maskedJson">
    /// 成功時回傳遮罩後的 JSON,失敗時為 <see langword="null"/>。
    /// Receives the masked JSON on success, or <see langword="null"/> on failure.
    /// </param>
    /// <returns>
    /// 遮罩成功回傳 <see langword="true"/>。
    /// <see langword="true"/> when the document was masked.
    /// </returns>
    /// <remarks>
    /// 回傳 <see langword="false"/> 時請不要退回去記錄原內容。<c>catch { log(原文) }</c> 會讓整套
    /// fail-closed 設計失效 —— 遮罩失敗的當下往往正是內容最不該被寫出去的時候。
    /// Do not fall back to logging the raw content when this returns <see langword="false"/>. A
    /// <c>catch { log(original) }</c> defeats the whole fail-closed design: the moment masking fails is
    /// usually the moment the content least belongs in a log.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="json"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="json"/> is <see langword="null"/>.
    /// </exception>
    public bool TryMaskJson(string json, out string? maskedJson)
    {
        ArgumentNullException.ThrowIfNull(json);

        try
        {
            maskedJson = MaskJsonCore(json);
            return true;
        }
        catch (JsonException)
        {
            maskedJson = null;
            return false;
        }
    }

    /// <summary>
    /// 建立忽略大小寫的名稱集合。
    /// Builds a case-insensitive set of names.
    /// </summary>
    /// <param name="defaults">
    /// 內建清單,不併入時傳入 <see langword="null"/>。
    /// The built-in list, or <see langword="null"/> when it is not included.
    /// </param>
    /// <param name="additional">
    /// 呼叫端擴充的清單。
    /// The caller's additions.
    /// </param>
    /// <returns>
    /// 名稱集合。
    /// The name set.
    /// </returns>
    private static HashSet<string> BuildNameSet(
        IReadOnlyCollection<string>? defaults,
        IReadOnlyCollection<string> additional)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (defaults is not null)
        {
            names.UnionWith(defaults);
        }

        foreach (string name in additional)
        {
            if (!string.IsNullOrWhiteSpace(name))
            {
                names.Add(name);
            }
        }

        return names;
    }

    /// <summary>
    /// 建立包含式比對用的片段陣列(去重後轉為陣列,遮罩路徑上是純迭代,不需要雜湊)。
    /// Builds the fragment array used for substring matching; it is deduplicated and flattened to an
    /// array because the masking path only iterates it and gains nothing from hashing.
    /// </summary>
    /// <param name="defaults">
    /// 內建片段,不併入時傳入 <see langword="null"/>。
    /// The built-in fragments, or <see langword="null"/> when they are not included.
    /// </param>
    /// <param name="additional">
    /// 呼叫端擴充的片段。
    /// The caller's additions.
    /// </param>
    /// <param name="alsoInclude">
    /// 需要一併併入的既有片段(例如全遮片段本來就屬於敏感片段)。
    /// Existing fragments to fold in as well (full-mask fragments are sensitive fragments by definition).
    /// </param>
    /// <returns>
    /// 片段陣列。
    /// The fragment array.
    /// </returns>
    private static string[] BuildFragmentList(
        IReadOnlyCollection<string>? defaults,
        IReadOnlyCollection<string> additional,
        IReadOnlyCollection<string>? alsoInclude = null)
    {
        var fragments = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (defaults is not null)
        {
            fragments.UnionWith(defaults);
        }

        foreach (string fragment in additional)
        {
            if (!string.IsNullOrWhiteSpace(fragment))
            {
                fragments.Add(fragment);
            }
        }

        if (alsoInclude is not null)
        {
            fragments.UnionWith(alsoInclude);
        }

        return [.. fragments];
    }

    /// <summary>
    /// 判斷名稱是否含有清單中的任一片段(忽略大小寫)。
    /// Determines whether a name contains any of the fragments, ignoring case.
    /// </summary>
    /// <param name="name">
    /// 欄位名。
    /// The field name.
    /// </param>
    /// <param name="fragments">
    /// 片段清單。
    /// The fragments to look for.
    /// </param>
    /// <returns>
    /// 命中任一片段時回傳 <see langword="true"/>。
    /// <see langword="true"/> when any fragment is found.
    /// </returns>
    private static bool ContainsAnyFragment(string name, string[] fragments)
    {
        foreach (string fragment in fragments)
        {
            if (name.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 判斷字串是否為純十六進位表示且含有字母(只有數字的話大小寫轉換沒有意義)。
    /// Determines whether a value is pure hexadecimal and contains at least one letter; an all-digit
    /// value has no casing variants to speak of.
    /// </summary>
    /// <param name="value">
    /// 待判斷的值。
    /// The value to inspect.
    /// </param>
    /// <returns>
    /// 是含字母的十六進位字串時回傳 <see langword="true"/>。
    /// <see langword="true"/> for hexadecimal text containing letters.
    /// </returns>
    private static bool IsHexWithLetters(string value)
    {
        bool hasLetter = false;

        foreach (char character in value)
        {
            if (char.IsAsciiDigit(character))
            {
                continue;
            }

            if (char.IsAsciiHexDigit(character))
            {
                hasLetter = true;
                continue;
            }

            return false;
        }

        return hasLetter;
    }

    /// <summary>
    /// 遮掉位址中 <c>//使用者:密碼@主機</c> 形式的密碼部分。
    /// 這種位址沒有 <c>?</c>,不會走 query 參數那條路徑,不處理的話 basic 認證憑證會完整寫進日誌。
    /// Masks the password in a <c>//user:password@host</c> style request target. Such a target has no
    /// <c>?</c> and never reaches the query-parameter path, so without this the basic-auth credentials
    /// would land in the log in full.
    /// </summary>
    /// <param name="target">
    /// 請求位址。
    /// The request target.
    /// </param>
    /// <returns>
    /// 密碼已遮掉的位址;沒有這種樣式時回傳原字串。
    /// The target with the password masked, or the original string when the pattern is absent.
    /// </returns>
    private string MaskUserInfo(string target)
    {
        int schemeSeparator = target.IndexOf("//", StringComparison.Ordinal);
        if (schemeSeparator < 0)
        {
            return target;
        }

        int authorityStart = schemeSeparator + 2;

        // 只在 authority 區段內尋找,避免把 query 或 fragment 裡碰巧出現的 @ 當成 userinfo。
        // Search inside the authority only, so an @ that happens to appear in a query or fragment is not
        // mistaken for userinfo.
        int authorityEnd = target.Length;
        for (int i = authorityStart; i < target.Length; i++)
        {
            if (target[i] is '/' or '?' or '#')
            {
                authorityEnd = i;
                break;
            }
        }

        if (authorityEnd <= authorityStart)
        {
            return target;
        }

        int at = target.LastIndexOf('@', authorityEnd - 1, authorityEnd - authorityStart);
        if (at < 0)
        {
            return target;
        }

        int colon = target.IndexOf(':', authorityStart, at - authorityStart);
        if (colon < 0)
        {
            return target;
        }

        return string.Concat(target.AsSpan(0, colon + 1), _maskSegment, target.AsSpan(at));
    }

    /// <summary>
    /// 遮罩單一組 <c>name=value</c>,名稱不敏感或格式不是鍵值對時原樣回傳。
    /// Masks a single <c>name=value</c> pair, returning it unchanged when the name is not sensitive
    /// or the segment is not a key/value pair at all.
    /// </summary>
    /// <param name="pair">
    /// query 字串中的一段。
    /// One segment of a query string.
    /// </param>
    /// <returns>
    /// 處理後的段落。
    /// The processed segment.
    /// </returns>
    private string MaskQueryPair(string pair)
    {
        int separator = pair.IndexOf('=');
        if (separator < 0)
        {
            return pair;
        }

        string name = pair[..separator];
        string decodedName = DecodeParameterName(name);

        // 比對用解碼後的名稱,輸出仍寫回原始名稱:遮罩的職責是遮值,不是改寫日誌內容。
        // Match on the decoded name but write the original one back: masking hides values, it does not
        // rewrite the log text.
        if (IsAlwaysFullyMaskedName(decodedName))
        {
            return string.Concat(name, "=", pair.Length > separator + 1 ? _maskSegment : string.Empty);
        }

        if (!IsSensitiveName(decodedName))
        {
            return pair;
        }

        return string.Concat(name, "=", Mask(pair[(separator + 1)..]));
    }

    /// <summary>
    /// 解碼 query 參數名的百分號跳脫。內容不是合法跳脫序列時退回原始名稱,不讓日誌路徑因此拋例外。
    /// Percent-decodes a query parameter name, falling back to the raw spelling when the escaping is
    /// malformed so a logging path never throws over it.
    /// </summary>
    /// <param name="name">
    /// 原始參數名。
    /// The raw parameter name.
    /// </param>
    /// <returns>
    /// 解碼後的參數名。
    /// The decoded parameter name.
    /// </returns>
    private static string DecodeParameterName(string name)
    {
        if (!name.Contains('%'))
        {
            return name;
        }

        try
        {
            return Uri.UnescapeDataString(name);
        }
        catch (UriFormatException)
        {
            return name;
        }
    }

    /// <summary>
    /// 實際執行 JSON 遮罩,解析失敗時讓 <see cref="JsonException"/> 往上拋。
    /// Performs the JSON masking, letting <see cref="JsonException"/> propagate on parse failures.
    /// </summary>
    /// <param name="json">
    /// 待遮罩的 JSON 內容。
    /// The JSON content to mask.
    /// </param>
    /// <returns>
    /// 遮罩後的 JSON 字串。
    /// The masked JSON text.
    /// </returns>
    private string MaskJsonCore(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);

        var buffer = new ArrayBufferWriter<byte>();
        var writerOptions = new JsonWriterOptions
        {
            Indented = false,
            Encoder = JsonOutputEncoder,
        };

        using (var writer = new Utf8JsonWriter(buffer, writerOptions))
        {
            WriteMasked(document.RootElement, writer);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>
    /// 遞迴寫出遮罩後的 JSON 節點。
    /// Recursively writes a JSON node with sensitive fields masked.
    /// </summary>
    /// <param name="element">
    /// 目前處理的節點。
    /// The node being processed.
    /// </param>
    /// <param name="writer">
    /// 輸出用的寫入器。
    /// The writer receiving the output.
    /// </param>
    private void WriteMasked(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (IsSensitiveName(property.Name))
                    {
                        writer.WriteString(
                            property.Name,
                            MaskElement(property.Value, IsAlwaysFullyMaskedName(property.Name)));
                    }
                    else
                    {
                        writer.WritePropertyName(property.Name);
                        WriteMasked(property.Value, writer);
                    }
                }

                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (JsonElement item in element.EnumerateArray())
                {
                    WriteMasked(item, writer);
                }

                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                // 非敏感欄位的字串值也過一次已知祕密清單:欄位名無害不代表值裡沒有夾帶憑證。
                // Even a harmless field name is no promise about its value, so string values still go
                // through the registry of known secrets.
                writer.WriteStringValue(MaskText(element.GetString()));
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }

    /// <summary>
    /// 取得單一節點遮罩後的字串表示。物件與陣列整個換成遮罩字串,
    /// 數值與布林值則先轉為原始文字再遮罩(輸出型別會變成字串,這是日誌可接受的取捨)。
    /// Produces the masked textual form of a single node. Objects and arrays are replaced wholesale by
    /// the mask segment; numbers and booleans are masked through their raw text, which turns them into
    /// strings — an acceptable trade-off for log output.
    /// </summary>
    /// <param name="element">
    /// 敏感欄位的值。
    /// The value of a sensitive field.
    /// </param>
    /// <param name="fullMask">
    /// 該欄位是否必須全遮(密碼類欄位)。
    /// Whether the field must be masked in full (a password-like field).
    /// </param>
    /// <returns>
    /// 遮罩後的字串。
    /// The masked text.
    /// </returns>
    private string MaskElement(JsonElement element, bool fullMask)
    {
        if (fullMask)
        {
            return _maskSegment;
        }

        return element.ValueKind switch
        {
            JsonValueKind.Null => _maskSegment,
            JsonValueKind.Object or JsonValueKind.Array => _maskSegment,
            JsonValueKind.String => Mask(element.GetString()) ?? _maskSegment,
            _ => Mask(element.GetRawText()) ?? _maskSegment,
        };
    }

    /// <summary>
    /// 把一個候選值加入待新增清單(已存在則略過)。呼叫端必須已持有登記鎖。
    /// Adds a candidate to the pending additions unless it is already registered. Callers must already
    /// hold the registration lock.
    /// </summary>
    /// <param name="candidate">
    /// 候選值。
    /// The candidate value.
    /// </param>
    /// <param name="additions">
    /// 待新增清單,尚未建立時由本方法建立。
    /// The pending additions; created here on first use.
    /// </param>
    private void CollectAddition(string candidate, ref List<string>? additions)
    {
        if (Array.IndexOf(_knownSecrets, candidate) >= 0)
        {
            return;
        }

        if (additions is not null && additions.Contains(candidate))
        {
            return;
        }

        additions ??= [];
        additions.Add(candidate);
    }
}
