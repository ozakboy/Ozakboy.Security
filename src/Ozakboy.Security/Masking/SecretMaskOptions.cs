namespace Ozakboy.Security.Masking;

/// <summary>
/// <see cref="SecretMasker"/> 的遮罩設定。以 record 表達不可變設定,建立後不再變動。
/// Options for <see cref="SecretMasker"/>. Modelled as an immutable record: once created, the
/// settings never change.
/// </summary>
public sealed record SecretMaskOptions
{
    /// <summary>
    /// 預設設定:頭尾各保留 4 個字元、中間固定 4 個星號、至少要遮掉 4 個字元才肯露出頭尾,
    /// 並啟用包含式名稱比對。實際露出的字元數還會受 <see cref="SecretMasker.MaximumRevealedLengthDivisor"/>
    /// 這條無條件底線壓制。
    /// The default options: four visible characters at each end, a fixed four-character mask, at least
    /// four hidden characters before anything is revealed, and substring name matching enabled. The
    /// number of characters actually revealed is additionally capped by the unconditional
    /// <see cref="SecretMasker.MaximumRevealedLengthDivisor"/> rule.
    /// </summary>
    public static SecretMaskOptions Default { get; } = new();

    /// <summary>
    /// 內建的敏感欄位名清單(完全比對)。名稱比對一律忽略大小寫,因此同一個名稱不需要重複列出大小寫變體。
    /// 只靠完全比對會漏掉 <c>binanceApiKey</c> 這類變體,所以另有
    /// <see cref="DefaultSensitiveNameFragments"/> 的包含式比對把關。
    /// The built-in sensitive field names, matched in full. Name matching is case-insensitive, so casing
    /// variants of the same name do not need to be listed separately. Exact matching alone would miss
    /// names such as <c>binanceApiKey</c>, which is what the substring pass over
    /// <see cref="DefaultSensitiveNameFragments"/> is for.
    /// </summary>
    public static IReadOnlyCollection<string> DefaultSensitiveNames { get; } =
    [
        "apiKey",
        "api_key",
        "api-key",
        "x-api-key",
        "x-mbx-apikey",
        "x-mbx-api-key",
        "apiSecret",
        "api_secret",
        "api-secret",
        "secret",
        "secretKey",
        "secret_key",
        "secret-key",
        "clientSecret",
        "client_secret",
        "webhookSecret",
        "webhook_secret",
        "webhook-secret",
        "signature",
        "sign",
        "token",
        "accessToken",
        "access_token",
        "access-token",
        "refreshToken",
        "refresh_token",
        "refresh-token",
        "idToken",
        "id_token",
        "bearer",
        "jwt",
        "otp",
        "totp",
        "mfaCode",
        "recoveryCode",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "mnemonic",
        "seed",
        "seedPhrase",
        "seed_phrase",
        "authorization",
        "proxy-authorization",
        "auth",
        "credential",
        "privateKey",
        "private_key",
        "private-key",
        "connectionString",
        "connection_string",
        "sessionId",
        "session_id",
        "session-id",
        "sessionKey",
        "session_key",
        "session-key",
        "cookie",
        "set-cookie",
    ];

    /// <summary>
    /// 內建的敏感片段清單(包含式比對)。名稱只要含有其中任一片段就視為敏感,同樣忽略大小寫。
    /// 這是為了擋住 <c>binanceApiKey</c>、<c>api_key_1</c>、<c>Api-Key-Secret</c> 這類完全比對抓不到的變體。
    /// 誤遮是刻意接受的代價:日誌少看到一個欄位值遠比漏遮一把金鑰便宜。
    /// The built-in sensitive fragments, matched as substrings and case-insensitively: a field is
    /// sensitive when its name contains any of them. This is what catches variants exact matching misses,
    /// such as <c>binanceApiKey</c>, <c>api_key_1</c> and <c>Api-Key-Secret</c>. Over-masking is a
    /// deliberate trade: one unreadable field in a log costs far less than one leaked key.
    /// </summary>
    /// <remarks>
    /// 已知的誤遮:名稱含 <c>key</c> 的無害欄位(<c>keyword</c>、<c>publicKey</c>、<c>partitionKey</c>)也會被遮掉。
    /// 不能接受時把 <see cref="UseSubstringMatching"/> 關掉,或改用自訂片段清單。
    /// Known over-matches: harmless names containing <c>key</c> (<c>keyword</c>, <c>publicKey</c>,
    /// <c>partitionKey</c>) are masked as well. Turn <see cref="UseSubstringMatching"/> off, or supply a
    /// custom fragment list, when that is unacceptable.
    /// </remarks>
    public static IReadOnlyCollection<string> DefaultSensitiveNameFragments { get; } =
    [
        "key",
        "secret",
        "token",
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "credential",
        "mnemonic",
        "signature",
        "session",
        "cookie",
    ];

    /// <summary>
    /// 內建的「一律全遮」欄位名清單(完全比對)。這些欄位的值不保留任何頭尾字元。
    /// 人類密碼的熵值遠低於隨機金鑰,露出頭尾兩碼配上組成習慣幾乎等於明文,因此不適用一般的頭尾保留規則。
    /// The built-in names whose values are always masked in full, matched exactly. Human passwords carry
    /// far less entropy than random keys: revealing a couple of characters at each end, combined with how
    /// people compose passwords, comes close to printing them, so the keep-both-ends rule does not apply.
    /// </summary>
    public static IReadOnlyCollection<string> DefaultFullMaskNames { get; } =
    [
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "pin",
        "mnemonic",
        "seed",
        "seedPhrase",
        "seed_phrase",
        "privateKey",
        "private_key",
        "private-key",
    ];

    /// <summary>
    /// 內建的「一律全遮」片段清單(包含式比對),僅在 <see cref="UseSubstringMatching"/> 為
    /// <see langword="true"/> 時生效,用來涵蓋 <c>binancePassword</c> 這類變體。
    /// The built-in fragments whose presence forces a full mask, matched as substrings and only while
    /// <see cref="UseSubstringMatching"/> is <see langword="true"/>; they cover variants such as
    /// <c>binancePassword</c>.
    /// </summary>
    public static IReadOnlyCollection<string> DefaultFullMaskNameFragments { get; } =
    [
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "mnemonic",
        "privatekey",
        "private_key",
        "private-key",
    ];

    /// <summary>
    /// 開頭保留幾個字元不遮,預設 4。實際露出的字元數仍受
    /// <see cref="SecretMasker.MaximumRevealedLengthDivisor"/> 這條底線壓制,短字串會自動縮減。
    /// How many leading characters stay visible; defaults to 4. The number actually revealed is still
    /// capped by the <see cref="SecretMasker.MaximumRevealedLengthDivisor"/> rule, which shrinks both
    /// ends automatically for short values.
    /// </summary>
    public int VisiblePrefixLength { get; init; } = 4;

    /// <summary>
    /// 結尾保留幾個字元不遮,預設 4。實際露出的字元數仍受
    /// <see cref="SecretMasker.MaximumRevealedLengthDivisor"/> 這條底線壓制。
    /// How many trailing characters stay visible; defaults to 4. The number actually revealed is still
    /// capped by the <see cref="SecretMasker.MaximumRevealedLengthDivisor"/> rule.
    /// </summary>
    public int VisibleSuffixLength { get; init; } = 4;

    /// <summary>
    /// 中間遮罩符號的固定長度,預設 4。刻意採固定長度,避免遮罩後仍洩漏原字串長度。
    /// The fixed length of the mask segment; defaults to 4. It is deliberately fixed so the masked
    /// output does not leak the length of the original value.
    /// </summary>
    public int MaskLength { get; init; } = 4;

    /// <summary>
    /// 遮罩符號,預設為星號。
    /// The mask character; defaults to an asterisk.
    /// </summary>
    public char MaskCharacter { get; init; } = '*';

    /// <summary>
    /// 至少要遮掉幾個字元才允許露出頭尾,預設 4,最小值為 1。
    /// 原字串太短時(長度小於保留頭 + 保留尾 + 本值)一律全遮,以免「保留頭尾」等於把整串短字串洩漏出去。
    /// 下限之所以不是 0:設成 0 時 8 個字元的祕密會輸出成 <c>abcd****efgh</c>,原值一字不漏卻看起來遮過了。
    /// The minimum number of characters that must stay hidden before any character is revealed; defaults
    /// to 4 and may not go below 1. Values shorter than prefix + suffix + this number are masked entirely,
    /// so keeping both ends visible never reveals a whole short secret. Zero is rejected because it lets
    /// an eight-character secret render as <c>abcd****efgh</c> — every original character intact, yet
    /// looking masked.
    /// </summary>
    public int MinimumHiddenLength { get; init; } = 4;

    /// <summary>
    /// 是否併入 <see cref="DefaultSensitiveNames"/>、<see cref="DefaultSensitiveNameFragments"/>,
    /// 預設 <see langword="true"/>。
    /// Whether <see cref="DefaultSensitiveNames"/> and <see cref="DefaultSensitiveNameFragments"/> are
    /// included; defaults to <see langword="true"/>.
    /// </summary>
    public bool IncludeDefaultSensitiveNames { get; init; } = true;

    /// <summary>
    /// 是否併入 <see cref="DefaultFullMaskNames"/>、<see cref="DefaultFullMaskNameFragments"/>,
    /// 預設 <see langword="true"/>。
    /// Whether <see cref="DefaultFullMaskNames"/> and <see cref="DefaultFullMaskNameFragments"/> are
    /// included; defaults to <see langword="true"/>.
    /// </summary>
    public bool IncludeDefaultFullMaskNames { get; init; } = true;

    /// <summary>
    /// 是否啟用包含式名稱比對,預設 <see langword="true"/>。
    /// 關掉之後只做完全比對,<c>binanceApiKey</c> 這類變體會整個穿過遮罩。
    /// Whether substring name matching is enabled; defaults to <see langword="true"/>. With it off only
    /// exact matching remains, and variants such as <c>binanceApiKey</c> pass straight through unmasked.
    /// </summary>
    public bool UseSubstringMatching { get; init; } = true;

    /// <summary>
    /// 呼叫端自行擴充的敏感欄位名(完全比對)。
    /// Additional sensitive field names supplied by the caller, matched exactly.
    /// </summary>
    public IReadOnlyCollection<string> AdditionalSensitiveNames { get; init; } = [];

    /// <summary>
    /// 呼叫端自行擴充的敏感片段(包含式比對),僅在 <see cref="UseSubstringMatching"/> 為
    /// <see langword="true"/> 時生效。
    /// Additional sensitive fragments supplied by the caller, matched as substrings and only while
    /// <see cref="UseSubstringMatching"/> is <see langword="true"/>.
    /// </summary>
    public IReadOnlyCollection<string> AdditionalSensitiveNameFragments { get; init; } = [];

    /// <summary>
    /// 呼叫端自行擴充的「一律全遮」欄位名(完全比對)。
    /// Additional always-fully-masked field names supplied by the caller, matched exactly.
    /// </summary>
    public IReadOnlyCollection<string> AdditionalFullMaskNames { get; init; } = [];

    /// <summary>
    /// 呼叫端自行擴充的「一律全遮」片段(包含式比對),僅在 <see cref="UseSubstringMatching"/> 為
    /// <see langword="true"/> 時生效。
    /// Additional always-fully-masked fragments supplied by the caller, matched as substrings and only
    /// while <see cref="UseSubstringMatching"/> is <see langword="true"/>.
    /// </summary>
    public IReadOnlyCollection<string> AdditionalFullMaskNameFragments { get; init; } = [];
}
