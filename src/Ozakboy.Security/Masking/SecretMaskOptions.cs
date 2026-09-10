namespace Ozakboy.Security.Masking;

/// <summary>
/// <see cref="SecretMasker"/> 的遮罩設定。以 record 表達不可變設定,建立後不再變動。
/// Options for <see cref="SecretMasker"/>. Modelled as an immutable record: once created, the
/// settings never change.
/// </summary>
public sealed record SecretMaskOptions
{
    /// <summary>
    /// 預設設定:頭尾各保留 4 個字元、中間固定 4 個星號、至少要遮掉 4 個字元才肯露出頭尾。
    /// The default options: four visible characters at each end, a fixed four-character mask, and at
    /// least four hidden characters before any character is revealed.
    /// </summary>
    public static SecretMaskOptions Default { get; } = new();

    /// <summary>
    /// 內建的敏感欄位名清單。名稱比對一律忽略大小寫,因此同一個名稱不需要重複列出大小寫變體。
    /// The built-in sensitive field names. Name matching is case-insensitive, so casing variants of
    /// the same name do not need to be listed separately.
    /// </summary>
    public static IReadOnlyCollection<string> DefaultSensitiveNames { get; } =
    [
        "apiKey",
        "api_key",
        "api-key",
        "x-api-key",
        "apiSecret",
        "api_secret",
        "api-secret",
        "secret",
        "secretKey",
        "secret_key",
        "secret-key",
        "clientSecret",
        "client_secret",
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
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "authorization",
        "auth",
        "credential",
        "privateKey",
        "private_key",
        "private-key",
        "connectionString",
        "connection_string",
        "cookie",
        "set-cookie",
    ];

    /// <summary>
    /// 開頭保留幾個字元不遮,預設 4。
    /// How many leading characters stay visible; defaults to 4.
    /// </summary>
    public int VisiblePrefixLength { get; init; } = 4;

    /// <summary>
    /// 結尾保留幾個字元不遮,預設 4。
    /// How many trailing characters stay visible; defaults to 4.
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
    /// 至少要遮掉幾個字元才允許露出頭尾,預設 4。
    /// 原字串太短時(長度小於保留頭 + 保留尾 + 本值)一律全遮,以免「保留頭尾」等於把整串短字串洩漏出去。
    /// The minimum number of characters that must stay hidden before any character is revealed;
    /// defaults to 4. Values shorter than prefix + suffix + this number are masked entirely, so that
    /// keeping both ends visible never ends up revealing a whole short secret.
    /// </summary>
    public int MinimumHiddenLength { get; init; } = 4;

    /// <summary>
    /// 是否併入 <see cref="DefaultSensitiveNames"/>,預設 <see langword="true"/>。
    /// Whether <see cref="DefaultSensitiveNames"/> is included; defaults to <see langword="true"/>.
    /// </summary>
    public bool IncludeDefaultSensitiveNames { get; init; } = true;

    /// <summary>
    /// 呼叫端自行擴充的敏感欄位名。
    /// Additional sensitive field names supplied by the caller.
    /// </summary>
    public IReadOnlyCollection<string> AdditionalSensitiveNames { get; init; } = [];
}
