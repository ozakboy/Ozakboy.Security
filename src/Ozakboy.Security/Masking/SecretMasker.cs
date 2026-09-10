using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;

namespace Ozakboy.Security.Masking;

/// <summary>
/// 敏感字串遮罩器:在寫入日誌前把憑證遮掉,只保留足以辨識的頭尾。
/// 支援純字串、URL query 參數與 JSON 欄位三種輸入,敏感欄位名比對一律忽略大小寫。
/// Masks sensitive values before they reach a log, keeping only enough of each end to recognise
/// which credential it was. Handles plain strings, URL query parameters and JSON fields; sensitive
/// field names are always matched case-insensitively.
/// </summary>
public sealed class SecretMasker
{
    /// <summary>
    /// JSON 輸出用的編碼器:允許所有 Unicode 字元原樣輸出(中文不被轉成跳脫序列),
    /// 但仍保留 HTML 敏感字元的跳脫,避免遮罩後的日誌被貼進網頁時出事。
    /// The encoder used for JSON output: it lets every Unicode character through verbatim (so
    /// non-ASCII text stays readable) while still escaping HTML-sensitive characters, in case the
    /// masked log line ends up rendered in a web page.
    /// </summary>
    private static readonly JavaScriptEncoder JsonOutputEncoder = JavaScriptEncoder.Create(UnicodeRanges.All);

    private readonly HashSet<string> _sensitiveNames;
    private readonly string _maskSegment;

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
    /// 長度設定為負數,或遮罩長度不是正數時拋出。
    /// Thrown when any length option is negative or the mask length is not positive.
    /// </exception>
    public SecretMasker(SecretMaskOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfNegative(options.VisiblePrefixLength, nameof(options));
        ArgumentOutOfRangeException.ThrowIfNegative(options.VisibleSuffixLength, nameof(options));
        ArgumentOutOfRangeException.ThrowIfNegative(options.MinimumHiddenLength, nameof(options));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(options.MaskLength, nameof(options));

        Options = options;
        _maskSegment = new string(options.MaskCharacter, options.MaskLength);
        _sensitiveNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.IncludeDefaultSensitiveNames)
        {
            foreach (string name in SecretMaskOptions.DefaultSensitiveNames)
            {
                _sensitiveNames.Add(name);
            }
        }

        foreach (string name in options.AdditionalSensitiveNames)
        {
            if (!string.IsNullOrWhiteSpace(name))
            {
                _sensitiveNames.Add(name);
            }
        }
    }

    /// <summary>
    /// 以預設設定建立的共用遮罩器。本型別為不可變且執行緒安全,可直接共用。
    /// A shared masker built from the default options. The type is immutable and thread-safe, so the
    /// same instance can be reused everywhere.
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

        return string.Concat(
            value.AsSpan(0, prefixLength),
            _maskSegment.AsSpan(),
            value.AsSpan(value.Length - suffixLength));
    }

    /// <summary>
    /// 判斷欄位名是否屬於敏感欄位(忽略大小寫)。
    /// Determines whether a field name is considered sensitive; matching ignores case.
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
        => !string.IsNullOrEmpty(name) && _sensitiveNames.Contains(name);

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
        => IsSensitiveName(name) ? Mask(value) : value;

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

        if (query.Length == 0)
        {
            return requestTarget;
        }

        string[] pairs = query.Split('&');
        for (int i = 0; i < pairs.Length; i++)
        {
            pairs[i] = MaskQueryPair(pairs[i]);
        }

        return head + string.Join('&', pairs) + fragment;
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
        if (!IsSensitiveName(name))
        {
            return pair;
        }

        return string.Concat(name, "=", Mask(pair[(separator + 1)..]));
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
                        writer.WriteString(property.Name, MaskElement(property.Value));
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
    /// <returns>
    /// 遮罩後的字串。
    /// The masked text.
    /// </returns>
    private string MaskElement(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Null => _maskSegment,
        JsonValueKind.Object or JsonValueKind.Array => _maskSegment,
        JsonValueKind.String => Mask(element.GetString()) ?? _maskSegment,
        _ => Mask(element.GetRawText()) ?? _maskSegment,
    };
}
