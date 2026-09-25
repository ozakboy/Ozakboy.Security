using System.Collections;

namespace Ozakboy.Security.Logging;

/// <summary>
/// 遮罩後的日誌狀態:一份(可能已改寫的)結構化屬性清單,加上遮罩後的格式化訊息。
/// 實作 <see cref="IReadOnlyList{T}"/> 是為了讓結構化接收端(JSON console、Serilog 橋接)照常讀到屬性。
/// The masked log state: a (possibly rewritten) list of structured properties plus the masked formatted message.
/// It implements <see cref="IReadOnlyList{T}"/> so structured sinks (JSON console, Serilog bridges) still see the properties.
/// </summary>
internal sealed class MaskedLogState : IReadOnlyList<KeyValuePair<string, object?>>
{
    /// <summary>
    /// 交給內層記錄器的格式化委派:直接回傳預先算好的遮罩訊息,不再格式化一次。
    /// The formatter handed to the inner logger: returns the precomputed masked message without formatting again.
    /// </summary>
    public static readonly Func<MaskedLogState, Exception?, string> Formatter = static (state, _) => state._text;

    private readonly IReadOnlyList<KeyValuePair<string, object?>> _properties;
    private readonly string _text;

    /// <summary>
    /// 建立遮罩後的狀態。
    /// Creates the masked state.
    /// </summary>
    /// <param name="properties">
    /// 結構化屬性(已遮罩)。
    /// The structured properties (masked).
    /// </param>
    /// <param name="text">
    /// 遮罩後的格式化訊息。
    /// The masked formatted message.
    /// </param>
    public MaskedLogState(IReadOnlyList<KeyValuePair<string, object?>> properties, string text)
    {
        _properties = properties;
        _text = text;
    }

    /// <inheritdoc />
    public int Count => _properties.Count;

    /// <inheritdoc />
    public KeyValuePair<string, object?> this[int index] => _properties[index];

    /// <inheritdoc />
    public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => _properties.GetEnumerator();

    /// <inheritdoc />
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>
    /// 遮罩後的格式化訊息。
    /// The masked formatted message.
    /// </summary>
    /// <returns>
    /// 遮罩後的訊息。
    /// The masked message.
    /// </returns>
    public override string ToString() => _text;
}
