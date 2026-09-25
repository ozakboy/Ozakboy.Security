using Microsoft.Extensions.Logging;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Logging;

/// <summary>
/// 把每一筆日誌先過 <see cref="SecretMasker"/> 再交給內層 <see cref="ILogger"/> 的包裝。
/// 遮的東西有三層:格式化後的訊息(<see cref="SecretMasker.MaskText"/>)、結構化狀態裡的字串屬性
/// (依屬性名稱與已登記祕密)、例外文字(找到祕密時換成 <see cref="MaskedException"/> 替身)。
/// An <see cref="ILogger"/> wrapper that runs every entry through a <see cref="SecretMasker"/> before the inner logger
/// sees it. Three layers are masked: the formatted message (<see cref="SecretMasker.MaskText"/>), string properties in
/// the structured state (by property name and by registered secret), and exception text (replaced with a
/// <see cref="MaskedException"/> stand-in when a secret is found).
/// </summary>
/// <remarks>
/// <para>
/// <b>效能。</b>內層對該層級沒開時直接返回,不格式化也不遮罩。開著時:訊息只格式化一次;
/// 沒有任何東西被改到(最常見的情況)就把原本的狀態、例外與格式化委派原封不動往下傳,不配置任何新物件;
/// 有改到才配置一個 <see cref="MaskedLogState"/>(以及一份屬性陣列)。
/// <b>Performance.</b> When the inner logger has the level off, it returns at once without formatting or masking.
/// When on, the message is formatted exactly once; when nothing turned out to need masking (the common case) the
/// original state, exception and formatter are forwarded untouched with no allocation at all, and only when something
/// changed is one <see cref="MaskedLogState"/> (plus one property array) allocated.
/// </para>
/// <para>
/// <b>限制。</b>只有<b>字串</b>屬性會逐個遮;非字串屬性(物件、<see cref="Uri"/>、數字)原樣通過,接收端若把它們
/// <c>ToString()</c> 進結構化欄位,那條路徑不在本包裝的視線內 —— 格式化後的訊息一定會過 <see cref="SecretMasker.MaskText"/>,
/// 但結構化欄位裡的物件不會。依名稱遮罩時,訊息裡對應的原值以字面替換改寫;短於 3 個字元的值不做訊息替換(那會把整行訊息改爛),
/// 只改屬性。<see cref="Exception.Data"/> 與例外的自訂屬性不遮。
/// <b>Limits.</b> Only <b>string</b> properties are masked individually; non-string properties (objects,
/// <see cref="Uri"/>, numbers) pass through as they are, and if a sink <c>ToString()</c>s them into structured fields
/// that path is outside this wrapper's sight: the formatted message always goes through
/// <see cref="SecretMasker.MaskText"/>, objects inside structured fields do not. When masking by name, the matching
/// original value in the message is rewritten by literal replacement; values shorter than 3 characters are not
/// replaced in the message (that would wreck the line), only in the property. <see cref="Exception.Data"/> and custom
/// exception properties are not masked.
/// </para>
/// </remarks>
public sealed class MaskingLogger : ILogger
{
    /// <summary>
    /// <c>ILogger</c> 擴充方法放範本字串的屬性名;它是範本不是值,不依名稱遮。
    /// The property name under which the <c>ILogger</c> extension methods store the template; it is a template, not a
    /// value, and is not masked by name.
    /// </summary>
    private const string OriginalFormatKey = "{OriginalFormat}";

    /// <summary>
    /// 依名稱遮罩時,原值至少要這麼長才會在訊息裡做字面替換。
    /// The minimum length of an original value before it is replaced literally in the message when masked by name.
    /// </summary>
    private const int MinimumMessageReplacementLength = 3;

    private readonly ILogger _inner;
    private readonly SecretMasker _masker;
    private readonly bool _maskPropertiesByName;

    /// <summary>
    /// 建立包裝。
    /// Creates the wrapper.
    /// </summary>
    /// <param name="inner">
    /// 內層記錄器,不可為 <see langword="null"/>。
    /// The inner logger; must not be <see langword="null"/>.
    /// </param>
    /// <param name="masker">
    /// 遮罩器,不可為 <see langword="null"/>。
    /// The masker; must not be <see langword="null"/>.
    /// </param>
    /// <param name="maskPropertiesByName">
    /// 是否依屬性名稱遮結構化屬性(見 <see cref="SecretMaskingOptions.MaskLogPropertiesByName"/>)。
    /// Whether to mask structured properties by name (see <see cref="SecretMaskingOptions.MaskLogPropertiesByName"/>).
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="inner"/> 或 <paramref name="masker"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="inner"/> or <paramref name="masker"/> is <see langword="null"/>.
    /// </exception>
    public MaskingLogger(ILogger inner, SecretMasker masker, bool maskPropertiesByName = true)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(masker);
        _inner = inner;
        _masker = masker;
        _maskPropertiesByName = maskPropertiesByName;
    }

    /// <summary>
    /// 內層記錄器。
    /// The inner logger.
    /// </summary>
    public ILogger Inner => _inner;

    /// <summary>
    /// 使用的遮罩器。
    /// The masker in use.
    /// </summary>
    public SecretMasker Masker => _masker;

    /// <summary>
    /// 是否依屬性名稱遮結構化屬性。
    /// Whether structured properties are masked by name.
    /// </summary>
    public bool MaskPropertiesByName => _maskPropertiesByName;

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull
    {
        if (state is IReadOnlyList<KeyValuePair<string, object?>> properties)
        {
            string text = state.ToString() ?? string.Empty;
            string masked = _masker.MaskText(text);
            KeyValuePair<string, object?>[]? maskedProperties = MaskProperties(properties, ref masked);
            if (maskedProperties is null && ReferenceEquals(text, masked))
            {
                return _inner.BeginScope(state);
            }

            return _inner.BeginScope(new MaskedLogState(maskedProperties ?? properties, masked));
        }

        if (state is string scopeText)
        {
            string masked = _masker.MaskText(scopeText);
            return ReferenceEquals(masked, scopeText) ? _inner.BeginScope(state) : _inner.BeginScope(masked);
        }

        return _inner.BeginScope(state);
    }

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => _inner.IsEnabled(logLevel);

    /// <inheritdoc />
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);

        if (!_inner.IsEnabled(logLevel))
        {
            return;
        }

        string original = formatter(state, exception);
        string message = _masker.MaskText(original);
        Exception? safeException = MaskException(exception);

        var properties = state as IReadOnlyList<KeyValuePair<string, object?>>;
        KeyValuePair<string, object?>[]? maskedProperties = properties is null ? null : MaskProperties(properties, ref message);

        if (maskedProperties is null && ReferenceEquals(message, original) && ReferenceEquals(safeException, exception))
        {
            _inner.Log(logLevel, eventId, state, exception, formatter);
            return;
        }

        var maskedState = new MaskedLogState(maskedProperties ?? properties ?? [], message);
        _inner.Log(logLevel, eventId, maskedState, safeException, MaskedLogState.Formatter);
    }

    /// <summary>
    /// 遮罩例外文字:訊息、堆疊或全文裡找到祕密時回傳 <see cref="MaskedException"/> 替身,否則回傳原例外。
    /// Masks exception text: returns a <see cref="MaskedException"/> stand-in when a secret is found in the message,
    /// stack trace or full text, otherwise the original exception.
    /// </summary>
    /// <param name="exception">
    /// 原例外,允許 <see langword="null"/>。
    /// The original exception; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 可安全交給接收端的例外。
    /// An exception safe to hand to the sink.
    /// </returns>
    private Exception? MaskException(Exception? exception)
    {
        if (exception is null)
        {
            return null;
        }

        string fullText = exception.ToString();
        string maskedFullText = _masker.MaskText(fullText);
        string exceptionMessage = exception.Message;
        string maskedMessage = _masker.MaskText(exceptionMessage);
        if (ReferenceEquals(fullText, maskedFullText) && ReferenceEquals(exceptionMessage, maskedMessage))
        {
            return exception;
        }

        return new MaskedException(
            exception.GetType().FullName,
            maskedMessage,
            _masker.MaskText(exception.StackTrace),
            maskedFullText,
            MaskException(exception.InnerException))
        {
            HResult = exception.HResult,
            Source = exception.Source,
        };
    }

    /// <summary>
    /// 遮罩結構化屬性中的字串值。有任何值被改到才配置新陣列並回傳,否則回傳 <see langword="null"/>;
    /// 依名稱遮到的值同時在 <paramref name="message"/> 裡做字面替換。
    /// Masks the string values among the structured properties. A new array is allocated and returned only when
    /// some value changed, otherwise <see langword="null"/>; a value masked by name is also replaced literally in
    /// <paramref name="message"/>.
    /// </summary>
    /// <param name="properties">
    /// 原始屬性。
    /// The original properties.
    /// </param>
    /// <param name="message">
    /// 格式化後的訊息,依名稱遮到的值會在這裡被替換。
    /// The formatted message, in which values masked by name are replaced.
    /// </param>
    /// <returns>
    /// 遮罩後的屬性陣列,或沒改到時為 <see langword="null"/>。
    /// The masked property array, or <see langword="null"/> when nothing changed.
    /// </returns>
    private KeyValuePair<string, object?>[]? MaskProperties(IReadOnlyList<KeyValuePair<string, object?>> properties, ref string message)
    {
        KeyValuePair<string, object?>[]? result = null;
        int count = properties.Count;
        for (int i = 0; i < count; i++)
        {
            KeyValuePair<string, object?> pair = properties[i];
            if (pair.Value is string value && value.Length > 0)
            {
                // 先做已登記祕密的字面替換,再依名稱遮:登記過的祕密要整個換成遮罩字串,
                // 若先依名稱保留頭尾,字面替換就再也找不到完整的祕密,結果是露出了頭尾。
                // Literal replacement of registered secrets first, name-based masking second: a registered secret must
                // be replaced whole, and if name masking kept its ends first the literal pass would no longer find the
                // complete secret, leaving those ends exposed.
                string masked = _masker.MaskText(value);
                if (ReferenceEquals(masked, value) && _maskPropertiesByName && !string.Equals(pair.Key, OriginalFormatKey, StringComparison.Ordinal))
                {
                    masked = _masker.MaskNamedValue(pair.Key, value);
                }

                if (!ReferenceEquals(masked, value))
                {
                    if (result is null)
                    {
                        result = new KeyValuePair<string, object?>[count];
                        for (int j = 0; j < i; j++)
                        {
                            result[j] = properties[j];
                        }
                    }

                    result[i] = new KeyValuePair<string, object?>(pair.Key, masked);

                    if (value.Length >= MinimumMessageReplacementLength && message.Contains(value, StringComparison.Ordinal))
                    {
                        message = message.Replace(value, masked, StringComparison.Ordinal);
                    }

                    continue;
                }
            }

            if (result is not null)
            {
                result[i] = pair;
            }
        }

        return result;
    }
}
