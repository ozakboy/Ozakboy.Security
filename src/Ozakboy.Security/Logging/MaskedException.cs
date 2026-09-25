namespace Ozakboy.Security.Logging;

/// <summary>
/// 交給日誌接收端的例外替身:原例外的訊息、堆疊與 <c>ToString()</c> 全文都經過遮罩,原型別名稱保留在 <see cref="OriginalTypeName"/>。
/// 例外物件本身改不了(<see cref="Exception.Message"/> 唯讀、<see cref="Exception.ToString"/> 可能被覆寫),
/// 所以 <see cref="MaskingLogger"/> 在文字裡真的找到祕密時,換成這個替身往下傳。
/// The stand-in handed to a log sink in place of an exception: the original's message, stack trace and full
/// <c>ToString()</c> text are masked, and the original type name is kept in <see cref="OriginalTypeName"/>. An
/// exception object cannot be edited in place (<see cref="Exception.Message"/> is read-only,
/// <see cref="Exception.ToString"/> may be overridden), so when <see cref="MaskingLogger"/> actually finds a secret in
/// the text it passes this stand-in down instead.
/// </summary>
/// <remarks>
/// 限制:接收端讀 <see cref="Exception.Data"/>、自訂屬性或以型別分派(<c>catch (HttpRequestException)</c> 之類)的行為,
/// 在替身上都看不到原本的內容;內層例外會遞迴換成替身(或者原物件,若它的文字沒有祕密)。
/// 沒有找到祕密的例外原封不動傳下去,不會被換掉。
/// Limits: a sink that reads <see cref="Exception.Data"/>, custom properties, or dispatches on the type
/// (<c>catch (HttpRequestException)</c> and the like) sees none of the original on the stand-in; inner exceptions are
/// replaced recursively (or kept as-is when their text holds no secret). An exception in which no secret is found is
/// passed through untouched, never replaced.
/// </remarks>
public sealed class MaskedException : Exception
{
    private readonly string? _stackTrace;
    private readonly string? _fullText;

    /// <summary>
    /// 以預設訊息建立例外。
    /// Initializes a new instance with a default message.
    /// </summary>
    public MaskedException()
    {
    }

    /// <summary>
    /// 以指定訊息建立例外。
    /// Initializes a new instance with the specified message.
    /// </summary>
    /// <param name="message">
    /// 錯誤訊息。
    /// The error message.
    /// </param>
    public MaskedException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// 以指定訊息與內部例外建立例外。
    /// Initializes a new instance with the specified message and inner exception.
    /// </summary>
    /// <param name="message">
    /// 錯誤訊息。
    /// The error message.
    /// </param>
    /// <param name="innerException">
    /// 內部例外。
    /// The inner exception.
    /// </param>
    public MaskedException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// 建立替身,所有文字都應已遮罩。
    /// Creates a stand-in; every text passed in is expected to be masked already.
    /// </summary>
    /// <param name="originalTypeName">
    /// 原例外的型別全名。
    /// The original exception's full type name.
    /// </param>
    /// <param name="message">
    /// 遮罩後的訊息。
    /// The masked message.
    /// </param>
    /// <param name="stackTrace">
    /// 遮罩後的堆疊文字,沒有則為 <see langword="null"/>。
    /// The masked stack trace text, or <see langword="null"/>.
    /// </param>
    /// <param name="fullText">
    /// 遮罩後的 <c>ToString()</c> 全文。
    /// The masked full <c>ToString()</c> text.
    /// </param>
    /// <param name="innerException">
    /// 內部例外(替身或原物件)。
    /// The inner exception (a stand-in or the original).
    /// </param>
    public MaskedException(string? originalTypeName, string message, string? stackTrace, string fullText, Exception? innerException)
        : base(message, innerException)
    {
        OriginalTypeName = originalTypeName;
        _stackTrace = stackTrace;
        _fullText = fullText;
    }

    /// <summary>
    /// 原例外的型別全名(例如 <c>System.Net.Http.HttpRequestException</c>),讓日誌仍看得出是哪種錯。
    /// The original exception's full type name (for example <c>System.Net.Http.HttpRequestException</c>), so the log
    /// still shows what kind of error it was.
    /// </summary>
    public string? OriginalTypeName { get; }

    /// <summary>
    /// 遮罩後的堆疊文字。
    /// The masked stack trace text.
    /// </summary>
    public override string? StackTrace => _stackTrace ?? base.StackTrace;

    /// <summary>
    /// 遮罩後的全文;建構時沒給則退回基底的格式。
    /// The masked full text, falling back to the base format when none was supplied.
    /// </summary>
    /// <returns>
    /// 例外的字串表示。
    /// The string form of the exception.
    /// </returns>
    public override string ToString() => _fullText ?? base.ToString();
}
