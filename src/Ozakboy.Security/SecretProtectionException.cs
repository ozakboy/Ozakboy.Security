namespace Ozakboy.Security;

/// <summary>
/// 保護或還原敏感資料失敗時拋出的例外,帶有可判讀的失敗原因,
/// 讓呼叫端能對「資料損毀」與「非本機/本使用者加密」做出不同處置。
/// Thrown when protecting or unprotecting sensitive data fails. Carries a machine-readable reason
/// so callers can react differently to malformed data and to data they are not entitled to decrypt.
/// </summary>
public sealed class SecretProtectionException : Exception
{
    /// <summary>
    /// 以預設訊息建立例外。
    /// Initializes a new instance with a default message.
    /// </summary>
    public SecretProtectionException()
        : base("敏感資料保護作業失敗。 The secret protection operation failed.")
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
    public SecretProtectionException(string message)
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
    /// 造成這次失敗的內部例外。
    /// The exception that caused this failure.
    /// </param>
    public SecretProtectionException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }

    /// <summary>
    /// 以失敗原因、訊息與內部例外建立例外。
    /// Initializes a new instance with a failure reason, message and inner exception.
    /// </summary>
    /// <param name="reason">
    /// 失敗原因分類。
    /// The failure reason.
    /// </param>
    /// <param name="message">
    /// 錯誤訊息。
    /// The error message.
    /// </param>
    /// <param name="innerException">
    /// 造成這次失敗的內部例外,沒有則傳入 <see langword="null"/>。
    /// The exception that caused this failure, or <see langword="null"/>.
    /// </param>
    public SecretProtectionException(SecretProtectionFailureReason reason, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Reason = reason;
    }

    /// <summary>
    /// 失敗原因分類。
    /// The classified failure reason.
    /// </summary>
    public SecretProtectionFailureReason Reason { get; }
}
