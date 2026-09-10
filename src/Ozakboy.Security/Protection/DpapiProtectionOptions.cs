using System.Text;

namespace Ozakboy.Security.Protection;

/// <summary>
/// <see cref="DpapiSecretProtector"/> 的設定。以 record 表達不可變設定,建立後不再變動。
/// Options for <see cref="DpapiSecretProtector"/>. Modelled as an immutable record: once created,
/// the settings never change.
/// </summary>
public sealed record DpapiProtectionOptions
{
    /// <summary>
    /// 保護範圍,預設為 <see cref="SecretProtectionScope.CurrentUser"/>。
    /// The protection scope; defaults to <see cref="SecretProtectionScope.CurrentUser"/>.
    /// </summary>
    public SecretProtectionScope Scope { get; init; } = SecretProtectionScope.CurrentUser;

    /// <summary>
    /// 額外熵值(選用)。加密與還原必須使用同一份熵值,否則無法還原;
    /// 它讓「取得同一個使用者的執行權限」還不足以解開這份資料。
    /// Optional additional entropy. The same entropy must be supplied when unprotecting, otherwise the
    /// data cannot be restored; it means running as the same user is not by itself enough to read it.
    /// </summary>
    public ReadOnlyMemory<byte> Entropy { get; init; }

    /// <summary>
    /// 以文字建立額外熵值,內部以 UTF-8 編碼。
    /// Builds the additional entropy from text, encoded as UTF-8.
    /// </summary>
    /// <param name="entropyText">
    /// 熵值文字,不可為 <see langword="null"/>。這是應用程式自訂的固定字串,不是密碼。
    /// The entropy text; must not be <see langword="null"/>. It is an application-specific constant,
    /// not a password.
    /// </param>
    /// <returns>
    /// 套用該熵值後的新設定物件。
    /// A new options instance carrying that entropy.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="entropyText"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="entropyText"/> is <see langword="null"/>.
    /// </exception>
    public DpapiProtectionOptions WithEntropyText(string entropyText)
    {
        ArgumentNullException.ThrowIfNull(entropyText);
        return this with { Entropy = Encoding.UTF8.GetBytes(entropyText) };
    }
}
