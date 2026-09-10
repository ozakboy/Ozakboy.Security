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
    /// 額外熵值(選用)。加密與還原必須使用同一份熵值,否則無法還原。
    /// Optional additional entropy. The same entropy must be supplied when unprotecting, otherwise the
    /// data cannot be restored.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>它防得住什麼:</b>拿到這個檔案、但不知道熵值的其他程式。通用型 DPAPI 解密工具、
    /// 備份還原後翻檔案的人,即使跑在同一個帳號下,少了熵值也解不開。
    /// <b>What it protects against:</b> other programs that hold this file but do not know the entropy —
    /// generic DPAPI decryption tools, or whoever restores a backup and goes through the files. Without
    /// the entropy they cannot open it, even running under the same account.
    /// </para>
    /// <para>
    /// <b>它防不住什麼:</b>以同一個帳號執行的程式碼。熵值若來自應用程式內的固定字串,它就被編進了組件裡,
    /// 任何能以同一使用者身分執行的程序反組譯就能拿到,DPAPI 也就沒有多攔下什麼。
    /// <b>What it does not protect against:</b> code running as the same user. An entropy value baked in
    /// as an application constant lives inside the assembly, and anything able to run as that user can
    /// decompile it out — at which point DPAPI is stopping nothing extra.
    /// </para>
    /// <para>
    /// 若真的要擋住同帳號執行的程式,熵值必須來自使用者輸入的通行碼、每次啟動時才取得,而且不落地。
    /// 那條路的代價是無人值守啟動不再可行 —— 沒有人在旁邊輸入,服務就起不來。
    /// To genuinely stop same-account code, the entropy has to come from a passphrase the user types in
    /// at start-up and it must never be written to disk. The price of that route is unattended start-up:
    /// with nobody there to type, the service cannot come up.
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> Entropy { get; init; }

    /// <summary>
    /// 以文字建立額外熵值,內部以 UTF-8 編碼。
    /// Builds the additional entropy from text, encoded as UTF-8.
    /// </summary>
    /// <param name="entropyText">
    /// 熵值文字,不可為 <see langword="null"/>。
    /// 傳入應用程式自訂的固定字串時,請理解它擋的是「別的程式拿到這個檔案」,不是「同帳號執行的程式碼」
    /// —— 固定字串會被編進組件,反組譯就能取得(詳見 <see cref="Entropy"/> 的說明)。
    /// The entropy text; must not be <see langword="null"/>. When it is an application-specific constant,
    /// understand what it buys: protection from other programs that get hold of the file, not from code
    /// running as the same user — a constant is compiled into the assembly and can be decompiled straight
    /// back out (see the remarks on <see cref="Entropy"/>).
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
