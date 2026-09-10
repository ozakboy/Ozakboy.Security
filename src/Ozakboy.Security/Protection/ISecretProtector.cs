namespace Ozakboy.Security.Protection;

/// <summary>
/// 敏感資料保護器:把憑證這類不該以明文落地的資料加密成可寫進設定檔的字串,並能還原。
/// 介面優先是為了讓測試能注入假物件,也讓非 Windows 環境可以換掉 DPAPI 實作。
/// Protects sensitive values (such as API credentials) so they never hit disk in plain text, and
/// restores them. The interface exists so tests can inject fakes and non-Windows hosts can swap in
/// a different implementation.
/// </summary>
public interface ISecretProtector
{
    /// <summary>
    /// 目前執行環境是否支援這個實作。
    /// Whether the current runtime environment supports this implementation.
    /// </summary>
    bool IsSupported { get; }

    /// <summary>
    /// 加密明文字串,回傳可直接寫進設定檔的 Base64 字串。
    /// Protects a plain-text string and returns a Base64 string safe to store in a configuration file.
    /// </summary>
    /// <param name="plainText">
    /// 要保護的明文,允許空字串。
    /// The plain text to protect; an empty string is allowed.
    /// </param>
    /// <returns>
    /// 加密後的 Base64 字串。
    /// The protected value as Base64 text.
    /// </returns>
    string Protect(string plainText);

    /// <summary>
    /// 還原以 <see cref="Protect(string)"/> 加密的字串。
    /// Restores a string previously produced by <see cref="Protect(string)"/>.
    /// </summary>
    /// <param name="protectedValue">
    /// 先前加密輸出的 Base64 字串。
    /// The Base64 text produced by a previous protect call.
    /// </param>
    /// <returns>
    /// 還原後的明文。
    /// The restored plain text.
    /// </returns>
    /// <exception cref="SecretProtectionException">
    /// 資料損毀、格式版本不符、保護範圍不符,或這份資料不是由本機/本使用者加密時拋出。
    /// Thrown when the payload is malformed, uses an unknown version, was protected under a
    /// different scope, or cannot be decrypted by this machine or user.
    /// </exception>
    string Unprotect(string protectedValue);

    /// <summary>
    /// 嘗試還原字串,失敗時回傳 <see langword="false"/> 而不拋例外。
    /// 設定檔跨機器複製、換使用者帳戶、被手動編輯都是預期會發生的情況,呼叫端通常該走這條路徑。
    /// Attempts to restore a string, returning <see langword="false"/> instead of throwing. Copying a
    /// configuration file between machines, switching user accounts and hand-editing are all expected
    /// situations, so callers usually want this path.
    /// </summary>
    /// <param name="protectedValue">
    /// 先前加密輸出的 Base64 字串。
    /// The Base64 text produced by a previous protect call.
    /// </param>
    /// <param name="plainText">
    /// 成功時回傳還原後的明文,失敗時為 <see langword="null"/>。
    /// Receives the restored plain text on success, or <see langword="null"/> on failure.
    /// </param>
    /// <returns>
    /// 還原成功回傳 <see langword="true"/>。
    /// <see langword="true"/> when the value was restored.
    /// </returns>
    bool TryUnprotect(string protectedValue, out string? plainText);

    /// <summary>
    /// 加密位元組資料。
    /// Protects raw bytes.
    /// </summary>
    /// <param name="plainBytes">
    /// 要保護的位元組資料。
    /// The bytes to protect.
    /// </param>
    /// <returns>
    /// 加密後的位元組資料(含格式標頭)。
    /// The protected bytes, including this library's envelope header.
    /// </returns>
    byte[] Protect(byte[] plainBytes);

    /// <summary>
    /// 還原以 <see cref="Protect(byte[])"/> 加密的位元組資料。
    /// Restores bytes previously produced by <see cref="Protect(byte[])"/>.
    /// </summary>
    /// <param name="protectedBytes">
    /// 先前加密輸出的位元組資料。
    /// The protected bytes from a previous protect call.
    /// </param>
    /// <returns>
    /// 還原後的位元組資料。
    /// The restored bytes.
    /// </returns>
    /// <exception cref="SecretProtectionException">
    /// 資料損毀、格式版本不符、保護範圍不符,或這份資料不是由本機/本使用者加密時拋出。
    /// Thrown when the payload is malformed, uses an unknown version, was protected under a
    /// different scope, or cannot be decrypted by this machine or user.
    /// </exception>
    byte[] Unprotect(byte[] protectedBytes);

    /// <summary>
    /// 嘗試還原位元組資料,失敗時回傳 <see langword="false"/> 而不拋例外。
    /// Attempts to restore bytes, returning <see langword="false"/> instead of throwing.
    /// </summary>
    /// <param name="protectedBytes">
    /// 先前加密輸出的位元組資料。
    /// The protected bytes from a previous protect call.
    /// </param>
    /// <param name="plainBytes">
    /// 成功時回傳還原後的位元組資料,失敗時為 <see langword="null"/>。
    /// Receives the restored bytes on success, or <see langword="null"/> on failure.
    /// </param>
    /// <returns>
    /// 還原成功回傳 <see langword="true"/>。
    /// <see langword="true"/> when the value was restored.
    /// </returns>
    bool TryUnprotect(byte[] protectedBytes, out byte[]? plainBytes);
}
