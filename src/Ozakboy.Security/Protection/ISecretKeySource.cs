namespace Ozakboy.Security.Protection;

/// <summary>
/// <see cref="KeyedSecretProtector"/> 的主金鑰來源。把「金鑰從哪裡來」與「怎麼加密」拆開:
/// 容器場景從環境變數拿(<see cref="EnvironmentVariableKeySource"/>)、EC2 場景從金鑰檔拿
/// (<see cref="KeyFileKeySource"/>),或者由呼叫端自己實作(雲端 KMS、作業系統金鑰鏈)。
/// The master-key source for <see cref="KeyedSecretProtector"/>. It separates "where the key comes
/// from" from "how values are encrypted": containers read it from an environment variable
/// (<see cref="EnvironmentVariableKeySource"/>), EC2 hosts from a key file
/// (<see cref="KeyFileKeySource"/>), and callers can implement their own (a cloud KMS, an OS keychain).
/// </summary>
/// <remarks>
/// 實作準則:每次呼叫 <see cref="ReadKey"/> 都回傳一個<b>新配置</b>的陣列,呼叫端用完會以
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(Span{byte})"/> 清零;
/// 因此實作不可回傳自己持有的共用緩衝區,否則第一次使用之後金鑰就被清成全零了。
/// 取不到金鑰時擲出 <see cref="SecretProtectionException"/> 並以
/// <see cref="SecretProtectionFailureReason.KeyUnavailable"/> 說明原因,訊息中不得包含金鑰內容。
/// Implementation contract: every <see cref="ReadKey"/> call returns a <b>freshly allocated</b> array,
/// which the caller zeroes with
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(Span{byte})"/> when done.
/// An implementation must therefore never hand out a shared buffer it keeps, or the key would be wiped
/// after its first use. When the key cannot be obtained, throw <see cref="SecretProtectionException"/>
/// with <see cref="SecretProtectionFailureReason.KeyUnavailable"/>; the message must never contain key
/// material.
/// </remarks>
public interface ISecretKeySource
{
    /// <summary>
    /// 這個來源的說明,用於錯誤訊息與日誌(例如「環境變數 APP_MASTER_KEY」),不得含金鑰內容。
    /// A description of this source for error messages and logs (for example "environment variable
    /// APP_MASTER_KEY"); it must never contain key material.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// 讀出主金鑰,長度必須是 <see cref="KeyedSecretProtector.KeyLengthInBytes"/>(32 位元組,AES-256)。
    /// Reads the master key; it must be exactly <see cref="KeyedSecretProtector.KeyLengthInBytes"/>
    /// (32 bytes, AES-256) long.
    /// </summary>
    /// <returns>
    /// 新配置的金鑰陣列,呼叫端用完必須清零。
    /// A freshly allocated key array that the caller must zero after use.
    /// </returns>
    /// <exception cref="SecretProtectionException">
    /// 取不到金鑰時擲出,<see cref="SecretProtectionException.Reason"/> 為
    /// <see cref="SecretProtectionFailureReason.KeyUnavailable"/>。
    /// Thrown when the key cannot be obtained, with <see cref="SecretProtectionException.Reason"/> set to
    /// <see cref="SecretProtectionFailureReason.KeyUnavailable"/>.
    /// </exception>
    byte[] ReadKey();
}
