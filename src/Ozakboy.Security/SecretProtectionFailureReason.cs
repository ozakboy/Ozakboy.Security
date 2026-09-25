namespace Ozakboy.Security;

/// <summary>
/// 保護資料還原失敗的原因分類,用於區分「資料本身壞掉」與「這台機器/這個使用者解不開」。
/// Classifies why protected data could not be restored, separating malformed payloads from
/// payloads this machine or user is simply not allowed to decrypt.
/// </summary>
public enum SecretProtectionFailureReason
{
    /// <summary>
    /// 沒有失敗(預設值)。
    /// No failure (default value).
    /// </summary>
    None = 0,

    /// <summary>
    /// 內容不是有效的保護資料:Base64 無法解碼、長度不足,或缺少本套件的格式標頭。
    /// 常見於設定檔被手動編輯、複製貼上時被截斷。
    /// The payload is not valid protected data: undecodable Base64, too short, or missing this
    /// library's format header. Typically caused by hand-editing or a truncated copy-paste.
    /// </summary>
    MalformedPayload = 1,

    /// <summary>
    /// 格式標頭版本不是目前程式庫認得的版本,多半是資料由較新版本產生。
    /// The envelope version is unknown to this library, usually data written by a newer version.
    /// </summary>
    UnsupportedFormatVersion = 2,

    /// <summary>
    /// 資料是以另一個保護範圍加密的(例如以 LocalMachine 加密、卻用 CurrentUser 還原)。
    /// The payload was protected under a different scope (for example protected with LocalMachine
    /// but being unprotected with CurrentUser).
    /// </summary>
    ScopeMismatch = 3,

    /// <summary>
    /// 底層解密拒絕還原:資料遭竄改、金鑰錯誤,或這份資料是由其他使用者帳戶/其他機器加密的。
    /// The underlying decryption refused the payload: tampered data, a wrong key, or data protected
    /// by a different user account or machine.
    /// </summary>
    DecryptionFailed = 4,

    /// <summary>
    /// 目前平台不支援這個保護機制(例如在非 Windows 上使用 DPAPI)。
    /// 註:內建的 DPAPI 實作遇到這個情況是拋出 <see cref="PlatformNotSupportedException"/>;
    /// 這個值保留給「寧可回報失敗原因、也不拋平台例外」的替代實作使用。
    /// The current platform does not support this protection mechanism (for example DPAPI on a
    /// non-Windows operating system). Note that the built-in DPAPI implementation throws
    /// <see cref="PlatformNotSupportedException"/> instead; this value exists for substitute
    /// implementations that would rather report a failure reason than throw.
    /// </summary>
    PlatformNotSupported = 5,

    /// <summary>
    /// 取不到主金鑰:環境變數未設定、金鑰檔不存在、長度不對,或金鑰檔的權限對群組/其他人開放而被拒絕。
    /// 這是金鑰式保護器(<c>KeyedSecretProtector</c>)特有的失敗;資料本身沒有問題,是這台機器沒有正確配置金鑰。
    /// The master key could not be obtained: the environment variable is unset, the key file is missing
    /// or the wrong length, or the key file's permissions are open to group or others and it was refused.
    /// Specific to the keyed protector (<c>KeyedSecretProtector</c>): the payload is fine, this host simply
    /// has no correctly provisioned key.
    /// </summary>
    KeyUnavailable = 6,
}
