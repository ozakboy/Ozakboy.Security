namespace Ozakboy.Security.Protection;

/// <summary>
/// 保護範圍:決定加密後的資料由誰能還原。
/// 本列舉刻意不直接沿用平台專屬型別,讓非 Windows 環境也能參照本套件的公開 API。
/// The protection scope, deciding who is able to restore the protected data. This enum deliberately
/// avoids platform-specific types so the public API stays usable on non-Windows targets.
/// </summary>
public enum SecretProtectionScope
{
    /// <summary>
    /// 只有加密當下的使用者帳戶能還原(預設,保護強度較高)。
    /// Only the user account that protected the data can restore it (default, stronger isolation).
    /// </summary>
    CurrentUser = 0,

    /// <summary>
    /// 同一台機器上的任何帳戶都能還原,適用於服務帳戶與桌面帳戶需共用同一份設定的情境。
    /// Any account on the same machine can restore it; use when a service account and a desktop
    /// account must share the same configuration file.
    /// </summary>
    LocalMachine = 1,
}
