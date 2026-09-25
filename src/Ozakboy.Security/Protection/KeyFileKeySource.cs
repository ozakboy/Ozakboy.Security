using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Ozakboy.Security.Protection;

/// <summary>
/// 從金鑰檔讀取主金鑰的 <see cref="ISecretKeySource"/>,這是 EC2 / VM 這類「有磁碟、沒有編排系統」場景的做法。
/// 檔案內容可以是 32 個原始位元組(<c>head -c 32 /dev/urandom &gt; app.key</c>),
/// 或是 32 位元組金鑰的 Base64 文字(<c>openssl rand -base64 32 &gt; app.key</c>);
/// 長度恰為 32 位元組、而且不全是 Base64 字母表字元時視為原始金鑰,否則視為 Base64 文字。
/// 「不全是 Base64 字元」這個條件是必要的:24 位元組金鑰的 Base64 恰好也是 32 個字元,少了這條就會把它當成一把弱金鑰照收;
/// 一把真正隨機的 32 位元組原始金鑰恰好全落在 Base64 字母表內的機率是 2^-64,可以忽略。
/// An <see cref="ISecretKeySource"/> that reads the master key from a key file, the arrangement for
/// EC2 / VM hosts that have a disk but no orchestrator. The file may hold 32 raw bytes
/// (<c>head -c 32 /dev/urandom &gt; app.key</c>) or the Base64 text of a 32-byte key
/// (<c>openssl rand -base64 32 &gt; app.key</c>). A file of exactly 32 bytes that is not made entirely
/// of Base64-alphabet characters is taken as raw; anything else as Base64 text. The "not entirely
/// Base64 characters" clause is essential: the Base64 of a 24-byte key is also exactly 32 characters,
/// and without it such a file would be accepted as a weak raw key. A genuinely random 32-byte raw key
/// lands entirely inside the Base64 alphabet with probability 2^-64, which is negligible.
/// </summary>
/// <remarks>
/// <para>
/// <b>每次讀取都檢查,而且拒絕開放的權限。</b>在 Unix 上,金鑰檔對群組或其他人有任何權限位元
/// (<c>r</c>、<c>w</c>、<c>x</c> 任一)就拒絕讀取,並在訊息中說明實際權限與修正方式(<c>chmod 600</c>)。
/// 檢查在每次 <see cref="ReadKey"/> 時都做,不只在啟動時:程序跑起來之後檔案被 <c>chmod</c> 鬆掉,
/// 下一次用到金鑰就會發現。這條檢查是刻意不可關閉的 —— 能關掉的安全檢查最終都會被關掉。
/// <b>Checked on every read, and open permissions are refused.</b> On Unix, any permission bit for group
/// or others (<c>r</c>, <c>w</c> or <c>x</c>) on the key file makes the read fail, with the actual mode and
/// the fix (<c>chmod 600</c>) in the message. The check runs on every <see cref="ReadKey"/>, not only at
/// start-up, so a file loosened with <c>chmod</c> after the process came up is caught the next time the
/// key is needed. The check deliberately cannot be switched off: a security check that can be disabled
/// eventually is.
/// </para>
/// <para>
/// <b>Windows 上不檢查權限。</b>NTFS 的 ACL 與 Unix 的權限位元不是同一套模型,本套件不假裝能翻譯;
/// 在 Windows 上請用 DPAPI(<see cref="DpapiSecretProtector"/>),那才是該平台保護金鑰的原生方式。
/// 這個來源在 Windows 上仍可運作(例如開發機),只是少了權限這道防線。
/// <b>No permission check on Windows.</b> NTFS ACLs and Unix mode bits are different models and this
/// library does not pretend to translate between them; on Windows use DPAPI
/// (<see cref="DpapiSecretProtector"/>), the platform's native way of protecting a key. The source still
/// works on Windows (a developer machine, say), only without that line of defence.
/// </para>
/// <para>
/// 讀出的位元組在轉成金鑰後立即清零(原始位元組的情況下直接回傳那個陣列,由呼叫端清零)。
/// The bytes read from the file are zeroed as soon as the key has been extracted (in the raw case the
/// array itself is returned, and the caller zeroes it).
/// </para>
/// </remarks>
public sealed class KeyFileKeySource : ISecretKeySource
{
    /// <summary>
    /// 群組與其他人的所有權限位元;金鑰檔上出現任何一個都拒絕。
    /// Every group and other permission bit; any of them on the key file is grounds for refusal.
    /// </summary>
    private const UnixFileMode DisallowedModes =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    private readonly string _path;

    /// <summary>
    /// 建立以指定檔案為來源的金鑰來源。建構時不讀檔,也不檢查存在與否 —— 那些都在 <see cref="ReadKey"/> 時做。
    /// Creates a key source backed by the given file. Nothing is read or checked at construction; all of
    /// that happens in <see cref="ReadKey"/>.
    /// </summary>
    /// <param name="path">
    /// 金鑰檔路徑,不可為空白。
    /// The key file path; must not be blank.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="path"/> 為 <see langword="null"/> 或空白時擲出。
    /// Thrown when <paramref name="path"/> is <see langword="null"/> or blank.
    /// </exception>
    public KeyFileKeySource(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    /// <summary>
    /// 金鑰檔的完整路徑。
    /// The full path of the key file.
    /// </summary>
    public string FilePath => _path;

    /// <inheritdoc />
    public string Description => "金鑰檔 / key file '" + _path + "'";

    /// <inheritdoc />
    public byte[] ReadKey()
    {
        if (!File.Exists(_path))
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "找不到金鑰檔 '" + _path + "',無法取得主金鑰。請以 32 位元組的隨機金鑰建立它(例如 head -c 32 /dev/urandom > 檔案,再 chmod 600)。 " +
                "Key file '" + _path + "' does not exist, so no master key is available. Create it with 32 random bytes (for example head -c 32 /dev/urandom > file, then chmod 600).");
        }

        EnsureRestrictedPermissions();

        byte[] fileBytes;
        try
        {
            fileBytes = File.ReadAllBytes(_path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "無法讀取金鑰檔 '" + _path + "':" + ex.GetType().Name + "。 " +
                "Key file '" + _path + "' could not be read: " + ex.GetType().Name + ".",
                ex);
        }

        if (fileBytes.Length == KeyedSecretProtector.KeyLengthInBytes && !IsEntirelyBase64Alphabet(fileBytes))
        {
            return fileBytes;
        }

        try
        {
            return DecodeBase64Text(fileBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileBytes);
        }
    }

    /// <summary>
    /// 檔案內容是否全由 Base64 字母表(A-Z、a-z、0-9、+、/、=)與空白組成。
    /// Whether the content consists only of Base64-alphabet characters (A-Z, a-z, 0-9, +, /, =) and whitespace.
    /// </summary>
    /// <param name="fileBytes">
    /// 檔案內容。
    /// The file content.
    /// </param>
    /// <returns>
    /// 全是 Base64 字元時回傳 <see langword="true"/>。
    /// <see langword="true"/> when every byte is a Base64 character.
    /// </returns>
    private static bool IsEntirelyBase64Alphabet(ReadOnlySpan<byte> fileBytes)
    {
        foreach (byte b in fileBytes)
        {
            bool isBase64 = b is (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9')
                or (byte)'+' or (byte)'/' or (byte)'=' or (byte)'\n' or (byte)'\r' or (byte)' ' or (byte)'\t';
            if (!isBase64)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// 把檔案內容當成 Base64 文字解碼;不是 Base64 或長度不對都以 KeyUnavailable 拒絕。
    /// Decodes the file content as Base64 text; anything that is not Base64, or not 32 bytes, is refused as KeyUnavailable.
    /// </summary>
    /// <param name="fileBytes">
    /// 檔案內容。
    /// The file content.
    /// </param>
    /// <returns>
    /// 解碼後的金鑰。
    /// The decoded key.
    /// </returns>
    private byte[] DecodeBase64Text(byte[] fileBytes)
    {
        byte[] key;
        try
        {
            string text = Encoding.UTF8.GetString(fileBytes).Trim();
            key = Convert.FromBase64String(text);
        }
        catch (FormatException ex)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "金鑰檔 '" + _path + "' 的長度是 " + fileBytes.Length.ToString(CultureInfo.InvariantCulture) +
                " 位元組:既不是 32 個原始位元組,也不是有效的 Base64 文字。 " +
                "Key file '" + _path + "' is " + fileBytes.Length.ToString(CultureInfo.InvariantCulture) +
                " bytes long: neither 32 raw bytes nor valid Base64 text.",
                ex);
        }

        if (key.Length != KeyedSecretProtector.KeyLengthInBytes)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "金鑰檔 '" + _path + "' 的 Base64 內容解碼後是 " + key.Length.ToString(CultureInfo.InvariantCulture) +
                " 位元組,主金鑰必須是 " + KeyedSecretProtector.KeyLengthInBytes.ToString(CultureInfo.InvariantCulture) + " 位元組(AES-256)。 " +
                "The Base64 content of key file '" + _path + "' decodes to " + key.Length.ToString(CultureInfo.InvariantCulture) +
                " bytes; the master key must be " + KeyedSecretProtector.KeyLengthInBytes.ToString(CultureInfo.InvariantCulture) + " bytes (AES-256).");
        }

        return key;
    }

    /// <summary>
    /// Unix 上檢查金鑰檔沒有對群組或其他人開放任何權限;Windows 上不做任何事。
    /// On Unix, verifies the key file grants nothing to group or others; does nothing on Windows.
    /// </summary>
    private void EnsureRestrictedPermissions()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        UnixFileMode mode;
        try
        {
            mode = File.GetUnixFileMode(_path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "無法讀取金鑰檔 '" + _path + "' 的權限:" + ex.GetType().Name + "。 " +
                "The permissions of key file '" + _path + "' could not be read: " + ex.GetType().Name + ".",
                ex);
        }

        UnixFileMode open = mode & DisallowedModes;
        if (open != UnixFileMode.None)
        {
            string octal = Convert.ToString((int)mode, 8).PadLeft(3, '0');
            throw new SecretProtectionException(
                SecretProtectionFailureReason.KeyUnavailable,
                "金鑰檔 '" + _path + "' 的權限是 " + octal + ",對群組或其他人開放(" + open.ToString() + ")。" +
                "主金鑰檔只能由擁有者讀寫,請執行 chmod 600 並確認擁有者是執行服務的帳號。 " +
                "Key file '" + _path + "' has mode " + octal + " and is open to group or others (" + open.ToString() + "). " +
                "A master-key file must be readable by its owner only: run chmod 600 and make sure the owner is the account the service runs as.");
        }
    }
}
