using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Ozakboy.Security.Configuration;

/// <summary>
/// 設定檔加密:以 AES-GCM 加密整份設定檔或其中的區段,輸出自帶版本標頭,方便日後換演算法時辨識舊資料。
/// AES-GCM 同時提供機密性與完整性,密文被改一個位元組就會解密失敗,不會悄悄還原成錯誤內容。
/// Encrypts a whole configuration file or a section of it with AES-GCM. The output carries a version
/// header so a future algorithm change can still recognise old data. AES-GCM provides confidentiality
/// and integrity together: flip one byte of the ciphertext and decryption fails loudly instead of
/// quietly returning something wrong.
/// </summary>
/// <remarks>
/// 輸出格式為 <c>OZCF</c> 標頭(4 位元組)+ 版本(1 位元組)+ nonce(12 位元組)+ 驗證標籤(16 位元組)+ 密文。
/// 標頭同時作為 AES-GCM 的關聯資料(associated data),因此標頭被竄改一樣會導致解密失敗。
/// 每次加密都會產生新的 nonce —— 同一把金鑰重複使用同一個 nonce 會直接摧毀 GCM 的安全性。
/// The layout is an <c>OZCF</c> magic header (4 bytes), a format version (1 byte), the nonce
/// (12 bytes), the authentication tag (16 bytes) and the ciphertext. The header is also fed to
/// AES-GCM as associated data, so tampering with it fails decryption too. A fresh nonce is generated
/// for every encryption: reusing a nonce under the same key destroys GCM's security outright.
/// </remarks>
public static class ConfigurationProtector
{
    /// <summary>
    /// 目前的封裝格式版本。
    /// The current envelope format version.
    /// </summary>
    public const byte FormatVersion = 1;

    /// <summary>
    /// AES-GCM 的 nonce 長度(位元組)。
    /// The AES-GCM nonce length in bytes.
    /// </summary>
    private const int NonceLengthInBytes = 12;

    /// <summary>
    /// AES-GCM 的驗證標籤長度(位元組)。
    /// The AES-GCM authentication tag length in bytes.
    /// </summary>
    private const int TagLengthInBytes = 16;

    /// <summary>
    /// 標頭長度:魔術字 4 + 版本 1。
    /// Header length: 4 magic bytes plus a version byte.
    /// </summary>
    private const int HeaderLengthInBytes = 5;

    /// <summary>
    /// 封裝的最小長度(標頭 + nonce + 標籤),空內容加密後就是這個長度。
    /// The minimum envelope length (header plus nonce plus tag); encrypting empty content yields exactly this.
    /// </summary>
    private const int MinimumEnvelopeLength = HeaderLengthInBytes + NonceLengthInBytes + TagLengthInBytes;

    /// <summary>
    /// 用來辨識本套件輸出的魔術字。
    /// Magic bytes identifying payloads written by this library.
    /// </summary>
    private static readonly byte[] MagicHeader = "OZCF"u8.ToArray();

    /// <summary>
    /// 加密字串,回傳可直接寫進設定檔的 Base64 字串。
    /// Encrypts a string and returns Base64 text that can be written straight into a configuration file.
    /// </summary>
    /// <param name="plainText">
    /// 要加密的明文,允許空字串。
    /// The plain text to encrypt; an empty string is allowed.
    /// </param>
    /// <param name="key">
    /// 對稱金鑰,長度必須是 16、24 或 32 位元組。金鑰來源由呼叫端決定(例如以 DPAPI 保護後存放)。
    /// The symmetric key; it must be 16, 24 or 32 bytes. Where it comes from is the caller's decision
    /// (for example a key kept under DPAPI protection).
    /// </param>
    /// <returns>
    /// 加密後的 Base64 字串。
    /// The encrypted payload as Base64 text.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="plainText"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="plainText"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// 金鑰長度不合法時拋出。
    /// Thrown when the key length is invalid.
    /// </exception>
    public static string Encrypt(string plainText, ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(plainText);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        try
        {
            return Convert.ToBase64String(Encrypt(plainBytes, key));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    /// <summary>
    /// 加密位元組資料。
    /// Encrypts raw bytes.
    /// </summary>
    /// <param name="plainBytes">
    /// 要加密的位元組資料。
    /// The bytes to encrypt.
    /// </param>
    /// <param name="key">
    /// 對稱金鑰,長度必須是 16、24 或 32 位元組。
    /// The symmetric key; it must be 16, 24 or 32 bytes.
    /// </param>
    /// <returns>
    /// 加密後的封裝資料。
    /// The encrypted envelope.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// 金鑰長度不合法時拋出。
    /// Thrown when the key length is invalid.
    /// </exception>
    public static byte[] Encrypt(ReadOnlySpan<byte> plainBytes, ReadOnlySpan<byte> key)
    {
        ValidateKey(key);

        byte[] envelope = new byte[MinimumEnvelopeLength + plainBytes.Length];
        Span<byte> span = envelope;

        MagicHeader.CopyTo(span);
        span[MagicHeader.Length] = FormatVersion;

        Span<byte> header = span[..HeaderLengthInBytes];
        Span<byte> nonce = span.Slice(HeaderLengthInBytes, NonceLengthInBytes);
        Span<byte> tag = span.Slice(HeaderLengthInBytes + NonceLengthInBytes, TagLengthInBytes);
        Span<byte> cipherText = span[MinimumEnvelopeLength..];

        RandomNumberGenerator.Fill(nonce);

        using var aesGcm = new AesGcm(key, TagLengthInBytes);
        aesGcm.Encrypt(nonce, plainBytes, cipherText, tag, header);

        return envelope;
    }

    /// <summary>
    /// 解密以 <see cref="Encrypt(string, ReadOnlySpan{byte})"/> 產生的 Base64 字串。
    /// Decrypts Base64 text produced by <see cref="Encrypt(string, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="protectedValue">
    /// 加密後的 Base64 字串。
    /// The encrypted payload as Base64 text.
    /// </param>
    /// <param name="key">
    /// 加密時使用的同一把金鑰。
    /// The same key used to encrypt.
    /// </param>
    /// <returns>
    /// 解密後的明文。
    /// The decrypted plain text.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="protectedValue"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="protectedValue"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// 金鑰長度不合法時拋出。
    /// Thrown when the key length is invalid.
    /// </exception>
    /// <exception cref="SecretProtectionException">
    /// 內容不是本套件的封裝格式、版本不支援,或金鑰錯誤/資料遭竄改時拋出。
    /// Thrown when the payload is not this library's envelope, uses an unsupported version, or fails
    /// authentication because the key is wrong or the data was tampered with.
    /// </exception>
    public static string Decrypt(string protectedValue, ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);

        byte[] envelope = DecodeBase64(protectedValue);
        byte[] plainBytes = Decrypt(envelope, key);
        try
        {
            return Encoding.UTF8.GetString(plainBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    /// <summary>
    /// 解密以 <see cref="Encrypt(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> 產生的封裝資料。
    /// Decrypts an envelope produced by <see cref="Encrypt(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
    /// </summary>
    /// <param name="protectedBytes">
    /// 加密後的封裝資料。
    /// The encrypted envelope.
    /// </param>
    /// <param name="key">
    /// 加密時使用的同一把金鑰。
    /// The same key used to encrypt.
    /// </param>
    /// <returns>
    /// 解密後的位元組資料。
    /// The decrypted bytes.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// 金鑰長度不合法時拋出。
    /// Thrown when the key length is invalid.
    /// </exception>
    /// <exception cref="SecretProtectionException">
    /// 內容不是本套件的封裝格式、版本不支援,或金鑰錯誤/資料遭竄改時拋出。
    /// Thrown when the payload is not this library's envelope, uses an unsupported version, or fails
    /// authentication because the key is wrong or the data was tampered with.
    /// </exception>
    public static byte[] Decrypt(ReadOnlySpan<byte> protectedBytes, ReadOnlySpan<byte> key)
    {
        ValidateKey(key);
        ValidateEnvelope(protectedBytes);

        ReadOnlySpan<byte> header = protectedBytes[..HeaderLengthInBytes];
        ReadOnlySpan<byte> nonce = protectedBytes.Slice(HeaderLengthInBytes, NonceLengthInBytes);
        ReadOnlySpan<byte> tag = protectedBytes.Slice(HeaderLengthInBytes + NonceLengthInBytes, TagLengthInBytes);
        ReadOnlySpan<byte> cipherText = protectedBytes[MinimumEnvelopeLength..];

        byte[] plainBytes = new byte[cipherText.Length];
        try
        {
            using var aesGcm = new AesGcm(key, TagLengthInBytes);
            aesGcm.Decrypt(nonce, cipherText, tag, plainBytes, header);
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(plainBytes);
            throw new SecretProtectionException(
                SecretProtectionFailureReason.DecryptionFailed,
                "無法解密設定內容:金鑰錯誤,或資料在儲存後遭到竄改。 " +
                "The configuration content could not be decrypted: the key is wrong, or the data was tampered with after it was written.",
                ex);
        }

        return plainBytes;
    }

    /// <summary>
    /// 嘗試解密字串,失敗時回傳 <see langword="false"/> 而不拋例外。
    /// 設定檔被手動編輯、換過金鑰都是預期會發生的情況。
    /// Attempts to decrypt a string, returning <see langword="false"/> instead of throwing.
    /// Hand-edited configuration files and rotated keys are expected situations.
    /// </summary>
    /// <param name="protectedValue">
    /// 加密後的 Base64 字串。
    /// The encrypted payload as Base64 text.
    /// </param>
    /// <param name="key">
    /// 加密時使用的同一把金鑰。
    /// The same key used to encrypt.
    /// </param>
    /// <param name="plainText">
    /// 成功時回傳解密後的明文,失敗時為 <see langword="null"/>。
    /// Receives the decrypted plain text on success, or <see langword="null"/> on failure.
    /// </param>
    /// <returns>
    /// 解密成功回傳 <see langword="true"/>。
    /// <see langword="true"/> when the payload was decrypted.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="protectedValue"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="protectedValue"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// 金鑰長度不合法時拋出(金鑰長度是程式錯誤,不是資料問題,因此仍然拋出)。
    /// Thrown when the key length is invalid; a bad key length is a programming error rather than a
    /// data problem, so it still throws.
    /// </exception>
    public static bool TryDecrypt(string protectedValue, ReadOnlySpan<byte> key, out string? plainText)
    {
        ArgumentNullException.ThrowIfNull(protectedValue);
        ValidateKey(key);

        try
        {
            plainText = Decrypt(protectedValue, key);
            return true;
        }
        catch (SecretProtectionException)
        {
            plainText = null;
            return false;
        }
    }

    /// <summary>
    /// 判斷字串是否為本套件加密過的內容(只看標頭,不需要金鑰)。
    /// 適合用來判斷設定檔的欄位是還沒加密的明文,還是已經加密過。
    /// Checks whether a string is content encrypted by this library, by inspecting the header only and
    /// without needing the key. Useful for telling an already-encrypted configuration value apart from
    /// one that is still in plain text.
    /// </summary>
    /// <param name="value">
    /// 待檢查的字串,允許 <see langword="null"/>。
    /// The value to inspect; <see langword="null"/> is allowed.
    /// </param>
    /// <returns>
    /// 具備本套件標頭時回傳 <see langword="true"/>。
    /// <see langword="true"/> when the value carries this library's header.
    /// </returns>
    public static bool IsProtectedValue(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        byte[] envelope;
        try
        {
            envelope = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            return false;
        }

        return envelope.Length >= MinimumEnvelopeLength
            && envelope.AsSpan(0, MagicHeader.Length).SequenceEqual(MagicHeader);
    }

    /// <summary>
    /// 檢查金鑰長度是否為 AES 支援的 16、24 或 32 位元組。
    /// Validates that the key length is one of the AES sizes: 16, 24 or 32 bytes.
    /// </summary>
    /// <param name="key">
    /// 對稱金鑰。
    /// The symmetric key.
    /// </param>
    private static void ValidateKey(ReadOnlySpan<byte> key)
    {
        if (key.Length is not (16 or 24 or 32))
        {
            throw new ArgumentException(
                "金鑰長度必須是 16、24 或 32 位元組(AES-128 / AES-192 / AES-256),目前為 " +
                key.Length.ToString(CultureInfo.InvariantCulture) + " 位元組。 " +
                "The key must be 16, 24 or 32 bytes (AES-128 / AES-192 / AES-256) but is " +
                key.Length.ToString(CultureInfo.InvariantCulture) + " bytes.",
                nameof(key));
        }
    }

    /// <summary>
    /// 檢查封裝標頭,並在不符時以對應的失敗原因拋出例外。
    /// Validates the envelope header and throws with the matching failure reason when it does not fit.
    /// </summary>
    /// <param name="envelope">
    /// 完整的封裝資料。
    /// The full envelope.
    /// </param>
    private static void ValidateEnvelope(ReadOnlySpan<byte> envelope)
    {
        if (envelope.Length < MinimumEnvelopeLength
            || !envelope[..MagicHeader.Length].SequenceEqual(MagicHeader))
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.MalformedPayload,
                "內容缺少本套件的格式標頭,可能已損毀、被截斷,或根本沒有加密過。 " +
                "The content is missing this library's format header; it may be corrupted, truncated, or never encrypted at all.");
        }

        byte version = envelope[MagicHeader.Length];
        if (version != FormatVersion)
        {
            string actualVersion = version.ToString(CultureInfo.InvariantCulture);
            string expectedVersion = FormatVersion.ToString(CultureInfo.InvariantCulture);
            throw new SecretProtectionException(
                SecretProtectionFailureReason.UnsupportedFormatVersion,
                "內容的格式版本為 " + actualVersion + ",本程式庫只支援版本 " + expectedVersion + ",資料可能由較新版本產生。 " +
                "The content uses envelope version " + actualVersion + " but this library only supports version " +
                expectedVersion + "; it may have been written by a newer version.");
        }
    }

    /// <summary>
    /// 以 Base64 解碼封裝資料,格式錯誤時轉為可判讀的失敗原因。
    /// Decodes a Base64 envelope, converting format errors into a classified failure.
    /// </summary>
    /// <param name="protectedValue">
    /// 加密後的 Base64 字串。
    /// The encrypted payload as Base64 text.
    /// </param>
    /// <returns>
    /// 解碼後的封裝資料。
    /// The decoded envelope.
    /// </returns>
    private static byte[] DecodeBase64(string protectedValue)
    {
        try
        {
            return Convert.FromBase64String(protectedValue);
        }
        catch (FormatException ex)
        {
            throw new SecretProtectionException(
                SecretProtectionFailureReason.MalformedPayload,
                "內容不是有效的 Base64,設定檔可能已損毀或被手動編輯。 " +
                "The content is not valid Base64; the configuration file may be corrupted or hand-edited.",
                ex);
        }
    }
}
