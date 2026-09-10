using System.Security.Cryptography;
using System.Text;
using Ozakboy.Security;
using Ozakboy.Security.Configuration;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="ConfigurationProtector"/> 的測試:往返正確、每次 nonce 不同、錯誤金鑰與竄改必須失敗。
/// Tests for <see cref="ConfigurationProtector"/>: round-trips work, every encryption uses a fresh
/// nonce, and both wrong keys and tampered payloads must fail loudly.
/// </summary>
[TestClass]
public sealed class ConfigurationProtectorTests
{
    /// <summary>封裝標頭長度(魔術字 4 + 版本 1)。</summary>
    private const int HeaderLength = 5;

    /// <summary>nonce 長度。</summary>
    private const int NonceLength = 12;

    /// <summary>驗證標籤長度。</summary>
    private const int TagLength = 16;

    private static byte[] CreateTestKey(byte seed = 1) => Enumerable.Range(0, 32).Select(i => (byte)(i + seed)).ToArray();

    [TestMethod]
    public void EncryptDecrypt_Text_RoundTrips()
    {
        byte[] key = CreateTestKey();
        const string plainText = """{"apiKey":"secret-value","endpoint":"https://example.com"}""";

        string encrypted = ConfigurationProtector.Encrypt(plainText, key);

        Assert.AreNotEqual(plainText, encrypted);
        Assert.AreEqual(plainText, ConfigurationProtector.Decrypt(encrypted, key));
    }

    [TestMethod]
    public void EncryptDecrypt_NonAsciiText_RoundTrips()
    {
        byte[] key = CreateTestKey();
        const string plainText = "繁體中文設定內容 with mixed ASCII";

        string encrypted = ConfigurationProtector.Encrypt(plainText, key);

        Assert.AreEqual(plainText, ConfigurationProtector.Decrypt(encrypted, key));
    }

    [TestMethod]
    public void EncryptDecrypt_EmptyText_RoundTrips()
    {
        byte[] key = CreateTestKey();

        string encrypted = ConfigurationProtector.Encrypt(string.Empty, key);

        Assert.AreEqual(string.Empty, ConfigurationProtector.Decrypt(encrypted, key));
    }

    [TestMethod]
    public void EncryptDecrypt_LargeContent_RoundTrips()
    {
        byte[] key = CreateTestKey();
        string plainText = new('a', 200_000);

        string encrypted = ConfigurationProtector.Encrypt(plainText, key);

        Assert.AreEqual(plainText, ConfigurationProtector.Decrypt(encrypted, key));
    }

    [TestMethod]
    public void EncryptDecrypt_Bytes_RoundTrips()
    {
        byte[] key = CreateTestKey();
        byte[] plainBytes = [0x00, 0x01, 0x7F, 0x80, 0xFF];

        byte[] encrypted = ConfigurationProtector.Encrypt(plainBytes, key);
        byte[] decrypted = ConfigurationProtector.Decrypt(encrypted, key);

        CollectionAssert.AreEqual(plainBytes, decrypted);
    }

    [TestMethod]
    public void EncryptDecrypt_AllSupportedKeySizes_RoundTrip()
    {
        foreach (int keyLength in new[] { 16, 24, 32 })
        {
            byte[] key = KeyDerivation.CreateKey(keyLength);

            string encrypted = ConfigurationProtector.Encrypt("payload", key);

            Assert.AreEqual("payload", ConfigurationProtector.Decrypt(encrypted, key), $"金鑰長度 {keyLength} 應可往返。");
        }
    }

    [TestMethod]
    public void Encrypt_CalledRepeatedly_UsesAFreshNonceEveryTime()
    {
        // 只比對兩次不足以看出 nonce 是不是真的每次都重抽;GCM 一旦重複使用 nonce,同一把金鑰就等於破了。
        const int rounds = 256;
        byte[] key = CreateTestKey();
        var nonces = new HashSet<string>(StringComparer.Ordinal);
        var cipherTexts = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < rounds; i++)
        {
            string encrypted = ConfigurationProtector.Encrypt("same content", key);
            byte[] envelope = Convert.FromBase64String(encrypted);

            nonces.Add(Convert.ToBase64String(envelope.AsSpan(HeaderLength, NonceLength)));
            cipherTexts.Add(encrypted);

            Assert.AreEqual("same content", ConfigurationProtector.Decrypt(encrypted, key));
        }

        Assert.HasCount(rounds, nonces, "每次加密都必須抽出不同的 nonce。");
        Assert.HasCount(rounds, cipherTexts, "nonce 不同,密文就不該重複。");
    }

    [TestMethod]
    public void Encrypt_Output_CarriesMagicHeaderAndVersionMarker()
    {
        byte[] key = CreateTestKey();

        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload", key));

        Assert.AreEqual("OZCF", Encoding.ASCII.GetString(envelope, 0, 4));
        Assert.AreEqual(ConfigurationProtector.FormatVersion, envelope[4]);
    }

    [TestMethod]
    public void Decrypt_WrongKey_ThrowsWithDecryptionFailedReason()
    {
        string encrypted = ConfigurationProtector.Encrypt("payload", CreateTestKey(1));

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(encrypted, CreateTestKey(2)));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_TamperedCipherText_ThrowsWithDecryptionFailedReason()
    {
        byte[] key = CreateTestKey();
        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload", key));
        envelope[^1] ^= 0xFF;

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(envelope), key));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_TamperedMagicHeader_ThrowsWithMalformedPayloadReason()
    {
        byte[] key = CreateTestKey();
        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload", key));

        // 改動魔術字會在格式檢查階段就被擋下,AES-GCM 根本沒被呼叫到。
        // 「標頭同時是關聯資料」這件事由 Decrypt_PayloadEncryptedWithDifferentAssociatedData_FailsAuthentication 驗證。
        envelope[0] = (byte)'X';

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(envelope), key));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_UnknownFormatVersion_ThrowsWithUnsupportedVersionReason()
    {
        byte[] key = CreateTestKey();
        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload", key));
        envelope[4] = 0x7F;

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(envelope), key));

        Assert.AreEqual(SecretProtectionFailureReason.UnsupportedFormatVersion, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_NotBase64_ThrowsWithMalformedPayloadReason()
    {
        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt("這不是 Base64", CreateTestKey()));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_TooShortPayload_ThrowsWithMalformedPayloadReason()
    {
        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(new byte[] { 1, 2, 3 }), CreateTestKey()));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void Encrypt_InvalidKeyLength_ThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(() => ConfigurationProtector.Encrypt("payload", new byte[15]));
        Assert.ThrowsExactly<ArgumentException>(() => ConfigurationProtector.Encrypt("payload", []));
    }

    [TestMethod]
    public void Encrypt_NullText_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => ConfigurationProtector.Encrypt((string)null!, CreateTestKey()));
    }

    [TestMethod]
    public void Decrypt_NullText_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => ConfigurationProtector.Decrypt((string)null!, CreateTestKey()));
    }

    [TestMethod]
    public void TryDecrypt_CorrectKey_ReturnsTrueAndPlainText()
    {
        byte[] key = CreateTestKey();
        string encrypted = ConfigurationProtector.Encrypt("payload", key);

        bool decrypted = ConfigurationProtector.TryDecrypt(encrypted, key, out string? plainText);

        Assert.IsTrue(decrypted);
        Assert.AreEqual("payload", plainText);
    }

    [TestMethod]
    public void TryDecrypt_WrongKey_ReturnsFalseWithoutThrowing()
    {
        string encrypted = ConfigurationProtector.Encrypt("payload", CreateTestKey(1));

        bool decrypted = ConfigurationProtector.TryDecrypt(encrypted, CreateTestKey(2), out string? plainText);

        Assert.IsFalse(decrypted);
        Assert.IsNull(plainText);
    }

    [TestMethod]
    public void TryDecrypt_PlainTextValue_ReturnsFalse()
    {
        bool decrypted = ConfigurationProtector.TryDecrypt("still-plain-text", CreateTestKey(), out string? plainText);

        Assert.IsFalse(decrypted);
        Assert.IsNull(plainText);
    }

    [TestMethod]
    public void Decrypt_PayloadEncryptedWithDifferentAssociatedData_FailsAuthentication()
    {
        // 標頭同時是 AES-GCM 的關聯資料 —— 這句宣稱要真的驗到,必須繞過格式檢查:
        // 底下這份封裝的標頭是合法的 OZCF v1(過得了格式檢查),但加密當下餵進去的關聯資料是別的內容,
        // 所以失敗一定來自 GCM 的驗證,而不是格式檢查。
        byte[] key = CreateTestKey();
        byte[] plainBytes = Encoding.UTF8.GetBytes("payload");
        byte[] realHeader = [.. "OZCF"u8, ConfigurationProtector.FormatVersion];
        byte[] otherAssociatedData = [.. "OZCF"u8, 0x02];

        byte[] wrongAad = BuildEnvelope(key, plainBytes, realHeader, otherAssociatedData);
        byte[] correctAad = BuildEnvelope(key, plainBytes, realHeader, realHeader);

        // 對照組:除了關聯資料以外完全相同的封裝,解得開。
        Assert.AreEqual("payload", ConfigurationProtector.Decrypt(Convert.ToBase64String(correctAad), key));

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(wrongAad), key));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_TamperedNonce_ThrowsWithDecryptionFailedReason()
    {
        byte[] key = CreateTestKey();
        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload", key));
        envelope[HeaderLength] ^= 0xFF;

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(envelope), key));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_TamperedAuthenticationTag_ThrowsWithDecryptionFailedReason()
    {
        byte[] key = CreateTestKey();
        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload", key));
        envelope[HeaderLength + NonceLength] ^= 0xFF;

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(envelope), key));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void Decrypt_TruncatedCipherText_ThrowsWithDecryptionFailedReason()
    {
        // 截掉尾巴的密文長度仍然合法(標頭齊全),所以格式檢查放行,擋下它的是 GCM 的驗證標籤。
        byte[] key = CreateTestKey();
        byte[] envelope = Convert.FromBase64String(ConfigurationProtector.Encrypt("payload-long-enough-to-truncate", key));
        byte[] truncated = envelope[..^8];

        Assert.IsTrue(truncated.Length > HeaderLength + NonceLength + TagLength, "截斷後仍須是格式上合法的封裝。");

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => ConfigurationProtector.Decrypt(Convert.ToBase64String(truncated), key));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void IsSupported_ReportsWhetherAesGcmIsAvailable()
    {
        Assert.AreEqual(System.Security.Cryptography.AesGcm.IsSupported, ConfigurationProtector.IsSupported);
    }

    [TestMethod]
    public void IsProtectedValue_RecognisesOwnOutputOnly()
    {
        string encrypted = ConfigurationProtector.Encrypt("payload", CreateTestKey());

        Assert.IsTrue(ConfigurationProtector.IsProtectedValue(encrypted));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue("plain text"));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue(Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6 })));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue(string.Empty));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue(null));
    }

    /// <summary>
    /// 手工組出一份 OZCF 封裝,讓測試可以指定加密當下使用的關聯資料。
    /// </summary>
    /// <param name="key">對稱金鑰。</param>
    /// <param name="plainBytes">明文。</param>
    /// <param name="header">寫進封裝的標頭(決定格式檢查看到什麼)。</param>
    /// <param name="associatedData">實際餵給 AES-GCM 的關聯資料。</param>
    /// <returns>完整封裝。</returns>
    private static byte[] BuildEnvelope(
        byte[] key,
        byte[] plainBytes,
        byte[] header,
        byte[] associatedData)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        byte[] tag = new byte[TagLength];
        byte[] cipherText = new byte[plainBytes.Length];

        using (var aesGcm = new AesGcm(key, TagLength))
        {
            aesGcm.Encrypt(nonce, plainBytes, cipherText, tag, associatedData);
        }

        return [.. header, .. nonce, .. tag, .. cipherText];
    }
}
