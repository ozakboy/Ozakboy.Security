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
    public void Encrypt_CalledTwice_ProducesDifferentCipherTextBecauseNonceIsFresh()
    {
        byte[] key = CreateTestKey();

        string first = ConfigurationProtector.Encrypt("same content", key);
        string second = ConfigurationProtector.Encrypt("same content", key);

        Assert.AreNotEqual(first, second, "每次加密都必須使用新的 nonce,密文不得重複。");
        Assert.AreEqual("same content", ConfigurationProtector.Decrypt(first, key));
        Assert.AreEqual("same content", ConfigurationProtector.Decrypt(second, key));
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

        // 標頭同時是 AES-GCM 的關聯資料,改動魔術字會被格式檢查擋下。
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
    public void IsProtectedValue_RecognisesOwnOutputOnly()
    {
        string encrypted = ConfigurationProtector.Encrypt("payload", CreateTestKey());

        Assert.IsTrue(ConfigurationProtector.IsProtectedValue(encrypted));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue("plain text"));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue(Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6 })));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue(string.Empty));
        Assert.IsFalse(ConfigurationProtector.IsProtectedValue(null));
    }
}
