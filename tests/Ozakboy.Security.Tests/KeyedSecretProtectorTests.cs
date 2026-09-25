using System.Security.Cryptography;
using System.Text;
using Ozakboy.Security;
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="KeyedSecretProtector"/> 的測試:跨平台往返、與 <see cref="ConfigurationProtector"/> 互通、
/// 金鑰用完清零、金鑰來源出錯時的分類。全部離線,不需要 Windows。
/// Tests for <see cref="KeyedSecretProtector"/>: cross-platform round-trips, interoperability with
/// <see cref="ConfigurationProtector"/>, key zeroing after use, and classification of key-source
/// failures. Fully offline and platform-independent.
/// </summary>
[TestClass]
public sealed class KeyedSecretProtectorTests
{
    /// <summary>
    /// 記錄每次交出去的金鑰陣列,讓測試能事後檢查它們是否被清零。
    /// Records every key array it hands out so tests can check afterwards that each was zeroed.
    /// </summary>
    private sealed class RecordingKeySource : ISecretKeySource
    {
        private readonly byte[] _key;

        public RecordingKeySource(byte[] key) => _key = key;

        public List<byte[]> HandedOut { get; } = [];

        public int ReadCount => HandedOut.Count;

        public string Description => "測試用金鑰來源";

        public byte[] ReadKey()
        {
            byte[] copy = [.. _key];
            HandedOut.Add(copy);
            return copy;
        }
    }

    /// <summary>
    /// 回傳長度錯誤金鑰的來源,模擬沒做驗證的第三方實作。
    /// A source that returns a wrong-length key, standing in for a third-party implementation that skipped validation.
    /// </summary>
    private sealed class WrongLengthKeySource : ISecretKeySource
    {
        public string Description => "壞掉的來源";

        public byte[] ReadKey() => new byte[16];
    }

    private sealed class ThrowingKeySource : ISecretKeySource
    {
        public string Description => "取不到";

        public byte[] ReadKey() => throw new SecretProtectionException(SecretProtectionFailureReason.KeyUnavailable, "沒有金鑰");
    }

    private static byte[] CreateTestKey(byte seed = 1) => Enumerable.Range(0, 32).Select(i => (byte)(i + seed)).ToArray();

    private static KeyedSecretProtector CreateProtector(byte seed = 1) => new(new RecordingKeySource(CreateTestKey(seed)));

    [TestMethod]
    public void ProtectUnprotect_Text_RoundTrips()
    {
        var protector = CreateProtector();
        const string secret = "line-channel-access-token-abcdefghijklmnop";

        string protectedValue = protector.Protect(secret);

        Assert.AreNotEqual(secret, protectedValue);
        Assert.AreEqual(secret, protector.Unprotect(protectedValue));
    }

    [TestMethod]
    public void ProtectUnprotect_EmptyAndNonAsciiText_RoundTrip()
    {
        var protector = CreateProtector();

        Assert.AreEqual(string.Empty, protector.Unprotect(protector.Protect(string.Empty)));
        Assert.AreEqual("繁體中文密鑰", protector.Unprotect(protector.Protect("繁體中文密鑰")));
    }

    [TestMethod]
    public void ProtectUnprotect_Bytes_RoundTrips()
    {
        var protector = CreateProtector();
        byte[] secret = [0x00, 0x10, 0x7F, 0x80, 0xFF];

        byte[] protectedBytes = protector.Protect(secret);

        CollectionAssert.AreEqual(secret, protector.Unprotect(protectedBytes));
    }

    [TestMethod]
    public void Protect_Output_IsTheOzcfEnvelope()
    {
        var protector = CreateProtector();

        string protectedValue = protector.Protect("value");
        byte[] envelope = Convert.FromBase64String(protectedValue);

        Assert.AreEqual("OZCF", Encoding.ASCII.GetString(envelope, 0, 4));
        Assert.AreEqual(ConfigurationProtector.FormatVersion, envelope[4]);
        Assert.IsTrue(KeyedSecretProtector.IsProtectedValue(protectedValue));
        Assert.IsTrue(ConfigurationProtector.IsProtectedValue(protectedValue));
    }

    [TestMethod]
    public void Protect_CalledTwice_ProducesDifferentPayloads()
    {
        var protector = CreateProtector();

        Assert.AreNotEqual(protector.Protect("value"), protector.Protect("value"));
    }

    [TestMethod]
    public void Protect_InteroperatesWithConfigurationProtector_UnderTheSameKey()
    {
        byte[] key = CreateTestKey();
        var protector = new KeyedSecretProtector(new RecordingKeySource(key));

        string encryptedByStaticTool = ConfigurationProtector.Encrypt("from-cli", key);
        string encryptedByProtector = protector.Protect("from-app");

        Assert.AreEqual("from-cli", protector.Unprotect(encryptedByStaticTool));
        Assert.AreEqual("from-app", ConfigurationProtector.Decrypt(encryptedByProtector, key));
    }

    [TestMethod]
    public void Unprotect_WithDifferentKey_ReportsDecryptionFailed()
    {
        var writer = CreateProtector(seed: 1);
        var reader = CreateProtector(seed: 2);

        string protectedValue = writer.Protect("secret");

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => reader.Unprotect(protectedValue));
        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
        Assert.IsFalse(reader.TryUnprotect(protectedValue, out string? plainText));
        Assert.IsNull(plainText);
    }

    [TestMethod]
    public void Unprotect_TamperedPayload_ReportsDecryptionFailed()
    {
        var protector = CreateProtector();
        byte[] envelope = Convert.FromBase64String(protector.Protect("secret"));
        envelope[^1] ^= 0xFF;

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect(envelope));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    public void Unprotect_NotBase64OrMissingHeader_ReportsMalformedPayload()
    {
        var protector = CreateProtector();

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload,
            Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect("這不是 Base64")).Reason);
        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload,
            Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })).Reason);
    }

    [TestMethod]
    public void Unprotect_DpapiEnvelope_ReportsMalformedPayload()
    {
        var protector = CreateProtector();
        byte[] dpapiLike = [.."OZDP"u8.ToArray(), 0x01, 0x00, 0x01, 0x02, 0x03];

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect(dpapiLike));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void EveryOperation_ReadsAFreshKeyAndZeroesItAfterwards()
    {
        var source = new RecordingKeySource(CreateTestKey());
        var protector = new KeyedSecretProtector(source);

        string protectedValue = protector.Protect("secret");
        Assert.AreEqual("secret", protector.Unprotect(protectedValue));
        Assert.IsTrue(protector.TryUnprotect(protectedValue, out _));

        Assert.AreEqual(3, source.ReadCount, "每次操作都應該向來源要一份新的金鑰。");
        foreach (byte[] handedOut in source.HandedOut)
        {
            Assert.IsTrue(handedOut.All(b => b == 0), "交出去的金鑰用完必須清零。");
        }
    }

    [TestMethod]
    public void KeyIsZeroedEvenWhenDecryptionFails()
    {
        var source = new RecordingKeySource(CreateTestKey());
        var protector = new KeyedSecretProtector(source);

        Assert.IsFalse(protector.TryUnprotect("not-base64!!", out _));

        Assert.AreEqual(1, source.ReadCount);
        Assert.IsTrue(source.HandedOut[0].All(b => b == 0));
    }

    [TestMethod]
    public void WrongLengthKeyFromSource_ReportsKeyUnavailable_WithoutTouchingAesGcm()
    {
        var protector = new KeyedSecretProtector(new WrongLengthKeySource());

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Protect("secret"));

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "壞掉的來源");
    }

    [TestMethod]
    public void KeyUnavailable_Protect_Throws_ButTryUnprotect_ReturnsFalse()
    {
        var protector = new KeyedSecretProtector(new ThrowingKeySource());

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Protect("secret"));
        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);

        string ciphertext = ConfigurationProtector.Encrypt("secret", CreateTestKey());
        Assert.IsFalse(protector.TryUnprotect(ciphertext, out string? plainText));
        Assert.IsNull(plainText);
        Assert.IsFalse(protector.TryUnprotect(Convert.FromBase64String(ciphertext), out byte[]? plainBytes));
        Assert.IsNull(plainBytes);
    }

    [TestMethod]
    public void IsSupported_MatchesAesGcm()
    {
        Assert.AreEqual(AesGcm.IsSupported, CreateProtector().IsSupported);
        Assert.AreEqual(ConfigurationProtector.IsSupported, CreateProtector().IsSupported);
    }

    [TestMethod]
    public void KeySource_IsExposed()
    {
        var source = new RecordingKeySource(CreateTestKey());

        Assert.AreSame(source, new KeyedSecretProtector(source).KeySource);
    }

    [TestMethod]
    public void IsProtectedValue_RejectsPlainTextAndDpapiOutput()
    {
        Assert.IsFalse(KeyedSecretProtector.IsProtectedValue("plain text"));
        Assert.IsFalse(KeyedSecretProtector.IsProtectedValue(null));
        Assert.IsFalse(KeyedSecretProtector.IsProtectedValue(string.Empty));
        Assert.IsFalse(KeyedSecretProtector.IsProtectedValue(Convert.ToBase64String([.."OZDP"u8.ToArray(), 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28])));
    }

    [TestMethod]
    public void Constructor_NullKeySource_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new KeyedSecretProtector(null!));
    }

    [TestMethod]
    public void ProtectAndUnprotect_NullArguments_ThrowArgumentNullException()
    {
        var protector = CreateProtector();

        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Protect((string)null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Protect((byte[])null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Unprotect((string)null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Unprotect((byte[])null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.TryUnprotect((string)null!, out _));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.TryUnprotect((byte[])null!, out _));
    }
}
