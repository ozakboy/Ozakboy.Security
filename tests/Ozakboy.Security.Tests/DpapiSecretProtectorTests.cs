using System.Text;
using Ozakboy.Security;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="DpapiSecretProtector"/> 的測試。
/// DPAPI 是 Windows 專屬機制,需要實際加解密的測試標記為 <c>Windows</c> 分類,
/// 並在非 Windows 環境以 <see cref="Assert.Inconclusive(string?)"/> 略過,避免 CI(ubuntu-latest)誤判為失敗。
/// Tests for <see cref="DpapiSecretProtector"/>. DPAPI is Windows-only, so tests that really encrypt
/// are tagged with the <c>Windows</c> category and bail out as inconclusive elsewhere, so the CI run
/// on ubuntu-latest does not report them as failures.
/// </summary>
[TestClass]
public sealed class DpapiSecretProtectorTests
{
    /// <summary>
    /// 非 Windows 環境直接把測試標為未定,不算失敗。
    /// Marks the test inconclusive rather than failed when the platform is not Windows.
    /// </summary>
    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("DPAPI 只在 Windows 可用,本測試在其他平台略過。");
        }
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void ProtectUnprotect_Text_RoundTrips()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();
        const string secret = "binance-api-key-abcdefghijklmnop";

        string protectedValue = protector.Protect(secret);

        Assert.AreNotEqual(secret, protectedValue);
        Assert.AreEqual(secret, protector.Unprotect(protectedValue));
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void ProtectUnprotect_EmptyAndNonAsciiText_RoundTrip()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();

        Assert.AreEqual(string.Empty, protector.Unprotect(protector.Protect(string.Empty)));
        Assert.AreEqual("繁體中文密鑰", protector.Unprotect(protector.Protect("繁體中文密鑰")));
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void ProtectUnprotect_Bytes_RoundTrips()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();
        byte[] secret = [0x00, 0x10, 0x7F, 0x80, 0xFF];

        byte[] protectedBytes = protector.Protect(secret);

        CollectionAssert.AreEqual(secret, protector.Unprotect(protectedBytes));
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void Protect_Output_CarriesMagicHeaderVersionAndScope()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();

        byte[] envelope = Convert.FromBase64String(protector.Protect("value"));

        Assert.AreEqual("OZDP", Encoding.ASCII.GetString(envelope, 0, 4));
        Assert.AreEqual(1, envelope[4]);
        Assert.AreEqual((byte)SecretProtectionScope.CurrentUser, envelope[5]);
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void Protect_CalledTwice_ProducesDifferentPayloads()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();

        Assert.AreNotEqual(protector.Protect("value"), protector.Protect("value"));
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void ProtectUnprotect_WithEntropy_RoundTrips()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector(new DpapiProtectionOptions().WithEntropyText("PulseTrade/v1"));

        string protectedValue = protector.Protect("secret");

        Assert.AreEqual("secret", protector.Unprotect(protectedValue));
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void Unprotect_WithDifferentEntropy_Fails()
    {
        RequireWindows();
        var writer = new DpapiSecretProtector(new DpapiProtectionOptions().WithEntropyText("entropy-a"));
        var reader = new DpapiSecretProtector(new DpapiProtectionOptions().WithEntropyText("entropy-b"));

        string protectedValue = writer.Protect("secret");

        Assert.IsFalse(reader.TryUnprotect(protectedValue, out string? plainText));
        Assert.IsNull(plainText);
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void Unprotect_TamperedPayload_ReportsDecryptionFailed()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();
        byte[] envelope = Convert.FromBase64String(protector.Protect("secret"));
        envelope[^1] ^= 0xFF;

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => protector.Unprotect(Convert.ToBase64String(envelope)));

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void Unprotect_PayloadFromAnotherScope_ReportsScopeMismatch()
    {
        RequireWindows();
        var machineProtector = new DpapiSecretProtector(new DpapiProtectionOptions
        {
            Scope = SecretProtectionScope.LocalMachine,
        });
        var userProtector = new DpapiSecretProtector();

        string protectedValue = machineProtector.Protect("secret");

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => userProtector.Unprotect(protectedValue));

        Assert.AreEqual(SecretProtectionFailureReason.ScopeMismatch, exception.Reason);
        StringAssert.Contains(exception.Message, "LocalMachine");
        StringAssert.Contains(exception.Message, "CurrentUser");
    }

    [TestMethod]
    [TestCategory("Windows")]
    public void IsProtectedValue_RecognisesOwnOutput()
    {
        RequireWindows();
        var protector = new DpapiSecretProtector();

        Assert.IsTrue(DpapiSecretProtector.IsProtectedValue(protector.Protect("secret")));
    }

    [TestMethod]
    public void IsSupported_MatchesTheRunningPlatform()
    {
        Assert.AreEqual(OperatingSystem.IsWindows(), new DpapiSecretProtector().IsSupported);
    }

    [TestMethod]
    public void Protect_OnNonWindows_ThrowsPlatformNotSupportedWithGuidance()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("本測試只在非 Windows 平台有意義。");
        }

        var protector = new DpapiSecretProtector();

        var exception = Assert.ThrowsExactly<PlatformNotSupportedException>(() => protector.Protect("secret"));

        StringAssert.Contains(exception.Message, "ISecretProtector");
    }

    [TestMethod]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new DpapiSecretProtector(null!));
    }

    [TestMethod]
    public void Constructor_UndefinedScope_ThrowsArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new DpapiSecretProtector(new DpapiProtectionOptions { Scope = (SecretProtectionScope)99 }));
    }

    [TestMethod]
    public void Scope_ReflectsTheConfiguredValue()
    {
        var protector = new DpapiSecretProtector(new DpapiProtectionOptions
        {
            Scope = SecretProtectionScope.LocalMachine,
        });

        Assert.AreEqual(SecretProtectionScope.LocalMachine, protector.Scope);
    }

    [TestMethod]
    public void Unprotect_NotBase64_ReportsMalformedPayload()
    {
        var protector = new DpapiSecretProtector();

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect("這不是 Base64"));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void Unprotect_PayloadWithoutHeader_ReportsMalformedPayload()
    {
        var protector = new DpapiSecretProtector();

        var exception = Assert.ThrowsExactly<SecretProtectionException>(
            () => protector.Unprotect(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void Unprotect_PayloadWithUnknownVersion_ReportsUnsupportedFormatVersion()
    {
        var protector = new DpapiSecretProtector();
        byte[] envelope = [.."OZDP"u8.ToArray(), 0x7F, (byte)SecretProtectionScope.CurrentUser, 0x01];

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect(envelope));

        Assert.AreEqual(SecretProtectionFailureReason.UnsupportedFormatVersion, exception.Reason);
    }

    [TestMethod]
    public void Unprotect_PayloadWithUndefinedScope_ReportsMalformedPayload()
    {
        var protector = new DpapiSecretProtector();
        byte[] envelope = [.."OZDP"u8.ToArray(), 0x01, 0x63, 0x01];

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect(envelope));

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
    }

    [TestMethod]
    public void TryUnprotect_MalformedPayloads_ReturnFalseWithoutThrowing()
    {
        var protector = new DpapiSecretProtector();

        Assert.IsFalse(protector.TryUnprotect("not-base64!!", out string? plainText));
        Assert.IsNull(plainText);
        Assert.IsFalse(protector.TryUnprotect(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, out byte[]? plainBytes));
        Assert.IsNull(plainBytes);
    }

    [TestMethod]
    public void IsProtectedValue_RejectsPlainTextAndEmptyValues()
    {
        Assert.IsFalse(DpapiSecretProtector.IsProtectedValue("plain text"));
        Assert.IsFalse(DpapiSecretProtector.IsProtectedValue(Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7 })));
        Assert.IsFalse(DpapiSecretProtector.IsProtectedValue(string.Empty));
        Assert.IsFalse(DpapiSecretProtector.IsProtectedValue(null));
    }

    [TestMethod]
    public void ProtectAndUnprotect_NullArguments_ThrowArgumentNullException()
    {
        var protector = new DpapiSecretProtector();

        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Protect((string)null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Protect((byte[])null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Unprotect((string)null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.Unprotect((byte[])null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.TryUnprotect((string)null!, out _));
        Assert.ThrowsExactly<ArgumentNullException>(() => protector.TryUnprotect((byte[])null!, out _));
    }

    [TestMethod]
    public void WithEntropyText_NullText_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new DpapiProtectionOptions().WithEntropyText(null!));
    }

    [TestMethod]
    public void WithEntropyText_ProducesNewOptionsWithoutMutatingTheOriginal()
    {
        var original = new DpapiProtectionOptions();

        DpapiProtectionOptions updated = original.WithEntropyText("entropy");

        Assert.IsTrue(original.Entropy.IsEmpty);
        Assert.AreEqual(Encoding.UTF8.GetByteCount("entropy"), updated.Entropy.Length);
        Assert.AreEqual(SecretProtectionScope.CurrentUser, updated.Scope);
    }
}
