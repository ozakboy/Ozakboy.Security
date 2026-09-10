using System.Text;
using Ozakboy.Security;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// 驗證 <see cref="ISecretProtector"/> 真的可以被替換:上層程式只依賴介面,測試就能注入假物件,
/// 非 Windows 環境也能換成別的保護機制。
/// Proves <see cref="ISecretProtector"/> is genuinely substitutable: upper layers depend on the
/// interface only, so tests can inject a fake and non-Windows hosts can swap in another mechanism.
/// </summary>
[TestClass]
public sealed class SubstitutableProtectorTests
{
    /// <summary>
    /// 假的保護器:只做 Base64 編碼,沒有任何加密效果,僅供測試替換能力使用。
    /// A fake protector that only Base64-encodes and provides no protection at all; test use only.
    /// </summary>
    private sealed class FakeSecretProtector : ISecretProtector
    {
        public bool IsSupported => true;

        public string Protect(string plainText) => Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText));

        public string Unprotect(string protectedValue)
        {
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(protectedValue));
            }
            catch (FormatException ex)
            {
                throw new SecretProtectionException(SecretProtectionFailureReason.MalformedPayload, "假的保護器解不開這份資料。", ex);
            }
        }

        public bool TryUnprotect(string protectedValue, out string? plainText)
        {
            try
            {
                plainText = Unprotect(protectedValue);
                return true;
            }
            catch (SecretProtectionException)
            {
                plainText = null;
                return false;
            }
        }

        public byte[] Protect(byte[] plainBytes) => [.. plainBytes];

        public byte[] Unprotect(byte[] protectedBytes) => [.. protectedBytes];

        public bool TryUnprotect(byte[] protectedBytes, out byte[]? plainBytes)
        {
            plainBytes = [.. protectedBytes];
            return true;
        }
    }

    /// <summary>
    /// 模擬上層元件:只認得介面,不知道背後是不是 DPAPI。
    /// Stands in for an upper-layer component that knows the interface and nothing else.
    /// </summary>
    private static string LoadCredential(ISecretProtector protector, string storedValue)
        => protector.TryUnprotect(storedValue, out string? plainText) ? plainText! : "(無法還原)";

    [TestMethod]
    public void UpperLayer_WorksAgainstTheInterface_WithoutKnowingTheImplementation()
    {
        ISecretProtector protector = new FakeSecretProtector();

        string stored = protector.Protect("api-key-value");

        Assert.AreEqual("api-key-value", LoadCredential(protector, stored));
        Assert.AreEqual("(無法還原)", LoadCredential(protector, "not-base64!!"));
    }

    [TestMethod]
    public void FakeProtector_ByteMembers_AreReachableThroughTheInterface()
    {
        ISecretProtector protector = new FakeSecretProtector();
        byte[] payload = [1, 2, 3];

        CollectionAssert.AreEqual(payload, protector.Unprotect(protector.Protect(payload)));
        Assert.IsTrue(protector.TryUnprotect(payload, out byte[]? restored));
        CollectionAssert.AreEqual(payload, restored);
        Assert.IsTrue(protector.IsSupported);
        Assert.ThrowsExactly<SecretProtectionException>(() => protector.Unprotect("not-base64!!"));
    }
}
