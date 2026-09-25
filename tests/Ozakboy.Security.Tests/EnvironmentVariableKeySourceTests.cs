using Ozakboy.Security;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="EnvironmentVariableKeySource"/> 的測試。每個測試用自己的變數名稱,測試方法層級平行執行時才不會互相踩到。
/// Tests for <see cref="EnvironmentVariableKeySource"/>. Each test uses its own variable name so
/// method-level parallel execution cannot interfere.
/// </summary>
[TestClass]
public sealed class EnvironmentVariableKeySourceTests
{
    private static string UniqueName() => "OZAKBOY_SECURITY_TEST_" + Guid.NewGuid().ToString("N").ToUpperInvariant();

    private static byte[] CreateTestKey() => Enumerable.Range(0, 32).Select(i => (byte)(i * 3)).ToArray();

    [TestMethod]
    public void ReadKey_ValidBase64Of32Bytes_ReturnsTheKey()
    {
        string name = UniqueName();
        byte[] key = CreateTestKey();
        Environment.SetEnvironmentVariable(name, Convert.ToBase64String(key));
        try
        {
            byte[] read = new EnvironmentVariableKeySource(name).ReadKey();

            CollectionAssert.AreEqual(key, read);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [TestMethod]
    public void ReadKey_SurroundingWhitespace_IsTolerated()
    {
        string name = UniqueName();
        byte[] key = CreateTestKey();
        Environment.SetEnvironmentVariable(name, "  " + Convert.ToBase64String(key) + "\n");
        try
        {
            CollectionAssert.AreEqual(key, new EnvironmentVariableKeySource(name).ReadKey());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [TestMethod]
    public void ReadKey_ReturnsAFreshArrayEveryCall()
    {
        string name = UniqueName();
        Environment.SetEnvironmentVariable(name, Convert.ToBase64String(CreateTestKey()));
        try
        {
            var source = new EnvironmentVariableKeySource(name);

            Assert.AreNotSame(source.ReadKey(), source.ReadKey());
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [TestMethod]
    public void ReadKey_UnsetVariable_ReportsKeyUnavailable_NamingTheVariable()
    {
        string name = UniqueName();

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new EnvironmentVariableKeySource(name).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, name);
    }

    [TestMethod]
    public void ReadKey_NotBase64_ReportsKeyUnavailable_WithoutEchoingTheValue()
    {
        string name = UniqueName();
        const string bogus = "this is not base64 at all!!";
        Environment.SetEnvironmentVariable(name, bogus);
        try
        {
            var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new EnvironmentVariableKeySource(name).ReadKey());

            Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
            Assert.IsFalse(exception.Message.Contains(bogus, StringComparison.Ordinal), "錯誤訊息不得回述變數內容。");
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [TestMethod]
    public void ReadKey_WrongLength_ReportsKeyUnavailable_StatingTheLength()
    {
        string name = UniqueName();
        Environment.SetEnvironmentVariable(name, Convert.ToBase64String(new byte[16]));
        try
        {
            var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new EnvironmentVariableKeySource(name).ReadKey());

            Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
            StringAssert.Contains(exception.Message, "16");
            StringAssert.Contains(exception.Message, "32");
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [TestMethod]
    public void Description_NamesTheVariable_AndNeverTheValue()
    {
        string name = UniqueName();
        var source = new EnvironmentVariableKeySource(name);

        StringAssert.Contains(source.Description, name);
        Assert.AreEqual(name, source.VariableName);
    }

    [TestMethod]
    public void Constructor_BlankName_ThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new EnvironmentVariableKeySource(null!));
        Assert.ThrowsExactly<ArgumentException>(() => new EnvironmentVariableKeySource("   "));
    }

    [TestMethod]
    public void EndToEnd_ProtectorOverEnvironmentVariable_RoundTrips()
    {
        string name = UniqueName();
        Environment.SetEnvironmentVariable(name, Convert.ToBase64String(CreateTestKey()));
        try
        {
            var protector = new KeyedSecretProtector(new EnvironmentVariableKeySource(name));

            Assert.AreEqual("api-secret", protector.Unprotect(protector.Protect("api-secret")));
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }
}
