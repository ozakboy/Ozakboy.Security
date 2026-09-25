using Microsoft.Extensions.Configuration;
using Ozakboy.Security;
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="ProtectedValueConfigurationBuilderExtensions.DecryptProtectedValues"/> 的測試:
/// 以 InMemory 來源模擬 appsettings,受保護的值自動解開、其餘原樣通過、失敗時指出鍵但不洩漏內容。
/// Tests for <see cref="ProtectedValueConfigurationBuilderExtensions.DecryptProtectedValues"/>: an in-memory
/// source stands in for appsettings; protected values open automatically, everything else passes through, and
/// failures name the key without leaking content.
/// </summary>
[TestClass]
public sealed class ProtectedValueConfigurationTests
{
    private sealed class FixedKeySource : ISecretKeySource
    {
        private readonly byte[] _key;

        public FixedKeySource(byte seed) => _key = Enumerable.Range(0, 32).Select(i => (byte)(i + seed)).ToArray();

        public int ReadCount { get; private set; }

        public string Description => "固定金鑰";

        public byte[] ReadKey()
        {
            ReadCount++;
            return [.. _key];
        }
    }

    private static readonly string[] ExpectedLineChildren = ["ChannelId", "ChannelSecret", "Nested"];

    private static KeyedSecretProtector CreateProtector(byte seed = 1) => new(new FixedKeySource(seed));

    [TestMethod]
    public void ProtectedValues_AreDecrypted_AndPlainValuesPassThrough()
    {
        var protector = CreateProtector();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Line:ChannelSecret"] = protector.Protect("real-channel-secret"),
                ["Line:ChannelId"] = "1234567890",
                ["ConnectionStrings:Default"] = protector.Protect("Server=db;Password=hunter2"),
                ["Empty"] = string.Empty,
                ["Null"] = null,
            })
            .DecryptProtectedValues(protector)
            .Build();

        Assert.AreEqual("real-channel-secret", configuration["Line:ChannelSecret"]);
        Assert.AreEqual("1234567890", configuration["Line:ChannelId"]);
        Assert.AreEqual("Server=db;Password=hunter2", configuration.GetConnectionString("Default"));
        Assert.AreEqual(string.Empty, configuration["Empty"]);
        Assert.IsNull(configuration["Null"]);
    }

    [TestMethod]
    public void Sections_Enumeration_AndBinding_WorkThroughTheWrapper()
    {
        var protector = CreateProtector();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Line:ChannelSecret"] = protector.Protect("secret"),
                ["Line:ChannelId"] = "id",
                ["Line:Nested:Token"] = protector.Protect("nested-token"),
            })
            .DecryptProtectedValues(protector)
            .Build();

        IConfigurationSection line = configuration.GetSection("Line");
        string[] children = line.GetChildren().Select(c => c.Key).Order(StringComparer.Ordinal).ToArray();

        CollectionAssert.AreEqual(ExpectedLineChildren, children);
        Assert.AreEqual("secret", line["ChannelSecret"]);
        Assert.AreEqual("nested-token", line.GetSection("Nested")["Token"]);
    }

    [TestMethod]
    public void LaterSourceOverridesEarlier_StillDecrypted()
    {
        var protector = CreateProtector();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = protector.Protect("from-first") })
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = protector.Protect("from-second") })
            .DecryptProtectedValues(protector)
            .Build();

        Assert.AreEqual("from-second", configuration["Key"]);
    }

    [TestMethod]
    public void SourcesAddedAfterTheCall_AreNotWrapped()
    {
        var protector = CreateProtector();
        string ciphertext = protector.Protect("late");
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Early"] = protector.Protect("early") })
            .DecryptProtectedValues(protector)
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Late"] = ciphertext })
            .Build();

        Assert.AreEqual("early", configuration["Early"]);
        Assert.AreEqual(ciphertext, configuration["Late"], "呼叫之後才加的來源不會被包到,這是文件寫明的行為。");
    }

    [TestMethod]
    public void CallingTwice_DoesNotDoubleWrap()
    {
        var protector = CreateProtector();
        var builder = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = protector.Protect("value") });

        builder.DecryptProtectedValues(protector).DecryptProtectedValues(protector);

        Assert.AreEqual(1, builder.Sources.Count);
        Assert.AreEqual("value", builder.Build()["Key"]);
    }

    [TestMethod]
    public void WrongKey_Throws_NamingTheKey_ButNotTheCiphertextOrPlainText()
    {
        var writer = CreateProtector(seed: 1);
        var reader = CreateProtector(seed: 2);
        const string plainText = "the-real-secret-value";
        string ciphertext = writer.Protect(plainText);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Line:ChannelSecret"] = ciphertext })
            .DecryptProtectedValues(reader)
            .Build();

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => configuration["Line:ChannelSecret"]);

        Assert.AreEqual(SecretProtectionFailureReason.DecryptionFailed, exception.Reason);
        StringAssert.Contains(exception.Message, "Line:ChannelSecret");
        Assert.IsFalse(exception.Message.Contains(ciphertext, StringComparison.Ordinal), "訊息不得含密文。");
        Assert.IsFalse(exception.Message.Contains(plainText, StringComparison.Ordinal), "訊息不得含明文。");
        Assert.IsNotNull(exception.InnerException);
    }

    [TestMethod]
    public void MissingKey_SurfacesAsKeyUnavailable_NamingTheKey()
    {
        string ciphertext = CreateProtector().Protect("value");
        string variable = "OZAKBOY_SECURITY_TEST_" + Guid.NewGuid().ToString("N");
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Db:Password"] = ciphertext })
            .DecryptProtectedValues(new KeyedSecretProtector(new EnvironmentVariableKeySource(variable)))
            .Build();

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => configuration["Db:Password"]);

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "Db:Password");
    }

    [TestMethod]
    public void DpapiEnvelope_WithKeyedProtector_FailsLoudly_RatherThanPassingCiphertextThrough()
    {
        string dpapiLike = Convert.ToBase64String([.."OZDP"u8.ToArray(), 1, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = dpapiLike })
            .DecryptProtectedValues(CreateProtector())
            .Build();

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => configuration["Key"]);

        Assert.AreEqual(SecretProtectionFailureReason.MalformedPayload, exception.Reason);
        StringAssert.Contains(exception.Message, "Key");
    }

    [TestMethod]
    public void CustomPredicate_LimitsWhatIsTreatedAsProtected()
    {
        var protector = CreateProtector();
        string ciphertext = protector.Protect("value");
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = ciphertext })
            .DecryptProtectedValues(protector, isProtectedValue: static _ => false)
            .Build();

        Assert.AreEqual(ciphertext, configuration["Key"]);
    }

    [TestMethod]
    public void EachCiphertext_IsDecryptedOnce_ThenServedFromCache()
    {
        var source = new FixedKeySource(seed: 1);
        var protector = new KeyedSecretProtector(source);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = protector.Protect("value") })
            .DecryptProtectedValues(protector)
            .Build();
        int readsAfterProtect = source.ReadCount;

        for (int i = 0; i < 5; i++)
        {
            Assert.AreEqual("value", configuration["Key"]);
        }

        Assert.AreEqual(readsAfterProtect + 1, source.ReadCount, "同一個密文只該解密一次。");
    }

    [TestMethod]
    public void ConfigurationManager_AsUsedByWebApplicationBuilder_IsSupported()
    {
        var protector = CreateProtector();
        using var manager = new ConfigurationManager();
        manager.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Line:ChannelSecret"] = protector.Protect("secret"),
            ["Line:ChannelId"] = "id",
        });

        manager.DecryptProtectedValues(protector);

        Assert.AreEqual("secret", manager["Line:ChannelSecret"]);
        Assert.AreEqual("id", manager["Line:ChannelId"]);
    }

    [TestMethod]
    public void ReloadToken_And_Set_DelegateToTheInnerProvider()
    {
        var protector = CreateProtector();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "plain" })
            .DecryptProtectedValues(protector)
            .Build();

        configuration["Key"] = protector.Protect("set-later");

        Assert.AreEqual("set-later", configuration["Key"]);
        Assert.IsNotNull(configuration.GetReloadToken());
        Assert.IsFalse(configuration.Providers.First().ToString()!.Contains("ProtectedValue", StringComparison.Ordinal),
            "除錯檢視應顯示內層提供者的名稱。");
    }

    [TestMethod]
    public void IsAnyProtectedValue_RecognisesBothEnvelopes()
    {
        string ozcf = CreateProtector().Protect("x");
        string ozdp = Convert.ToBase64String([.."OZDP"u8.ToArray(), 1, 0, 1, 2, 3]);

        Assert.IsTrue(ProtectedValueConfigurationBuilderExtensions.IsAnyProtectedValue(ozcf));
        Assert.IsTrue(ProtectedValueConfigurationBuilderExtensions.IsAnyProtectedValue(ozdp));
        Assert.IsFalse(ProtectedValueConfigurationBuilderExtensions.IsAnyProtectedValue("plain"));
        Assert.IsFalse(ProtectedValueConfigurationBuilderExtensions.IsAnyProtectedValue(null));
    }

    [TestMethod]
    public void NullArguments_ThrowArgumentNullException()
    {
        var builder = new ConfigurationBuilder();

        Assert.ThrowsExactly<ArgumentNullException>(() => ((IConfigurationBuilder)null!).DecryptProtectedValues(CreateProtector()));
        Assert.ThrowsExactly<ArgumentNullException>(() => builder.DecryptProtectedValues(null!));
    }
}
