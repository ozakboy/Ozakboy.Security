using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Ozakboy.Security;
using Ozakboy.Security.Masking;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <c>AddOzakboySecurity</c> 的測試:遮罩器的註冊與已知祕密登記、保護器的明確選擇、便利多載依作業系統的行為。
/// 全部只用 ServiceCollection,不啟動 Host。
/// Tests for <c>AddOzakboySecurity</c>: masker registration and known-secret registration, explicit protector
/// selection, and the OS-dependent convenience overload. ServiceCollection only, no host.
/// </summary>
[TestClass]
public sealed class OzakboySecurityServiceCollectionExtensionsTests
{
    private sealed class FixedKeySource : ISecretKeySource
    {
        public string Description => "固定金鑰";

        public byte[] ReadKey() => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    }

    [TestMethod]
    public void AddOzakboySecurity_RegistersASingletonMasker_AndNoProtector()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity();
        using ServiceProvider provider = services.BuildServiceProvider();

        var masker = provider.GetRequiredService<SecretMasker>();

        Assert.AreSame(masker, provider.GetRequiredService<SecretMasker>());
        Assert.AreNotSame(SecretMasker.Default, masker);
        Assert.IsNull(provider.GetService<ISecretProtector>(), "沒有明確選保護器就不該有註冊。");
    }

    [TestMethod]
    public void KnownSecrets_AreRegisteredOnTheMasker_ButNotOnDefault_WhenMirroringIsOff()
    {
        const string secret = "line-channel-secret-0123456789";
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security
            .ConfigureMasking(options => options.AlsoRegisterOnDefaultMasker = false)
            .RegisterKnownSecret(secret));
        using ServiceProvider provider = services.BuildServiceProvider();

        var masker = provider.GetRequiredService<SecretMasker>();

        Assert.AreEqual(1, masker.KnownSecretCount);
        Assert.AreEqual("token=" + masker.MaskSegment, masker.MaskText("token=" + secret));
        Assert.AreEqual("token=" + secret, SecretMasker.Default.MaskText("token=" + secret), "關掉鏡射時不得動到共用遮罩器。");
    }

    [TestMethod]
    public void KnownSecrets_AddedThroughOptionsAfterTheCall_AreStillRegistered()
    {
        const string secret = "added-later-secret-value";
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.ConfigureMasking(options => options.AlsoRegisterOnDefaultMasker = false));
        services.Configure<SecretMaskingOptions>(options => options.KnownSecrets.Add(secret));
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.AreEqual(1, provider.GetRequiredService<SecretMasker>().KnownSecretCount);
    }

    [TestMethod]
    public void MaskOptions_AreHonoured()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.ConfigureMasking(options =>
        {
            options.AlsoRegisterOnDefaultMasker = false;
            options.MaskOptions = new SecretMaskOptions { MaskCharacter = '#', MaskLength = 6 };
        }));
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.AreEqual("######", provider.GetRequiredService<SecretMasker>().MaskSegment);
    }

    [TestMethod]
    public void RegisterKnownSecret_TooShort_ThrowsImmediately_WithoutEchoingTheValue()
    {
        const string tooShort = "abc";
        var services = new ServiceCollection();

        var exception = Assert.ThrowsExactly<ArgumentException>(
            () => services.AddOzakboySecurity(security => security.RegisterKnownSecret(tooShort)));

        Assert.IsFalse(exception.Message.Contains(tooShort, StringComparison.Ordinal));
        Assert.ThrowsExactly<ArgumentNullException>(() => services.AddOzakboySecurity(security => security.RegisterKnownSecret(null!)));
    }

    [TestMethod]
    public void KnownSecrets_TooShortViaOptions_FailValidation_NamingTheIndex_NotTheValue()
    {
        const string tooShort = "zq7!x";
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.ConfigureMasking(options =>
        {
            options.AlsoRegisterOnDefaultMasker = false;
            options.KnownSecrets.Add("long-enough-secret-value");
            options.KnownSecrets.Add(tooShort);
        }));
        using ServiceProvider provider = services.BuildServiceProvider();

        var exception = Assert.ThrowsExactly<OptionsValidationException>(() => provider.GetRequiredService<SecretMasker>());

        StringAssert.Contains(exception.Message, "KnownSecrets[1]");
        Assert.IsFalse(exception.Message.Contains(tooShort, StringComparison.Ordinal));
    }

    [TestMethod]
    public void UseKeyedProtector_RegistersAKeyedProtectorSingleton()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.UseKeyedProtector(new FixedKeySource()));
        using ServiceProvider provider = services.BuildServiceProvider();

        var protector = provider.GetRequiredService<ISecretProtector>();

        Assert.IsInstanceOfType<KeyedSecretProtector>(protector);
        Assert.AreSame(protector, provider.GetRequiredService<ISecretProtector>());
        Assert.AreEqual("value", protector.Unprotect(protector.Protect("value")));
    }

    [TestMethod]
    public void UseKeyFromEnvironmentVariable_AndUseKeyFromFile_PickTheMatchingSource()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.UseKeyFromEnvironmentVariable("APP_MASTER_KEY"));
        using (ServiceProvider provider = services.BuildServiceProvider())
        {
            var protector = (KeyedSecretProtector)provider.GetRequiredService<ISecretProtector>();
            Assert.IsInstanceOfType<EnvironmentVariableKeySource>(protector.KeySource);
        }

        services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.UseKeyFromFile("/etc/app/app.key"));
        using (ServiceProvider provider = services.BuildServiceProvider())
        {
            var protector = (KeyedSecretProtector)provider.GetRequiredService<ISecretProtector>();
            Assert.IsInstanceOfType<KeyFileKeySource>(protector.KeySource);
        }
    }

    [TestMethod]
    public void UseDpapiProtector_RegistersDpapi_WithTheGivenOptions()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.UseDpapiProtector(new DpapiProtectionOptions { Scope = SecretProtectionScope.LocalMachine }));
        using ServiceProvider provider = services.BuildServiceProvider();

        var protector = provider.GetRequiredService<ISecretProtector>();

        Assert.IsInstanceOfType<DpapiSecretProtector>(protector);
        Assert.AreEqual(SecretProtectionScope.LocalMachine, ((DpapiSecretProtector)protector).Scope);
        Assert.AreEqual(OperatingSystem.IsWindows(), protector.IsSupported);
    }

    [TestMethod]
    public void UseDpapiOnWindowsOtherwiseKeyed_PicksByOperatingSystem_AtResolutionTime()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.UseDpapiOnWindowsOtherwiseKeyed(new FixedKeySource()));
        using ServiceProvider provider = services.BuildServiceProvider();

        var protector = provider.GetRequiredService<ISecretProtector>();

        if (OperatingSystem.IsWindows())
        {
            Assert.IsInstanceOfType<DpapiSecretProtector>(protector);
        }
        else
        {
            Assert.IsInstanceOfType<KeyedSecretProtector>(protector);
        }

        Assert.IsTrue(protector.IsSupported, "不論哪個平台,便利多載選出來的保護器都必須是可用的。");
    }

    [TestMethod]
    public void LastProtectorChoiceWins()
    {
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security
            .UseDpapiProtector()
            .UseKeyedProtector(new FixedKeySource()));
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.AreEqual(1, services.Count(d => d.ServiceType == typeof(ISecretProtector)));
        Assert.IsInstanceOfType<KeyedSecretProtector>(provider.GetRequiredService<ISecretProtector>());
    }

    [TestMethod]
    public void UseProtector_CustomFactory_IsUsed()
    {
        var services = new ServiceCollection();
        var custom = new KeyedSecretProtector(new FixedKeySource());
        services.AddOzakboySecurity(security => security.UseProtector(_ => custom));
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.AreSame(custom, provider.GetRequiredService<ISecretProtector>());
    }

    [TestMethod]
    public void HostRegisteredMasker_IsKept()
    {
        var services = new ServiceCollection();
        var hostMasker = new SecretMasker();
        services.AddSingleton(hostMasker);
        services.AddOzakboySecurity();
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.AreSame(hostMasker, provider.GetRequiredService<SecretMasker>());
    }

    [TestMethod]
    public void NullArguments_ThrowArgumentNullException()
    {
        var services = new ServiceCollection();

        Assert.ThrowsExactly<ArgumentNullException>(() => ((IServiceCollection)null!).AddOzakboySecurity());
        Assert.ThrowsExactly<ArgumentNullException>(() => services.AddOzakboySecurity(null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => services.AddOzakboySecurity(s => s.UseKeyedProtector(null!)));
        Assert.ThrowsExactly<ArgumentNullException>(() => services.AddOzakboySecurity(s => s.UseDpapiOnWindowsOtherwiseKeyed(null!)));
        Assert.ThrowsExactly<ArgumentNullException>(() => services.AddOzakboySecurity(s => s.UseProtector(null!)));
        Assert.ThrowsExactly<ArgumentNullException>(() => services.AddOzakboySecurity(s => s.ConfigureMasking(null!)));
    }
}
