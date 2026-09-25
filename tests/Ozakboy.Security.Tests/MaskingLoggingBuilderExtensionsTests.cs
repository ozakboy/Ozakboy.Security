using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ozakboy.Security;
using Ozakboy.Security.Logging;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <c>AddOzakboySecretMasking</c> 的測試:透過真正的 <c>AddLogging</c> + <see cref="LoggerFactory"/> 驗證
/// 工廠被包住、<c>ILogger&lt;T&gt;</c> 與晚加入的提供者都經過遮罩、遮罩器來自 <c>AddOzakboySecurity</c>。
/// Tests for <c>AddOzakboySecretMasking</c>: through the real <c>AddLogging</c> + <see cref="LoggerFactory"/> they
/// prove the factory is wrapped, that <c>ILogger&lt;T&gt;</c> and late-added providers are masked, and that the masker
/// comes from <c>AddOzakboySecurity</c>.
/// </summary>
[TestClass]
public sealed class MaskingLoggingBuilderExtensionsTests
{
    private const string Secret = "cohort-db-password-0123456789";

    private sealed class CapturingProvider : ILoggerProvider
    {
        public List<(string Category, string Message, object? State, Exception? Exception)> Entries { get; } = [];

        public ILogger CreateLogger(string categoryName) => new ProviderLogger(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class ProviderLogger(CapturingProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
                => owner.Entries.Add((category, formatter(state, exception), state, exception));
        }
    }

    private sealed class Service
    {
    }

    [TestMethod]
    public void ILoggerOfT_AndLateProviders_AreMasked_WithTheContainerMasker()
    {
        var provider = new CapturingProvider();
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security
            .ConfigureMasking(options => options.AlsoRegisterOnDefaultMasker = false)
            .RegisterKnownSecret(Secret));
        services.AddLogging(logging =>
        {
            logging.AddOzakboySecretMasking();
            logging.AddProvider(provider);   // 在掛上遮罩之後才加,仍應被涵蓋。
        });
        using ServiceProvider container = services.BuildServiceProvider();

        Assert.IsInstanceOfType<MaskingLoggerFactory>(container.GetRequiredService<ILoggerFactory>());
        var logger = container.GetRequiredService<ILogger<Service>>();
        logger.LogError(new InvalidOperationException("boom " + Secret), "connect failed pwd={Password} secret={Secret}", "hunter2!", Secret);

        Assert.AreEqual(1, provider.Entries.Count);
        (string category, string message, object? state, Exception? exception) = provider.Entries[0];
        StringAssert.Contains(category, nameof(Service));
        Assert.AreEqual("connect failed pwd=**** secret=****", message);
        Assert.IsFalse(message.Contains(Secret, StringComparison.Ordinal));
        Assert.IsInstanceOfType<MaskedException>(exception);
        Assert.IsFalse(exception!.ToString().Contains(Secret, StringComparison.Ordinal));
        var properties = (IReadOnlyList<KeyValuePair<string, object?>>)state!;
        Assert.AreEqual("****", properties.Single(p => p.Key == "Secret").Value);
    }

    [TestMethod]
    public void WithoutAddOzakboySecurity_FallsBackToTheDefaultMasker()
    {
        var provider = new CapturingProvider();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(provider).AddOzakboySecretMasking());
        using ServiceProvider container = services.BuildServiceProvider();

        var factory = (MaskingLoggerFactory)container.GetRequiredService<ILoggerFactory>();

        Assert.AreSame(SecretMasker.Default, factory.Masker);
    }

    [TestMethod]
    public void ExplicitMasker_IsUsed_AndByNameSwitchIsHonoured()
    {
        var provider = new CapturingProvider();
        var masker = new SecretMasker();
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(provider).AddOzakboySecretMasking(masker, maskPropertiesByName: false));
        using ServiceProvider container = services.BuildServiceProvider();

        var factory = (MaskingLoggerFactory)container.GetRequiredService<ILoggerFactory>();
        factory.CreateLogger("cat").LogInformation("token={Token}", "unregistered-token-value");

        Assert.AreSame(masker, factory.Masker);
        Assert.AreEqual("token=unregistered-token-value", provider.Entries[0].Message);
    }

    [TestMethod]
    public void MaskLogPropertiesByName_FromOptions_IsHonoured()
    {
        var provider = new CapturingProvider();
        var services = new ServiceCollection();
        services.AddOzakboySecurity(security => security.ConfigureMasking(options =>
        {
            options.AlsoRegisterOnDefaultMasker = false;
            options.MaskLogPropertiesByName = false;
        }));
        services.AddLogging(logging => logging.AddProvider(provider).AddOzakboySecretMasking());
        using ServiceProvider container = services.BuildServiceProvider();

        container.GetRequiredService<ILoggerFactory>().CreateLogger("cat").LogInformation("token={Token}", "unregistered-token-value");

        Assert.AreEqual("token=unregistered-token-value", provider.Entries[0].Message);
    }

    [TestMethod]
    public void CallingTwice_WrapsOnlyOnce()
    {
        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddOzakboySecretMasking().AddOzakboySecretMasking());
        using ServiceProvider container = services.BuildServiceProvider();

        Assert.AreEqual(1, services.Count(d => d.ServiceType == typeof(ILoggerFactory)));
        Assert.IsInstanceOfType<MaskingLoggerFactory>(container.GetRequiredService<ILoggerFactory>());
    }

    [TestMethod]
    public void FactoryRegisteredAsInstance_OrAsFactory_IsWrappedToo()
    {
        var provider = new CapturingProvider();
        var services = new ServiceCollection();
        services.AddLogging();
        using var innerFactory = new LoggerFactory([provider]);
        services.AddSingleton<ILoggerFactory>(innerFactory);
        services.AddLogging(logging => logging.AddOzakboySecretMasking(new SecretMasker()));
        using ServiceProvider container = services.BuildServiceProvider();

        container.GetRequiredService<ILoggerFactory>().CreateLogger("cat").LogInformation("password={Password}", "hunter2!");

        Assert.AreEqual("password=****", provider.Entries[0].Message);

        var services2 = new ServiceCollection();
        services2.AddLogging();
        services2.AddSingleton<ILoggerFactory>(_ => new LoggerFactory([provider]));
        services2.AddLogging(logging => logging.AddOzakboySecretMasking(new SecretMasker()));
        using ServiceProvider container2 = services2.BuildServiceProvider();

        container2.GetRequiredService<ILoggerFactory>().CreateLogger("cat").LogInformation("password={Password}", "hunter2!");

        Assert.AreEqual("password=****", provider.Entries[1].Message);
    }

    [TestMethod]
    public void CreateLogger_CachesPerCategory()
    {
        using var inner = new LoggerFactory();
        using var factory = new MaskingLoggerFactory(inner, new SecretMasker());

        Assert.AreSame(factory.CreateLogger("a"), factory.CreateLogger("a"));
        Assert.AreNotSame(factory.CreateLogger("a"), factory.CreateLogger("b"));
    }

    [TestMethod]
    public void WithoutAddLogging_ThrowsInvalidOperationException_WithGuidance()
    {
        var services = new ServiceCollection();
        var builder = new FakeLoggingBuilder(services);

        var exception = Assert.ThrowsExactly<InvalidOperationException>(() => builder.AddOzakboySecretMasking());

        StringAssert.Contains(exception.Message, "AddLogging");
    }

    [TestMethod]
    public void NullArguments_ThrowArgumentNullException()
    {
        var services = new ServiceCollection();
        var builder = new FakeLoggingBuilder(services);

        Assert.ThrowsExactly<ArgumentNullException>(() => ((ILoggingBuilder)null!).AddOzakboySecretMasking());
        Assert.ThrowsExactly<ArgumentNullException>(() => builder.AddOzakboySecretMasking(null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => new MaskingLoggerFactory(null!, new SecretMasker()));
        Assert.ThrowsExactly<ArgumentNullException>(() => new MaskingLoggerFactory(new LoggerFactory(), null!));
    }

    private sealed class FakeLoggingBuilder(IServiceCollection services) : ILoggingBuilder
    {
        public IServiceCollection Services { get; } = services;
    }
}
