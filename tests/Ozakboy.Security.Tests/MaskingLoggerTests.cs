using Microsoft.Extensions.Logging;
using Ozakboy.Security.Logging;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="MaskingLogger"/> 的測試:用假的 <see cref="ILogger"/> 收集內層真正收到的東西,
/// 驗證訊息、結構化屬性、例外都經過遮罩,而沒東西要遮時原物件原封不動往下傳。
/// Tests for <see cref="MaskingLogger"/>: a fake <see cref="ILogger"/> captures what the inner logger actually
/// receives, proving message, structured properties and exception are masked, and that with nothing to mask the
/// original objects pass through untouched.
/// </summary>
[TestClass]
public sealed class MaskingLoggerTests
{
    private const string ApiKey = "binance-api-key-ABCDEFGHIJKLMNOP";

    /// <summary>
    /// 收集內層收到的每一筆紀錄。
    /// Captures every entry the inner logger receives.
    /// </summary>
    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, EventId EventId, object? State, Exception? Exception, string Message)> Entries { get; } = [];

        public List<object> Scopes { get; } = [];

        public LogLevel MinimumLevel { get; set; } = LogLevel.Trace;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
        {
            Scopes.Add(state);
            return null;
        }

        public bool IsEnabled(LogLevel logLevel) => logLevel >= MinimumLevel;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId, state, exception, formatter(state, exception)));
    }

    private static SecretMasker CreateMasker(bool withKnownSecret = true)
    {
        var masker = new SecretMasker();
        if (withKnownSecret)
        {
            masker.RegisterKnownSecret(ApiKey);
        }

        return masker;
    }

    private static IReadOnlyList<KeyValuePair<string, object?>> Properties(object? state)
        => (IReadOnlyList<KeyValuePair<string, object?>>)state!;

    [TestMethod]
    public void RegisteredSecretInFormattedMessage_IsMasked()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());

        logger.LogError("order failed key={Key}", ApiKey);

        Assert.AreEqual(1, inner.Entries.Count);
        Assert.AreEqual("order failed key=****", inner.Entries[0].Message);
        Assert.AreEqual(LogLevel.Error, inner.Entries[0].Level);
    }

    [TestMethod]
    public void RegisteredSecretInStructuredProperty_IsMasked_AndTemplateIsKept()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker(), maskPropertiesByName: false);

        logger.LogInformation("symbol={Symbol} payload={Payload}", "BTCUSDT", "k=" + ApiKey);

        IReadOnlyList<KeyValuePair<string, object?>> properties = Properties(inner.Entries[0].State);
        Assert.AreEqual("BTCUSDT", properties.Single(p => p.Key == "Symbol").Value);
        Assert.AreEqual("k=****", properties.Single(p => p.Key == "Payload").Value);
        Assert.AreEqual("symbol={Symbol} payload={Payload}", properties.Single(p => p.Key == "{OriginalFormat}").Value);
        Assert.AreEqual("symbol=BTCUSDT payload=k=****", inner.Entries[0].Message);
        Assert.AreEqual(inner.Entries[0].Message, inner.Entries[0].State!.ToString());
    }

    [TestMethod]
    public void SensitivePropertyName_IsMaskedByName_EvenWhenUnregistered_InBothPropertyAndMessage()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker(withKnownSecret: false));
        const string token = "unregistered-token-value-0123456789";

        logger.LogWarning("refresh token={Token} for {UserId}", token, "user-42");

        IReadOnlyList<KeyValuePair<string, object?>> properties = Properties(inner.Entries[0].State);
        string maskedToken = (string)properties.Single(p => p.Key == "Token").Value!;
        Assert.AreNotEqual(token, maskedToken);
        StringAssert.StartsWith(maskedToken, "unre");
        StringAssert.EndsWith(maskedToken, "6789");
        Assert.AreEqual("user-42", properties.Single(p => p.Key == "UserId").Value);
        Assert.AreEqual("refresh token=" + maskedToken + " for user-42", inner.Entries[0].Message);
    }

    [TestMethod]
    public void PasswordLikePropertyName_IsFullyMasked()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker(withKnownSecret: false));

        logger.LogInformation("login user={User} password={Password}", "alice", "hunter2!");

        Assert.AreEqual("login user=alice password=****", inner.Entries[0].Message);
    }

    [TestMethod]
    public void MaskByName_Off_LeavesUnregisteredSensitiveProperties_Alone()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker(withKnownSecret: false), maskPropertiesByName: false);
        var state = new List<KeyValuePair<string, object?>> { new("Token", "unregistered-token-value") };

        logger.Log(LogLevel.Information, default, state, null, static (s, _) => "token=" + s[0].Value);

        Assert.AreSame(state, inner.Entries[0].State);
        Assert.AreEqual("token=unregistered-token-value", inner.Entries[0].Message);
    }

    [TestMethod]
    public void VeryShortSensitiveValue_IsMaskedInProperty_ButNotReplacedInMessage()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker(withKnownSecret: false));

        logger.LogInformation("cache key={Key} for area {Area}", "a", "area-a");

        IReadOnlyList<KeyValuePair<string, object?>> properties = Properties(inner.Entries[0].State);
        Assert.AreEqual("****", properties.Single(p => p.Key == "Key").Value);
        Assert.AreEqual("cache key=a for area area-a", inner.Entries[0].Message, "單字元的值不做訊息替換,否則整行都被改爛。");
    }

    [TestMethod]
    public void NothingToMask_ForwardsOriginalStateExceptionAndFormatter_WithoutCopying()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());
        var state = new List<KeyValuePair<string, object?>> { new("Symbol", "BTCUSDT"), new("Quantity", 1.5) };
        var exception = new InvalidOperationException("harmless");

        logger.Log(LogLevel.Information, new EventId(7, "Order"), state, exception, static (s, _) => "symbol=" + s[0].Value);

        Assert.AreSame(state, inner.Entries[0].State);
        Assert.AreSame(exception, inner.Entries[0].Exception);
        Assert.AreEqual(7, inner.Entries[0].EventId.Id);
        Assert.AreEqual("symbol=BTCUSDT", inner.Entries[0].Message);
    }

    [TestMethod]
    public void NonStringProperties_PassThrough_Unchanged()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());
        var uri = new Uri("https://example.com/");

        logger.LogInformation("count={Count} uri={Uri} key={Key}", 3, uri, ApiKey);

        IReadOnlyList<KeyValuePair<string, object?>> properties = Properties(inner.Entries[0].State);
        Assert.AreEqual(3, properties.Single(p => p.Key == "Count").Value);
        Assert.AreSame(uri, properties.Single(p => p.Key == "Uri").Value);
        Assert.AreEqual("****", properties.Single(p => p.Key == "Key").Value);
    }

    [TestMethod]
    public void ExceptionContainingASecret_IsReplacedByAMaskedStandIn_KeepingTypeNameAndInner()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());
        var original = new HttpRequestException("401 for key " + ApiKey, new TimeoutException("inner " + ApiKey));

        logger.LogError(original, "request failed");

        Exception? forwarded = inner.Entries[0].Exception;
        var standIn = Assert.IsInstanceOfType<MaskedException>(forwarded);
        Assert.AreEqual(typeof(HttpRequestException).FullName, standIn.OriginalTypeName);
        Assert.AreEqual("401 for key ****", standIn.Message);
        Assert.IsFalse(standIn.ToString().Contains(ApiKey, StringComparison.Ordinal));
        StringAssert.Contains(standIn.ToString(), "HttpRequestException");
        var innerStandIn = Assert.IsInstanceOfType<MaskedException>(standIn.InnerException);
        Assert.AreEqual("inner ****", innerStandIn.Message);
        Assert.AreEqual(typeof(TimeoutException).FullName, innerStandIn.OriginalTypeName);
    }

    [TestMethod]
    public void ThrownException_StackTraceIsPreservedOnTheStandIn()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());
        Exception thrown;
        try
        {
            throw new InvalidOperationException("leak " + ApiKey);
        }
        catch (InvalidOperationException ex)
        {
            thrown = ex;
        }

        logger.LogError(thrown, "failed");

        var standIn = Assert.IsInstanceOfType<MaskedException>(inner.Entries[0].Exception);
        Assert.IsNotNull(standIn.StackTrace);
        StringAssert.Contains(standIn.StackTrace, nameof(ThrownException_StackTraceIsPreservedOnTheStandIn));
        Assert.AreEqual(thrown.HResult, standIn.HResult);
    }

    [TestMethod]
    public void ExceptionWithoutSecrets_IsPassedThrough_NotReplaced()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());
        var harmless = new InvalidOperationException("nothing to see");

        logger.LogError(harmless, "failed with {Key}", ApiKey);

        Assert.AreSame(harmless, inner.Entries[0].Exception);
        Assert.AreEqual("failed with ****", inner.Entries[0].Message);
    }

    [TestMethod]
    public void DisabledLevel_ReturnsEarly_WithoutInvokingTheFormatter()
    {
        var inner = new CapturingLogger { MinimumLevel = LogLevel.Warning };
        var logger = new MaskingLogger(inner, CreateMasker());
        bool formatted = false;

        logger.Log(LogLevel.Debug, default, "state", null, (_, _) => { formatted = true; return "x"; });

        Assert.IsFalse(formatted);
        Assert.AreEqual(0, inner.Entries.Count);
        Assert.IsFalse(logger.IsEnabled(LogLevel.Debug));
        Assert.IsTrue(logger.IsEnabled(LogLevel.Error));
    }

    [TestMethod]
    public void PlainStringState_WithSecret_IsMaskedIntoAnEmptyPropertyState()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());

        logger.Log(LogLevel.Information, default, "key " + ApiKey, null, static (s, _) => s);

        Assert.AreEqual("key ****", inner.Entries[0].Message);
        Assert.AreEqual(0, Properties(inner.Entries[0].State).Count);
    }

    [TestMethod]
    public void Scope_WithSecretInProperties_IsMasked_AndHarmlessScopeIsForwardedAsIs()
    {
        var inner = new CapturingLogger();
        var logger = new MaskingLogger(inner, CreateMasker());
        var harmless = new List<KeyValuePair<string, object?>> { new("RequestId", "r-1") };

        using (logger.BeginScope(harmless))
        using (logger.BeginScope(new List<KeyValuePair<string, object?>> { new("ApiKey", ApiKey) }))
        using (logger.BeginScope("scope " + ApiKey))
        {
        }

        Assert.AreSame(harmless, inner.Scopes[0]);
        Assert.AreEqual("****", Properties(inner.Scopes[1]).Single().Value);
        Assert.AreEqual("scope ****", inner.Scopes[2]);
    }

    [TestMethod]
    public void Properties_ExposeTheWiring()
    {
        var inner = new CapturingLogger();
        SecretMasker masker = CreateMasker();

        var logger = new MaskingLogger(inner, masker, maskPropertiesByName: false);

        Assert.AreSame(inner, logger.Inner);
        Assert.AreSame(masker, logger.Masker);
        Assert.IsFalse(logger.MaskPropertiesByName);
    }

    [TestMethod]
    public void Constructor_NullArguments_ThrowArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new MaskingLogger(null!, CreateMasker()));
        Assert.ThrowsExactly<ArgumentNullException>(() => new MaskingLogger(new CapturingLogger(), null!));
        Assert.ThrowsExactly<ArgumentNullException>(() => new MaskingLogger(new CapturingLogger(), CreateMasker()).Log(LogLevel.Information, default, "s", null, null!));
    }

    [TestMethod]
    public void MaskedException_StandardConstructors_Work()
    {
        var inner = new InvalidOperationException("inner");

        Assert.AreEqual("m", new MaskedException("m").Message);
        Assert.AreSame(inner, new MaskedException("m", inner).InnerException);
        Assert.IsNull(new MaskedException().OriginalTypeName);
        StringAssert.Contains(new MaskedException("m").ToString(), "m");
    }
}
