using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="SecretMasker.MaskQueryString(string)"/> 的測試:敏感參數要遮掉,端點與其他參數必須看得見。
/// Tests for <see cref="SecretMasker.MaskQueryString(string)"/>: sensitive parameters are masked while
/// the endpoint and the harmless parameters stay readable.
/// </summary>
[TestClass]
public sealed class SecretMaskerQueryStringTests
{
    [TestMethod]
    public void MaskQueryString_MasksSensitiveParametersAndKeepsTheRest()
    {
        const string target = "/api/v3/order?symbol=BTCUSDT&apiKey=abcdefghijklmnopqrst&signature=0123456789abcdef";

        string masked = SecretMasker.Default.MaskQueryString(target);

        Assert.AreEqual("/api/v3/order?symbol=BTCUSDT&apiKey=abcd****qrst&signature=0123****cdef", masked);
    }

    [TestMethod]
    public void MaskQueryString_AbsoluteUrl_KeepsSchemeHostAndPath()
    {
        const string target = "https://example.com/v1/account?token=abcdefghijklmnopqrst";

        string masked = SecretMasker.Default.MaskQueryString(target);

        Assert.AreEqual("https://example.com/v1/account?token=abcd****qrst", masked);
    }

    [TestMethod]
    public void MaskQueryString_ParameterNames_MatchIgnoringCase()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?APIKEY=abcdefghijklmnopqrst");

        Assert.AreEqual("/a?APIKEY=abcd****qrst", masked);
    }

    [TestMethod]
    public void MaskQueryString_BareQueryStringWithoutQuestionMark_IsStillMasked()
    {
        string masked = SecretMasker.Default.MaskQueryString("symbol=BTCUSDT&secret=abcdefghijklmnopqrst");

        Assert.AreEqual("symbol=BTCUSDT&secret=abcd****qrst", masked);
    }

    [TestMethod]
    public void MaskQueryString_NoQueryString_ReturnsInputUnchanged()
    {
        const string target = "https://example.com/v1/time";

        Assert.AreEqual(target, SecretMasker.Default.MaskQueryString(target));
    }

    [TestMethod]
    public void MaskQueryString_ShortSensitiveValue_IsMaskedEntirely()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?apiKey=short");

        Assert.AreEqual("/a?apiKey=****", masked);
    }

    [TestMethod]
    public void MaskQueryString_EmptySensitiveValue_StaysEmpty()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?apiKey=&symbol=BTCUSDT");

        Assert.AreEqual("/a?apiKey=&symbol=BTCUSDT", masked);
    }

    [TestMethod]
    public void MaskQueryString_SegmentWithoutEqualsSign_IsLeftAlone()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?flag&apiKey=abcdefghijklmnopqrst");

        Assert.AreEqual("/a?flag&apiKey=abcd****qrst", masked);
    }

    [TestMethod]
    public void MaskQueryString_Fragment_IsPreserved()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?token=abcdefghijklmnopqrst#section");

        Assert.AreEqual("/a?token=abcd****qrst#section", masked);
    }

    [TestMethod]
    public void MaskQueryString_EmptyString_ReturnsEmptyString()
    {
        Assert.AreEqual(string.Empty, SecretMasker.Default.MaskQueryString(string.Empty));
    }

    [TestMethod]
    public void MaskQueryString_QuestionMarkWithoutQuery_ReturnsInputUnchanged()
    {
        Assert.AreEqual("/a?", SecretMasker.Default.MaskQueryString("/a?"));
    }

    [TestMethod]
    public void MaskQueryString_Null_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => SecretMasker.Default.MaskQueryString(null!));
    }
}
