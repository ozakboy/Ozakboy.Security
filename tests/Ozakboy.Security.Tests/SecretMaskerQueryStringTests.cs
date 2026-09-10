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

        Assert.AreEqual("/api/v3/order?symbol=BTCUSDT&apiKey=abc****rst&signature=012****ef", masked);
    }

    [TestMethod]
    public void MaskQueryString_AbsoluteUrl_KeepsSchemeHostAndPath()
    {
        const string target = "https://example.com/v1/account?token=abcdefghijklmnopqrst";

        string masked = SecretMasker.Default.MaskQueryString(target);

        Assert.AreEqual("https://example.com/v1/account?token=abc****rst", masked);
    }

    [TestMethod]
    public void MaskQueryString_ParameterNames_MatchIgnoringCase()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?APIKEY=abcdefghijklmnopqrst");

        Assert.AreEqual("/a?APIKEY=abc****rst", masked);
    }

    [TestMethod]
    public void MaskQueryString_BareQueryStringWithoutQuestionMark_IsStillMasked()
    {
        string masked = SecretMasker.Default.MaskQueryString("symbol=BTCUSDT&secret=abcdefghijklmnopqrst");

        Assert.AreEqual("symbol=BTCUSDT&secret=abc****rst", masked);
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

        Assert.AreEqual("/a?flag&apiKey=abc****rst", masked);
    }

    [TestMethod]
    public void MaskQueryString_Fragment_IsPreserved()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?token=abcdefghijklmnopqrst#section");

        Assert.AreEqual("/a?token=abc****rst#section", masked);
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

    [TestMethod]
    public void MaskQueryString_PercentEncodedParameterName_IsStillRecognised()
    {
        // %4B 就是 K,解碼後是 apiKey;比對原始字面值的話這個變形會整個穿過去。
        string masked = SecretMasker.Default.MaskQueryString("/a?api%4Bey=abcdefghijklmnopqrst");

        Assert.AreEqual("/a?api%4Bey=abc****rst", masked, "參數名要先解碼再比對,但輸出仍用原始寫法。");
    }

    [TestMethod]
    public void MaskQueryString_PercentEncodedNameMatchesTheJsonPath()
    {
        // JSON 路徑由 JsonDocument 負責解碼,本來就是拿解碼後的名稱比對;query 路徑現在一致。
        string maskedQuery = SecretMasker.Default.MaskQueryString("/a?%70assword=hunter2hunter2");
        string maskedJson = SecretMasker.Default.MaskJson("""{"password":"hunter2hunter2"}""");

        Assert.AreEqual("/a?%70assword=****", maskedQuery);
        Assert.AreEqual("""{"password":"****"}""", maskedJson);
    }

    [TestMethod]
    public void MaskQueryString_MalformedPercentEscape_DoesNotThrow()
    {
        string masked = SecretMasker.Default.MaskQueryString("/a?ap%ZZiKey=abcdefghijklmnopqrst&apiKey=abcdefghijklmnopqrst");

        Assert.AreEqual("/a?ap%ZZiKey=abc****rst&apiKey=abc****rst", masked);
    }

    [TestMethod]
    public void MaskQueryString_BasicAuthCredentialsInTheAuthority_ArePartlyMasked()
    {
        // 這種位址沒有 '?',不處理的話整組 basic 認證憑證會原樣寫進日誌。
        string masked = SecretMasker.Default.MaskQueryString("https://user:hunter2@example.com/api");

        Assert.AreEqual("https://user:****@example.com/api", masked);
    }

    [TestMethod]
    public void MaskQueryString_BasicAuthCredentialsWithQuery_ArePartlyMasked()
    {
        string masked = SecretMasker.Default.MaskQueryString("https://user:hunter2@example.com/api?apiKey=abcdefghijklmnopqrst");

        Assert.AreEqual("https://user:****@example.com/api?apiKey=abc****rst", masked);
    }

    [TestMethod]
    public void MaskQueryString_AuthorityWithoutPassword_IsLeftAlone()
    {
        Assert.AreEqual("https://example.com/api", SecretMasker.Default.MaskQueryString("https://example.com/api"));
        Assert.AreEqual("https://user@example.com/api", SecretMasker.Default.MaskQueryString("https://user@example.com/api"));
    }

    [TestMethod]
    public void MaskQueryString_AtSignInsideTheQuery_IsNotMistakenForUserInfo()
    {
        string masked = SecretMasker.Default.MaskQueryString("https://example.com/api?email=a:b@example.com");

        Assert.AreEqual("https://example.com/api?email=a:b@example.com", masked);
    }

    [TestMethod]
    public void MaskQueryString_EmptyAuthority_IsLeftAlone()
    {
        // "//" 後面沒有任何 authority,不該在這裡誤判成 userinfo 或索引越界。
        Assert.AreEqual("//", SecretMasker.Default.MaskQueryString("//"));
        Assert.AreEqual("//?apiKey=abc****rst", SecretMasker.Default.MaskQueryString("//?apiKey=abcdefghijklmnopqrst"));
    }

    [TestMethod]
    public void MaskQueryString_PasswordParameter_IsMaskedInFull()
    {
        string masked = SecretMasker.Default.MaskQueryString("/login?user=alice&password=Tr0ub4dor3xy");

        Assert.AreEqual("/login?user=alice&password=****", masked);
    }
}
