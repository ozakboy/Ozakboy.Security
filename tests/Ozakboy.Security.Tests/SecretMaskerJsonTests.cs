using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="SecretMasker.MaskJson(string)"/> 的測試:只遮敏感欄位,其餘結構與型別保持原樣。
/// Tests for <see cref="SecretMasker.MaskJson(string)"/>: only sensitive fields are masked while the
/// rest of the structure and its value types survive untouched.
/// </summary>
[TestClass]
public sealed class SecretMaskerJsonTests
{
    [TestMethod]
    public void MaskJson_TopLevelSensitiveField_IsMasked()
    {
        const string json = """{"apiKey":"abcdefghijklmnopqrst","symbol":"BTCUSDT","quantity":1.5}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"apiKey":"abcd****qrst","symbol":"BTCUSDT","quantity":1.5}""", masked);
    }

    [TestMethod]
    public void MaskJson_FieldNames_MatchIgnoringCase()
    {
        const string json = """{"API_KEY":"abcdefghijklmnopqrst"}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"API_KEY":"abcd****qrst"}""", masked);
    }

    [TestMethod]
    public void MaskJson_NestedObject_IsMaskedRecursively()
    {
        const string json = """{"request":{"headers":{"signature":"0123456789abcdef"},"symbol":"ETHUSDT"}}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"request":{"headers":{"signature":"0123****cdef"},"symbol":"ETHUSDT"}}""", masked);
    }

    [TestMethod]
    public void MaskJson_SensitiveFieldHoldingObject_ReplacesWholeSubtree()
    {
        const string json = """{"authorization":{"scheme":"Bearer","token":"abcdefghijklmnopqrst"}}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"authorization":"****"}""", masked);
    }

    [TestMethod]
    public void MaskJson_ArrayElements_AreMaskedIndividually()
    {
        const string json = """{"items":[{"secret":"abcdefghijklmnopqrst"},"plain",7]}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"items":[{"secret":"abcd****qrst"},"plain",7]}""", masked);
    }

    [TestMethod]
    public void MaskJson_RootArray_IsSupported()
    {
        const string json = """[{"password":"abcdefghijklmnopqrst"}]""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""[{"password":"abcd****qrst"}]""", masked);
    }

    [TestMethod]
    public void MaskJson_SensitiveNumberOrNull_IsMaskedAsText()
    {
        const string json = """{"token":1234567890123456,"refreshToken":null}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"token":"1234****3456","refreshToken":"****"}""", masked);
    }

    [TestMethod]
    public void MaskJson_RootScalar_IsReturnedUnchanged()
    {
        Assert.AreEqual("\"plain\"", SecretMasker.Default.MaskJson("\"plain\""));
    }

    [TestMethod]
    public void MaskJson_NonAsciiText_StaysReadable()
    {
        const string json = """{"note":"中文備註"}""";

        string masked = SecretMasker.Default.MaskJson(json);

        Assert.AreEqual("""{"note":"中文備註"}""", masked, "非 ASCII 內容不該被轉成跳脫序列,否則日誌沒法讀。");
    }

    [TestMethod]
    public void MaskJson_InvalidJson_ThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(() => SecretMasker.Default.MaskJson("這不是 JSON"));
    }

    [TestMethod]
    public void MaskJson_Null_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => SecretMasker.Default.MaskJson(null!));
    }

    [TestMethod]
    public void TryMaskJson_ValidJson_ReturnsTrueAndMaskedText()
    {
        bool masked = SecretMasker.Default.TryMaskJson("""{"pwd":"abcdefghijklmnopqrst"}""", out string? result);

        Assert.IsTrue(masked);
        Assert.AreEqual("""{"pwd":"abcd****qrst"}""", result);
    }

    [TestMethod]
    public void TryMaskJson_InvalidJson_ReturnsFalseWithoutThrowing()
    {
        bool masked = SecretMasker.Default.TryMaskJson("{ broken", out string? result);

        Assert.IsFalse(masked);
        Assert.IsNull(result);
    }

    [TestMethod]
    public void TryMaskJson_Null_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => SecretMasker.Default.TryMaskJson(null!, out _));
    }

    [TestMethod]
    public void MaskJson_CustomSensitiveName_IsHonoured()
    {
        var masker = new SecretMasker(new SecretMaskOptions { AdditionalSensitiveNames = ["listenKey"] });

        string masked = masker.MaskJson("""{"listenKey":"abcdefghijklmnopqrst"}""");

        Assert.AreEqual("""{"listenKey":"abcd****qrst"}""", masked);
    }
}
