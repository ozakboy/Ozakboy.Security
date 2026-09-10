using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="SecretMasker"/> 的字串遮罩行為測試,重點在短字串不得因「保留頭尾」而整串外洩。
/// Tests for <see cref="SecretMasker"/> string masking, focused on short values never leaking in full.
/// </summary>
[TestClass]
public sealed class SecretMaskerTests
{
    [TestMethod]
    public void Mask_LongValue_KeepsFourCharactersAtEachEnd()
    {
        string masked = SecretMasker.Default.Mask("abcdefghijklmnopqrstuvwxyz");

        Assert.AreEqual("abcd****wxyz", masked);
    }

    [TestMethod]
    public void Mask_ValueExactlyAtThreshold_RevealsBothEnds()
    {
        // 4(頭)+ 4(尾)+ 4(最少遮掉)= 12,剛好可以露出頭尾。
        string masked = SecretMasker.Default.Mask("abcdefghijkl");

        Assert.AreEqual("abcd****ijkl", masked);
    }

    [TestMethod]
    public void Mask_ValueShorterThanThreshold_MasksEverything()
    {
        const string alphabet = "abcdefghijk";

        for (int length = 1; length <= alphabet.Length; length++)
        {
            string value = alphabet[..length];
            string masked = SecretMasker.Default.Mask(value);

            Assert.AreEqual("****", masked, $"長度 {length} 的字串必須全遮,不得保留任何原字元。");
        }
    }

    [TestMethod]
    public void Mask_Null_ReturnsNull()
    {
        Assert.IsNull(SecretMasker.Default.Mask(null));
    }

    [TestMethod]
    public void Mask_EmptyString_ReturnsEmptyString()
    {
        Assert.AreEqual(string.Empty, SecretMasker.Default.Mask(string.Empty));
    }

    [TestMethod]
    public void Mask_VeryLongValue_ProducesFixedLengthOutput()
    {
        string longSecret = new('x', 10_000);
        string shorterSecret = new('x', 500);

        string maskedLong = SecretMasker.Default.Mask(longSecret);
        string maskedShorter = SecretMasker.Default.Mask(shorterSecret);

        Assert.AreEqual(12, maskedLong.Length);
        Assert.AreEqual(maskedLong.Length, maskedShorter.Length, "遮罩長度固定,輸出不得透露原字串長度。");
    }

    [TestMethod]
    public void Mask_CustomOptions_AppliesVisibleLengthsAndMaskCharacter()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            VisiblePrefixLength = 2,
            VisibleSuffixLength = 1,
            MaskLength = 6,
            MaskCharacter = '#',
            MinimumHiddenLength = 1,
        });

        Assert.AreEqual("ab######f", masker.Mask("abcdef"));
        Assert.AreEqual("######", masker.Mask("abc"), "長度不足時仍須全遮。");
    }

    [TestMethod]
    public void Mask_ZeroVisibleLengths_MasksEverything()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            VisiblePrefixLength = 0,
            VisibleSuffixLength = 0,
        });

        Assert.AreEqual("****", masker.Mask("abcdefghijklmnop"));
    }

    [TestMethod]
    public void MaskSegment_ReflectsConfiguredCharacterAndLength()
    {
        var masker = new SecretMasker(new SecretMaskOptions { MaskLength = 3, MaskCharacter = '?' });

        Assert.AreEqual("???", masker.MaskSegment);
    }

    [TestMethod]
    public void IsSensitiveName_BuiltInNames_MatchIgnoringCase()
    {
        SecretMasker masker = SecretMasker.Default;

        Assert.IsTrue(masker.IsSensitiveName("apiKey"));
        Assert.IsTrue(masker.IsSensitiveName("APIKEY"));
        Assert.IsTrue(masker.IsSensitiveName("ApI_KeY"));
        Assert.IsTrue(masker.IsSensitiveName("signature"));
        Assert.IsTrue(masker.IsSensitiveName("Authorization"));
        Assert.IsTrue(masker.IsSensitiveName("password"));
    }

    [TestMethod]
    public void IsSensitiveName_HarmlessOrEmptyNames_ReturnFalse()
    {
        SecretMasker masker = SecretMasker.Default;

        Assert.IsFalse(masker.IsSensitiveName("symbol"));
        Assert.IsFalse(masker.IsSensitiveName(null));
        Assert.IsFalse(masker.IsSensitiveName(string.Empty));
    }

    [TestMethod]
    public void IsSensitiveName_AdditionalNames_ExtendTheBuiltInList()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            AdditionalSensitiveNames = ["listenKey", "  "],
        });

        Assert.IsTrue(masker.IsSensitiveName("LISTENKEY"));
        Assert.IsTrue(masker.IsSensitiveName("apiKey"), "擴充名稱不應取代內建清單。");
        Assert.IsFalse(masker.IsSensitiveName("  "), "空白名稱應被忽略。");
    }

    [TestMethod]
    public void IsSensitiveName_WithoutDefaults_OnlyMatchesAdditionalNames()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            IncludeDefaultSensitiveNames = false,
            AdditionalSensitiveNames = ["listenKey"],
        });

        Assert.IsTrue(masker.IsSensitiveName("listenKey"));
        Assert.IsFalse(masker.IsSensitiveName("apiKey"));
    }

    [TestMethod]
    public void MaskNamedValue_MasksOnlySensitiveNames()
    {
        SecretMasker masker = SecretMasker.Default;

        Assert.AreEqual("****", masker.MaskNamedValue("apiKey", "short"));
        Assert.AreEqual("BTCUSDT", masker.MaskNamedValue("symbol", "BTCUSDT"));
        Assert.IsNull(masker.MaskNamedValue("apiKey", null));
    }

    [TestMethod]
    public void Constructor_NullOptions_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new SecretMasker(null!));
    }

    [TestMethod]
    public void Constructor_NegativeLengths_ThrowArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new SecretMasker(new SecretMaskOptions { VisiblePrefixLength = -1 }));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new SecretMasker(new SecretMaskOptions { VisibleSuffixLength = -1 }));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new SecretMasker(new SecretMaskOptions { MinimumHiddenLength = -1 }));
    }

    [TestMethod]
    public void Constructor_NonPositiveMaskLength_ThrowsArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new SecretMasker(new SecretMaskOptions { MaskLength = 0 }));
    }

    [TestMethod]
    public void Options_ExposesTheSuppliedInstance()
    {
        var options = new SecretMaskOptions { VisiblePrefixLength = 1 };
        var masker = new SecretMasker(options);

        Assert.AreSame(options, masker.Options);
    }

    [TestMethod]
    public void DefaultSensitiveNames_CoverCommonCredentialFields()
    {
        Assert.IsNotEmpty(SecretMaskOptions.DefaultSensitiveNames);
        CollectionAssert.Contains(SecretMaskOptions.DefaultSensitiveNames.ToList(), "signature");
    }
}
