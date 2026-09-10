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
    public void Mask_ValueExactlyAtThreshold_IsCappedByTheRevealRatio()
    {
        // 4(頭)+ 4(尾)+ 4(最少遮掉)= 12,長度剛好過設定的門檻;
        // 但 12 個字元最多只能露出 12 / 3 = 4 個,所以頭尾各自縮到 2。
        string masked = SecretMasker.Default.Mask("abcdefghijkl");

        Assert.AreEqual("ab****kl", masked);
    }

    [TestMethod]
    public void Mask_RevealedCharacters_NeverExceedOneThirdOfTheValue()
    {
        // 這條底線不論設定怎麼調都成立,是遮罩最後一道保險。
        var masker = new SecretMasker(new SecretMaskOptions
        {
            VisiblePrefixLength = 32,
            VisibleSuffixLength = 32,
            MaskLength = 1,
            MinimumHiddenLength = 1,
        });

        for (int length = 1; length <= 200; length++)
        {
            string value = string.Create(length, length, static (span, _) =>
            {
                for (int i = 0; i < span.Length; i++)
                {
                    span[i] = (char)('a' + (i % 26));
                }
            });

            string masked = masker.Mask(value);
            int revealed = masked.Length - masker.MaskSegment.Length;
            int allowed = length / SecretMasker.MaximumRevealedLengthDivisor;

            Assert.IsTrue(
                revealed <= allowed,
                $"長度 {length} 的值露出了 {revealed} 個字元,超過上限 {allowed}。");
        }
    }

    [TestMethod]
    public void Mask_EightCharacterSecret_IsNotReproducedInFull()
    {
        // 舊行為的破口:prefix 4 / suffix 4 / minHidden 0 會讓 8 個字元的祕密原封不動輸出成 abcd****efgh。
        // 現在 MinimumHiddenLength 的下限是 1,即使有人硬設 0 也會在建構子被擋下。
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new SecretMasker(new SecretMaskOptions { MinimumHiddenLength = 0 }));

        string masked = SecretMasker.Default.Mask("abcdefgh");

        Assert.AreEqual("****", masked);
        Assert.IsFalse(masked.Contains("abcd", StringComparison.Ordinal));
        Assert.IsFalse(masked.Contains("efgh", StringComparison.Ordinal));
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
    public void Mask_CustomOptions_AppliesMaskCharacterButStillObeysTheRevealRatio()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            VisiblePrefixLength = 2,
            VisibleSuffixLength = 1,
            MaskLength = 6,
            MaskCharacter = '#',
            MinimumHiddenLength = 1,
        });

        // 這組設定原本會讓 6 個字元的值露出 3 個(一半),遮了等於沒遮;
        // 現在露出字元數一律不得超過長度的 1/3,所以 6 個字元最多露出 2 個。
        string masked = masker.Mask("abcdef");

        Assert.AreEqual("ab######", masked);
        Assert.AreEqual(2, masked.Length - masker.MaskSegment.Length, "6 個字元的值最多只能露出 2 個。");
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

    [TestMethod]
    public void IsSensitiveName_ExchangeApiKeyHeaders_AreCovered()
    {
        SecretMasker masker = SecretMasker.Default;

        // 幣安以 X-MBX-APIKEY 這個標頭傳 API 金鑰,漏掉它等於整條下單路徑都沒遮。
        Assert.IsTrue(masker.IsSensitiveName("X-MBX-APIKEY"));
        Assert.IsTrue(masker.IsSensitiveName("x-mbx-apikey"));
        Assert.IsTrue(masker.IsSensitiveName("x-mbx-api-key"));
        Assert.IsTrue(masker.IsSensitiveName("x-api-key"));
        Assert.IsTrue(masker.IsSensitiveName("bearer"));
        Assert.IsTrue(masker.IsSensitiveName("jwt"));
        Assert.IsTrue(masker.IsSensitiveName("otp"));
        Assert.IsTrue(masker.IsSensitiveName("mnemonic"));
        Assert.IsTrue(masker.IsSensitiveName("seed"));
        Assert.IsTrue(masker.IsSensitiveName("sessionId"));
        Assert.IsTrue(masker.IsSensitiveName("sessionKey"));
        Assert.IsTrue(masker.IsSensitiveName("webhookSecret"));
        Assert.IsTrue(masker.IsSensitiveName("privateKey"));
        Assert.IsTrue(masker.IsSensitiveName("passphrase"));
    }

    [TestMethod]
    public void IsSensitiveName_SubstringMatching_CatchesNamingVariants()
    {
        SecretMasker masker = SecretMasker.Default;

        Assert.IsTrue(masker.Options.UseSubstringMatching, "包含式比對預設必須開啟。");
        Assert.IsTrue(masker.IsSensitiveName("binanceApiKey"));
        Assert.IsTrue(masker.IsSensitiveName("api_key_1"));
        Assert.IsTrue(masker.IsSensitiveName("Api-Key-Secret"));
        Assert.IsTrue(masker.IsSensitiveName("myAccessTokenForVenue"));
        Assert.IsTrue(masker.IsSensitiveName("dbPassword"));
        Assert.IsTrue(masker.IsSensitiveName("serviceCredentials"));
    }

    [TestMethod]
    public void IsSensitiveName_SubstringMatchingDisabled_FallsBackToExactMatching()
    {
        var masker = new SecretMasker(new SecretMaskOptions { UseSubstringMatching = false });

        Assert.IsTrue(masker.IsSensitiveName("apiKey"), "完全比對仍須有效。");
        Assert.IsFalse(masker.IsSensitiveName("binanceApiKey"), "關掉之後只做完全比對。");
    }

    [TestMethod]
    public void IsSensitiveName_AdditionalFragments_ExtendTheSubstringList()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            AdditionalSensitiveNameFragments = ["listen", "  "],
        });

        Assert.IsTrue(masker.IsSensitiveName("binanceListenIdentifier"));
        Assert.IsTrue(masker.IsSensitiveName("apiKey"), "擴充片段不應取代內建清單。");
        Assert.IsFalse(masker.IsSensitiveName("symbol"));
    }

    [TestMethod]
    public void IsAlwaysFullyMaskedName_PasswordLikeNames_AreMaskedInFull()
    {
        SecretMasker masker = SecretMasker.Default;

        Assert.IsTrue(masker.IsAlwaysFullyMaskedName("password"));
        Assert.IsTrue(masker.IsAlwaysFullyMaskedName("PASSWD"));
        Assert.IsTrue(masker.IsAlwaysFullyMaskedName("pwd"));
        Assert.IsTrue(masker.IsAlwaysFullyMaskedName("passphrase"));
        Assert.IsTrue(masker.IsAlwaysFullyMaskedName("binancePassword"), "包含式比對也要涵蓋全遮欄位。");
        Assert.IsFalse(masker.IsAlwaysFullyMaskedName("apiKey"), "高熵金鑰仍可保留頭尾以利辨識。");
        Assert.IsFalse(masker.IsAlwaysFullyMaskedName(null));
    }

    [TestMethod]
    public void MaskNamedValue_PasswordField_LeavesNothingVisible()
    {
        SecretMasker masker = SecretMasker.Default;

        // 13 個字元的人類密碼,舊行為會露出 8 個,配上密碼組成習慣幾乎等於明文。
        string masked = masker.MaskNamedValue("password", "Tr0ub4dor&3xy");

        Assert.AreEqual("****", masked);
        Assert.AreEqual("****", masker.MaskNamedValue("dbPassphrase", "correct horse battery staple"));
        Assert.AreEqual(string.Empty, masker.MaskNamedValue("password", string.Empty), "空值沒有東西可洩漏。");
        Assert.IsNull(masker.MaskNamedValue("password", null));
    }

    [TestMethod]
    public void MaskNamedValue_ApiKeyField_StillKeepsBothEndsForIdentification()
    {
        // 64 個字元的高熵金鑰:露出頭尾各 4 個字元(共 8 / 64,遠低於 1/3 上限)以利辨識是哪一把。
        string apiKey = new string('a', 30) + new string('b', 34);

        string masked = SecretMasker.Default.MaskNamedValue("x-mbx-apikey", apiKey);

        Assert.AreEqual("aaaa****bbbb", masked);
    }

    [TestMethod]
    public void FullMaskNames_CanBeExtendedByTheCaller()
    {
        var masker = new SecretMasker(new SecretMaskOptions
        {
            AdditionalFullMaskNames = ["withdrawWhitelistAddress"],
        });

        Assert.IsTrue(masker.IsAlwaysFullyMaskedName("withdrawWhitelistAddress"));
        Assert.IsTrue(masker.IsSensitiveName("withdrawWhitelistAddress"), "全遮欄位本來就屬於敏感欄位。");
        Assert.AreEqual("****", masker.MaskNamedValue("withdrawWhitelistAddress", "0x0123456789abcdef0123"));
    }

    [TestMethod]
    public void DefaultFullMaskNames_AndFragments_AreNotEmpty()
    {
        Assert.IsNotEmpty(SecretMaskOptions.DefaultFullMaskNames);
        Assert.IsNotEmpty(SecretMaskOptions.DefaultFullMaskNameFragments);
        Assert.IsNotEmpty(SecretMaskOptions.DefaultSensitiveNameFragments);
    }
}
