using System.Collections.Concurrent;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="SecretMasker.RegisterKnownSecret(string)"/> 與 <see cref="SecretMasker.MaskText(string?)"/> 的測試:
/// 自由文字(格式化日誌、例外訊息)是金鑰最常見的外洩路徑,呼叫端在那些地方沒機會逐欄位交出值。
/// Tests for <see cref="SecretMasker.RegisterKnownSecret(string)"/> and
/// <see cref="SecretMasker.MaskText(string?)"/>: free-form text such as formatted log messages and
/// exception output is where credentials leak most often, and the caller never gets to hand values over
/// field by field there.
/// </summary>
/// <remarks>
/// 每個測試都建立自己的 <see cref="SecretMasker"/> 實例,不碰 <see cref="SecretMasker.Default"/>:
/// 測試以方法層級平行執行,共用單例的已登記清單會讓測試互相汙染。
/// Every test builds its own <see cref="SecretMasker"/> and leaves <see cref="SecretMasker.Default"/>
/// alone: tests run in parallel at method level, and a shared registry would let them contaminate one
/// another.
/// </remarks>
[TestClass]
public sealed class SecretMaskerTextTests
{
    private const string ApiKey = "vmPUZE6mv9SD5VNHk4HlWFsOr6aKE9Uc9qc3trIgm2VBu4Yhr7hDLmSyPYQyDT2E";

    [TestMethod]
    public void MaskText_RegisteredSecretInFormattedLogMessage_IsReplaced()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        // 這正是 logger.LogError("下單失敗 key={Key}", apiKey) 之後留在日誌裡的樣子。
        string masked = masker.MaskText($"下單失敗 key={ApiKey} symbol=BTCUSDT");

        Assert.AreEqual("下單失敗 key=**** symbol=BTCUSDT", masked);
        Assert.IsFalse(masked.Contains(ApiKey, StringComparison.Ordinal));
    }

    [TestMethod]
    public void MaskText_SecretInsideExceptionText_IsReplaced()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        var exception = new InvalidOperationException($"呼叫 /api/v3/order?apiKey={ApiKey} 失敗");
        string masked = masker.MaskText(exception.ToString());

        Assert.IsFalse(masked.Contains(ApiKey, StringComparison.Ordinal), "例外訊息裡的金鑰必須被攔下來。");
        StringAssert.Contains(masked, "/api/v3/order?apiKey=****");
    }

    [TestMethod]
    public void MaskText_MultipleOccurrences_AreAllReplaced()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        string masked = masker.MaskText($"{ApiKey} 與 {ApiKey}");

        Assert.AreEqual("**** 與 ****", masked);
    }

    [TestMethod]
    public void MaskText_NestedSecrets_ReplaceTheLongerOneFirst()
    {
        var masker = new SecretMasker();
        const string longSecret = "abcdefghijklmnop";
        const string shortSecret = "abcdefgh";

        masker.RegisterKnownSecret(shortSecret);
        masker.RegisterKnownSecret(longSecret);

        // 先換短的會在輸出留下 ****ijklmnop 這種殘片,所以登記清單依長度由長到短排序。
        Assert.AreEqual("****", masker.MaskText(longSecret));
    }

    [TestMethod]
    public void MaskText_WithoutAnyRegisteredSecret_ReturnsTheSameInstance()
    {
        var masker = new SecretMasker();
        const string text = "沒有登記任何祕密時,熱路徑不該有額外配置。";

        Assert.AreSame(text, masker.MaskText(text));
        Assert.AreEqual(0, masker.KnownSecretCount);
    }

    [TestMethod]
    public void MaskText_TextWithoutTheSecret_ReturnsTheSameInstance()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);
        const string text = "一般日誌內容,沒有夾帶祕密。";

        Assert.AreSame(text, masker.MaskText(text), "沒命中就不該配置新字串。");
    }

    [TestMethod]
    public void MaskText_NullOrEmpty_IsReturnedAsIs()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        Assert.IsNull(masker.MaskText(null));
        Assert.AreEqual(string.Empty, masker.MaskText(string.Empty));
    }

    [TestMethod]
    public void MaskText_UsesTheConfiguredMaskSegment()
    {
        var masker = new SecretMasker(new SecretMaskOptions { MaskCharacter = '#', MaskLength = 3 });
        masker.RegisterKnownSecret(ApiKey);

        Assert.AreEqual("key=###", masker.MaskText($"key={ApiKey}"));
    }

    [TestMethod]
    public void RegisterKnownSecret_SameValueTwice_IsRegisteredOnce()
    {
        var masker = new SecretMasker();

        Assert.IsTrue(masker.RegisterKnownSecret(ApiKey));
        Assert.IsFalse(masker.RegisterKnownSecret(ApiKey), "重複登記不應累積清單。");
        Assert.AreEqual(1, masker.KnownSecretCount);
    }

    [TestMethod]
    public void RegisterKnownSecret_TooShortValue_IsRejectedWithoutEchoingTheValue()
    {
        var masker = new SecretMasker();
        const string tooShort = "abc";

        var exception = Assert.ThrowsExactly<ArgumentException>(() => masker.RegisterKnownSecret(tooShort));

        Assert.IsFalse(
            exception.Message.Contains(tooShort, StringComparison.Ordinal),
            "例外訊息不得回述被拒絕的值 —— 呼叫端多半會把例外寫進日誌。");
        Assert.AreEqual(0, masker.KnownSecretCount);
    }

    [TestMethod]
    public void RegisterKnownSecret_ValueAtTheMinimumLength_IsAccepted()
    {
        var masker = new SecretMasker();
        string atMinimum = new('z', SecretMasker.MinimumKnownSecretLength);

        Assert.IsTrue(masker.RegisterKnownSecret(atMinimum));
        Assert.ThrowsExactly<ArgumentException>(
            () => masker.RegisterKnownSecret(new string('z', SecretMasker.MinimumKnownSecretLength - 1)));
    }

    [TestMethod]
    public void RegisterKnownSecret_WhitespaceOnlyValue_IsRejected()
    {
        var masker = new SecretMasker();

        Assert.ThrowsExactly<ArgumentException>(() => masker.RegisterKnownSecret("          "));
    }

    [TestMethod]
    public void RegisterKnownSecret_Null_ThrowsArgumentNullException()
    {
        var masker = new SecretMasker();

        Assert.ThrowsExactly<ArgumentNullException>(() => masker.RegisterKnownSecret(null!));
    }

    [TestMethod]
    public void RegisterKnownSecret_HexValue_AlsoCoversTheOtherCasing()
    {
        var masker = new SecretMasker();
        const string signature = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";

        masker.RegisterKnownSecret(signature);

        // 十六進位表示(簽章、雜湊)常在不同函式庫之間換大小寫,兩種寫法都要擋。
        Assert.AreEqual("sig=****", masker.MaskText("sig=" + signature));
        Assert.AreEqual("sig=****", masker.MaskText("sig=" + signature.ToUpperInvariant()));
    }

    [TestMethod]
    public void MaskText_NonHexSecret_IsMatchedCaseSensitively()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        // 憑證本身區分大小寫;若改成忽略大小寫比對,只是大小寫碰巧相同的一般文字也會被誤遮。
        string masked = masker.MaskText($"key={ApiKey.ToUpperInvariant()}");

        Assert.AreEqual($"key={ApiKey.ToUpperInvariant()}", masked);
    }

    [TestMethod]
    public void ClearKnownSecrets_EmptiesTheRegistry()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        masker.ClearKnownSecrets();

        Assert.AreEqual(0, masker.KnownSecretCount);
        Assert.AreEqual($"key={ApiKey}", masker.MaskText($"key={ApiKey}"));
    }

    [TestMethod]
    public void MaskJson_RegisteredSecretInsideAHarmlessField_IsStillMasked()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        // 欄位名無害不代表值裡沒夾帶憑證,這是逐欄位遮罩本身補不到的破口。
        string masked = masker.MaskJson($$"""{"message":"rejected for key {{ApiKey}}"}""");

        Assert.AreEqual("""{"message":"rejected for key ****"}""", masked);
    }

    [TestMethod]
    public void MaskQueryString_RegisteredSecretInAnUnnamedSegment_IsStillMasked()
    {
        var masker = new SecretMasker();
        masker.RegisterKnownSecret(ApiKey);

        string masked = masker.MaskQueryString($"/api/v3/session/{ApiKey}/orders?symbol=BTCUSDT");

        Assert.AreEqual("/api/v3/session/****/orders?symbol=BTCUSDT", masked);
    }

    [TestMethod]
    public void RegisterKnownSecret_AndMaskText_AreSafeUnderConcurrency()
    {
        var masker = new SecretMasker();
        const int secretCount = 64;
        string[] secrets = [.. Enumerable.Range(0, secretCount).Select(i => $"secret-value-{i:D4}-abcdefgh")];
        var damaged = new ConcurrentBag<string>();

        // 交易系統是多執行緒的:登記與遮罩會同時發生。
        // 每個迭代都先登記自己的祕密再遮罩,所以不論其他執行緒正在改什麼,這一筆都必須已經遮掉 ——
        // 讀到半成品的清單就會在這裡露餡。
        Parallel.For(0, secretCount * 4, index =>
        {
            string secret = secrets[index % secretCount];

            masker.RegisterKnownSecret(secret);

            string masked = masker.MaskText($"payload {secret} tail");
            if (!string.Equals(masked, "payload **** tail", StringComparison.Ordinal))
            {
                damaged.Add(masked);
            }
        });

        Assert.AreEqual(secretCount, masker.KnownSecretCount, "重複登記不得讓清單長出重複項目。");
        Assert.IsEmpty(damaged, "並行讀取不得讀到半成品的登記清單。");

        foreach (string secret in secrets)
        {
            Assert.AreEqual("payload **** tail", masker.MaskText($"payload {secret} tail"));
        }
    }
}
