using System.Security.Cryptography;
using System.Text;
using Ozakboy.Security.Configuration;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="KeyDerivation"/> 的測試:同樣輸入必然派生出同一把金鑰,參數把關要擋住太弱的設定。
/// Tests for <see cref="KeyDerivation"/>: identical inputs always derive the same key, and the guard
/// rails reject settings that would be too weak to matter.
/// </summary>
[TestClass]
public sealed class KeyDerivationTests
{
    private const int FastIterations = KeyDerivation.MinimumIterations;

    [TestMethod]
    public void DeriveKey_SameInputs_ProduceSameKey()
    {
        byte[] salt = KeyDerivation.CreateSalt();

        byte[] first = KeyDerivation.DeriveKey("correct horse battery staple", salt, FastIterations);
        byte[] second = KeyDerivation.DeriveKey("correct horse battery staple", salt, FastIterations);

        CollectionAssert.AreEqual(first, second);
    }

    [TestMethod]
    public void DeriveKey_DifferentSalt_ProducesDifferentKey()
    {
        byte[] first = KeyDerivation.DeriveKey("password", KeyDerivation.CreateSalt(), FastIterations);
        byte[] second = KeyDerivation.DeriveKey("password", KeyDerivation.CreateSalt(), FastIterations);

        CollectionAssert.AreNotEqual(first, second, "不同鹽值必須派生出不同金鑰,否則彩虹表就有用武之地。");
    }

    [TestMethod]
    public void DeriveKey_DifferentPassword_ProducesDifferentKey()
    {
        byte[] salt = KeyDerivation.CreateSalt();

        byte[] first = KeyDerivation.DeriveKey("password-a", salt, FastIterations);
        byte[] second = KeyDerivation.DeriveKey("password-b", salt, FastIterations);

        CollectionAssert.AreNotEqual(first, second);
    }

    [TestMethod]
    public void DeriveKey_DifferentIterationCount_ProducesDifferentKey()
    {
        byte[] salt = KeyDerivation.CreateSalt();

        byte[] first = KeyDerivation.DeriveKey("password", salt, FastIterations);
        byte[] second = KeyDerivation.DeriveKey("password", salt, FastIterations + 1);

        CollectionAssert.AreNotEqual(first, second);
    }

    [TestMethod]
    public void DeriveKey_ReturnsRequestedKeyLength()
    {
        byte[] salt = KeyDerivation.CreateSalt();

        Assert.HasCount(32, KeyDerivation.DeriveKey("password", salt, FastIterations));
        Assert.HasCount(16, KeyDerivation.DeriveKey("password", salt, FastIterations, 16));
    }

    [TestMethod]
    public void DeriveKey_ResultIsUsableAsConfigurationKey()
    {
        byte[] key = KeyDerivation.DeriveKey("password", KeyDerivation.CreateSalt(), FastIterations);

        string encrypted = ConfigurationProtector.Encrypt("payload", key);

        Assert.AreEqual("payload", ConfigurationProtector.Decrypt(encrypted, key));
    }

    [TestMethod]
    public void DeriveKey_NullPassword_ThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(
            () => KeyDerivation.DeriveKey((string)null!, KeyDerivation.CreateSalt(), FastIterations));
    }

    [TestMethod]
    public void DeriveKey_IterationsBelowMinimum_ThrowsArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => KeyDerivation.DeriveKey("password", KeyDerivation.CreateSalt(), KeyDerivation.MinimumIterations - 1));
    }

    [TestMethod]
    public void DeriveKey_SaltTooShort_ThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => KeyDerivation.DeriveKey("password", new byte[KeyDerivation.MinimumSaltLengthInBytes - 1], FastIterations));
    }

    [TestMethod]
    public void DeriveKey_NonPositiveKeyLength_ThrowsArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => KeyDerivation.DeriveKey("password", KeyDerivation.CreateSalt(), FastIterations, 0));
    }

    [TestMethod]
    public void CreateSalt_ReturnsRequestedLengthAndVariesEachCall()
    {
        byte[] first = KeyDerivation.CreateSalt();
        byte[] second = KeyDerivation.CreateSalt();

        Assert.HasCount(KeyDerivation.DefaultSaltLengthInBytes, first);
        Assert.HasCount(24, KeyDerivation.CreateSalt(24));
        CollectionAssert.AreNotEqual(first, second, "鹽值必須每次隨機產生。");
    }

    [TestMethod]
    public void CreateSalt_TooShort_ThrowsArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => KeyDerivation.CreateSalt(KeyDerivation.MinimumSaltLengthInBytes - 1));
    }

    [TestMethod]
    public void CreateKey_ReturnsRequestedLengthAndVariesEachCall()
    {
        byte[] first = KeyDerivation.CreateKey();
        byte[] second = KeyDerivation.CreateKey();

        Assert.HasCount(KeyDerivation.DefaultKeyLengthInBytes, first);
        Assert.HasCount(16, KeyDerivation.CreateKey(16));
        CollectionAssert.AreNotEqual(first, second, "金鑰必須每次隨機產生。");
    }

    [TestMethod]
    public void CreateKey_NonPositiveLength_ThrowsArgumentOutOfRangeException()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KeyDerivation.CreateKey(0));
    }

    [TestMethod]
    public void DeriveKey_ByteSpanPassword_MatchesTheStringOverload()
    {
        // 位元組多載存在的理由是密碼的生命週期可控,不是換一套派生規則;結果必須與字串多載完全一致。
        byte[] salt = KeyDerivation.CreateSalt();
        byte[] passwordBytes = Encoding.UTF8.GetBytes("correct horse battery staple");

        byte[] fromBytes = KeyDerivation.DeriveKey(passwordBytes.AsSpan(), salt, FastIterations);
        byte[] fromString = KeyDerivation.DeriveKey("correct horse battery staple", salt, FastIterations);

        CollectionAssert.AreEqual(fromString, fromBytes);

        // 用完立刻歸零,這正是字串多載做不到的事。
        CryptographicOperations.ZeroMemory(passwordBytes);
        Assert.IsTrue(passwordBytes.All(static b => b == 0), "密碼緩衝區必須可以被清零。");
    }

    [TestMethod]
    public void DeriveKey_ByteSpanPassword_NonAsciiMatchesUtf8Encoding()
    {
        byte[] salt = KeyDerivation.CreateSalt();
        const string password = "繁體中文通行碼";

        byte[] fromBytes = KeyDerivation.DeriveKey(Encoding.UTF8.GetBytes(password), salt, FastIterations);
        byte[] fromString = KeyDerivation.DeriveKey(password, salt, FastIterations);

        CollectionAssert.AreEqual(fromString, fromBytes, "字串多載即是以 UTF-8 編碼後派生。");
    }

    [TestMethod]
    public void DeriveKey_ByteSpanPassword_ValidatesSaltAndIterations()
    {
        byte[] password = Encoding.UTF8.GetBytes("password");

        Assert.ThrowsExactly<ArgumentException>(
            () => KeyDerivation.DeriveKey(password.AsSpan(), new byte[KeyDerivation.MinimumSaltLengthInBytes - 1], FastIterations));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => KeyDerivation.DeriveKey(password.AsSpan(), KeyDerivation.CreateSalt(), KeyDerivation.MinimumIterations - 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => KeyDerivation.DeriveKey(password.AsSpan(), KeyDerivation.CreateSalt(), FastIterations, 0));
    }

    [TestMethod]
    public void DeriveKey_ByteSpanPassword_ReturnsRequestedKeyLength()
    {
        byte[] salt = KeyDerivation.CreateSalt();
        byte[] password = Encoding.UTF8.GetBytes("password");

        Assert.HasCount(32, KeyDerivation.DeriveKey(password.AsSpan(), salt));
        Assert.HasCount(16, KeyDerivation.DeriveKey(password.AsSpan(), salt, FastIterations, 16));
    }

    [TestMethod]
    public void DeriveKey_SaltOf15Bytes_IsRejectedWhile16BytesIsAccepted()
    {
        // NIST SP 800-132 對 PBKDF2 鹽值的建議下限是 128 bits;15 位元組必須被擋下。
        Assert.ThrowsExactly<ArgumentException>(
            () => KeyDerivation.DeriveKey("password", new byte[15], FastIterations));
        Assert.HasCount(32, KeyDerivation.DeriveKey("password", new byte[16], FastIterations));
        Assert.HasCount(KeyDerivation.MinimumSaltLengthInBytes, KeyDerivation.CreateSalt());
    }

    [TestMethod]
    public void DeriveKey_WithoutIterationArgument_UsesDefaultIterations()
    {
        // 直接比對「不傳迭代次數」與「明示傳入 DefaultIterations」的結果,確認預設值真的被套用。
        byte[] salt = KeyDerivation.CreateSalt();

        byte[] implicitDefault = KeyDerivation.DeriveKey("password", salt);
        byte[] explicitDefault = KeyDerivation.DeriveKey("password", salt, KeyDerivation.DefaultIterations);

        CollectionAssert.AreEqual(implicitDefault, explicitDefault);
    }
}
