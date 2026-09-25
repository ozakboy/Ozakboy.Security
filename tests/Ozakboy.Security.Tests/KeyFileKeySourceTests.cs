using Ozakboy.Security;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="KeyFileKeySource"/> 的測試:用真實的暫存檔驗證存在、長度、兩種內容格式,
/// 以及 Unix 上的權限檢查(那部分在 Windows 上沒有對應的機制,標記為 Unix 分類並略過)。
/// Tests for <see cref="KeyFileKeySource"/>: real temporary files exercise existence, length, both content
/// formats, and the Unix permission check (which has no Windows counterpart; those are tagged Unix and skipped there).
/// </summary>
[TestClass]
public sealed class KeyFileKeySourceTests
{
    private static byte[] CreateTestKey() => Enumerable.Range(0, 32).Select(i => (byte)(255 - i)).ToArray();

    /// <summary>
    /// 在專屬的暫存目錄裡建立金鑰檔;Unix 上順便設成 0600,讓「正常情況」的測試不被權限檢查擋下。
    /// Creates a key file in a private temporary directory, set to 0600 on Unix so the happy-path tests
    /// are not stopped by the permission check.
    /// </summary>
    private static string WriteKeyFile(byte[] content, UnixFileMode? mode = null)
    {
        string directory = Path.Combine(Path.GetTempPath(), "ozakboy-security-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "app.key");
        File.WriteAllBytes(path, content);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, mode ?? (UnixFileMode.UserRead | UnixFileMode.UserWrite));
        }

        return path;
    }

    private static void RequireUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Unix 權限位元在 Windows 上沒有對應機制,本測試略過。");
        }
    }

    [TestMethod]
    public void ReadKey_RawThirtyTwoBytes_ReturnsTheKey()
    {
        byte[] key = CreateTestKey();
        string path = WriteKeyFile(key);

        CollectionAssert.AreEqual(key, new KeyFileKeySource(path).ReadKey());
    }

    [TestMethod]
    public void ReadKey_Base64TextWithTrailingNewline_ReturnsTheKey()
    {
        byte[] key = CreateTestKey();
        string path = WriteKeyFile(System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(key) + "\n"));

        CollectionAssert.AreEqual(key, new KeyFileKeySource(path).ReadKey());
    }

    [TestMethod]
    public void ReadKey_ReturnsAFreshArrayEveryCall()
    {
        string path = WriteKeyFile(CreateTestKey());
        var source = new KeyFileKeySource(path);

        Assert.AreNotSame(source.ReadKey(), source.ReadKey());
    }

    [TestMethod]
    public void ReadKey_MissingFile_ReportsKeyUnavailable_NamingThePath()
    {
        string path = Path.Combine(Path.GetTempPath(), "ozakboy-security-tests", Guid.NewGuid().ToString("N"), "missing.key");

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, path);
    }

    [TestMethod]
    public void ReadKey_WrongRawLength_ReportsKeyUnavailable()
    {
        string path = WriteKeyFile(new byte[31]);

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "31");
    }

    [TestMethod]
    public void ReadKey_Base64OfWrongLength_ReportsKeyUnavailable()
    {
        string path = WriteKeyFile(System.Text.Encoding.ASCII.GetBytes(Convert.ToBase64String(new byte[24])));

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "24");
    }

    [TestMethod]
    public void ReadKey_GarbageContent_ReportsKeyUnavailable_WithoutEchoingIt()
    {
        const string garbage = "definitely not a key, and not base64 either!!";
        string path = WriteKeyFile(System.Text.Encoding.ASCII.GetBytes(garbage));

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        Assert.IsFalse(exception.Message.Contains(garbage, StringComparison.Ordinal));
    }

    [TestMethod]
    [TestCategory("Unix")]
    public void ReadKey_GroupReadable_IsRefused_WithChmodGuidance()
    {
        RequireUnix();
        string path = WriteKeyFile(CreateTestKey(), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "640");
        StringAssert.Contains(exception.Message, "chmod 600");
        StringAssert.Contains(exception.Message, "GroupRead");
    }

    [TestMethod]
    [TestCategory("Unix")]
    public void ReadKey_WorldReadable_IsRefused()
    {
        RequireUnix();
        string path = WriteKeyFile(CreateTestKey(), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "644");
    }

    [TestMethod]
    [TestCategory("Unix")]
    public void ReadKey_OtherWritableOnly_IsRefused()
    {
        RequireUnix();
        string path = WriteKeyFile(CreateTestKey(), UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherWrite);

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => new KeyFileKeySource(path).ReadKey());

        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
        StringAssert.Contains(exception.Message, "OtherWrite");
    }

    [TestMethod]
    [TestCategory("Unix")]
    public void ReadKey_OwnerReadOnly_IsAccepted()
    {
        RequireUnix();
        byte[] key = CreateTestKey();
        string path = WriteKeyFile(key, UnixFileMode.UserRead);

        CollectionAssert.AreEqual(key, new KeyFileKeySource(path).ReadKey());
    }

    [TestMethod]
    [TestCategory("Unix")]
    public void PermissionCheck_RunsOnEveryRead_NotOnlyTheFirst()
    {
        RequireUnix();
        string path = WriteKeyFile(CreateTestKey());
        var source = new KeyFileKeySource(path);
        _ = source.ReadKey();

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        }

        var exception = Assert.ThrowsExactly<SecretProtectionException>(() => source.ReadKey());
        Assert.AreEqual(SecretProtectionFailureReason.KeyUnavailable, exception.Reason);
    }

    [TestMethod]
    public void Constructor_ResolvesToFullPath_AndDescriptionNamesIt()
    {
        var source = new KeyFileKeySource("relative.key");

        Assert.IsTrue(Path.IsPathRooted(source.FilePath));
        StringAssert.Contains(source.Description, source.FilePath);
    }

    [TestMethod]
    public void Constructor_BlankPath_ThrowsArgumentException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new KeyFileKeySource(null!));
        Assert.ThrowsExactly<ArgumentException>(() => new KeyFileKeySource(" "));
    }

    [TestMethod]
    public void EndToEnd_ProtectorOverKeyFile_RoundTrips()
    {
        string path = WriteKeyFile(CreateTestKey());
        var protector = new KeyedSecretProtector(new KeyFileKeySource(path));

        string stored = protector.Protect("db-password-value");

        Assert.IsTrue(protector.TryUnprotect(stored, out string? plainText));
        Assert.AreEqual("db-password-value", plainText);
    }
}
