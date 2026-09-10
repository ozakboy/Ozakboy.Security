using Ozakboy.Security;

namespace Ozakboy.Security.Tests;

/// <summary>
/// <see cref="SecretProtectionException"/> 的建構行為測試。
/// Tests for how <see cref="SecretProtectionException"/> is constructed.
/// </summary>
[TestClass]
public sealed class SecretProtectionExceptionTests
{
    [TestMethod]
    public void DefaultConstructor_HasMessageAndNoReason()
    {
        var exception = new SecretProtectionException();

        Assert.AreEqual(SecretProtectionFailureReason.None, exception.Reason);
        Assert.IsNotEmpty(exception.Message);
    }

    [TestMethod]
    public void MessageConstructor_KeepsTheMessage()
    {
        var exception = new SecretProtectionException("壞掉了");

        Assert.AreEqual("壞掉了", exception.Message);
        Assert.AreEqual(SecretProtectionFailureReason.None, exception.Reason);
    }

    [TestMethod]
    public void MessageAndInnerConstructor_KeepsBoth()
    {
        var inner = new InvalidOperationException("內層");

        var exception = new SecretProtectionException("外層", inner);

        Assert.AreEqual("外層", exception.Message);
        Assert.AreSame(inner, exception.InnerException);
    }

    [TestMethod]
    public void ReasonConstructor_KeepsReasonMessageAndInner()
    {
        var inner = new InvalidOperationException("內層");

        var exception = new SecretProtectionException(
            SecretProtectionFailureReason.ScopeMismatch,
            "範圍不符",
            inner);

        Assert.AreEqual(SecretProtectionFailureReason.ScopeMismatch, exception.Reason);
        Assert.AreEqual("範圍不符", exception.Message);
        Assert.AreSame(inner, exception.InnerException);
    }
}
