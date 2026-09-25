using Microsoft.Extensions.Configuration;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security.Configuration;

/// <summary>
/// 包住既有 <see cref="IConfigurationSource"/> 的來源:建出來的提供者會把受保護的值在讀取時解密。
/// 由 <see cref="ProtectedValueConfigurationBuilderExtensions.DecryptProtectedValues"/> 建立,不直接公開。
/// A source wrapping an existing <see cref="IConfigurationSource"/>; the provider it builds decrypts
/// protected values on read. Created by
/// <see cref="ProtectedValueConfigurationBuilderExtensions.DecryptProtectedValues"/>; not public.
/// </summary>
internal sealed class ProtectedValueConfigurationSource : IConfigurationSource
{
    private readonly IConfigurationSource _inner;
    private readonly ISecretProtector _protector;
    private readonly Func<string?, bool> _isProtectedValue;

    /// <summary>
    /// 建立包裝來源。
    /// Creates the wrapping source.
    /// </summary>
    /// <param name="inner">
    /// 被包住的原始來源。
    /// The original source being wrapped.
    /// </param>
    /// <param name="protector">
    /// 用來解密的保護器。
    /// The protector used to decrypt.
    /// </param>
    /// <param name="isProtectedValue">
    /// 判斷值是否受保護的述詞。
    /// The predicate deciding whether a value is protected.
    /// </param>
    public ProtectedValueConfigurationSource(IConfigurationSource inner, ISecretProtector protector, Func<string?, bool> isProtectedValue)
    {
        _inner = inner;
        _protector = protector;
        _isProtectedValue = isProtectedValue;
    }

    /// <summary>
    /// 被包住的原始來源。
    /// The original source being wrapped.
    /// </summary>
    public IConfigurationSource Inner => _inner;

    /// <inheritdoc />
    public IConfigurationProvider Build(IConfigurationBuilder builder)
        => new ProtectedValueConfigurationProvider(_inner.Build(builder), _protector, _isProtectedValue);
}
