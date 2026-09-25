using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Logging;

/// <summary>
/// 把內層 <see cref="ILoggerFactory"/> 建出來的每個記錄器包成 <see cref="MaskingLogger"/> 的工廠。
/// 在工廠這一層包,<c>ILogger&lt;T&gt;</c>(它經由工廠取記錄器)與直接 <c>CreateLogger</c> 的呼叫端都會被涵蓋,
/// 之後才加進來的提供者也一樣 —— 不必知道內層是哪個實作。
/// A factory that wraps every logger the inner <see cref="ILoggerFactory"/> creates in a <see cref="MaskingLogger"/>.
/// Wrapping at the factory covers <c>ILogger&lt;T&gt;</c> (which obtains its logger through the factory) and direct
/// <c>CreateLogger</c> callers alike, as well as providers added later, without knowing which implementation sits inside.
/// </summary>
public sealed class MaskingLoggerFactory : ILoggerFactory
{
    private readonly ILoggerFactory _inner;
    private readonly SecretMasker _masker;
    private readonly bool _maskPropertiesByName;
    private readonly ConcurrentDictionary<string, MaskingLogger> _loggers = new(StringComparer.Ordinal);

    /// <summary>
    /// 建立包裝工廠。內層工廠的生命週期由這個物件接管:<see cref="Dispose"/> 會一併釋放它。
    /// Creates the wrapping factory. It takes ownership of the inner factory: <see cref="Dispose"/> disposes it too.
    /// </summary>
    /// <param name="inner">
    /// 內層工廠,不可為 <see langword="null"/>。
    /// The inner factory; must not be <see langword="null"/>.
    /// </param>
    /// <param name="masker">
    /// 遮罩器,不可為 <see langword="null"/>。
    /// The masker; must not be <see langword="null"/>.
    /// </param>
    /// <param name="maskPropertiesByName">
    /// 是否依屬性名稱遮結構化屬性。
    /// Whether to mask structured properties by name.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="inner"/> 或 <paramref name="masker"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="inner"/> or <paramref name="masker"/> is <see langword="null"/>.
    /// </exception>
    public MaskingLoggerFactory(ILoggerFactory inner, SecretMasker masker, bool maskPropertiesByName = true)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(masker);
        _inner = inner;
        _masker = masker;
        _maskPropertiesByName = maskPropertiesByName;
    }

    /// <summary>
    /// 使用的遮罩器。
    /// The masker in use.
    /// </summary>
    public SecretMasker Masker => _masker;

    /// <inheritdoc />
    public ILogger CreateLogger(string categoryName)
        => _loggers.GetOrAdd(categoryName, static (name, self) => new MaskingLogger(self._inner.CreateLogger(name), self._masker, self._maskPropertiesByName), this);

    /// <inheritdoc />
    public void AddProvider(ILoggerProvider provider) => _inner.AddProvider(provider);

    /// <inheritdoc />
    public void Dispose() => _inner.Dispose();
}
