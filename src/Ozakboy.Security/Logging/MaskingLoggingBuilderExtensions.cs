using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security.Logging;

/// <summary>
/// <see cref="ILoggingBuilder"/> 的擴充:把容器裡的 <see cref="ILoggerFactory"/> 換成會遮罩的 <see cref="MaskingLoggerFactory"/>。
/// Extensions for <see cref="ILoggingBuilder"/> that swap the container's <see cref="ILoggerFactory"/> for the masking
/// <see cref="MaskingLoggerFactory"/>.
/// </summary>
public static class MaskingLoggingBuilderExtensions
{
    /// <summary>
    /// 已經掛過的標記,讓重複呼叫成為 no-op。
    /// A marker recording that masking is already attached, so a repeated call is a no-op.
    /// </summary>
    private sealed class MaskingAttachedMarker
    {
    }

    /// <summary>
    /// 讓所有經由 <see cref="ILoggerFactory"/> / <c>ILogger&lt;T&gt;</c> 取得的記錄器都先經過遮罩。
    /// 遮罩器取自容器中的 <see cref="SecretMasker"/>(由 <c>AddOzakboySecurity</c> 註冊),沒有的話退回 <see cref="SecretMasker.Default"/>;
    /// 「依名稱遮屬性」的開關取自 <see cref="SecretMaskingOptions.MaskLogPropertiesByName"/>。
    /// Makes every logger obtained through <see cref="ILoggerFactory"/> / <c>ILogger&lt;T&gt;</c> pass through masking.
    /// The masker is the container's <see cref="SecretMasker"/> (registered by <c>AddOzakboySecurity</c>), falling back to
    /// <see cref="SecretMasker.Default"/>; the mask-by-name switch comes from
    /// <see cref="SecretMaskingOptions.MaskLogPropertiesByName"/>.
    /// </summary>
    /// <param name="builder">
    /// 日誌建構器,不可為 <see langword="null"/>。
    /// The logging builder; must not be <see langword="null"/>.
    /// </param>
    /// <returns>
    /// 同一個建構器,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <remarks>
    /// <para>
    /// 做法是把現有的 <see cref="ILoggerFactory"/> 註冊(通常是 <c>AddLogging</c> 放進去的 <c>LoggerFactory</c>)取出來,
    /// 換成「先用原註冊建出內層、再包一層 <see cref="MaskingLoggerFactory"/>」的工廠註冊。因為包的是工廠而不是個別提供者,
    /// 在這個呼叫之後才 <c>AddConsole()</c> / <c>AddProvider()</c> 的提供者一樣被涵蓋,順序無所謂。
    /// It takes the existing <see cref="ILoggerFactory"/> registration (usually the <c>LoggerFactory</c> that
    /// <c>AddLogging</c> put there) and replaces it with a factory registration that builds the inner factory from the
    /// original descriptor and wraps it in a <see cref="MaskingLoggerFactory"/>. Because the factory rather than each
    /// provider is wrapped, providers added after this call (<c>AddConsole()</c>, <c>AddProvider()</c>) are covered too,
    /// and ordering does not matter.
    /// </para>
    /// <para>
    /// 涵蓋不到的路徑:直接解析 <see cref="ILoggerProvider"/> 自己建記錄器的程式碼,以及不經 Microsoft.Extensions.Logging 的日誌函式庫。
    /// Not covered: code that resolves an <see cref="ILoggerProvider"/> and creates loggers itself, and logging libraries
    /// that bypass Microsoft.Extensions.Logging altogether.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// 容器裡沒有 <see cref="ILoggerFactory"/> 註冊時擲出(請先呼叫 <c>AddLogging</c>)。
    /// Thrown when the container has no <see cref="ILoggerFactory"/> registration (call <c>AddLogging</c> first).
    /// </exception>
    public static ILoggingBuilder AddOzakboySecretMasking(this ILoggingBuilder builder)
        => AddCore(builder, masker: null, maskPropertiesByName: null);

    /// <summary>
    /// 同 <see cref="AddOzakboySecretMasking(ILoggingBuilder)"/>,但使用指定的遮罩器與開關,不從容器取。
    /// The same as <see cref="AddOzakboySecretMasking(ILoggingBuilder)"/>, but with an explicit masker and switch rather
    /// than the container's.
    /// </summary>
    /// <param name="builder">
    /// 日誌建構器,不可為 <see langword="null"/>。
    /// The logging builder; must not be <see langword="null"/>.
    /// </param>
    /// <param name="masker">
    /// 遮罩器,不可為 <see langword="null"/>。
    /// The masker; must not be <see langword="null"/>.
    /// </param>
    /// <param name="maskPropertiesByName">
    /// 是否依屬性名稱遮結構化屬性。
    /// Whether to mask structured properties by name.
    /// </param>
    /// <returns>
    /// 同一個建構器,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> 或 <paramref name="masker"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="builder"/> or <paramref name="masker"/> is <see langword="null"/>.
    /// </exception>
    public static ILoggingBuilder AddOzakboySecretMasking(this ILoggingBuilder builder, SecretMasker masker, bool maskPropertiesByName = true)
    {
        ArgumentNullException.ThrowIfNull(masker);
        return AddCore(builder, masker, maskPropertiesByName);
    }

    /// <summary>
    /// 共同實作:找出 <see cref="ILoggerFactory"/> 的最後一筆非具名註冊並以包裝工廠取代。
    /// The shared implementation: finds the last unkeyed <see cref="ILoggerFactory"/> registration and replaces it with
    /// the wrapping factory.
    /// </summary>
    /// <param name="builder">
    /// 日誌建構器。
    /// The logging builder.
    /// </param>
    /// <param name="masker">
    /// 指定的遮罩器,<see langword="null"/> 表示從容器取。
    /// The explicit masker, or <see langword="null"/> to take the container's.
    /// </param>
    /// <param name="maskPropertiesByName">
    /// 指定的開關,<see langword="null"/> 表示從 Options 取。
    /// The explicit switch, or <see langword="null"/> to take it from the Options.
    /// </param>
    /// <returns>
    /// 同一個建構器。
    /// The same builder.
    /// </returns>
    private static ILoggingBuilder AddCore(ILoggingBuilder builder, SecretMasker? masker, bool? maskPropertiesByName)
    {
        ArgumentNullException.ThrowIfNull(builder);
        IServiceCollection services = builder.Services;

        if (services.Any(static descriptor => descriptor.ServiceType == typeof(MaskingAttachedMarker)))
        {
            return builder;
        }

        ServiceDescriptor? original = null;
        for (int i = services.Count - 1; i >= 0; i--)
        {
            ServiceDescriptor candidate = services[i];
            if (candidate.ServiceType == typeof(ILoggerFactory) && !candidate.IsKeyedService)
            {
                original = candidate;
                break;
            }
        }

        if (original is null)
        {
            throw new InvalidOperationException(
                "容器裡沒有 ILoggerFactory 的註冊,無法掛上遮罩。請先呼叫 AddLogging(在 ASP.NET Core 裡 Host 已經做了)。 " +
                "The container has no ILoggerFactory registration to wrap. Call AddLogging first (the ASP.NET Core host already does).");
        }

        Func<IServiceProvider, object> createInner = CreateInnerFactory(original);
        services.Remove(original);
        services.Add(new ServiceDescriptor(
            typeof(ILoggerFactory),
            provider => new MaskingLoggerFactory(
                (ILoggerFactory)createInner(provider),
                masker ?? provider.GetService<SecretMasker>() ?? SecretMasker.Default,
                maskPropertiesByName ?? provider.GetService<IOptions<SecretMaskingOptions>>()?.Value.MaskLogPropertiesByName ?? true),
            original.Lifetime));
        services.AddSingleton(new MaskingAttachedMarker());

        return builder;
    }

    /// <summary>
    /// 把原本的 <see cref="ServiceDescriptor"/> 轉成能建出內層工廠的委派,三種註冊方式(型別、工廠、實例)都支援。
    /// Turns the original <see cref="ServiceDescriptor"/> into a delegate that builds the inner factory, for all three
    /// registration shapes (type, factory, instance).
    /// </summary>
    /// <param name="descriptor">
    /// 原本的註冊。
    /// The original registration.
    /// </param>
    /// <returns>
    /// 建立內層工廠的委派。
    /// The delegate that builds the inner factory.
    /// </returns>
    private static Func<IServiceProvider, object> CreateInnerFactory(ServiceDescriptor descriptor)
    {
        if (descriptor.ImplementationInstance is { } instance)
        {
            return _ => instance;
        }

        if (descriptor.ImplementationFactory is { } factory)
        {
            return factory;
        }

        Type implementationType = descriptor.ImplementationType
            ?? throw new InvalidOperationException("ILoggerFactory 的註冊沒有實作型別、工廠或實例。 The ILoggerFactory registration has no implementation type, factory or instance.");
        return provider => ActivatorUtilities.CreateInstance(provider, implementationType);
    }
}
