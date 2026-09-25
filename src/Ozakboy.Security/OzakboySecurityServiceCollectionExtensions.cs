using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Ozakboy.Security.Masking;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security;

/// <summary>
/// 把本套件掛進 DI 容器的擴充:註冊 <see cref="SecretMasker"/>(依 <see cref="SecretMaskingOptions"/> 建立)與
/// 呼叫端明確選定的 <see cref="ISecretProtector"/>。
/// Extensions that wire this library into a DI container: they register a <see cref="SecretMasker"/> (built from
/// <see cref="SecretMaskingOptions"/>) and whichever <see cref="ISecretProtector"/> the caller explicitly picks.
/// </summary>
public static class OzakboySecurityServiceCollectionExtensions
{
    /// <summary>
    /// 註冊 <see cref="SecretMasker"/> 單例(依 <see cref="SecretMaskingOptions"/> 建立、登記其中的已知祕密),
    /// 不註冊任何 <see cref="ISecretProtector"/>。只需要遮罩、不需要保護器的宿主用這個多載。
    /// Registers the <see cref="SecretMasker"/> singleton (built from <see cref="SecretMaskingOptions"/>, with its
    /// known secrets registered) and no <see cref="ISecretProtector"/>. For hosts that need masking but no protector.
    /// </summary>
    /// <param name="services">
    /// 服務集合,不可為 <see langword="null"/>。
    /// The service collection; must not be <see langword="null"/>.
    /// </param>
    /// <returns>
    /// 同一個服務集合,便於串接。
    /// The same service collection, for chaining.
    /// </returns>
    public static IServiceCollection AddOzakboySecurity(this IServiceCollection services)
        => AddOzakboySecurity(services, static _ => { });

    /// <summary>
    /// 註冊 <see cref="SecretMasker"/> 單例,並透過 <paramref name="configure"/> 選擇 <see cref="ISecretProtector"/>、
    /// 調整遮罩、登記已知祕密。
    /// Registers the <see cref="SecretMasker"/> singleton and lets <paramref name="configure"/> choose the
    /// <see cref="ISecretProtector"/>, adjust masking and register known secrets.
    /// </summary>
    /// <param name="services">
    /// 服務集合,不可為 <see langword="null"/>。
    /// The service collection; must not be <see langword="null"/>.
    /// </param>
    /// <param name="configure">
    /// 設定委派,不可為 <see langword="null"/>。
    /// The configuration delegate; must not be <see langword="null"/>.
    /// </param>
    /// <returns>
    /// 同一個服務集合,便於串接。
    /// The same service collection, for chaining.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <see cref="SecretMasker"/> 以 <c>TryAddSingleton</c> 註冊:宿主若已經自己註冊了一個,保留宿主的。
    /// 已知祕密在遮罩器<b>第一次被解析</b>時登記(那時 Options 才綁定完成),而不是在這個方法裡;
    /// 要確保啟動就登記,請在啟動流程早期解析一次 <see cref="SecretMasker"/>(日誌遮罩的 <c>AddOzakboySecretMasking</c> 會做這件事)。
    /// <see cref="SecretMasker"/> is registered with <c>TryAddSingleton</c>: a host that already registered its own keeps it.
    /// Known secrets are registered when the masker is <b>first resolved</b> (which is when the Options are bound), not
    /// inside this method; to make sure that happens at start-up, resolve <see cref="SecretMasker"/> once early (the
    /// logging integration's <c>AddOzakboySecretMasking</c> does exactly that).
    /// </para>
    /// <para>
    /// 保護器不會自動選:沒呼叫 <c>Use…Protector</c> 就沒有 <see cref="ISecretProtector"/> 註冊,解析會得到 <see langword="null"/>
    /// (<c>GetService</c>)或擲例外(<c>GetRequiredService</c>)。
    /// No protector is chosen automatically: without a <c>Use…Protector</c> call there is no <see cref="ISecretProtector"/>
    /// registration, and resolving it yields <see langword="null"/> (<c>GetService</c>) or throws (<c>GetRequiredService</c>).
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="services"/> 或 <paramref name="configure"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="services"/> or <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    public static IServiceCollection AddOzakboySecurity(this IServiceCollection services, Action<OzakboySecurityBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions();
        // 以實例註冊而不是工廠:TryAddEnumerable 靠實作型別去重,工廠描述元沒有實作型別會被拒絕。
        // Registered as an instance rather than a factory: TryAddEnumerable de-duplicates by implementation type,
        // and a factory descriptor has none, so it is rejected.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<SecretMaskingOptions>>(new SecretMaskingOptionsValidator()));
        services.TryAddSingleton(static provider => CreateMasker(provider.GetRequiredService<IOptions<SecretMaskingOptions>>().Value));

        configure(new OzakboySecurityBuilder(services));
        return services;
    }

    /// <summary>
    /// 依設定建立遮罩器並登記已知祕密;設定要求時同步登記到 <see cref="SecretMasker.Default"/>。
    /// Builds the masker from the options and registers the known secrets, mirroring them onto
    /// <see cref="SecretMasker.Default"/> when the options ask for it.
    /// </summary>
    /// <param name="options">
    /// 已驗證的設定。
    /// The validated options.
    /// </param>
    /// <returns>
    /// 建好的遮罩器。
    /// The masker.
    /// </returns>
    internal static SecretMasker CreateMasker(SecretMaskingOptions options)
    {
        var masker = new SecretMasker(options.MaskOptions);
        foreach (string secret in options.KnownSecrets)
        {
            masker.RegisterKnownSecret(secret);
            if (options.AlsoRegisterOnDefaultMasker)
            {
                SecretMasker.Default.RegisterKnownSecret(secret);
            }
        }

        return masker;
    }
}
