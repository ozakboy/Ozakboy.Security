using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Ozakboy.Security.Masking;
using Ozakboy.Security.Protection;

namespace Ozakboy.Security;

/// <summary>
/// <c>AddOzakboySecurity</c> 的設定介面:選擇 <see cref="ISecretProtector"/> 的實作、調整遮罩設定、登記已知祕密。
/// 保護器<b>必須由呼叫端明確選</b>,本套件不依作業系統偷偷猜 —— 唯一的例外是
/// <see cref="UseDpapiOnWindowsOtherwiseKeyed"/>,那是把「猜」寫在方法名稱上的便利多載。
/// The configuration surface of <c>AddOzakboySecurity</c>: pick the <see cref="ISecretProtector"/> implementation,
/// adjust masking, register known secrets. The protector <b>is chosen explicitly by the caller</b>; this library never
/// guesses from the operating system behind your back. The single exception is
/// <see cref="UseDpapiOnWindowsOtherwiseKeyed"/>, a convenience overload that spells the guess out in its name.
/// </summary>
public sealed class OzakboySecurityBuilder
{
    /// <summary>
    /// 建立設定介面。
    /// Creates the builder.
    /// </summary>
    /// <param name="services">
    /// 服務集合。
    /// The service collection.
    /// </param>
    internal OzakboySecurityBuilder(IServiceCollection services)
    {
        Services = services;
    }

    /// <summary>
    /// 底層的服務集合,需要額外註冊時直接用。
    /// The underlying service collection, for any extra registration.
    /// </summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// 以 Windows DPAPI 作為 <see cref="ISecretProtector"/>。只在 Windows 上有效;在其他平台上解析得到保護器,
    /// 但 <see cref="ISecretProtector.IsSupported"/> 為 <see langword="false"/>,加解密會擲 <see cref="PlatformNotSupportedException"/>。
    /// Uses Windows DPAPI as the <see cref="ISecretProtector"/>. Effective on Windows only; elsewhere the protector
    /// resolves, but <see cref="ISecretProtector.IsSupported"/> is <see langword="false"/> and protect/unprotect throw
    /// <see cref="PlatformNotSupportedException"/>.
    /// </summary>
    /// <param name="options">
    /// DPAPI 設定,<see langword="null"/> 用預設(CurrentUser、無額外熵值)。
    /// The DPAPI options; <see langword="null"/> means the defaults (CurrentUser, no additional entropy).
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    public OzakboySecurityBuilder UseDpapiProtector(DpapiProtectionOptions? options = null)
    {
        DpapiProtectionOptions effective = options ?? new DpapiProtectionOptions();
        return UseProtector(_ => new DpapiSecretProtector(effective));
    }

    /// <summary>
    /// 以 <see cref="KeyedSecretProtector"/>(AES-256-GCM,跨平台)作為 <see cref="ISecretProtector"/>,主金鑰來自指定來源。
    /// Uses <see cref="KeyedSecretProtector"/> (AES-256-GCM, cross-platform) as the <see cref="ISecretProtector"/>, with
    /// the master key from the given source.
    /// </summary>
    /// <param name="keySource">
    /// 主金鑰來源,不可為 <see langword="null"/>。
    /// The master-key source; must not be <see langword="null"/>.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="keySource"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="keySource"/> is <see langword="null"/>.
    /// </exception>
    public OzakboySecurityBuilder UseKeyedProtector(ISecretKeySource keySource)
    {
        ArgumentNullException.ThrowIfNull(keySource);
        return UseProtector(_ => new KeyedSecretProtector(keySource));
    }

    /// <summary>
    /// <see cref="UseKeyedProtector"/> 的捷徑:主金鑰來自環境變數(容器場景)。
    /// A shortcut for <see cref="UseKeyedProtector"/> with the key in an environment variable (containers).
    /// </summary>
    /// <param name="variableName">
    /// 環境變數名稱,內容為 32 位元組金鑰的 Base64。
    /// The environment variable name, holding the Base64 of a 32-byte key.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    public OzakboySecurityBuilder UseKeyFromEnvironmentVariable(string variableName)
        => UseKeyedProtector(new EnvironmentVariableKeySource(variableName));

    /// <summary>
    /// <see cref="UseKeyedProtector"/> 的捷徑:主金鑰來自金鑰檔(EC2 / VM 場景),Unix 上讀取時檢查權限必須是擁有者獨有。
    /// A shortcut for <see cref="UseKeyedProtector"/> with the key in a file (EC2 / VM hosts); on Unix the read checks
    /// that the file is owner-only.
    /// </summary>
    /// <param name="path">
    /// 金鑰檔路徑。
    /// The key file path.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    public OzakboySecurityBuilder UseKeyFromFile(string path)
        => UseKeyedProtector(new KeyFileKeySource(path));

    /// <summary>
    /// 便利多載:Windows 上用 DPAPI,其他平台用金鑰式保護器。這是唯一「看作業系統決定」的方法,
    /// 適合同一份程式碼在 Windows 開發機與 Linux 主機之間來回的專案;判斷在<b>解析保護器的當下</b>做,不是註冊時。
    /// A convenience overload: DPAPI on Windows, the keyed protector everywhere else. It is the only method that
    /// decides by operating system, meant for code that moves between a Windows development machine and Linux hosts;
    /// the decision is made <b>when the protector is resolved</b>, not at registration.
    /// </summary>
    /// <param name="keySource">
    /// 非 Windows 平台用的主金鑰來源,不可為 <see langword="null"/>。
    /// The master-key source for non-Windows platforms; must not be <see langword="null"/>.
    /// </param>
    /// <param name="dpapiOptions">
    /// Windows 上的 DPAPI 設定,<see langword="null"/> 用預設。
    /// The DPAPI options on Windows; <see langword="null"/> means the defaults.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="keySource"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="keySource"/> is <see langword="null"/>.
    /// </exception>
    public OzakboySecurityBuilder UseDpapiOnWindowsOtherwiseKeyed(ISecretKeySource keySource, DpapiProtectionOptions? dpapiOptions = null)
    {
        ArgumentNullException.ThrowIfNull(keySource);
        DpapiProtectionOptions effective = dpapiOptions ?? new DpapiProtectionOptions();
        return UseProtector(_ => OperatingSystem.IsWindows()
            ? new DpapiSecretProtector(effective)
            : new KeyedSecretProtector(keySource));
    }

    /// <summary>
    /// 以自訂工廠註冊 <see cref="ISecretProtector"/>(單例)。先前註冊的 <see cref="ISecretProtector"/> 會被取代,
    /// 所以最後一次呼叫的設定生效。
    /// Registers <see cref="ISecretProtector"/> (singleton) from a custom factory. Any earlier
    /// <see cref="ISecretProtector"/> registration is replaced, so the last call wins.
    /// </summary>
    /// <param name="factory">
    /// 建立保護器的工廠,不可為 <see langword="null"/>。
    /// The factory creating the protector; must not be <see langword="null"/>.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="factory"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="factory"/> is <see langword="null"/>.
    /// </exception>
    public OzakboySecurityBuilder UseProtector(Func<IServiceProvider, ISecretProtector> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        Services.RemoveAll<ISecretProtector>();
        Services.AddSingleton(factory);
        return this;
    }

    /// <summary>
    /// 調整遮罩設定(等同 <c>Services.Configure&lt;SecretMaskingOptions&gt;</c>)。
    /// Adjusts the masking options (the same as <c>Services.Configure&lt;SecretMaskingOptions&gt;</c>).
    /// </summary>
    /// <param name="configure">
    /// 設定委派,不可為 <see langword="null"/>。
    /// The configuration delegate; must not be <see langword="null"/>.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="configure"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    public OzakboySecurityBuilder ConfigureMasking(Action<SecretMaskingOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(configure);
        return this;
    }

    /// <summary>
    /// 登記一個已知祕密,遮罩器建立時會把它加進去。值會立刻檢查長度,不合格當場擲出而不是等到啟動;
    /// 例外訊息不回述值。
    /// Registers a known secret to be added when the masker is built. The value is length-checked immediately so a
    /// bad one fails here rather than at start-up; the exception message never echoes the value.
    /// </summary>
    /// <param name="secret">
    /// 祕密的原始值,長度至少 <see cref="SecretMasker.MinimumKnownSecretLength"/>。
    /// The raw secret value, at least <see cref="SecretMasker.MinimumKnownSecretLength"/> characters long.
    /// </param>
    /// <returns>
    /// 同一個設定介面,便於串接。
    /// The same builder, for chaining.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="secret"/> 為 <see langword="null"/> 時擲出。
    /// Thrown when <paramref name="secret"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="secret"/> 空白或過短時擲出。
    /// Thrown when <paramref name="secret"/> is blank or too short.
    /// </exception>
    public OzakboySecurityBuilder RegisterKnownSecret(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (string.IsNullOrWhiteSpace(secret) || secret.Length < SecretMasker.MinimumKnownSecretLength)
        {
            throw new ArgumentException(
                "登記的祕密值不得空白,且長度至少 " + SecretMasker.MinimumKnownSecretLength.ToString(System.Globalization.CultureInfo.InvariantCulture) + " 個字元。 " +
                "A registered secret must not be blank and must be at least " + SecretMasker.MinimumKnownSecretLength.ToString(System.Globalization.CultureInfo.InvariantCulture) + " characters long.",
                nameof(secret));
        }

        return ConfigureMasking(options => options.KnownSecrets.Add(secret));
    }
}
