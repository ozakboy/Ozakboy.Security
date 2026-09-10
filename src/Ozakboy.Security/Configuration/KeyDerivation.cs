using System.Globalization;
using System.Security.Cryptography;

namespace Ozakboy.Security.Configuration;

/// <summary>
/// 金鑰輔助工具:以 PBKDF2 從密碼派生金鑰,以及產生密碼學安全的隨機鹽值與金鑰。
/// 本套件不內建任何預設金鑰或固定鹽值 —— 金鑰來源一律由呼叫端決定。
/// Key helpers: derives a key from a password with PBKDF2 and generates cryptographically secure
/// random salts and keys. This library ships no built-in key and no hard-coded salt; where key
/// material comes from is always the caller's decision.
/// </summary>
public static class KeyDerivation
{
    /// <summary>
    /// 預設 PBKDF2 迭代次數。取用目前業界建議的量級(OWASP 對 PBKDF2-HMAC-SHA256 的建議值),
    /// 硬體變快時應該往上調,所以此值可由呼叫端覆寫。
    /// The default PBKDF2 iteration count, following the current industry guidance for
    /// PBKDF2-HMAC-SHA256. It should rise as hardware gets faster, which is why callers can override it.
    /// </summary>
    public const int DefaultIterations = 600_000;

    /// <summary>
    /// 允許的最低迭代次數。低於此值的設定會被拒絕,避免呼叫端不小心把成本調到沒有保護力。
    /// The lowest accepted iteration count. Anything below it is rejected so a caller cannot
    /// accidentally dial the cost down to something that offers no protection.
    /// </summary>
    public const int MinimumIterations = 100_000;

    /// <summary>
    /// 預設派生金鑰長度(位元組),32 位元組即 AES-256。
    /// The default derived key length in bytes; 32 bytes means AES-256.
    /// </summary>
    public const int DefaultKeyLengthInBytes = 32;

    /// <summary>
    /// 預設鹽值長度(位元組)。
    /// The default salt length in bytes.
    /// </summary>
    public const int DefaultSaltLengthInBytes = 16;

    /// <summary>
    /// 允許的最短鹽值長度(位元組)。取 16 位元組(128 bits),即 NIST SP 800-132 對 PBKDF2 鹽值的建議下限。
    /// The shortest accepted salt length in bytes: 16 bytes (128 bits), the floor NIST SP 800-132
    /// recommends for a PBKDF2 salt.
    /// </summary>
    public const int MinimumSaltLengthInBytes = 16;

    /// <summary>
    /// 以 PBKDF2(HMAC-SHA256)從密碼派生金鑰。同一組密碼、鹽值、迭代次數與長度必然派生出同一把金鑰,
    /// 因此鹽值必須與密文一起保存,而且鹽值不是機密。
    /// Derives a key from a password using PBKDF2 with HMAC-SHA256. The same password, salt, iteration
    /// count and length always produce the same key, so the salt must be stored alongside the
    /// ciphertext — and the salt is not a secret.
    /// </summary>
    /// <param name="password">
    /// 使用者密碼,不可為 <see langword="null"/>。
    /// 密碼一旦進了 <see cref="string"/> 就清不掉:字串不可變、無法歸零,GC 搬移時還會留下多份副本,
    /// 最後出現在記憶體傾印與分頁檔裡。需要控制密碼生命週期時請改用
    /// <see cref="DeriveKey(ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, int)"/> 多載。
    /// The user password; must not be <see langword="null"/>. Once a password is in a
    /// <see cref="string"/> it cannot be scrubbed: strings are immutable, cannot be zeroed, and the GC
    /// leaves copies behind as it moves them, which is how passwords end up in memory dumps and page
    /// files. Use the <see cref="DeriveKey(ReadOnlySpan{byte}, ReadOnlySpan{byte}, int, int)"/> overload
    /// when the password's lifetime needs to be controlled.
    /// </param>
    /// <param name="salt">
    /// 鹽值,長度至少 <see cref="MinimumSaltLengthInBytes"/> 位元組,且每份資料應各自隨機產生。
    /// The salt; at least <see cref="MinimumSaltLengthInBytes"/> bytes, generated randomly per secret.
    /// </param>
    /// <param name="iterations">
    /// 迭代次數,預設 <see cref="DefaultIterations"/>,不得低於 <see cref="MinimumIterations"/>。
    /// The iteration count; defaults to <see cref="DefaultIterations"/> and may not fall below
    /// <see cref="MinimumIterations"/>.
    /// </param>
    /// <param name="keyLengthInBytes">
    /// 派生金鑰長度(位元組),預設 <see cref="DefaultKeyLengthInBytes"/>。
    /// The derived key length in bytes; defaults to <see cref="DefaultKeyLengthInBytes"/>.
    /// </param>
    /// <returns>
    /// 派生出的金鑰。
    /// The derived key.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="password"/> 為 <see langword="null"/> 時拋出。
    /// Thrown when <paramref name="password"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// 鹽值長度不足時拋出。
    /// Thrown when the salt is too short.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// 迭代次數低於下限,或金鑰長度不是正數時拋出。
    /// Thrown when the iteration count is below the minimum or the key length is not positive.
    /// </exception>
    public static byte[] DeriveKey(
        string password,
        ReadOnlySpan<byte> salt,
        int iterations = DefaultIterations,
        int keyLengthInBytes = DefaultKeyLengthInBytes)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinimumIterations);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyLengthInBytes);

        ValidateSalt(salt);

        // CA5388:分析器無法在編譯期確認 iterations 的值,因此無條件示警。
        // 這裡已在上方以 MinimumIterations(100,000)強制把關,且預設值為 600,000,故明示抑制。
        // CA5388: the analyzer cannot see the runtime value of `iterations`, so it always warns.
        // The minimum is enforced above (100,000) and the default is 600,000, hence the explicit suppression.
#pragma warning disable CA5388
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, keyLengthInBytes);
#pragma warning restore CA5388
    }

    /// <summary>
    /// 以 PBKDF2(HMAC-SHA256)從密碼位元組派生金鑰。與字串多載結果完全相同(字串多載即是以 UTF-8 編碼後派生),
    /// 差別在於呼叫端可以自行掌握密碼緩衝區:用完立刻以
    /// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> 歸零,不必等 GC。
    /// Derives a key from password bytes using PBKDF2 with HMAC-SHA256. The result is identical to the
    /// string overload (which simply encodes as UTF-8); what differs is that the caller owns the password
    /// buffer and can zero it with <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> the moment
    /// it is done, instead of waiting on the GC.
    /// </summary>
    /// <param name="password">
    /// 密碼的位元組表示(一般為 UTF-8 編碼),允許空緩衝區。
    /// The password as bytes, normally UTF-8 encoded; an empty buffer is allowed.
    /// </param>
    /// <param name="salt">
    /// 鹽值,長度至少 <see cref="MinimumSaltLengthInBytes"/> 位元組,且每份資料應各自隨機產生。
    /// The salt; at least <see cref="MinimumSaltLengthInBytes"/> bytes, generated randomly per secret.
    /// </param>
    /// <param name="iterations">
    /// 迭代次數,預設 <see cref="DefaultIterations"/>,不得低於 <see cref="MinimumIterations"/>。
    /// The iteration count; defaults to <see cref="DefaultIterations"/> and may not fall below
    /// <see cref="MinimumIterations"/>.
    /// </param>
    /// <param name="keyLengthInBytes">
    /// 派生金鑰長度(位元組),預設 <see cref="DefaultKeyLengthInBytes"/>。
    /// The derived key length in bytes; defaults to <see cref="DefaultKeyLengthInBytes"/>.
    /// </param>
    /// <returns>
    /// 派生出的金鑰。用完請以 <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> 歸零。
    /// The derived key. Zero it with <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> when
    /// you are done with it.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// 鹽值長度不足時拋出。
    /// Thrown when the salt is too short.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// 迭代次數低於下限,或金鑰長度不是正數時拋出。
    /// Thrown when the iteration count is below the minimum or the key length is not positive.
    /// </exception>
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int iterations = DefaultIterations,
        int keyLengthInBytes = DefaultKeyLengthInBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinimumIterations);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyLengthInBytes);
        ValidateSalt(salt);

        // CA5388:同上,迭代次數已於上方強制把關。
        // CA5388: as above, the iteration count is already enforced.
#pragma warning disable CA5388
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, keyLengthInBytes);
#pragma warning restore CA5388
    }

    /// <summary>
    /// 檢查鹽值長度是否達到下限。
    /// Validates that the salt meets the minimum length.
    /// </summary>
    /// <param name="salt">
    /// 鹽值。
    /// The salt.
    /// </param>
    private static void ValidateSalt(ReadOnlySpan<byte> salt)
    {
        if (salt.Length < MinimumSaltLengthInBytes)
        {
            throw new ArgumentException(
                "鹽值長度至少需要 " + MinimumSaltLengthInBytes.ToString(CultureInfo.InvariantCulture) + " 位元組。 " +
                "The salt must be at least " + MinimumSaltLengthInBytes.ToString(CultureInfo.InvariantCulture) + " bytes long.",
                nameof(salt));
        }
    }

    /// <summary>
    /// 產生密碼學安全的隨機鹽值。
    /// Generates a cryptographically secure random salt.
    /// </summary>
    /// <param name="lengthInBytes">
    /// 鹽值長度(位元組),預設 <see cref="DefaultSaltLengthInBytes"/>。
    /// The salt length in bytes; defaults to <see cref="DefaultSaltLengthInBytes"/>.
    /// </param>
    /// <returns>
    /// 隨機鹽值。
    /// The random salt.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// 長度小於 <see cref="MinimumSaltLengthInBytes"/> 時拋出。
    /// Thrown when the length is below <see cref="MinimumSaltLengthInBytes"/>.
    /// </exception>
    public static byte[] CreateSalt(int lengthInBytes = DefaultSaltLengthInBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(lengthInBytes, MinimumSaltLengthInBytes);
        return RandomNumberGenerator.GetBytes(lengthInBytes);
    }

    /// <summary>
    /// 產生密碼學安全的隨機金鑰。
    /// Generates a cryptographically secure random key.
    /// </summary>
    /// <param name="lengthInBytes">
    /// 金鑰長度(位元組),預設 <see cref="DefaultKeyLengthInBytes"/>。
    /// The key length in bytes; defaults to <see cref="DefaultKeyLengthInBytes"/>.
    /// </param>
    /// <returns>
    /// 隨機金鑰。
    /// The random key.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// 長度不是正數時拋出。
    /// Thrown when the length is not positive.
    /// </exception>
    public static byte[] CreateKey(int lengthInBytes = DefaultKeyLengthInBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(lengthInBytes);
        return RandomNumberGenerator.GetBytes(lengthInBytes);
    }
}
