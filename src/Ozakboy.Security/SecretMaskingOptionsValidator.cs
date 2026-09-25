using System.Globalization;
using Microsoft.Extensions.Options;
using Ozakboy.Security.Masking;

namespace Ozakboy.Security;

/// <summary>
/// <see cref="SecretMaskingOptions"/> 的驗證器:已知祕密不得空白、不得短於最小長度。訊息只指出索引,不回述值。
/// Validator for <see cref="SecretMaskingOptions"/>: known secrets must be non-blank and at least the minimum
/// length. The message names the index only and never echoes the value.
/// </summary>
internal sealed class SecretMaskingOptionsValidator : IValidateOptions<SecretMaskingOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, SecretMaskingOptions options)
    {
        if (options is null)
        {
            return ValidateOptionsResult.Fail("SecretMaskingOptions 不可為 null。 SecretMaskingOptions must not be null.");
        }

        if (options.MaskOptions is null)
        {
            return ValidateOptionsResult.Fail("SecretMaskingOptions.MaskOptions 不可為 null。 SecretMaskingOptions.MaskOptions must not be null.");
        }

        List<string>? failures = null;
        for (int i = 0; i < options.KnownSecrets.Count; i++)
        {
            string? secret = options.KnownSecrets[i];
            if (string.IsNullOrWhiteSpace(secret) || secret.Length < SecretMasker.MinimumKnownSecretLength)
            {
                failures ??= [];
                failures.Add(
                    "KnownSecrets[" + i.ToString(CultureInfo.InvariantCulture) + "] 為空白或短於 " +
                    SecretMasker.MinimumKnownSecretLength.ToString(CultureInfo.InvariantCulture) + " 個字元;過短的值會讓正常日誌內容被大量誤遮。 " +
                    "KnownSecrets[" + i.ToString(CultureInfo.InvariantCulture) + "] is blank or shorter than " +
                    SecretMasker.MinimumKnownSecretLength.ToString(CultureInfo.InvariantCulture) + " characters; such a value would mask large amounts of ordinary log text.");
            }
        }

        return failures is null ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
