# Ozakboy.Security

.NET 10 的憑證與敏感資料保護工具,只做三件事:

1. **DPAPI 金鑰保護** —— 用 Windows DPAPI 加密憑證,讓 API Key 這類東西不以明文落地,而且整個機制藏在介面後面,隨時可以換掉。
2. **敏感字串遮罩** —— 寫進日誌前把憑證遮掉,支援純字串、URL query 參數與 JSON 欄位。
3. **設定檔加密** —— 用 AES-GCM 加密整份設定檔或其中的區段,附 PBKDF2 金鑰派生。

English documentation: [README.md](README.md)

## 設計取捨

- **零第三方相依。** 全部建立在 BCL 之上。唯一的套件參照 `System.Security.Cryptography.ProtectedData` 由 Microsoft 官方發佈,是 .NET 取用 DPAPI 的唯一途徑。
- **失敗原因是判斷出來的,不是用猜的。** 兩種封裝格式都帶魔術字標頭與版本位元組,所以「資料損毀」「格式版本不認得」「保護範圍不符」都能在真正解密之前就分辨出來;剩下分不出來的才回報 `DecryptionFailed`。
- **預期內的失敗不拋例外。** 設定檔從別台機器複製過來、被手動編輯、金鑰輪替過,都是正常會發生的事。每條還原路徑都有對應的 `Try…` 版本,失敗只回傳 `false`。
- **不內建預設金鑰,也沒有寫死的鹽值。** 金鑰從哪裡來,由呼叫端決定。

## 安裝

```bash
dotnet add package Ozakboy.Security
```

目標框架:`net10.0`。

## 一、DPAPI 金鑰保護

```csharp
using Ozakboy.Security.Protection;

ISecretProtector protector = new DpapiSecretProtector();

// 加密一次,把結果寫進設定檔即可。
string stored = protector.Protect("my-api-key-value");
Console.WriteLine(stored);            // Base64,開頭是 OZDP 標頭

// 讀回來。TryUnprotect 遇到壞資料不會拋例外。
if (protector.TryUnprotect(stored, out string? apiKey))
{
    Console.WriteLine(apiKey);        // my-api-key-value
}
else
{
    Console.WriteLine("這台機器/這個帳戶還原不了這份資料。");
}
```

指定保護範圍與額外熵值:

```csharp
using Ozakboy.Security.Protection;

var options = new DpapiProtectionOptions
{
    // CurrentUser(預設):只有加密當下的使用者帳戶讀得回來。
    // LocalMachine:同一台機器上的任何帳戶都讀得回來,Windows 服務通常需要這個。
    Scope = SecretProtectionScope.LocalMachine,
}.WithEntropyText("MyApp/credentials/v1");

var protector = new DpapiSecretProtector(options);
string stored = protector.Protect("my-api-key-value");
```

需要知道還原不了的確切原因時,改用 `Unprotect` 並攔截例外:

```csharp
using Ozakboy.Security;
using Ozakboy.Security.Protection;

try
{
    string apiKey = new DpapiSecretProtector().Unprotect(stored);
}
catch (SecretProtectionException ex) when (ex.Reason == SecretProtectionFailureReason.ScopeMismatch)
{
    // 以 LocalMachine 加密、卻用 CurrentUser 還原(或反過來)。
}
catch (SecretProtectionException ex) when (ex.Reason == SecretProtectionFailureReason.MalformedPayload)
{
    // 設定檔被截斷或被手動編輯過。
}
catch (SecretProtectionException)
{
    // DecryptionFailed:資料遭竄改,或它是由其他使用者帳戶、其他機器加密的。
}
```

DPAPI 是 Windows 專屬機制。在其他平台上 `IsSupported` 會是 `false`,加解密呼叫會拋出訊息明確的 `PlatformNotSupportedException`。
`ISecretProtector` 存在的理由正是如此:換一個實作注入進去(環境變數、作業系統金鑰鏈、雲端 KMS),其他程式碼一行都不用改。

## 二、敏感字串遮罩

```csharp
using Ozakboy.Security.Masking;

SecretMasker masker = SecretMasker.Default;

Console.WriteLine(masker.Mask("abcdefghijklmnopqrstuvwxyz"));
// abcd****wxyz

Console.WriteLine(masker.Mask("short"));
// **** —— 太短的字串保留頭尾等於整串外洩,所以一律全遮

Console.WriteLine(masker.MaskQueryString("/api/v3/order?symbol=BTCUSDT&apiKey=abcdefghijklmnopqrst"));
// /api/v3/order?symbol=BTCUSDT&apiKey=abcd****qrst

Console.WriteLine(masker.MaskJson("""{"apiKey":"abcdefghijklmnopqrst","symbol":"BTCUSDT","quantity":1.5}"""));
// {"apiKey":"abcd****qrst","symbol":"BTCUSDT","quantity":1.5}
```

端點與非敏感參數會刻意保留:除錯的時候,一份看不出打了哪支 API 的日誌沒什麼用。
欄位名比對一律忽略大小寫,內建清單涵蓋 `apiKey`、`api_key`、`secret`、`secretKey`、`signature`、`token`、`password`、`authorization` 等數十個名稱。

要調整保留幾碼,或擴充敏感欄位名:

```csharp
using Ozakboy.Security.Masking;

var masker = new SecretMasker(new SecretMaskOptions
{
    VisiblePrefixLength = 2,
    VisibleSuffixLength = 2,
    MaskLength = 6,
    MaskCharacter = '#',
    AdditionalSensitiveNames = ["listenKey", "x-mbx-apikey"],
});

Console.WriteLine(masker.Mask("abcdefghijklmnop"));              // ab######op
Console.WriteLine(masker.MaskNamedValue("symbol", "BTCUSDT"));   // BTCUSDT(非敏感欄位,原樣保留)
```

遮罩符號長度固定,所以輸出不會洩漏原字串有多長。日誌路徑請用 `TryMaskJson`,內容不是有效 JSON 時回傳 `false` 而不是拋例外:

```csharp
if (SecretMasker.Default.TryMaskJson(responseBody, out string? safeToLog))
{
    logger.LogInformation("response: {Body}", safeToLog);
}
```

## 三、設定檔加密

```csharp
using Ozakboy.Security.Configuration;

// 鹽值要跟密文放在一起,而且鹽值不是機密。
byte[] salt = KeyDerivation.CreateSalt();
byte[] key = KeyDerivation.DeriveKey("使用者的密碼", salt);

string encrypted = ConfigurationProtector.Encrypt(File.ReadAllText("appsettings.json"), key);
File.WriteAllText("appsettings.protected", encrypted);
File.WriteAllText("appsettings.salt", Convert.ToBase64String(salt));

if (ConfigurationProtector.TryDecrypt(encrypted, key, out string? json))
{
    Console.WriteLine(json);
}
```

或者產生隨機金鑰,再把金鑰本身交給 DPAPI 保管:

```csharp
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Protection;

byte[] key = KeyDerivation.CreateKey();                 // 32 位元組,AES-256
var protector = new DpapiSecretProtector();

// 落到設定檔裡的是 DPAPI 保護過的金鑰,不是金鑰本身。
string storedKey = protector.Protect(Convert.ToBase64String(key));
string encrypted = ConfigurationProtector.Encrypt("""{"apiKey":"…"}""", key);
```

每次加密都會產生新的 nonce,所以同樣的內容加密兩次不會得到相同密文。
AES-GCM 除了加密還會驗證完整性:密文被改一個位元組就直接解密失敗,不會悄悄還原成錯誤內容。

`ConfigurationProtector.IsProtectedValue(value)` 不需要金鑰就能判斷設定值是已加密還是還沒加密,遷移既有設定檔時很好用。

## 封裝格式

| | 魔術字 | 版面 |
| --- | --- | --- |
| `DpapiSecretProtector` | `OZDP` | 魔術字(4)+ 版本(1)+ 保護範圍(1)+ DPAPI 密文 |
| `ConfigurationProtector` | `OZCF` | 魔術字(4)+ 版本(1)+ nonce(12)+ 驗證標籤(16)+ 密文 |

兩者的字串形式都是 Base64。`OZCF` 的標頭同時作為 AES-GCM 的關聯資料,所以標頭被改一樣會導致驗證失敗。

## 失敗原因

`SecretProtectionException.Reason` 的可能值:

| 原因 | 意義 |
| --- | --- |
| `MalformedPayload` | 不是有效 Base64、長度不足,或缺少格式標頭。 |
| `UnsupportedFormatVersion` | 資料由較新版本的程式庫寫入。 |
| `ScopeMismatch` | 以 `LocalMachine` 加密卻用 `CurrentUser` 還原,或反過來。 |
| `DecryptionFailed` | 資料遭竄改、金鑰錯誤,或由其他使用者帳戶/其他機器加密。 |
| `PlatformNotSupported` | 目前平台不支援。內建的 DPAPI 實作遇到這個情況是拋 `PlatformNotSupportedException`,這個值保留給寧可回報原因、也不拋平台例外的替代實作。 |

## 執行需求

- .NET 10
- DPAPI 部分需要 Windows;遮罩、AES-GCM 與 PBKDF2 跨平台都能用。

## 授權

MIT,詳見 [LICENSE](LICENSE)。
