# Ozakboy.Security

.NET 10 的憑證與敏感資料保護工具,只做四件事:

1. **憑證保護** —— 把憑證加密,讓 API Key 這類東西不以明文落地:Windows 上用 DPAPI,其他平台用 AES-256-GCM 的金鑰式保護器(主金鑰來自環境變數或權限受檢的金鑰檔),兩者藏在同一個介面後面,隨時可以換掉。
2. **敏感字串遮罩** —— 寫進日誌前把憑證遮掉,支援純字串、URL query 參數、JSON 欄位、呼叫端根本沒機會交出值的自由文字,以及一個把整個程序每一行日誌都遮過的 `ILogger` 包裝。
3. **設定檔加密** —— 用 AES-GCM 加密整份設定檔或其中的區段,附 PBKDF2 金鑰派生;`IConfiguration` 裡加密過的值讀取時自動解開。
4. **ASP.NET Core 掛法** —— `DecryptProtectedValues`、`AddOzakboySecurity`、`AddOzakboySecretMasking`,`Program.cs` 裡三行。

English documentation: [README.md](README.md)

## 設計取捨

- **零第三方相依。** 全部建立在 BCL 與 Microsoft 官方套件之上:`System.Security.Cryptography.ProtectedData`(.NET 取用 DPAPI 的唯一途徑),以及設定、DI、日誌、Options 的 `Microsoft.Extensions.*` 抽象層。遞移相依圖裡沒有任何一項來自別處。
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

### 額外熵值實際上防得住什麼

這一點很容易被讀得太樂觀,所以說清楚:

- **防得住**:拿到這個檔案、但不知道熵值的其他程式。通用型 DPAPI 解密工具、備份還原後翻檔案的人,即使跑在同一個帳號下,少了熵值也解不開。
- **防不住**:以同一個帳號執行的程式碼。像上面那樣傳入應用程式自訂的固定字串,熵值就被編進了組件裡,任何能以同一使用者身分執行的程序反組譯就能拿到,DPAPI 沒有多攔下什麼。
- **真的要擋同帳號執行的程式**:熵值必須來自操作者在啟動時輸入的通行碼,而且不落地。代價是無人值守啟動不再可行 —— 沒有人在旁邊輸入,服務就起不來。

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
`ISecretProtector` 存在的理由正是如此 —— 而 Linux 主機與容器要用的另一個實作,本套件自己就有:見[在 Linux 上用](#四在-linux-與容器上用)。

## 二、敏感字串遮罩

```csharp
using Ozakboy.Security.Masking;

SecretMasker masker = SecretMasker.Default;

Console.WriteLine(masker.Mask("abcdefghijklmnopqrstuvwxyz"));
// abcd****wxyz

Console.WriteLine(masker.Mask("short"));
// **** —— 太短的字串保留頭尾等於整串外洩,所以一律全遮

Console.WriteLine(masker.MaskQueryString("/api/v3/order?symbol=BTCUSDT&apiKey=abcdefghijklmnopqrst"));
// /api/v3/order?symbol=BTCUSDT&apiKey=abc****rst

Console.WriteLine(masker.MaskJson("""{"apiKey":"abcdefghijklmnopqrst","symbol":"BTCUSDT","quantity":1.5}"""));
// {"apiKey":"abc****rst","symbol":"BTCUSDT","quantity":1.5}
```

端點與非敏感參數會刻意保留:除錯的時候,一份看不出打了哪支 API 的日誌沒什麼用。

### 到底會露出多少

有兩層限制,而且第二層調不掉:

1. 設定的頭尾長度(預設各 4),以及最少要遮掉幾個字元才肯露出頭尾(預設 4,下限為 1)。
2. **露出的字元數一律不得超過原值長度的三分之一。** 不論設定怎麼調:12 個字元的值只露出 2 + 2,不是 4 + 4;64 個字元的交易所 API 金鑰照設定露出 4 + 4,離上限還很遠。
   這一條的存在理由是:設定被調鬆之後,輸出可能看起來遮過了,實際上把原值一字不漏地印出來。

密碼類欄位 —— `password`、`passwd`、`pwd`、`passphrase`、`mnemonic`、`privateKey` 與它們的變體 —— **一律全遮**,頭尾一個字元都不留。
人類密碼的熵值太低,「保留頭尾」這條規則套在它們身上並不安全。

### 哪些欄位名算敏感

名稱比對一律忽略大小寫,分兩關:

- **完全比對**內建清單:涵蓋 `apiKey`、`api_key`、`x-api-key`、`x-mbx-apikey`(幣安傳 API 金鑰用的標頭)、`secret`、`secretKey`、`signature`、`token`、`bearer`、`jwt`、`otp`、`mnemonic`、`seed`、`sessionId`、`webhookSecret`、`privateKey`、`password`、`authorization` 等數十個名稱。
- **包含式比對**(`UseSubstringMatching`,預設開啟):名稱中含有 `key`、`secret`、`token`、`password`、`credential`、`passphrase`、`signature`、`session`、`cookie` 等片段就算敏感。
  這一關才擋得住 `binanceApiKey`、`api_key_1`、`Api-Key-Secret` —— 完全比對清單永遠追不上這些變體。

包含式比對會誤遮,這是刻意的:`keyword`、`publicKey` 這類欄位也會被遮掉。對日誌遮罩而言這筆帳划得來 —— 少看到一個欄位值,遠比漏掉一把金鑰便宜。
不能接受時設 `UseSubstringMatching = false`,或改用自訂片段清單。

query 參數名在比對前會先做百分號解碼,所以 `?api%4Bey=…`(`%4B` 就是 `K`)不會穿過去;輸出仍寫回原始寫法。
JSON 路徑由 `JsonDocument` 負責解碼,本來就是拿解碼後的名稱比對,兩條路徑的比對基準一致。

要調整保留幾碼,或擴充清單:

```csharp
using Ozakboy.Security.Masking;

var masker = new SecretMasker(new SecretMaskOptions
{
    VisiblePrefixLength = 2,
    VisibleSuffixLength = 2,
    MaskLength = 6,
    MaskCharacter = '#',
    AdditionalSensitiveNames = ["listenKey"],
    AdditionalSensitiveNameFragments = ["venue"],
    AdditionalFullMaskNames = ["withdrawWhitelistAddress"],
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

> **絕對不要寫那個 fallback。** `try { log(MaskJson(x)) } catch { log(x) }` 會讓整套 fail-closed 設計當場失效:
> 遮罩失敗的當下,往往正是那份內容最不該被寫出去的時候。`TryMaskJson` 回傳 `false` 時,請記錄「遮罩失敗」這件事,不要記錄原內容。

### 那些你根本沒機會交出來的值

上面三個 API 都需要呼叫端主動把值交出來。但實務上金鑰不是從那裡漏的:

```csharp
logger.LogError("下單失敗 key={Key}", apiKey);            // 上面三個都攔不到
catch (Exception ex) { logger.LogError(ex.ToString()); }  // 例外訊息裡夾帶的金鑰也攔不到
```

啟動時把祕密登記一次,自由文字寫出去之前過一次 `MaskText`:

```csharp
using Ozakboy.Security.Masking;

// 啟動時,憑證剛解密出來的當下。
SecretMasker.Default.RegisterKnownSecret(apiKey);
SecretMasker.Default.RegisterKnownSecret(apiSecret);

// 任何要把文字寫進日誌的地方。
logger.LogError("下單失敗:{Message}", SecretMasker.Default.MaskText(ex.ToString()));
```

- 長度不足 `SecretMasker.MinimumKnownSecretLength`(8 個字元)的值會被拒絕:登記過短的字串會讓正常日誌內容被大量誤遮。拒絕時的例外訊息不會回述那個值。
- 比對採**區分大小寫的序數比對**,因為憑證本身區分大小寫。唯一例外是十六進位值(簽章、雜湊):不同函式庫對大小寫沒共識,所以兩種寫法都會一起登記。
- 登記是執行緒安全的,而且讀取端不需要鎖:`MaskText` 讀的是不可變快照,交易迴圈的每條執行緒都可以直接呼叫。沒有登記任何祕密時它原樣回傳輸入字串,不做任何配置。
- `MaskJson` 與 `MaskQueryString` 的輸出也會再過一次已登記的祕密,所以夾在無害欄位名底下的金鑰一樣攔得到。

`MaskText` 是墊在另外三個之下的網子,不是它們的替代品 —— 它只認得你登記過的值。

## 三、設定檔加密

```csharp
using System.Security.Cryptography;
using Ozakboy.Security.Configuration;

// 鹽值要跟密文放在一起,而且鹽值不是機密。長度至少 16 位元組(128 bits)。
byte[] salt = KeyDerivation.CreateSalt();
byte[] key = KeyDerivation.DeriveKey("使用者的密碼", salt);
try
{
    string encrypted = ConfigurationProtector.Encrypt(File.ReadAllText("appsettings.json"), key);
    File.WriteAllText("appsettings.protected", encrypted);
    File.WriteAllText("appsettings.salt", Convert.ToBase64String(salt));

    if (ConfigurationProtector.TryDecrypt(encrypted, key, out string? json))
    {
        Console.WriteLine(json);
    }
}
finally
{
    // 派生出來的金鑰就是一般的位元組陣列:用完立刻歸零,不要等 GC。
    CryptographicOperations.ZeroMemory(key);
}
```

密碼一旦進了 `string` 就清不掉 —— 字串不可變、無法歸零,GC 搬移時還會留下多份副本,最後出現在記憶體傾印與分頁檔裡。
密碼來源在你手上時,請改用位元組多載,自己把緩衝區清乾淨:

```csharp
using System.Security.Cryptography;
using System.Text;
using Ozakboy.Security.Configuration;

byte[] password = Encoding.UTF8.GetBytes(ReadPassphraseFromOperator());
byte[] salt = KeyDerivation.CreateSalt();
byte[] key = KeyDerivation.DeriveKey(password, salt);   // 結果與字串多載完全相同
try
{
    string encrypted = ConfigurationProtector.Encrypt("""{"apiKey":"…"}""", key);
}
finally
{
    CryptographicOperations.ZeroMemory(password);
    CryptographicOperations.ZeroMemory(key);
}
```

或者產生隨機金鑰,再把金鑰本身交給 DPAPI 保管:

```csharp
using System.Security.Cryptography;
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Protection;

byte[] key = KeyDerivation.CreateKey();                 // 32 位元組,AES-256
var protector = new DpapiSecretProtector();
try
{
    // 落到設定檔裡的是 DPAPI 保護過的金鑰,不是金鑰本身。
    string storedKey = protector.Protect(Convert.ToBase64String(key));
    string encrypted = ConfigurationProtector.Encrypt("""{"apiKey":"…"}""", key);
}
finally
{
    CryptographicOperations.ZeroMemory(key);
}
```

每次加密都會產生新的 nonce,所以同樣的內容加密兩次不會得到相同密文。
AES-GCM 除了加密還會驗證完整性:密文被改一個位元組就直接解密失敗,不會悄悄還原成錯誤內容。
nonce 是 96 bits 的隨機值,依生日界限,同一把金鑰的加密次數建議不超過 2^32 次(約 43 億)就該輪替 —— 設定檔加密的實際用量離這個量級很遠。

`ConfigurationProtector.IsProtectedValue(value)` 不需要金鑰就能判斷設定值是已加密還是還沒加密,遷移既有設定檔時很好用。
`ConfigurationProtector.IsSupported` 則回報目前平台有沒有 AES-GCM,請在啟動時檢查,不要等到第一次寫設定檔才發現。

## 四、在 Linux 與容器上用

Windows 以外沒有 DPAPI。`KeyedSecretProtector` 是跨平台的 `ISecretProtector`:AES-256-GCM,主金鑰由應用程式自己持有,
透過 `ISecretKeySource` 提供。內建兩種來源,對應兩種部署形態。

**容器(Docker / ECS / Kubernetes):金鑰放環境變數**,由編排系統的 secret 機制注入,不落在映像檔也不落在設定檔。

```bash
openssl rand -base64 32        # 產生一次,以 APP_MASTER_KEY 存進 secret 管理員
```

```csharp
using Ozakboy.Security.Protection;

ISecretProtector protector = new KeyedSecretProtector(new EnvironmentVariableKeySource("APP_MASTER_KEY"));

string stored = protector.Protect("line-channel-secret");      // Base64,OZCF 封裝
if (protector.TryUnprotect(stored, out string? channelSecret))
{
    // …
}
```

**EC2 / VM:金鑰放檔案**,而且只有執行服務的帳號讀得到。

```bash
sudo install -m 600 -o myapp -g myapp /dev/null /etc/myapp/master.key
sudo sh -c 'head -c 32 /dev/urandom > /etc/myapp/master.key'   # 32 個原始位元組;Base64 文字(openssl rand -base64 32)也可以
```

```csharp
ISecretProtector protector = new KeyedSecretProtector(new KeyFileKeySource("/etc/myapp/master.key"));
```

金鑰檔來源**每次讀取**都會檢查,不是只在啟動時:

- 檔案必須存在,內容恰好 32 位元組(原始金鑰),或解碼後是 32 位元組的 Base64 文字。長度 32 位元組但全是 Base64 字元的檔案會被當成 Base64 文字讀 ——
  24 位元組金鑰的 Base64 恰好也是 32 個字元,少了這條規則它會被當成一把弱金鑰照收。
- Unix 上,**檔案對群組或其他人開放任何權限位元(`r`、`w`、`x`)就拒絕讀取**,訊息附實際權限與 `chmod 600`。
  程序跑起來之後檔案被 `chmod` 鬆掉,下一次用到金鑰就會發現。這條檢查關不掉:能關掉的安全檢查最終都會被關掉。
- Windows 上不檢查權限。NTFS 的 ACL 與 Unix 的權限位元不是同一套模型,本套件不假裝能翻譯;Windows 上 DPAPI 才是原生的答案。
  這個來源在 Windows 上仍可運作(例如開發機),只是少了權限這道防線。

關於 `KeyedSecretProtector` 值得知道的幾件事:

- **輸出就是 `ConfigurationProtector` 的 `OZCF` 封裝**,沒有第三種格式。同一把金鑰下,在建置機用
  `ConfigurationProtector.Encrypt(value, key)` 加密的值,部署後保護器解得開,反過來也一樣。一個把值加密的一次性小工具長這樣:

  ```csharp
  using System.Security.Cryptography;
  using Ozakboy.Security.Configuration;
  using Ozakboy.Security.Protection;

  byte[] key = new KeyFileKeySource("/etc/myapp/master.key").ReadKey();   // 或 EnvironmentVariableKeySource
  try
  {
      Console.WriteLine(ConfigurationProtector.Encrypt(args[0], key));  // 輸出貼進 appsettings.json
  }
  finally
  {
      CryptographicOperations.ZeroMemory(key);
  }
  ```

- **金鑰從不常駐。** 每次加解密都向來源要一份新的、用完立刻清零;保護器本身不持有金鑰、不需要 `Dispose`,記憶體傾印裡也不會有一份長期存在的金鑰。
  代價是每次操作讀一次來源(金鑰檔的話是一次檔案讀取加權限檢查)。憑證保護不是熱路徑,而下面的設定整合每個值只解一次。
- **`KeyUnavailable` 把「部署沒配好」與「資料有問題」分開。** 變數未設定、檔案不存在、長度不對、權限太開,都是
  `Reason == SecretProtectionFailureReason.KeyUnavailable` 的 `SecretProtectionException`;訊息指出變數名或路徑,不會有內容。
  `TryUnprotect` 遇到它跟其他失敗一樣回 `false`。
- **Windows 上也能用。** 它不是「只給 Linux 的」:多台 Windows 機器要共用同一把金鑰 —— DPAPI 綁機器或使用者,做不到這件事 —— 就用這個。
- **自己的金鑰來源**(雲端 KMS、作業系統金鑰鏈)只要實作一個介面:`ISecretKeySource` 有給錯誤訊息用的 `Description`,
  與 `ReadKey()` —— 每次呼叫都必須回傳新配置的 32 位元組陣列,因為呼叫端會把它清零。

## 五、ASP.NET Core 整合

`Program.cs` 裡三行,彼此獨立:

```csharp
using Ozakboy.Security;
using Ozakboy.Security.Configuration;
using Ozakboy.Security.Logging;
using Ozakboy.Security.Protection;

var builder = WebApplication.CreateBuilder(args);

// 1. appsettings.json、環境變數、User Secrets 裡加密過的值,讀取時自動解開。
//    所有設定來源都加完之後再呼叫 —— 之後才加的來源不會被涵蓋。
var protector = new KeyedSecretProtector(new KeyFileKeySource("/etc/myapp/master.key"));
builder.Configuration.DecryptProtectedValues(protector);

// 2. 把 SecretMasker 與 ISecretProtector 放進容器。保護器由你明確選,套件不猜。
builder.Services.AddOzakboySecurity(security => security
    .UseProtector(_ => protector)
    .RegisterKnownSecret(builder.Configuration["Line:ChannelSecret"]!)
    .RegisterKnownSecret(builder.Configuration.GetConnectionString("Default")!));

// 3. 所有 ILogger<T> 的訊息、結構化屬性、例外文字,先遮罩再交給任何提供者。
builder.Logging.AddOzakboySecretMasking();
```

```json
{
  "Line": {
    "ChannelId": "1234567890",
    "ChannelSecret": "T1pDRgE…"
  }
}
```

上面的 `ChannelSecret` 是 `ConfigurationProtector.Encrypt`(或 `KeyedSecretProtector.Protect`)印出來的東西;`ChannelId` 是明文就維持明文。
你的 options 類別與 `IOptions<T>` 綁定完全感覺不到差別。

### 設定值解密

- 沒加密的值原樣通過,包括空字串與 `null`。哪些值算「受保護」預設由 `ProtectedValueConfigurationBuilderExtensions.IsAnyProtectedValue` 判斷
  —— `OZCF` 與 `OZDP` 兩種封裝都認 —— 也可以傳自己的述詞。金鑰式保護器遇到 `OZDP` 的值會大聲失敗,而不是把密文放行:
  密文被當明文用,比啟動失敗糟得多。
- 解密失敗擲 `SecretProtectionException`,訊息指出**是哪個設定鍵**(`Line:ChannelSecret`),但不含密文也不含明文;
  `Reason` 沿用保護器回報的原因,`KeyUnavailable` 是「去修部署」、`DecryptionFailed` 是「金鑰不對或值被改過」。
  失敗發生在第一次讀到那個值的時候,通常就是啟動時綁定 options 的當下。
- 每個密文只解密一次,以密文為鍵快取,反覆綁定與 `IOptionsSnapshot` 不會再碰金鑰檔。重新載入後值沒變直接命中,變了自然失效。
- `WebApplicationBuilder.Configuration` 是 `ConfigurationManager`,同時也是 `IConfigurationBuilder`,替換來源會立即重載。重複呼叫不會重複包。

### DI 註冊

- `SecretMasker` 註冊為單例(`TryAddSingleton`,你自己註冊過的會保留),依 `SecretMaskingOptions` 建立:
  `MaskOptions`、`KnownSecrets`、`AlsoRegisterOnDefaultMasker`、`MaskLogPropertiesByName`。因為走 Options 模式,設定綁定之後還能補登記:

  ```csharp
  builder.Services.Configure<SecretMaskingOptions>(options =>
      options.KnownSecrets.Add(builder.Configuration["Binance:ApiSecret"]!));
  ```

  每個已知祕密在遮罩器第一次被解析時驗證(非空白、至少 8 個字元);驗證訊息只指出第幾項,不回述值。
  builder 上的 `RegisterKnownSecret(...)` 則當場檢查。
- `AlsoRegisterOnDefaultMasker`(預設 `true`)把已知祕密同步登記到 `SecretMasker.Default`,因為 `Ozakboy.Http` 有些關口在沒拿到具名遮罩器時會退回它。
  多登記一份不花什麼,少登記一份就是外洩。共用的靜態遮罩器不能動時(例如測試隔離)再關掉。
- 保護器是選項:`UseDpapiProtector(options?)`、`UseKeyedProtector(keySource)`、`UseKeyFromEnvironmentVariable(name)`、
  `UseKeyFromFile(path)` 或 `UseProtector(factory)`。沒選就沒有 `ISecretProtector` 註冊。唯一會看作業系統的是
  `UseDpapiOnWindowsOtherwiseKeyed(keySource)`,給在 Windows 開發機與 Linux 主機之間來回的程式碼用;它把「猜」寫在名字上,而且在解析保護器的當下才判斷。

### 日誌遮罩

`AddOzakboySecretMasking()` 把容器裡的 `ILoggerFactory` 換成 `MaskingLoggerFactory`,它建出的每個記錄器都被 `MaskingLogger` 包住。
因為包的是工廠而不是逐個提供者,`ILogger<T>` 與之後才加的提供者(`AddConsole()`、`AddProvider(...)`)一樣被涵蓋,順序無所謂。
遮罩器取自 `AddOzakboySecurity`(沒有就退回 `SecretMasker.Default`);`AddOzakboySecretMasking(masker, maskPropertiesByName)` 可以明確指定。
兩個型別都是公開的,也可以手動包單一個 `ILogger` 或 `ILoggerFactory`。

遮的東西有三層:

1. **格式化後的訊息**,過 `MaskText` —— 每個已登記的祕密不管出現在哪裡都被換掉。
2. **結構化狀態裡的字串屬性**(`logger.LogError("下單失敗 key={Key}", apiKey)`):已登記的祕密整個換掉;沒登記的值**依屬性名稱**遮,
   規則與 `MaskNamedValue` 相同 —— `{Token}`、`{Password}`、`{ApiKey}` 就算沒人登記過那個值也會被遮,格式化訊息裡對應的文字也一併改寫。
   包含式比對也適用,所以 `{CacheKey}` 一樣會被遮;`MaskLogPropertiesByName = false` 可以把這層縮到只剩已登記的祕密。
3. **例外文字。** 例外的訊息、堆疊或 `ToString()` 裡含有祕密時,提供者收到的是 `MaskedException` 替身:遮罩後的訊息、堆疊與全文,
   原型別名稱放在 `OriginalTypeName`,內層例外遞迴處理。沒有祕密的例外原封不動傳下去。

**不**遮的東西 —— 依賴它之前先讀這段:

- 只有**字串**屬性會逐個遮。物件、`Uri`、數字原樣通過,接收端若把物件 `ToString()` 進結構化欄位,那條路徑不在包裝的視線內。
  格式化訊息一定過 `MaskText`,結構化欄位裡的物件不會。
- 依名稱遮到、但短於 3 個字元的值只改屬性、不在訊息裡替換,因為把一行裡每個 `a` 都換掉會把整行改爛。
- `Exception.Data` 與例外的自訂屬性不遮;接收端以例外型別分派時看到的是 `MaskedException`,不是原型別。
- 自己解析 `ILoggerProvider` 建記錄器的程式碼,以及不經 `Microsoft.Extensions.Logging` 的日誌函式庫,不在涵蓋範圍。

效能:層級沒開的話在格式化之前就返回。開著時訊息只格式化一次;沒有東西需要遮 —— 最常見的情況 —— 原本的狀態、例外與格式化委派原封不動往下傳,
不配置任何東西。有改到才配置一個狀態物件(加一份屬性陣列)。

## 封裝格式

| | 魔術字 | 版面 |
| --- | --- | --- |
| `DpapiSecretProtector` | `OZDP` | 魔術字(4)+ 版本(1)+ 保護範圍(1)+ DPAPI 密文 |
| `ConfigurationProtector` | `OZCF` | 魔術字(4)+ 版本(1)+ nonce(12)+ 驗證標籤(16)+ 密文 |
| `KeyedSecretProtector` | `OZCF` | 與 `ConfigurationProtector` 完全相同的封裝 —— 同一把金鑰下兩者互通 |

兩者的字串形式都是 Base64。`OZCF` 的標頭同時作為 AES-GCM 的關聯資料,把標頭與密文綁在同一個驗證標籤底下。

不過要說清楚現在實際會發生什麼:目前格式版本只有 1,所以魔術字或版本被改時,格式檢查會**先**擋下來,AES-GCM 根本沒被呼叫到 —— 那次拒絕來自格式檢查,不是驗證標籤。
關聯資料真正的用處是在日後多個格式版本並存時維持這層綁定;而它確實有生效這件事,由測試以「標頭是合法 v1、但密文是用不同關聯資料加密」的封裝驗證過。

## 失敗原因

`SecretProtectionException.Reason` 的可能值:

| 原因 | 意義 |
| --- | --- |
| `MalformedPayload` | 不是有效 Base64、長度不足,或缺少格式標頭。 |
| `UnsupportedFormatVersion` | 資料由較新版本的程式庫寫入。 |
| `ScopeMismatch` | 以 `LocalMachine` 加密卻用 `CurrentUser` 還原,或反過來。 |
| `DecryptionFailed` | 資料遭竄改、金鑰錯誤,或由其他使用者帳戶/其他機器加密。 |
| `PlatformNotSupported` | 目前平台不支援。內建的 DPAPI 實作遇到這個情況是拋 `PlatformNotSupportedException`,這個值保留給寧可回報原因、也不拋平台例外的替代實作。 |
| `KeyUnavailable` | `KeyedSecretProtector` 取不到主金鑰:變數未設定、金鑰檔不存在、長度不對,或權限對群組/其他人開放。資料沒問題,是這台主機沒配好。 |

## 執行需求與限制

- .NET 10。
- 只有 `DpapiSecretProtector` 需要 Windows。其餘全部 —— `KeyedSecretProtector`、遮罩、`ILogger` 包裝、`ConfigurationProtector`、PBKDF2 與
  ASP.NET Core 整合 —— 在 Linux、macOS、Windows 上都一樣能用。AES-GCM 需要平台的密碼學提供者支援,
  `ConfigurationProtector.IsSupported`(等同 `KeyedSecretProtector.IsSupported`)會回報,主流的 .NET 10 平台都有。
- 金鑰檔的權限檢查只針對 Unix 權限位元;Windows 上金鑰檔不經檢查直接讀。
- 日誌遮罩包裝遮的是字串屬性、格式化訊息與例外文字;它碰不到的部分見[日誌遮罩](#日誌遮罩)。

## 授權

MIT,詳見 [LICENSE](LICENSE)。
