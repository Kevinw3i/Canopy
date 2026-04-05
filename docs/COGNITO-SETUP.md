# AWS Cognito User Pool 設定指南

本文件說明如何建立 AWS Cognito User Pool 作為 Canopy 的 OIDC Provider。

---

## 為什麼需要這個

Production 模式下，Canopy 不接受 username 直接登入。所有使用者必須透過 OIDC Provider 驗證身分。Cognito User Pool 就是 AWS 提供的 OIDC Provider — 你建一個 User Pool，把使用者加進去，Canopy 就能透過它驗證「這個人是誰」。

```
維運人員                Canopy              Cognito
  │                    (Control Plane)           (User Pool)
  │                         │                        │
  │── 點擊 SSO Login ─────▶│                        │
  │◀── 打開瀏覽器 ─────────│                        │
  │── 在瀏覽器輸入帳密 ───────────────────────────▶│
  │◀── 驗證成功，回傳 token ─────────────────────────│
  │                         │── 驗證 token ────────▶│
  │                         │◀── 確認身分 ──────────│
  │◀── 登入成功 ────────────│                        │
```

---

## 第一步：建立 User Pool

1. 登入 AWS Console
2. 搜尋 **Cognito** → 點擊進入
3. 點擊 **Create user pool**

### Configure sign-in experience

| 設定 | 選什麼 |
|------|--------|
| Authentication providers | **Cognito user pool** |
| Cognito user pool sign-in options | 勾選 **Email** |

點擊 **Next**

### Configure security requirements

| 設定 | 選什麼 |
|------|--------|
| Password policy | 用預設值即可（或依公司政策調整） |
| Multi-factor authentication | **No MFA**（或選 Optional，依需求） |
| User account recovery | 勾選 **Email** |

點擊 **Next**

### Configure sign-up experience

| 設定 | 選什麼 |
|------|--------|
| Self-registration | **取消勾選**（不讓人自己註冊，由管理員建帳號） |
| Cognito-assisted verification | 勾選 **email** |
| Required attributes | 選 **email**、**name** |

點擊 **Next**

### Configure message delivery

| 設定 | 選什麼 |
|------|--------|
| Email provider | **Send email with Cognito**（免費，夠用） |

點擊 **Next**

### Integrate your app

這一步最重要：

| 設定 | 填什麼 |
|------|--------|
| User pool name | `canopy-users` |
| Hosted authentication pages | **Use the Cognito hosted UI** 打勾 |
| Domain type | **Use a Cognito domain** |
| Cognito domain | 輸入一個唯一名稱，例如 `canopy-yourcompany`（會變成 `https://canopy-yourcompany.auth.{region}.amazoncognito.com`） |

往下捲到 **Initial app client**：

| 設定 | 填什麼 |
|------|--------|
| App type | **Public client** |
| App client name | `canopy-tui` |
| Client secret | **Don't generate a client secret**（PKCE 不需要 secret） |
| Allowed callback URLs | `http://localhost:9876/callback` |
| Allowed sign-out URLs | （留空） |

展開 **Advanced app client settings**：

| 設定 | 確認 |
|------|------|
| OAuth 2.0 grant types | 確認 **Authorization code grant** 有勾選 |
| OpenID Connect scopes | 勾選 **openid**、**profile**、**email** |

點擊 **Next** → 確認設定 → **Create user pool**

---

## 第二步：記錄設定值

User Pool 建好後，在 Cognito 主控台找到以下資訊：

### User Pool ID

User Pool 詳細頁面的最上方，格式如：`us-east-1_AbCdEfGhI`

### App Client ID

左側選單 → **App integration** → 捲到最下方 **App clients and analytics** → 點擊你的 app client → 複製 **Client ID**

格式如：`1a2b3c4d5e6f7g8h9i0j`

### Cognito Domain

左側選單 → **App integration** → 最上方的 **Domain** 區塊

格式如：`https://canopy-yourcompany.auth.us-east-1.amazoncognito.com`

### 組合成 issuer_url

```
https://cognito-idp.{region}.amazonaws.com/{user-pool-id}
```

例如：
```
https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI
```

---

## 第三步：更新 config.toml

把上面的值填入 Control Plane 的設定檔：

```toml
dev_mode = false

[oidc]
issuer_url = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"
client_id = "1a2b3c4d5e6f7g8h9i0j"
# client_secret 不需要（PKCE public client）
scopes = ["openid", "profile", "email"]

# Cognito 的 authorization endpoint 需要手動指定（它的 .well-known 回傳的是 hosted UI domain）
authorization_endpoint = "https://canopy-yourcompany.auth.us-east-1.amazoncognito.com/oauth2/authorize"
token_endpoint = "https://canopy-yourcompany.auth.us-east-1.amazoncognito.com/oauth2/token"
device_authorization_endpoint = "https://canopy-yourcompany.auth.us-east-1.amazoncognito.com/oauth2/device_authorization"
```

---

## 第四步：建立使用者

### 方法 A：AWS Console

1. Cognito → 你的 User Pool → **Users** 分頁
2. 點擊 **Create user**
3. 填寫：
   - Email address：`alice@yourcompany.com`
   - Temporary password：設一個臨時密碼（使用者首次登入會被要求改）
4. 點擊 **Create user**

對每位維運人員重複。

### 方法 B：AWS CLI（批量建立）

```bash
# 建立單一使用者
aws cognito-idp admin-create-user \
  --user-pool-id us-east-1_AbCdEfGhI \
  --username alice@yourcompany.com \
  --user-attributes Name=email,Value=alice@yourcompany.com Name=name,Value="Alice Chen" \
  --temporary-password 'TempPass123!' \
  --message-action SUPPRESS

# 批量建立（從檔案讀取）
while IFS=, read -r email name; do
  aws cognito-idp admin-create-user \
    --user-pool-id us-east-1_AbCdEfGhI \
    --username "$email" \
    --user-attributes Name=email,Value="$email" Name=name,Value="$name" \
    --temporary-password 'TempPass123!' \
    --message-action SUPPRESS
  echo "Created: $email"
done << 'USERS'
alice@yourcompany.com,Alice Chen
bob@yourcompany.com,Bob Wang
charlie@yourcompany.com,Charlie Lin
USERS
```

---

## 第五步：更新 entitlements.toml

`[[memberships]]` 裡的 `user_id` 要對應 Cognito 使用者的 **sub**（UUID）或 **email**。

Cognito 的 `id_token` 預設包含 `sub`（UUID 格式如 `a1b2c3d4-e5f6-7890-abcd-ef1234567890`）和 `email`。我們的 Control Plane 用 `sub` 作為 user_id。

有兩種做法：

### 做法 A：用 email 作為 user_id（推薦，易讀）

先確認 Cognito 使用者的 sub：

```bash
aws cognito-idp admin-get-user \
  --user-pool-id us-east-1_AbCdEfGhI \
  --username alice@yourcompany.com \
  --query 'Username' --output text
```

但更簡單的做法是直接用 email。需要修改 Control Plane 的 `AuthService::exchange_oidc_code` 讓它用 `email` 而不是 `sub` 作為 user_id。目前的程式碼已經支援——`IdTokenClaims` 裡有 `email` 欄位，`identity_from_oidc_claims` 會優先使用。

在 `entitlements.toml` 中：

```toml
[[memberships]]
user_id = "alice@yourcompany.com"
group = "platform-engineering"

[[memberships]]
user_id = "bob@yourcompany.com"
group = "readonly-ops"
```

### 做法 B：用 Cognito sub（UUID）作為 user_id

```toml
[[memberships]]
user_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
group = "platform-engineering"
```

---

## 第六步：測試

1. 啟動 Control Plane（`dev_mode = false`）
2. 啟動 TUI（`dev_mode = false`）
3. 點擊 **SSO / OIDC (PKCE)**
4. 瀏覽器打開 Cognito Hosted UI
5. 輸入使用者的 email 和密碼
6. 首次登入會要求改密碼
7. 認證成功後瀏覽器顯示 "Authentication Successful"
8. 回到終端機，自動進入 Dashboard

---

## 常見問題

### Q: 瀏覽器打開後顯示 "redirect_mismatch"

Cognito 的 **Allowed callback URLs** 沒有包含 `http://localhost:9876/callback`。

到 Cognito → App integration → App client → 編輯 → 加入 callback URL。

### Q: 登入成功但 TUI 顯示 "Failed to fetch entitlements" 或權限全空

`entitlements.toml` 裡的 `user_id` 和 Cognito 回傳的身分不匹配。

除錯步驟：
1. 看 Control Plane 的日誌，找到 `audit` 行裡的 `actor` 欄位
2. 把那個值填進 `entitlements.toml` 的 `user_id`

### Q: 想啟用 Device Code 流程（headless 終端機）

Cognito 從 2024 年開始支援 Device Code 流程。需要在 App client 設定中啟用：

1. Cognito → App integration → App client
2. 編輯 → OAuth 2.0 grant types → 勾選 **Device code grant**

### Q: 想讓使用者用 Google/GitHub 帳號登入

Cognito 支援 Federation：
1. Cognito → Sign-in experience → Federated identity providers
2. 新增 Google / GitHub / SAML provider
3. 使用者就可以在 Hosted UI 上選擇第三方登入

### Q: 費用

- Cognito User Pool：前 50,000 MAU 免費
- 之後 $0.0055/MAU
- 內部維運工具通常不會超過免費額度
