# Release 流程

本專案使用 monorepo 結構，TUI Client 和 Control-Plane 各自獨立發版。
推送對應格式的 git tag 後，GitHub Actions 會自動建置並建立 Release。

---

## TUI Client 發版

### Tag 格式

| 類型 | Tag 格式 | 範例 | Release 標記 |
|------|---------|------|-------------|
| 正式版 | `tui-v<semver>` | `tui-v1.0.0` | Latest |
| Pre-release | `tui-v<semver>-<label>` | `tui-v0.2.0-alpha.1` | Pre-release |

Tag 名稱包含 `alpha`、`beta`、`rc` 時會自動標記為 Pre-release。

### 發版步驟

```bash
# 1. 確認在主分支且工作目錄乾淨
git checkout main
git pull origin main
git status  # 確認沒有未提交的變更

# 2. 更新版號（workspace 統一管理）
#    編輯 Cargo.toml 中的 [workspace.package] version
#    例如 version = "0.2.0"

# 3. 提交版號變更
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to 0.2.0"
git push origin main

# 4. 建立 tag 並推送
git tag tui-v0.2.0
git push origin tui-v0.2.0
```

### 自動化流程

推送 tag 後，`.github/workflows/release-tui.yml` 會自動執行：

1. **Build（4 平台平行編譯）**

   | 平台 | Target | 產出檔名 |
   |------|--------|---------|
   | macOS Apple Silicon | `aarch64-apple-darwin` | `canopy-darwin-arm64.tar.gz` |
   | macOS Intel | `x86_64-apple-darwin` | `canopy-darwin-amd64.tar.gz` |
   | Linux x86_64 | `x86_64-unknown-linux-gnu` | `canopy-linux-amd64.tar.gz` |
   | Linux ARM64 | `aarch64-unknown-linux-gnu` | `canopy-linux-arm64.tar.gz` |

2. **產生 SHA256 驗證檔** — 每個 `.tar.gz` 附帶一個 `.tar.gz.sha256`

3. **建立 GitHub Release** — 自動帶安裝說明，上傳所有 assets

### 查看狀態

```bash
# 查看 CI 是否正在跑
gh run list --workflow=release-tui.yml

# 查看特定 run 的狀態
gh run view <run-id>

# 列出已發布的 releases
gh release list
```

---

## 版本號規則

採用 [Semantic Versioning](https://semver.org/)：

- **MAJOR** — 不相容的 API 變更（control-plane 端點變動導致舊 TUI 無法使用）
- **MINOR** — 新增功能（新畫面、新操作）
- **PATCH** — Bug 修復、UI 微調

### Pre-release 標籤

| 標籤 | 用途 | 範例 |
|------|------|------|
| `alpha` | 早期測試，功能可能不完整 | `tui-v0.3.0-alpha.1` |
| `beta` | 功能完整，內部測試中 | `tui-v0.3.0-beta.1` |
| `rc` | Release candidate，準備上線 | `tui-v0.3.0-rc.1` |

---

## 手動發版（緊急修復）

如果 CI 失敗或需要手動發版：

```bash
# 在本機編譯指定平台
cargo build --release -p tui-client --target aarch64-apple-darwin

# 打包
cd target/aarch64-apple-darwin/release
cp tui-client canopy
tar czf canopy-darwin-arm64.tar.gz canopy
shasum -a 256 canopy-darwin-arm64.tar.gz > canopy-darwin-arm64.tar.gz.sha256

# 手動上傳到現有 release
gh release upload tui-v0.2.0 canopy-darwin-arm64.tar.gz canopy-darwin-arm64.tar.gz.sha256

# 或建立新 release
gh release create tui-v0.2.0 canopy-darwin-arm64.tar.gz canopy-darwin-arm64.tar.gz.sha256 \
  --title "TUI Client 0.2.0" \
  --notes "Emergency release"
```

---

## 使用者安裝

Release 頁面會自動包含安裝指令。使用者也可以用 `scripts/package.sh` 產生完整的分發資料夾（含 config + install script）。

### 下載驗證

每個 asset 都附有 SHA256 驗證檔：

```bash
# 下載
curl -LO https://github.com/<owner>/<repo>/releases/download/tui-v0.2.0/canopy-darwin-arm64.tar.gz
curl -LO https://github.com/<owner>/<repo>/releases/download/tui-v0.2.0/canopy-darwin-arm64.tar.gz.sha256

# 驗證
shasum -a 256 -c canopy-darwin-arm64.tar.gz.sha256

# 安裝
tar xzf canopy-darwin-arm64.tar.gz
chmod +x canopy
sudo mv canopy /usr/local/bin/
```

---

## Control-Plane Image 發版

Control-plane 部署到 ECS Fargate，用 Docker image 管理，不走 GitHub Releases。
推送 `cp-v*` tag 後，`.github/workflows/release-control-plane.yml` 會自動 build Docker image 並推送到 ECR。

### 一次性 AWS / GitHub 設定

GitHub Actions 使用 OIDC assume AWS role，不需要長期 AWS access key。

AWS account `<AWS_ACCOUNT_ID>` 需要有一個給 GitHub Actions 使用的 IAM role。Trust policy 範例：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<AWS_ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": [
            "repo:Kevinw3i/Canopy:ref:refs/tags/cp-v*",
            "repo:Kevinw3i/Canopy:ref:refs/heads/master"
          ]
        }
      }
    }
  ]
}
```

該 role 需要最小 ECR push 權限：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrAuth",
      "Effect": "Allow",
      "Action": "ecr:GetAuthorizationToken",
      "Resource": "*"
    },
    {
      "Sid": "PushCanopyControlPlane",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart"
      ],
      "Resource": "arn:aws:ecr:ap-northeast-1:<AWS_ACCOUNT_ID>:repository/canopy/control-plane"
    }
  ]
}
```

GitHub repo secrets：

| Secret | 用途 |
|--------|------|
| `AWS_GHA_ECR_PUSH_ROLE_ARN` | GitHub Actions 要 assume 的 AWS role ARN |
| `CONTROL_PLANE_ENTITLEMENTS_TOML_B64` | `entitlements.toml` 的 base64 內容，build image 時寫回檔案 |
| `CONTROL_PLANE_TFVARS_B64` | `infra/terraform.tfvars` 的 base64 內容，用來在 CI 驗證 Terraform 部署 preconditions 與 entitlements，並依 `cpu_architecture` 決定 Docker platform、依 `project` 決定 ECR repository |

設定 secrets：

```bash
gh secret set AWS_GHA_ECR_PUSH_ROLE_ARN \
  --body "arn:aws:iam::<AWS_ACCOUNT_ID>:role/<github-actions-ecr-push-role>"

gh secret set CONTROL_PLANE_ENTITLEMENTS_TOML_B64 \
  --body "$(base64 < entitlements.toml | tr -d '\n')"

gh secret set CONTROL_PLANE_TFVARS_B64 \
  --body "$(base64 < infra/terraform.tfvars | tr -d '\n')"
```

### 發版步驟

```bash
git checkout master
git pull origin master

git tag cp-v0.1.0
git push origin cp-v0.1.0
```

Workflow 完成後會推送 image：

```text
<AWS_ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:cp-v0.1.0
```

ECR repository 是 immutable，同一個 tag 不能重複推送，且不可使用 `latest`。
需要重新發版時請建立新 tag，例如 `cp-v0.1.1`。
Workflow 會從 `CONTROL_PLANE_TFVARS_B64` 還原 `infra/terraform.tfvars`，先以
`scripts/validate-terraform-tfvars.sh infra -var="create_service=true" -var="image_tag=<release-tag>"`
驗證 Phase 2 部署 preconditions，再驗證 entitlements，最後推送到
`<project>/control-plane`。如果 `project` 不是 `canopy`，請同步調整
GitHub Actions ECR push role 的 repository ARN。

### 部署到 ECS

GitHub Actions 只負責 build/push image，不會自動修改 ECS。image 推送完成後，再手動執行 Terraform Phase 2：

```bash
AWS_PROFILE=your-aws-profile terraform -chdir=infra plan \
  -var="create_service=true" \
  -var="image_tag=cp-v0.1.0" \
  -out=tfplan.phase2

AWS_PROFILE=your-aws-profile terraform -chdir=infra apply tfplan.phase2
```
