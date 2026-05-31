# Control-Plane 首次部署到 AWS ECS（Terraform）

> 本文件是從零開始的完整部署教學。
> 假設你的 AWS 環境已有 VPC 和其他服務在運行，但尚未建立任何 Canopy 相關資源。
>
> 基礎設施定義在 [`infra/`](../../infra/) 目錄，所有資源由 Terraform 管理。

---

## 架構概覽

```
使用者 (TUI Client)
    │
    ▼ HTTPS :443
┌─────────┐
│   ALB   │  ← ACM 憑證 + Security Group (允許指定 CIDR)
└────┬────┘
     │ :8443
     ▼
┌──────────────────┐
│  ECS Fargate     │  ← Private Subnet × 2 AZ
│  control-plane   │  ← Task Role: STS AssumeRole, EC2, CloudWatch
│  (desired: 2)    │  ← Execution Role: ECR pull, Secrets Manager
└────────┬─────────┘
         │
    ┌────┴────┐
    ▼         ▼
 AWS APIs   OIDC Provider
(STS/EC2)  (Google/Okta)
```

**Terraform 會建立的資源：**

| 資源 | 用途 |
|------|------|
| ECR Repository | 存放 control-plane Docker image |
| ECS Cluster + Service | Fargate 執行 control-plane 容器 |
| ALB + Target Group | HTTPS 入口 + health check |
| Security Groups | ALB 允許 443 入站；ECS task 只接受 ALB 流量 |
| IAM Roles | Task Execution（拉 image、讀 secret）+ Task（呼叫 AWS API） |
| CloudWatch Log Group | 容器日誌 |
| Route 53 Record | DNS 指向 ALB（可選） |

---

## 前置條件

你的 AWS 環境需要已存在以下資源：

| 需要的東西 | 說明 |
|-----------|------|
| VPC | 一個已存在的 VPC |
| Public Subnets ×2 | 至少 2 個 AZ，放 ALB 用（若 ALB 對外） |
| Private Subnets ×2 | 至少 2 個 AZ，放 ECS task |
| NAT Gateway | Private subnet 需要對外連線（拉 ECR image、打 OIDC、AWS API） |
| ACM 憑證 | HTTPS 用的 TLS 憑證 |
| OIDC Provider | 例如 Google Workspace、Okta，需要 issuer URL + client ID |

本機需安裝：

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- AWS CLI v2（已 `aws configure`，有足夠權限）
- Docker

以下範例使用 Region `ap-northeast-1`。AWS CLI / Terraform 會使用 default credential chain；若需要指定 profile，先 `export AWS_PROFILE=<write-profile>`。

---

## Step 0：查詢現有 VPC / Subnet 資訊

如果你不確定現有的 VPC 和 Subnet ID，先查一下：

```bash
# 列出所有 VPC
aws ec2 describe-vpcs \
  --query 'Vpcs[*].{ID:VpcId,CIDR:CidrBlock,Name:Tags[?Key==`Name`].Value|[0]}' \
  --output table

# 列出指定 VPC 的所有 Subnet
aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=vpc-xxxxxxxxx" \
  --query 'Subnets[*].{ID:SubnetId,AZ:AvailabilityZone,CIDR:CidrBlock,Public:MapPublicIpOnLaunch}' \
  --output table
```

記下你要使用的：
- `vpc_id`
- `public_subnet_ids`（`MapPublicIpOnLaunch: true` 的那些）
- `private_subnet_ids`（`MapPublicIpOnLaunch: false` 的那些）

---

## Step 1：建立 Terraform Remote State 的 S3 Backend

Terraform state 存在 S3，避免 local state 遺失：

```bash
aws s3api create-bucket \
  --bucket canopy-terraform-state \
  --region ap-northeast-1 \
  --create-bucket-configuration LocationConstraint=ap-northeast-1

aws s3api put-bucket-versioning \
  --bucket canopy-terraform-state \
  --versioning-configuration Status=Enabled

aws dynamodb create-table \
  --table-name canopy-tflock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region ap-northeast-1
```

從範本建立本機 `infra/backend.hcl`。`backend.hcl.example` 會進 repo，
實際的 `backend.hcl` 會被 `.gitignore` 排除，避免把環境專用的
state bucket 寫進版本庫：

```bash
cd infra
cp backend.hcl.example backend.hcl
```

```hcl
bucket         = "canopy-terraform-state"
key            = "control-plane/terraform.tfstate"
region         = "ap-northeast-1"
dynamodb_table = "canopy-tflock"
encrypt        = true
```

> **注意：** S3 bucket 名稱是全球唯一的。如果 `canopy-terraform-state` 已被佔用，
> 請替換為你自己的名稱，並同步更新 `backend.hcl`。

---

## Step 2：建立 JWT Signing Secret

JWT 密鑰故意不放在 Terraform state 裡（安全考量），在 Terraform 外先建好：

```bash
AWS_REGION=${AWS_REGION:-ap-northeast-1}

aws secretsmanager create-secret \
  --name canopy/jwt-secret \
  --secret-string "$(openssl rand -base64 44)" \
  --region "$AWS_REGION"
```

記下 ARN 和 Version ID（後續填入 `terraform.tfvars`）：

```bash
AWS_REGION=${AWS_REGION:-ap-northeast-1}

JWT_ARN=$(aws secretsmanager describe-secret \
  --secret-id canopy/jwt-secret \
  --query ARN --output text \
  --region "$AWS_REGION")
echo "JWT_ARN = $JWT_ARN"

JWT_VER=$(aws secretsmanager list-secret-version-ids \
  --secret-id canopy/jwt-secret \
  --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId | [0]' \
  --output text \
  --region "$AWS_REGION")
echo "JWT_VER = $JWT_VER"
```

---

## Step 3：準備 `terraform.tfvars`

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
```

編輯 `terraform.tfvars`，填入你環境的實際值：

```hcl
aws_region         = "ap-northeast-1"

# ── 網路 ──
vpc_id             = "vpc-xxxxxxxxx"
public_subnet_ids  = ["subnet-aaa", "subnet-bbb"]
private_subnet_ids = ["subnet-ccc", "subnet-ddd"]

# ── TLS ──
acm_certificate_arn = "arn:aws:acm:ap-northeast-1:123456789012:certificate/xxxxx"

# ── Secrets ──
jwt_secret_arn        = "<Step 2 拿到的 JWT_ARN>"
jwt_secret_version_id = "<Step 2 拿到的 JWT_VER>"

# ── ALB ──
alb_allowed_cidrs = ["10.0.0.0/16"]
alb_internal      = true

# ── OIDC 認證 ──
oidc_issuer_url = "https://accounts.google.com"
oidc_client_id  = "your-google-client-id"

# ── Image（Phase 1 先留空）──
image_tag = ""
```

完整變數說明見 [`infra/README.md`](../../infra/README.md)。

---

## Step 4：Phase 1 — 建立基礎設施（不含 ECS Service）

第一次 apply 時 ECR 還沒有 image，用 `create_service=false` 只建基礎設施：

```bash
cd infra

terraform init -backend-config=backend.hcl

terraform plan -var="create_service=false"

terraform apply -var="create_service=false"
```

這會建立：ECR Repository、ECS Cluster、ALB、Security Groups、IAM Roles、CloudWatch Log Group。

> Phase 1 可以讓 `image_tag = ""`，因為此時還不會建立 ECS Task
> Definition / Service。Phase 2 開始建立 service 時必須提供明確 image tag。

---

## Step 5：準備 `entitlements.toml`

權限規則檔，會 bake 進 Docker image：

```bash
cd /path/to/Canopy
cp entitlements.sample.toml entitlements.toml
```

編輯 `entitlements.toml`，設定你的使用者、帳號、區域對應關係。
格式說明見 [`entitlements.sample.toml`](../../entitlements.sample.toml)。

Phase 1 還沒有 image，部署前先用 `create_service=false` 確認 Terraform
變數本身有效，並確認 entitlements 與 Terraform 變數一致：

```bash
./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=false"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars
```

第一個檢查會用 backendless Terraform mock plan 驗證 `terraform.tfvars` 的
ALB/DNS/subnet/service preconditions。第二個檢查會同時驗證 active
entitlements 沒有 sample placeholder、AssumeRole ARN 都列在
`assumable_role_arns`、Organizations role template 都列在
`assumable_role_arn_patterns`、`role_arn` 格式有效且 IAM Role ARN 不含 wildcard、
使用 `direct` 時已啟用 `enable_direct_access`、部署時禁止的 `profile:*`、
ECS Exec rule 必須使用 AssumeRole ARN 並同時授權 ECS view、授予 ECS
存取的 rule 必須有明確 `allowed_clusters` 且寬鬆 wildcard 需要
`allow_broad_cluster_discovery=true`，以及 SSM rule 必須設定明確的
`allowed_os_users`。

---

## Step 6：Build & Push Docker Image

建議從 repo root 使用本機部署 helper 執行 Step 6-8。它會先驗證
Terraform Phase 2 inputs 與 entitlements，再產生 plan、檢查 image tag
是否已存在、build/push image、apply Terraform，最後等待 ECS service stable：

```bash
cd /path/to/Canopy

VERSION=cp-v0.1.0

# 先只產生並檢查 Terraform Phase 2 plan，不 build/push/apply。
./scripts/deploy-control-plane-local.sh "$VERSION" --plan-only

# 確認 plan 後執行完整部署；預設會在 push 和 apply 前互動確認。
./scripts/deploy-control-plane-local.sh "$VERSION"
```

如果需要拆開手動執行，保留下列 Step 6-8 流程。

```bash
cd /path/to/Canopy

ECR_URL=$(cd infra && terraform output -raw ecr_repository_url)
ECR_REGISTRY=$(echo "$ECR_URL" | cut -d/ -f1)
ECR_REPOSITORY=$(echo "$ECR_URL" | cut -d/ -f2-)
AWS_REGION=$(awk -F= '/^[[:space:]]*aws_region[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
AWS_REGION=${AWS_REGION:-ap-northeast-1}

VERSION=$(git describe --tags --always)
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in X86_64) PLATFORM="linux/amd64" ;; ARM64) PLATFORM="linux/arm64" ;; *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;; esac

./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=true" \
  -var="image_tag=$VERSION"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars

terraform -chdir=infra plan \
  -var="create_service=true" \
  -var="image_tag=$VERSION" \
  -out=tfplan.phase2

if TAG_CHECK_OUTPUT=$(aws ecr describe-images \
  --region "$AWS_REGION" \
  --repository-name "$ECR_REPOSITORY" \
  --image-ids "imageTag=$VERSION" 2>&1); then
  echo "$TAG_CHECK_OUTPUT"
  echo "ECR image tag already exists: $VERSION"
  exit 1
else
  TAG_CHECK_STATUS=$?
  if ! grep -q "ImageNotFoundException" <<< "$TAG_CHECK_OUTPUT"; then
    echo "$TAG_CHECK_OUTPUT"
    exit "$TAG_CHECK_STATUS"
  fi
fi

aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" \
  -t "$ECR_URL:$VERSION" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -f apps/control-plane/Dockerfile .

docker push "$ECR_URL:$VERSION"

echo "Image tag: $VERSION"
```

> `--platform` 須與 `terraform.tfvars` 中的 `cpu_architecture` 一致：
> `X86_64` → `linux/amd64`、`ARM64` → `linux/arm64`。

---

## Step 7：Phase 2 — 啟動 ECS Service

```bash
terraform -chdir=infra apply tfplan.phase2
```

Terraform 會建立 ECS Task Definition + Service，Fargate 拉取你剛 push 的 image 並啟動。

---

## Step 8：驗證部署

```bash
AWS_REGION=${AWS_REGION:-$(awk -F= '/^[[:space:]]*aws_region[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)}
AWS_REGION=${AWS_REGION:-ap-northeast-1}

# 等待 service 穩定
aws ecs wait services-stable \
  --cluster $(cd infra && terraform output -raw ecs_cluster_name) \
  --services $(cd infra && terraform output -raw ecs_service_name) \
  --region "$AWS_REGION"

# 檢查 service 狀態
aws ecs describe-services \
  --cluster $(cd infra && terraform output -raw ecs_cluster_name) \
  --services $(cd infra && terraform output -raw ecs_service_name) \
  --region "$AWS_REGION" \
  --query 'services[0].{status:status,running:runningCount,desired:desiredCount}'

# 測試 health endpoint
curl -s https://$(cd infra && terraform output -raw alb_dns_name)/health

# 查看容器日誌
aws logs tail $(cd infra && terraform output -raw log_group_name) \
  --region "$AWS_REGION" \
  --follow
```

---

## 日後更新部署

程式碼或 entitlements 改動後：

```bash
ECR_URL=$(cd infra && terraform output -raw ecr_repository_url)
ECR_REGISTRY=$(echo "$ECR_URL" | cut -d/ -f1)
ECR_REPOSITORY=$(echo "$ECR_URL" | cut -d/ -f2-)
AWS_REGION=$(awk -F= '/^[[:space:]]*aws_region[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
AWS_REGION=${AWS_REGION:-ap-northeast-1}
VERSION=$(git describe --tags --always)
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in X86_64) PLATFORM="linux/amd64" ;; ARM64) PLATFORM="linux/arm64" ;; *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;; esac

./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=true" \
  -var="image_tag=$VERSION"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars

terraform -chdir=infra plan \
  -var="create_service=true" \
  -var="image_tag=$VERSION" \
  -out=tfplan.phase2

if TAG_CHECK_OUTPUT=$(aws ecr describe-images \
  --region "$AWS_REGION" \
  --repository-name "$ECR_REPOSITORY" \
  --image-ids "imageTag=$VERSION" 2>&1); then
  echo "$TAG_CHECK_OUTPUT"
  echo "ECR image tag already exists: $VERSION"
  exit 1
else
  TAG_CHECK_STATUS=$?
  if ! grep -q "ImageNotFoundException" <<< "$TAG_CHECK_OUTPUT"; then
    echo "$TAG_CHECK_OUTPUT"
    exit "$TAG_CHECK_STATUS"
  fi
fi

aws ecr get-login-password --region "$AWS_REGION" | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" \
  -t "$ECR_URL:$VERSION" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -f apps/control-plane/Dockerfile .

docker push "$ECR_URL:$VERSION"

terraform -chdir=infra apply tfplan.phase2
```

> **Entitlements 變更注意：** entitlements 是 bake 進 image 的，rolling update 期間
> 可能短暫存在新舊規則並存。`force_new_deployment = true` 只會觸發新部署，
> 不會在 `desired_count > 1` 時保證無重疊替換。若這次變更要求授權規則
> 不可重疊，先暫時把 `desired_count` 降到 `1`，新 image 穩定後再擴回原數量。

---

## 疑難排解

### Task 啟動失敗

```bash
# 查看 stopped task 的原因
aws ecs list-tasks --cluster canopy --service-name control-plane --desired-status STOPPED
aws ecs describe-tasks --cluster canopy --tasks <TASK_ARN> \
  --query 'tasks[0].{reason:stoppedReason,container:containers[0].{reason:reason,exit:exitCode}}'
```

### 常見問題

| 症狀 | 可能原因 |
|------|---------|
| Task 一直重啟 | Health check 失敗 — 檢查 `/health` 是否可達、config 是否正確 |
| `CannotPullContainerError` | ECR 登入過期、image tag 不存在、或 private subnet 沒有 NAT |
| `ResourceNotFoundException` (secret) | `jwt_secret_arn` 不正確或 secret 已刪除 |
| OIDC 驗證失敗 | `oidc_issuer_url` / `oidc_client_id` 設定錯誤，或 task 無法連外（NAT 問題） |

---

## 相關文件

- [`infra/README.md`](../../infra/README.md) — Terraform 變數說明、日常操作指令
- [`ECS_FARGATE_DEPLOYMENT.md`](ECS_FARGATE_DEPLOYMENT.md) — 手動 AWS CLI 部署參考（不使用 Terraform 時）
- [`config.sample.toml`](../../config.sample.toml) — 設定檔範本
- [`entitlements.sample.toml`](../../entitlements.sample.toml) — 權限規則範本
