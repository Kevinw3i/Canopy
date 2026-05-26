# Control-Plane Infrastructure (Terraform)

本目錄管理 Control-Plane 在 AWS 上的所有基礎設施。

## 管理的資源

| 資源 | 用途 |
|------|------|
| ECR Repository | 存放 control-plane Docker image |
| ECS Cluster + Service | Fargate 執行 control-plane 容器 |
| ALB + Target Group | HTTPS 入口 + health check |
| Security Groups | ALB 允許 443 入站；ECS task 只接受 ALB 流量 |
| IAM Roles | Task Execution（拉 image、讀 secret）+ Task（呼叫 AWS API） |
| Secrets Manager | JWT signing secret |
| CloudWatch Log Group | 容器日誌 |
| Route 53 Record | DNS 指向 ALB（可選） |

## 前置準備

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- AWS CLI 已設定，且有足夠權限建立上述資源
- 一個 VPC，至少 2 個 public subnet（ALB，僅 `alb_internal = false` 時需要）+ 2 個 private subnet（ECS task）
- **Private subnet 須有對外連線能力**（NAT Gateway 或 VPC Endpoints），ECS task 需要存取：ECR、Secrets Manager、CloudWatch Logs、AWS API、外部 OIDC issuer
- ACM 憑證（HTTPS 用）
- JWT signing secret 已建立於 Secrets Manager（見下方首次部署流程）

## 快速開始

首次部署請直接跳至「首次部署完整流程」。此處僅供已部署環境的日常操作。

```bash
cd infra
cp backend.hcl.example backend.hcl
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

## 首次部署完整流程

首次部署需要兩階段：先建 ECR（不建 ECS service），push image 後再建 service。

### Phase 1: 建立基礎設施 + ECR（不含 ECS service）

```bash
# 建立 JWT signing secret（只需做一次）
aws secretsmanager create-secret \
  --name canopy/jwt-secret \
  --secret-string "$(openssl rand -base64 44)" \
  --region ap-northeast-1

# 取得 secret ARN 和 version ID，填入 terraform.tfvars
JWT_ARN=$(aws secretsmanager describe-secret --secret-id canopy/jwt-secret --query ARN --output text)
JWT_VER=$(aws secretsmanager list-secret-version-ids --secret-id canopy/jwt-secret \
  --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId | [0]' --output text)

# 編輯 terraform.tfvars：
#   jwt_secret_arn        = "<上面的 ARN>"
#   jwt_secret_version_id = "<上面的 version ID>"

cd infra
cp backend.hcl.example backend.hcl
terraform init -backend-config=backend.hcl
../scripts/validate-terraform-tfvars.sh . -var="create_service=false"
terraform apply -var="create_service=false"
```

### Phase 2: Build image + 啟動 ECS service

建議從 repo root 使用本機部署 helper。它會先跑
`validate-terraform-tfvars.sh`、`validate-entitlements.sh`、Terraform Phase 2
plan、image tag collision 檢查、Docker build/push，最後 apply 並等待 ECS
service stable：

```bash
cd /path/to/Canopy

VERSION=cp-v0.1.0

# 先只產生並檢查 Terraform Phase 2 plan，不 build/push/apply。
./scripts/deploy-control-plane-local.sh "$VERSION" --plan-only

# 確認 plan 後執行完整部署；預設會在 push 和 apply 前互動確認。
./scripts/deploy-control-plane-local.sh "$VERSION"
```

如需手動拆步執行，流程如下：

```bash
# 取得 ECR URL
ECR_URL=$(terraform output -raw ecr_repository_url)

# 取得 ECR repository 與 region
ECR_REGISTRY=$(echo "$ECR_URL" | cut -d/ -f1)
ECR_REPOSITORY=$(echo "$ECR_URL" | cut -d/ -f2-)
AWS_REGION=$(awk -F= '/^[[:space:]]*aws_region[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' terraform.tfvars)
AWS_REGION=${AWS_REGION:-ap-northeast-1}

# Build & push（platform 須與 Terraform 的 cpu_architecture 一致）
cd ..
# entitlements.toml 應已由 entitlements.sample.toml 複製並填入實際權限規則
test -s entitlements.toml
VERSION=$(git describe --tags --always)
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in X86_64) PLATFORM="linux/amd64" ;; ARM64) PLATFORM="linux/arm64" ;; *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;; esac
./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=true" \
  -var="image_tag=$VERSION"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars

# 先產生 Phase 2 plan，確認不會 destroy 非預期資源。
terraform -chdir=infra plan \
  -var="create_service=true" \
  -var="image_tag=$VERSION" \
  -out=tfplan.phase2

# ECR 是 immutable；tag 已存在就換一個 VERSION。
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

DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" -t "$ECR_URL:$VERSION" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -f apps/control-plane/Dockerfile .
docker push "$ECR_URL:$VERSION"

terraform -chdir=infra apply tfplan.phase2
```

## 部署新版本

程式碼改動後，重新 build image 並部署。

> **重要：** 因為 entitlements 是 bake 進 Docker image 的，rolling update 期間會有新舊授權規則同時生效的短暫窗口。
> 如果此次變更包含 entitlements 修改，建議用 `desired_count=1` 先縮容，部署完再擴回原數量，以確保授權規則一致性。
>
> 部署前請先用即將部署的 image tag 驗證 Terraform Phase 2 變數本身有效，
> 並驗證 entitlements 與 Terraform 變數一致：
> ```bash
> VERSION=<new-image-tag>
> ./scripts/validate-terraform-tfvars.sh infra \
>   -var="create_service=true" \
>   -var="image_tag=$VERSION"
> ./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars
> ```
>
> 第一個檢查會用 backendless Terraform mock plan 驗證 `terraform.tfvars` 的
> ALB/DNS/subnet/service preconditions。第二個檢查會同時驗證 active
> entitlements 沒有 sample placeholder、AssumeRole ARN 都列在
> `assumable_role_arns`、`role_arn` 格式有效且 IAM Role ARN 不含 wildcard、
> 使用 `direct` 時已啟用 `enable_direct_access`、部署時禁止的 `profile:*`、
> ECS Exec rule 必須使用 AssumeRole ARN 並同時授權 ECS view、授予 ECS
> 存取的 rule 必須有明確 `allowed_clusters` 且寬鬆 wildcard 需要
> `allow_broad_cluster_discovery=true`，以及 SSM rule 必須設定明確的
> `allowed_os_users`。

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

# Build + push（帶 platform 和 entitlements）
DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -t "$ECR_URL:$VERSION" \
  -f apps/control-plane/Dockerfile .
docker push "$ECR_URL:$VERSION"

# 用新版 image tag 更新 Terraform（ECR 是 IMMUTABLE，不再使用 latest）
terraform -chdir=infra apply tfplan.phase2

# 等待部署完成
aws ecs wait services-stable \
  --cluster $(cd infra && terraform output -raw ecs_cluster_name) \
  --services $(cd infra && terraform output -raw ecs_service_name) \
  --region "$AWS_REGION"
```

## 修改基礎設施

改動 `.tf` 檔案後：

```bash
terraform plan    # 預覽影響範圍
terraform apply   # 確認後套用
```

## 遠端 State（建議）

正式使用前，先複製範本並填入你的 bucket：

```bash
cp backend.hcl.example backend.hcl
```

內容如下：

```hcl
bucket         = "canopy-tfstate-<ACCOUNT_ID>"
key            = "control-plane/terraform.tfstate"
region         = "ap-northeast-1"
dynamodb_table = "canopy-tflock"
encrypt        = true
```

然後重新 `terraform init` 遷移 state。

## 變數說明

| 變數 | 必填 | 說明 |
|------|------|------|
| `vpc_id` | Yes | `create_vpc = false` 時必填的 VPC ID |
| `public_subnet_ids` | Conditional | `create_vpc = false` 且 `alb_internal = false` 時必須至少 2 個 subnet IDs |
| `private_subnet_ids` | Yes | `create_vpc = false` 時必須至少 2 個 subnet IDs；ECS task 所在 subnets |
| `acm_certificate_arn` | Yes | HTTPS 憑證 ACM certificate ARN |
| `jwt_secret_arn` | Yes | Secrets Manager secret ARN（JWT 簽署密鑰，須在 Terraform 外建立） |
| `oidc_issuer_url` | Yes | OIDC provider HTTPS issuer URL（不可含 query、fragment 或 whitespace） |
| `oidc_client_id` | Yes | OIDC client ID（不可為空或含 whitespace） |
| `project` | No | 預設 `canopy`；1-28 字元，僅 lowercase letters、numbers、hyphens，且不可頭尾 hyphen |
| `image_tag` | Phase 2 | 有效 Docker tag 或 git SHA（不可使用 `latest`）；`create_service = false` 的 Phase 1 可留空 |
| `alb_allowed_cidrs` | Yes | ALB 入站允許的 IPv4 CIDR 清單；public ALB 使用 `0.0.0.0/0` 時必須明確 opt-in |
| `aws_region` | No | 預設 `ap-northeast-1` |
| `cpu` / `memory` | No | 預設 512 / 1024；必須符合 AWS Fargate Linux task size 組合 |
| `desired_count` | No | 預設 2（跨 AZ）；必須是非負整數 |
| `alb_internal` | No | 預設 `true`（內部 ALB） |
| `allow_public_alb_world_cidr` | No | 預設 `false`；只有 public ALB 必須允許全網段時才設為 `true` |
| `sts_external_id` | No | 預設 `canopy`，跨帳號 AssumeRole 的 ExternalId；必須符合 STS ExternalId 格式限制 |
| `jwt_expiry_seconds` | No | 預設 3600；必須是正整數 |
| `aws_session_duration_seconds` | No | 預設 3600；STS AssumeRole session 秒數，必須介於 900 到 43200 |
| `entitlements_file` | No | 預設 `/etc/canopy/entitlements.toml`；必須是容器內絕對路徑 |
| `route53_zone_id` / `domain_name` | No | 設定後自動建 DNS record；必須同時設定，或同時留空 |
| `assumable_role_arns` | No | 跨帳號 AssumeRole 的目標 IAM role ARN 清單；不允許 wildcard |
| `enable_direct_access` | No | 預設 `false`；設為 `true` 時允許 `role_arn = "direct"` 查看部署帳號的 EC2、ECS task inventory、CloudWatch Logs |
| `log_retention_days` | No | 預設 90 天；必須是 CloudWatch Logs 支援的 retention 天數 |
| `cors_allowed_origins` | No | CORS 允許的 origins；只接受 scheme + host + optional port |

## 監控

```bash
AWS_REGION=$(awk -F= '/^[[:space:]]*aws_region[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
AWS_REGION=${AWS_REGION:-ap-northeast-1}

# 查看 service 狀態
aws ecs describe-services \
  --cluster $(terraform -chdir=infra output -raw ecs_cluster_name) \
  --services $(terraform -chdir=infra output -raw ecs_service_name) \
  --region "$AWS_REGION" \
  --query 'services[0].{status:status,running:runningCount,desired:desiredCount}'

# 查看容器日誌
aws logs tail $(terraform -chdir=infra output -raw log_group_name) \
  --region "$AWS_REGION" \
  --follow

# 測試 health endpoint
curl -s https://$(terraform -chdir=infra output -raw alb_dns_name)/health
```

## 銷毀

`terraform destroy` 會刪除 Terraform 管理的 ECS/ALB/IAM/CloudWatch/Route 53
資源。ECR repository 設有 `prevent_destroy = true` 且 `force_delete = false`，
因此不會連同 image 被自動刪除；JWT/OIDC Secrets Manager secrets 也是
out-of-band 建立並以 ARN 傳入，不會由 Terraform destroy 刪除。

```bash
terraform destroy
```
