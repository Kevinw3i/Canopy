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
  --query 'Versions[?VersionStages[0]==`AWSCURRENT`].VersionId | [0]' --output text)

# 編輯 terraform.tfvars：
#   jwt_secret_arn        = "<上面的 ARN>"
#   jwt_secret_version_id = "<上面的 version ID>"

cd infra
cp backend.hcl.example backend.hcl
terraform init -backend-config=backend.hcl
terraform apply -var="create_service=false"
```

### Phase 2: Build image + 啟動 ECS service

```bash
# 取得 ECR URL
ECR_URL=$(terraform output -raw ecr_repository_url)

# 登入 ECR
ECR_REGISTRY=$(echo "$ECR_URL" | cut -d/ -f1)
aws ecr get-login-password --region ap-northeast-1 | \
  docker login --username AWS --password-stdin "$ECR_REGISTRY"

# Build & push（platform 須與 Terraform 的 cpu_architecture 一致）
cd ..
VERSION=$(git describe --tags --always)
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in X86_64) PLATFORM="linux/amd64" ;; ARM64) PLATFORM="linux/arm64" ;; *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;; esac
DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" -t "$ECR_URL:$VERSION" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -f apps/control-plane/Dockerfile .
docker push "$ECR_URL:$VERSION"

# 回到 infra，建立 ECS service（create_service 預設 true）
cd infra
terraform apply -var="image_tag=$VERSION"
```

## 部署新版本

程式碼改動後，重新 build image 並部署。

> **重要：** 因為 entitlements 是 bake 進 Docker image 的，rolling update 期間會有新舊授權規則同時生效的短暫窗口。
> 如果此次變更包含 entitlements 修改，建議用 `desired_count=1` 先縮容，部署完再擴回原數量，以確保授權規則一致性。
>
> 部署前請先驗證 entitlements 與 Terraform 變數一致：
> ```bash
> ./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars
> ```

```bash
ECR_URL=$(cd infra && terraform output -raw ecr_repository_url)
VERSION=$(git describe --tags --always)
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in X86_64) PLATFORM="linux/amd64" ;; ARM64) PLATFORM="linux/arm64" ;; *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;; esac

# Build + push（帶 platform 和 entitlements）
DOCKER_BUILDKIT=1 docker build --platform "$PLATFORM" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -t "$ECR_URL:$VERSION" \
  -f apps/control-plane/Dockerfile .
docker push "$ECR_URL:$VERSION"

# 用新版 image tag 更新 Terraform（ECR 是 IMMUTABLE，不再使用 latest）
cd infra
terraform apply -var="image_tag=$VERSION"

# 等待部署完成
aws ecs wait services-stable \
  --cluster $(terraform output -raw ecs_cluster_name) \
  --services $(terraform output -raw ecs_service_name)
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
| `vpc_id` | Yes | VPC ID |
| `public_subnet_ids` | Yes | ALB 所在的 public subnets |
| `private_subnet_ids` | Yes | ECS task 所在的 private subnets |
| `acm_certificate_arn` | Yes | HTTPS 憑證 ARN |
| `jwt_secret_arn` | Yes | Secrets Manager ARN（JWT 簽署密鑰，須在 Terraform 外建立） |
| `oidc_issuer_url` | Yes | OIDC provider URL |
| `oidc_client_id` | Yes | OIDC client ID |
| `image_tag` | Phase 2 | 版本 tag 或 git SHA（不可使用 `latest`）；`create_service = false` 的 Phase 1 可留空 |
| `alb_allowed_cidrs` | Yes | ALB 入站允許的 CIDR 清單 |
| `aws_region` | No | 預設 `ap-northeast-1` |
| `cpu` / `memory` | No | 預設 512 / 1024 |
| `desired_count` | No | 預設 2（跨 AZ） |
| `alb_internal` | No | 預設 `true`（內部 ALB） |
| `sts_external_id` | No | 預設 `canopy`，跨帳號 AssumeRole 的 ExternalId |
| `route53_zone_id` / `domain_name` | No | 設定後自動建 DNS record |
| `assumable_role_arns` | No | 跨帳號 AssumeRole 的目標 role ARN 清單 |
| `enable_direct_access` | No | 預設 `false`；設為 `true` 時允許 `role_arn = "direct"` 查看部署帳號的 EC2、ECS task inventory、CloudWatch Logs |
| `log_retention_days` | No | 預設 90 天 |
| `cors_allowed_origins` | No | CORS 允許的來源 |

## 監控

```bash
# 查看 service 狀態
aws ecs describe-services \
  --cluster $(terraform output -raw ecs_cluster_name) \
  --services $(terraform output -raw ecs_service_name) \
  --query 'services[0].{status:status,running:runningCount,desired:desiredCount}'

# 查看容器日誌
aws logs tail $(terraform output -raw log_group_name) --follow

# 測試 health endpoint
curl -s https://$(terraform output -raw alb_dns_name)/health
```

## 銷毀

```bash
terraform destroy
```

> 注意：這會刪除所有資源，包括 ECR 裡的 image 和 Secrets Manager 的 secret。
