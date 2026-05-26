# Control-Plane 部署到 AWS ECS Fargate

> **推薦方式**：專案已提供 Terraform IaC，可一鍵建立以下所有基礎設施。
> 詳見 [`infra/README.md`](../infra/README.md)。
>
> 以下手動 AWS CLI 步驟保留作為參考，適用於無法使用 Terraform 的環境或需要理解各資源細節的場景。

本文件說明如何將 Control-Plane 部署到 AWS ECS Fargate，使用 ALB 做 TLS termination。

## 架構

```
Internet
   │
   ▼
┌─────────────────────────┐
│  ALB (HTTPS :443)       │  ← TLS termination + ACM 憑證
│  Health check: /health  │
└────────┬────────────────┘
         │ HTTP :8443
         ▼
┌─────────────────────────┐
│  ECS Fargate Task       │  ← control-plane container
│  ┌───────────────────┐  │
│  │ control-plane     │  │  ← JWT_SECRET 由 ECS secrets 注入
│  │ port 8443         │  │  ← entitlements.toml 已 bake 進 image
│  └───────────────────┘  │
└────────┬────────────────┘
         │ AWS SDK (Task Role)
         ▼
┌─────────────────────────┐
│  AWS APIs               │
│  - EC2, CloudWatch Logs │
│  - STS (AssumeRole)     │
└─────────────────────────┘
```

---

## 前置準備

- AWS CLI v2 已設定
- Docker 已安裝
- 一個 AWS 帳號，有 ECR、ECS、ALB、Secrets Manager 權限
- 一個已註冊的域名（用於 ALB + ACM 憑證）

以下範例使用：
- Region: `ap-northeast-1`
- 帳號 ID: `<ACCOUNT_ID>`（替換成你的）
- 專案名稱: `canopy`

---

## Step 1: 建立 ECR Repository

```bash
aws ecr create-repository \
  --repository-name canopy/control-plane \
  --region ap-northeast-1

# 登入 ECR
aws ecr get-login-password --region ap-northeast-1 | \
  docker login --username AWS --password-stdin \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com
```

---

## Step 2: Build & Push Docker Image

```bash
# 在專案根目錄執行（因為 Dockerfile 需要 workspace context）
# entitlements.toml 必須先準備完成；若尚未建立，先完成 Step 5。
# Docker build 會把它 bake 進 image。
test -s entitlements.toml
VERSION=$(git describe --tags --always)
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in
  X86_64) PLATFORM="linux/amd64" ;;
  ARM64) PLATFORM="linux/arm64" ;;
  *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;;
esac

./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=true" \
  -var="image_tag=$VERSION"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars

DOCKER_BUILDKIT=1 docker build \
  --platform "$PLATFORM" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -t canopy/control-plane:${VERSION} \
  -f apps/control-plane/Dockerfile .

# Tag
docker tag canopy/control-plane:${VERSION} \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:${VERSION}

# Push
docker push \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:${VERSION}
```

ECR tag 應使用 git tag 或 commit hash；不要使用 `latest`，因為 Terraform
範本將 repository 設為 immutable。

`--platform` 必須和 `terraform.tfvars` 中的 `cpu_architecture`
一致：`X86_64` 對應 `linux/amd64`，`ARM64` 對應 `linux/arm64`。

---

## Step 3: 建立 Secrets Manager Secret

把敏感設定存到 Secrets Manager，不要寫在 config 檔或環境變數：

```bash
aws secretsmanager create-secret \
  --name canopy/jwt-secret \
  --secret-string "$(openssl rand -base64 32)" \
  --region ap-northeast-1

JWT_SECRET_ARN=$(aws secretsmanager describe-secret \
  --secret-id canopy/jwt-secret \
  --query ARN --output text \
  --region ap-northeast-1)
JWT_SECRET_VERSION_ID=$(aws secretsmanager list-secret-version-ids \
  --secret-id canopy/jwt-secret \
  --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId | [0]' \
  --output text \
  --region ap-northeast-1)
```

如果有 OIDC client secret：

```bash
aws secretsmanager create-secret \
  --name canopy/oidc-client-secret \
  --secret-string "your-oidc-client-secret" \
  --region ap-northeast-1

OIDC_CLIENT_SECRET_ARN=$(aws secretsmanager describe-secret \
  --secret-id canopy/oidc-client-secret \
  --query ARN --output text \
  --region ap-northeast-1)
OIDC_CLIENT_SECRET_VERSION_ID=$(aws secretsmanager list-secret-version-ids \
  --secret-id canopy/oidc-client-secret \
  --query 'Versions[?contains(VersionStages, `AWSCURRENT`)].VersionId | [0]' \
  --output text \
  --region ap-northeast-1)
```

Task definition 的 ECS secret `valueFrom` 建議 pin 到明確 version ID：
`<SECRET_ARN>:::<VERSION_ID>`。這能避免 rolling update 期間新舊 task
讀到不同 secret version。

---

## Step 4: 準備啟動設定值

正式 ECS 部署不需要預先產生 `config.toml`，也不要把 secret 寫進 repo、
Terraform state、或 baked config file。Task definition 設定 `GENERATE_CONFIG=1`
後，entrypoint 會從環境變數和 ECS-native `secrets` 在
`/tmp/canopy-config.toml` 產生啟動設定。

> **注意**：正式 ECS 部署建議使用 repo 內建的
> [`scripts/docker-entrypoint.sh`](../scripts/docker-entrypoint.sh)。Dockerfile
> 會把這個 entrypoint 放進 image；Terraform task definition 會用
> ECS-native `secrets` 注入 `JWT_SECRET` / `OIDC_CLIENT_SECRET`，並設定
> `GENERATE_CONFIG=1` 讓 entrypoint 在 `/tmp/canopy-config.toml` 產生啟動設定。
> 這樣 secret 不需要寫進 repo、Terraform state、或 baked config file。

entrypoint 的行為摘要：

```bash
GENERATE_CONFIG=1
JWT_SECRET=<injected by ECS secrets>
OIDC_ISSUER_URL=https://accounts.google.com
OIDC_CLIENT_ID=<client id>
ENTITLEMENTS_FILE=/etc/canopy/entitlements.toml
```

---

## Step 5: 準備 entitlements build secret

這一步必須在 Step 2 build image 之前完成。

`entitlements.toml` 不 commit 到 repo，也不要放進 Terraform state。正式 image
build 時透過 BuildKit secret 注入，Dockerfile 會把檔案 bake 到
`/etc/canopy/entitlements.toml` 並設為唯讀。

```bash
cp entitlements.sample.toml entitlements.toml
vi entitlements.toml

VERSION=${VERSION:-$(git describe --tags --always)}
./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=true" \
  -var="image_tag=$VERSION"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars
```

第一個檢查會用 backendless Terraform mock plan 驗證 `terraform.tfvars` 的
ALB/DNS/subnet/service preconditions。第二個檢查會確認 active entitlements
沒有 sample placeholder、AssumeRole ARN 已列在 `assumable_role_arns`、
`role_arn` 格式有效且 IAM Role ARN 不含 wildcard、使用 `direct` 時已啟用
`enable_direct_access`、`profile:*` 未被部署到 ECS、ECS Exec rule 不使用
direct/profile credentials 且同時授權 ECS view、授予 ECS 存取的 rule 有明確
`allowed_clusters` 且寬鬆 wildcard 已設定 `allow_broad_cluster_discovery=true`，
以及 SSM rule 有明確 `allowed_os_users`。

---

## Step 6: 建立 IAM Roles

### 6a. Task Execution Role（ECS 用來拉 image、讀 secret）

```bash
# 建立 role
aws iam create-role \
  --role-name canopy-task-execution \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# 附加 ECS 執行基本權限
aws iam attach-role-policy \
  --role-name canopy-task-execution \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# 加上 Secrets Manager 讀取權限
aws iam put-role-policy \
  --role-name canopy-task-execution \
  --policy-name secrets-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": [
        "arn:aws:secretsmanager:ap-northeast-1:<ACCOUNT_ID>:secret:canopy/*"
      ]
    }]
  }'

# config 由 entrypoint 產生，entitlements 已 bake 進 image；
# 目前不需要給 execution role 讀 S3 設定檔的權限。
```

### 6b. Task Role（control-plane 用來呼叫 AWS API）

```bash
aws iam create-role \
  --role-name canopy-task-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ecs-tasks.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# control-plane 需要的權限：
# - STS AssumeRole（跨帳號存取）
# - IAM SimulatePrincipalPolicy（connect/ECS Exec 前檢查候選 AssumeRole）
# - CloudWatch Logs（自身 log + 查詢）
# - EC2 DescribeInstances, DescribeInstanceConnectEndpoints
# - ECS task inventory（使用 `role_arn = "direct"` 查看部署帳號 ECS tasks 時）
aws iam put-role-policy \
  --role-name canopy-task-role \
  --policy-name canopy-permissions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AssumeTargetRoles",
        "Effect": "Allow",
        "Action": [
          "sts:AssumeRole",
          "sts:TagSession"
        ],
        "Resource": [
          "arn:aws:iam::<ACCOUNT_ID>:role/CanopyRole"
        ]
      },
      {
        "Sid": "SimulatePolicy",
        "Effect": "Allow",
        "Action": "iam:SimulatePrincipalPolicy",
        "Resource": [
          "arn:aws:iam::<ACCOUNT_ID>:role/CanopyRole"
        ]
      },
      {
        "Sid": "DirectAccessFallback",
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceConnectEndpoints",
          "ecs:DescribeClusters",
          "ecs:DescribeTasks",
          "ecs:ListClusters",
          "ecs:ListTasks",
          "logs:DescribeLogGroups",
          "logs:FilterLogEvents",
          "logs:StartQuery",
          "logs:GetQueryResults",
          "logs:StartLiveTail"
        ],
        "Resource": "*"
      }
    ]
  }'
```

> **`role_arn = "direct"` 模式**：如果 entitlements 裡用 `"direct"`，
> control-plane 會直接用 Task Role 的權限存取 inventory/logs 相關 AWS API，
> 不走 AssumeRole。確保 Task Role 有足夠權限。
>
> ECS Exec 在非 mock deployment 中仍需要可 AssumeRole 的 IAM role ARN，
> 因為 control-plane 必須回傳 scope 過的 STS credentials；不要用
> `direct` 或 `profile:*` 開啟 ECS Exec。
> ECS Exec 的 inline session policy 只允許目標 task 的 `ecs:ExecuteCommand`，
> 並以 `aws:RequestedRegion` 限制 `ecs:DescribeTasks` 與 `ssmmessages`
> helper channel actions 到同一個 requested region。
>
> **跨帳號模式**：如果要存取其他帳號的資源，在 `AssumeTargetRoles` 加上對應的 role ARN，
> 並在目標帳號的 role trust policy 信任這個 Task Role。Canopy 的 AssumeRole
> 會帶 ExternalId 與 STS session tags，所以 trust policy 也要允許
> `sts:TagSession` 並檢查 `sts:ExternalId`。

---

## Step 7: 建立 ECS Cluster

```bash
aws ecs create-cluster \
  --cluster-name canopy \
  --region ap-northeast-1
```

---

## Step 8: 建立 CloudWatch Log Group

```bash
aws logs create-log-group \
  --log-group-name /ecs/canopy/control-plane \
  --retention-in-days 90 \
  --region ap-northeast-1
```

---

## Step 9: 建立 Task Definition

```bash
cat > /tmp/task-def.json << 'EOF'
{
  "family": "canopy-control-plane",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "runtimePlatform": {
    "operatingSystemFamily": "LINUX",
    "cpuArchitecture": "X86_64"
  },
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/canopy-task-execution",
  "taskRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/canopy-task-role",
  "containerDefinitions": [
    {
      "name": "control-plane",
      "image": "<ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:<IMAGE_TAG>",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8443,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "RUST_LOG", "value": "control_plane=info,tower_http=info"},
        {"name": "GENERATE_CONFIG", "value": "1"},
        {"name": "OIDC_ISSUER_URL", "value": "https://accounts.google.com"},
        {"name": "OIDC_CLIENT_ID", "value": "<OIDC_CLIENT_ID>"},
        {"name": "JWT_EXPIRY_SECONDS", "value": "3600"},
        {"name": "AWS_DEFAULT_REGION", "value": "ap-northeast-1"},
        {"name": "AWS_SESSION_DURATION_SECONDS", "value": "3600"},
        {"name": "ENTITLEMENTS_FILE", "value": "/etc/canopy/entitlements.toml"},
        {"name": "CORS_ALLOWED_ORIGINS", "value": "https://your-domain.com"},
        {"name": "STS_EXTERNAL_ID", "value": "canopy"}
      ],
      "secrets": [
        {"name": "JWT_SECRET", "valueFrom": "<JWT_SECRET_ARN>:::<JWT_SECRET_VERSION_ID>"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/canopy/control-plane",
          "awslogs-region": "ap-northeast-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8443/health || exit 1"],
        "interval": 15,
        "timeout": 5,
        "retries": 5,
        "startPeriod": 180
      },
      "stopTimeout": 30
    }
  ]
}
EOF

aws ecs register-task-definition \
  --cli-input-json file:///tmp/task-def.json \
  --region ap-northeast-1
```

若 OIDC provider 使用 confidential client，另外在 `secrets` 加入下列項目，
並讓 execution role 可讀該 secret：

```json
{
  "name": "OIDC_CLIENT_SECRET",
  "valueFrom": "<OIDC_CLIENT_SECRET_ARN>:::<OIDC_CLIENT_SECRET_VERSION_ID>"
}
```

`entitlements.toml` 由 Docker build 透過 BuildKit secret bake 進 image，
不要放進 task definition 環境變數或 Terraform state。

---

## Step 10: 建立 ALB

### 10a. 建立 Security Groups

```bash
# ALB Security Group — 允許 HTTPS 入站
ALB_SG=$(aws ec2 create-security-group \
  --group-name canopy-alb-sg \
  --description "ALB for canopy" \
  --vpc-id <YOUR_VPC_ID> \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $ALB_SG \
  --protocol tcp --port 443 --cidr <OFFICE_OR_VPN_CIDR>

# 只有明確需要公開給全網際網路時，才改用 0.0.0.0/0。

# ECS Task Security Group — 只允許來自 ALB 的流量
TASK_SG=$(aws ec2 create-security-group \
  --group-name canopy-task-sg \
  --description "ECS tasks for canopy" \
  --vpc-id <YOUR_VPC_ID> \
  --query 'GroupId' --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $TASK_SG \
  --protocol tcp --port 8443 \
  --source-group $ALB_SG
```

### 10b. 建立 ALB + Target Group

```bash
# 建立 ALB
ALB_ARN=$(aws elbv2 create-load-balancer \
  --name canopy-alb \
  --subnets <SUBNET_1> <SUBNET_2> \
  --security-groups $ALB_SG \
  --scheme internet-facing \
  --type application \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text)

# 建立 Target Group（IP type for Fargate）
TG_ARN=$(aws elbv2 create-target-group \
  --name canopy-tg \
  --protocol HTTP \
  --port 8443 \
  --vpc-id <YOUR_VPC_ID> \
  --target-type ip \
  --health-check-path /health \
  --health-check-interval-seconds 15 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3 \
  --query 'TargetGroups[0].TargetGroupArn' --output text)

# 建立 HTTPS Listener（需要先有 ACM 憑證）
aws elbv2 create-listener \
  --load-balancer-arn $ALB_ARN \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=<YOUR_ACM_CERT_ARN> \
  --default-actions Type=forward,TargetGroupArn=$TG_ARN
```

---

## Step 11: 建立 ECS Service

```bash
aws ecs create-service \
  --cluster canopy \
  --service-name control-plane \
  --task-definition canopy-control-plane \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration '{
    "awsvpcConfiguration": {
      "subnets": ["<PRIVATE_SUBNET_1>", "<PRIVATE_SUBNET_2>"],
      "securityGroups": ["'"$TASK_SG"'"],
      "assignPublicIp": "DISABLED"
    }
  }' \
  --load-balancers '[{
    "targetGroupArn": "'"$TG_ARN"'",
    "containerName": "control-plane",
    "containerPort": 8443
  }]' \
  --deployment-configuration '{
    "maximumPercent": 200,
    "minimumHealthyPercent": 100,
    "deploymentCircuitBreaker": {
      "enable": true,
      "rollback": true
    }
  }' \
  --region ap-northeast-1
```

> **`assignPublicIp: DISABLED`**：Task 放在 private subnet，透過 NAT Gateway 存取外部服務（OIDC provider、AWS API）。
> 如果沒有 NAT Gateway，改用 `ENABLED` 並放在 public subnet（不建議用於生產）。

---

## Step 12: 設定 DNS

把你的域名 CNAME 指向 ALB 的 DNS name：

```bash
# 取得 ALB DNS name
aws elbv2 describe-load-balancers \
  --names canopy-alb \
  --query 'LoadBalancers[0].DNSName' --output text
```

在 Route 53 或你的 DNS provider 建立：

```
canopy.your-domain.com  CNAME  canopy-alb-xxxx.ap-northeast-1.elb.amazonaws.com
```

---

## 更新部署

```bash
# 1. Build & push 新 image
VERSION=v0.2.0
test -s entitlements.toml
ENTITLEMENTS_SHA=$(shasum -a 256 entitlements.toml | awk '{print $1}')
CPU_ARCH=$(awk -F= '/^[[:space:]]*cpu_architecture[[:space:]]*=/{value=$2; sub(/#.*/, "", value); gsub(/[[:space:]"]/, "", value); print value; exit}' infra/terraform.tfvars)
CPU_ARCH=${CPU_ARCH:-X86_64}
case "$CPU_ARCH" in
  X86_64) PLATFORM="linux/amd64" ;;
  ARM64) PLATFORM="linux/arm64" ;;
  *) echo "Unsupported cpu_architecture: $CPU_ARCH"; exit 1 ;;
esac

./scripts/validate-terraform-tfvars.sh infra \
  -var="create_service=true" \
  -var="image_tag=$VERSION"
./scripts/validate-entitlements.sh entitlements.toml infra/terraform.tfvars

DOCKER_BUILDKIT=1 docker build \
  --platform "$PLATFORM" \
  --build-arg "ENTITLEMENTS_SHA=$ENTITLEMENTS_SHA" \
  --secret id=entitlements_toml,src=entitlements.toml \
  -t canopy/control-plane:$VERSION \
  -f apps/control-plane/Dockerfile .
docker tag canopy/control-plane:$VERSION \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:$VERSION
docker push \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:$VERSION

# 2. 更新 task definition 的 image tag
#    （編輯 task-def.json 改 image tag，重新 register）

# 3. 更新 service（觸發 rolling update）
aws ecs update-service \
  --cluster canopy \
  --service control-plane \
  --force-new-deployment \
  --region ap-northeast-1

# 4. 等待部署完成
aws ecs wait services-stable \
  --cluster canopy \
  --services control-plane \
  --region ap-northeast-1
```

---

## 監控 & 除錯

```bash
# 查看 service 狀態
aws ecs describe-services \
  --cluster canopy \
  --services control-plane \
  --query 'services[0].{status:status,running:runningCount,desired:desiredCount,deployments:deployments[*].{status:status,running:runningCount,desired:desiredCount}}' \
  --region ap-northeast-1

# 查看 task 狀態（如果啟動失敗）
aws ecs list-tasks --cluster canopy --service-name control-plane --region ap-northeast-1
aws ecs describe-tasks --cluster canopy --tasks <TASK_ARN> --region ap-northeast-1

# 查看 container logs
aws logs tail /ecs/canopy/control-plane --follow --region ap-northeast-1

# 測試 health endpoint
curl -s https://canopy.your-domain.com/health
```

---

## 資源估算

| 項目 | 建議值 | 說明 |
|------|--------|------|
| CPU | 0.5 vCPU (512) | Rust binary 很輕量 |
| Memory | 1 GB (1024) | 包含 AWS SDK 連線池 |
| Desired count | 2 | 跨 AZ 高可用 |
| ALB | 1 | HTTPS termination |
| NAT Gateway | 1-2 | Private subnet 出站（已有可共用） |

---

## Checklist

部署前確認：

- [ ] `bind_address` 設為 `0.0.0.0:8443`
- [ ] `dev_mode = false`
- [ ] `entitlements_file` 指向容器內的路徑
- [ ] `entitlements.toml` 已通過 `scripts/validate-entitlements.sh`
- [ ] 授予 ECS 存取的 rule 有明確 `allowed_clusters`
- [ ] 寬鬆 ECS cluster wildcard 已明確設定 `allow_broad_cluster_discovery=true`
- [ ] SSM rule 有明確 `allowed_os_users`
- [ ] JWT secret 從 Secrets Manager 注入（不寫死在 config）
- [ ] OIDC `issuer_url` 和 `client_id` 設定正確
- [ ] `cors_allowed_origins` 列出 TUI client 的 callback URL
- [ ] Task Role 有 STS/IAM/EC2/ECS/CloudWatch 權限
- [ ] ALB health check 指向 `/health`
- [ ] CloudWatch Log Group 已建立
- [ ] DNS 已指向 ALB
- [ ] 目標帳號的 IAM Role trust policy 信任 Task Role，並允許 `sts:TagSession` / 檢查 `sts:ExternalId`（跨帳號情境）
