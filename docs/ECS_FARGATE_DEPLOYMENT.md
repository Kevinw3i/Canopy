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
│  │ control-plane     │  │  ← 從 Secrets Manager 讀 JWT secret
│  │ port 8443         │  │  ← 從 S3/EFS 讀 entitlements.toml
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
docker build \
  --secret id=entitlements_toml,src=entitlements.toml \
  -t canopy/control-plane:latest \
  -f apps/control-plane/Dockerfile .

# Tag
docker tag canopy/control-plane:latest \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:latest

# Push
docker push \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:latest
```

建議用 git tag 或 commit hash 做 image tag：

```bash
VERSION=$(git describe --tags --always)
docker tag canopy/control-plane:latest \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:${VERSION}
docker push \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:${VERSION}
```

---

## Step 3: 建立 Secrets Manager Secret

把敏感設定存到 Secrets Manager，不要寫在 config 檔或環境變數：

```bash
aws secretsmanager create-secret \
  --name canopy/jwt-secret \
  --secret-string "$(openssl rand -base64 32)" \
  --region ap-northeast-1
```

如果有 OIDC client secret：

```bash
aws secretsmanager create-secret \
  --name canopy/oidc-client-secret \
  --secret-string "your-oidc-client-secret" \
  --region ap-northeast-1
```

---

## Step 4: 準備設定檔

建立生產用的 `config.toml`（不含 secret，secret 從環境變數注入）：

```toml
# config.production.toml

bind_address = "0.0.0.0:8443"    # Fargate 容器內必須綁 0.0.0.0
dev_mode = false

entitlements_file = "/etc/canopy/entitlements.toml"

# 不設 audit_log — audit 事件透過 tracing 輸出到 stdout
# ECS 會自動把 stdout 送到 CloudWatch Logs

cors_allowed_origins = ["https://your-domain.com"]

[oidc]
issuer_url = "https://accounts.google.com"
client_id = "your-client-id"
# client_secret 從環境變數注入（見 Step 6 task definition）

[jwt]
secret = "placeholder"           # 會被環境變數覆寫（見下方說明）
expiry_seconds = 3600

[aws]
default_region = "ap-northeast-1"
session_duration_seconds = 3600
```

> **注意**：目前 config 從 TOML 檔讀取，JWT secret 寫在檔案裡。
> 若要從 Secrets Manager 注入，有兩種做法：
>
> 1. **Container entrypoint script**：啟動時用 `aws secretsmanager get-secret-value` 取值，
>    用 `sed` 寫入 config.toml，再啟動 control-plane
> 2. **改程式碼**：讓 `AppConfig` 支援從環境變數覆寫個別欄位（推薦，未來再做）
>
> 以下用做法 1 的 wrapper script。

建立 entrypoint wrapper：

```bash
# scripts/docker-entrypoint.sh
#!/bin/sh
set -e

CONFIG_PATH="${CONFIG_PATH:-/etc/canopy/config.toml}"

# 從 Secrets Manager 注入 JWT secret（如果環境變數有設定 ARN）
if [ -n "$JWT_SECRET_ARN" ]; then
  JWT_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id "$JWT_SECRET_ARN" \
    --query SecretString --output text)
  sed -i "s|^secret = .*|secret = \"${JWT_SECRET}\"|" "$CONFIG_PATH"
fi

exec control-plane "$@"
```

---

## Step 5: 上傳設定檔到 S3

```bash
# 建立 S3 bucket（或用現有的）
aws s3 mb s3://canopy-config-<ACCOUNT_ID> --region ap-northeast-1

# 上傳設定檔
aws s3 cp config.production.toml s3://canopy-config-<ACCOUNT_ID>/config.toml
aws s3 cp entitlements.production.toml s3://canopy-config-<ACCOUNT_ID>/entitlements.toml
```

> 或者直接把設定檔 bake 進 Docker image：在 Dockerfile 加 `COPY config.production.toml /etc/canopy/config.toml`。
> S3 方式的優點是更新設定不需要重新 build image。

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

# 加上 S3 設定檔讀取權限（如果用 S3 存設定）
aws iam put-role-policy \
  --role-name canopy-task-execution \
  --policy-name config-s3-access \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::canopy-config-<ACCOUNT_ID>/*"
    }]
  }'
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
# - CloudWatch Logs（自身 log + 查詢）
# - EC2 DescribeInstances, DescribeInstanceConnectEndpoints
aws iam put-role-policy \
  --role-name canopy-task-role \
  --policy-name canopy-permissions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AssumeTargetRoles",
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
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
> control-plane 會直接用 Task Role 的權限存取 AWS API，不走 AssumeRole。
> 確保 Task Role 有足夠權限。
>
> **跨帳號模式**：如果要存取其他帳號的資源，在 `AssumeTargetRoles` 加上對應的 role ARN，
> 並在目標帳號的 role trust policy 信任這個 Task Role。

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
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/canopy-task-execution",
  "taskRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/canopy-task-role",
  "containerDefinitions": [
    {
      "name": "control-plane",
      "image": "<ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8443,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "CONFIG_PATH", "value": "/etc/canopy/config.toml"},
        {"name": "RUST_LOG", "value": "control_plane=info,tower_http=info"}
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
        "timeout": 3,
        "retries": 3,
        "startPeriod": 10
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

> **設定檔注入方式**（擇一）：
>
> 1. **Bake 進 image** — 最簡單，但更新設定需重新 build
> 2. **S3 + init container** — 在 task definition 加一個 init container 從 S3 下載設定
> 3. **EFS mount** — 掛載 EFS volume 存放設定檔
>
> 建議初期用方式 1（把 config 和 entitlements COPY 進 Dockerfile），穩定後再改用方式 2 或 3。

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
  --protocol tcp --port 443 --cidr 0.0.0.0/0

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
docker build --secret id=entitlements_toml,src=entitlements.toml \
  -t canopy/control-plane:v0.2.0 -f apps/control-plane/Dockerfile .
docker tag canopy/control-plane:v0.2.0 \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:v0.2.0
docker push \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-1.amazonaws.com/canopy/control-plane:v0.2.0

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
- [ ] JWT secret 從 Secrets Manager 注入（不寫死在 config）
- [ ] OIDC `issuer_url` 和 `client_id` 設定正確
- [ ] `cors_allowed_origins` 列出 TUI client 的 callback URL
- [ ] Task Role 有 STS/EC2/CloudWatch 權限
- [ ] ALB health check 指向 `/health`
- [ ] CloudWatch Log Group 已建立
- [ ] DNS 已指向 ALB
- [ ] 目標帳號的 IAM Role trust policy 信任 Task Role（跨帳號情境）
