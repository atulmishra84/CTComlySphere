#!/usr/bin/env bash
# =============================================================================
# CT ComplySphere — Azure Deployment Script
# Deploys to: Azure Container Apps + Azure Database for PostgreSQL
# =============================================================================
set -euo pipefail

# ── CONFIGURATION — edit these before running ────────────────────────────────
RESOURCE_GROUP="complysphere-rg"
LOCATION="eastus"
ACR_NAME="complysphereacr"          # must be globally unique, lowercase
APP_NAME="complysphere-app"
PG_SERVER_NAME="complysphere-db"    # must be globally unique
PG_ADMIN_USER="complyadmin"
PG_ADMIN_PASS="$(openssl rand -base64 20)Aa1!"   # auto-generated
PG_DB_NAME="complysphere"
SESSION_SECRET="$(openssl rand -hex 32)"
CONTAINER_ENV_NAME="complysphere-env"
IMAGE_TAG="latest"
# ─────────────────────────────────────────────────────────────────────────────

echo "=================================================================="
echo "  CT ComplySphere — Azure Deployment"
echo "=================================================================="

# 1. Login check
echo ""
echo "[1/9] Checking Azure CLI login..."
az account show --query "name" -o tsv || { echo "Run: az login"; exit 1; }

# 2. Resource group
echo ""
echo "[2/9] Creating resource group: $RESOURCE_GROUP in $LOCATION..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" -o none

# 3. Azure Container Registry
echo ""
echo "[3/9] Creating Azure Container Registry: $ACR_NAME..."
az acr create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACR_NAME" \
  --sku Basic \
  --admin-enabled true \
  -o none

ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

# 4. Build and push Docker image
echo ""
echo "[4/9] Building and pushing Docker image to $ACR_LOGIN_SERVER..."
az acr build \
  --registry "$ACR_NAME" \
  --image "$APP_NAME:$IMAGE_TAG" \
  .

# 5. Azure Database for PostgreSQL
echo ""
echo "[5/9] Creating Azure Database for PostgreSQL (Flexible Server)..."
az postgres flexible-server create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$PG_SERVER_NAME" \
  --location "$LOCATION" \
  --admin-user "$PG_ADMIN_USER" \
  --admin-password "$PG_ADMIN_PASS" \
  --sku-name "Standard_B1ms" \
  --tier "Burstable" \
  --storage-size 32 \
  --version 15 \
  --public-access "0.0.0.0" \
  -o none

echo "      Creating database: $PG_DB_NAME..."
az postgres flexible-server db create \
  --resource-group "$RESOURCE_GROUP" \
  --server-name "$PG_SERVER_NAME" \
  --database-name "$PG_DB_NAME" \
  -o none

PG_HOST=$(az postgres flexible-server show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$PG_SERVER_NAME" \
  --query "fullyQualifiedDomainName" -o tsv)

DATABASE_URL="postgresql://${PG_ADMIN_USER}:${PG_ADMIN_PASS}@${PG_HOST}:5432/${PG_DB_NAME}?sslmode=require"

# 6. Container Apps environment
echo ""
echo "[6/9] Creating Container Apps environment: $CONTAINER_ENV_NAME..."
az containerapp env create \
  --name "$CONTAINER_ENV_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  -o none

# 7. Deploy the app
echo ""
echo "[7/9] Deploying Container App: $APP_NAME..."
az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$CONTAINER_ENV_NAME" \
  --image "$ACR_LOGIN_SERVER/$APP_NAME:$IMAGE_TAG" \
  --registry-server "$ACR_LOGIN_SERVER" \
  --registry-username "$ACR_NAME" \
  --registry-password "$ACR_PASSWORD" \
  --target-port 5000 \
  --ingress external \
  --cpu 1.0 \
  --memory 2.0Gi \
  --min-replicas 1 \
  --max-replicas 3 \
  --env-vars \
      DATABASE_URL="$DATABASE_URL" \
      SESSION_SECRET="$SESSION_SECRET" \
  -o none

echo "      Configuring liveness and readiness probes to /health..."
PROBE_YAML=$(mktemp /tmp/probes-XXXXXX.yaml)
cat > "$PROBE_YAML" <<YAML_EOF
properties:
  template:
    containers:
      - name: ${APP_NAME}
        probes:
          - type: liveness
            httpGet:
              path: /health
              port: 5000
            initialDelaySeconds: 15
            periodSeconds: 30
            failureThreshold: 3
          - type: readiness
            httpGet:
              path: /health
              port: 5000
            initialDelaySeconds: 10
            periodSeconds: 15
            failureThreshold: 3
YAML_EOF
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --yaml "$PROBE_YAML" \
  -o none
rm -f "$PROBE_YAML"

APP_URL=$(az containerapp show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" -o tsv)

# 8. Seed the data
echo ""
echo "[8/9] Running data seed (Contoso Health Systems Azure dummy data)..."
az containerapp job create \
  --name "complysphere-seed" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$CONTAINER_ENV_NAME" \
  --image "$ACR_LOGIN_SERVER/$APP_NAME:$IMAGE_TAG" \
  --registry-server "$ACR_LOGIN_SERVER" \
  --registry-username "$ACR_NAME" \
  --registry-password "$ACR_PASSWORD" \
  --replica-timeout 600 \
  --replica-retry-limit 1 \
  --trigger-type Manual \
  --parallelism 1 \
  --replica-completion-count 1 \
  --env-vars \
      DATABASE_URL="$DATABASE_URL" \
      SESSION_SECRET="$SESSION_SECRET" \
  --command "python3" "seed_azure_data.py" \
  -o none

az containerapp job start \
  --name "complysphere-seed" \
  --resource-group "$RESOURCE_GROUP" \
  -o none

echo "      Waiting for seed job to complete (up to 5 min)..."
sleep 60

# 9. Done
echo ""
echo "=================================================================="
echo "  DEPLOYMENT COMPLETE"
echo "=================================================================="
echo ""
echo "  App URL        : https://$APP_URL"
echo "  Resource Group : $RESOURCE_GROUP"
echo "  Database       : $PG_HOST"
echo "  DB Name        : $PG_DB_NAME"
echo "  DB User        : $PG_ADMIN_USER"
echo "  DB Password    : $PG_ADMIN_PASS   ← save this!"
echo "  Session Secret : $SESSION_SECRET   ← save this!"
echo ""
echo "  To tear down everything:"
echo "    az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo ""
