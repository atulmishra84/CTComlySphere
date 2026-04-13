#!/usr/bin/env bash
# =============================================================================
# CT ComplySphere — Azure First-Time Setup & Deploy
#
# Run this once to create all required Azure resources, then push to GitHub
# to trigger the CI/CD pipeline for future deploys.
#
# Prerequisites:
#   1. Azure CLI installed and logged in (az login)
#   2. Docker installed and running
#   3. Fill in the CONFIGURATION section below
# =============================================================================
set -euo pipefail

# =============================================================================
# CONFIGURATION — fill these in before running
# =============================================================================
SUBSCRIPTION_ID="0ffed277-661a-48d7-bb45-3691c755352e"          # az account list --output table
RESOURCE_GROUP="complysphere-rg"
LOCATION="westeurope"       # e.g. westeurope | eastus | australiaeast
ACR_NAME="complysphereacr"  # must be globally unique, alphanumeric only
APP_NAME="complysphere-app"
ENVIRONMENT_NAME="complysphere-env"

# Azure PostgreSQL (Flexible Server)
PG_SERVER_NAME="complysphere-pg"
PG_DATABASE="complysphere"
PG_ADMIN_USER="complyadmin"
PG_ADMIN_PASSWORD="Pritisha@2022"        # min 8 chars, uppercase + number + special

# Flask session secret (generate with: python3 -c "import secrets; print(secrets.token_hex(32))")
SESSION_SECRET=""
# =============================================================================

# ── Validate ──────────────────────────────────────────────────────────────────
if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$PG_ADMIN_PASSWORD" ] || [ -z "$SESSION_SECRET" ]; then
    echo "ERROR: Fill in SUBSCRIPTION_ID, PG_ADMIN_PASSWORD and SESSION_SECRET before running."
    exit 1
fi

echo "=================================================================="
echo "  CT ComplySphere — Azure Deployment"
echo "  Region:         $LOCATION"
echo "  Resource Group: $RESOURCE_GROUP"
echo "=================================================================="

# ── 1. Set subscription ───────────────────────────────────────────────────────
echo ""
echo "[1/8] Setting Azure subscription..."
az account set --subscription "$SUBSCRIPTION_ID"

# ── 2. Create resource group ──────────────────────────────────────────────────
echo ""
echo "[2/8] Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

# ── 3. Create Azure Container Registry ───────────────────────────────────────
echo ""
echo "[3/8] Creating Container Registry ($ACR_NAME)..."
az acr create \
    --name "$ACR_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --sku Basic \
    --admin-enabled true \
    --output none

ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)
echo "  Registry: $ACR_LOGIN_SERVER"

# ── 4. Build and push Docker image ────────────────────────────────────────────
echo ""
echo "[4/8] Building and pushing Docker image..."
az acr login --name "$ACR_NAME"
docker build -t "$ACR_LOGIN_SERVER/complysphere:latest" .
docker push "$ACR_LOGIN_SERVER/complysphere:latest"

# ── 5. Create Azure PostgreSQL Flexible Server ────────────────────────────────
echo ""
echo "[5/8] Creating PostgreSQL Flexible Server..."
az postgres flexible-server create \
    --name "$PG_SERVER_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --admin-user "$PG_ADMIN_USER" \
    --admin-password "$PG_ADMIN_PASSWORD" \
    --sku-name "Standard_B1ms" \
    --tier "Burstable" \
    --storage-size 32 \
    --version 16 \
    --public-access 0.0.0.0 \
    --output none

az postgres flexible-server db create \
    --server-name "$PG_SERVER_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --database-name "$PG_DATABASE" \
    --output none

PG_HOST=$(az postgres flexible-server show \
    --name "$PG_SERVER_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "fullyQualifiedDomainName" -o tsv)

DATABASE_URL="postgresql://${PG_ADMIN_USER}:${PG_ADMIN_PASSWORD}@${PG_HOST}:5432/${PG_DATABASE}?sslmode=require"
echo "  PostgreSQL host: $PG_HOST"

# ── 6. Create Container Apps environment ─────────────────────────────────────
echo ""
echo "[6/8] Creating Container Apps environment..."
az extension add --name containerapp --upgrade --output none 2>/dev/null || true
az provider register --namespace Microsoft.App --output none 2>/dev/null || true

az containerapp env create \
    --name "$ENVIRONMENT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --output none

# ── 7. Get ACR credentials for Container Apps ─────────────────────────────────
ACR_USERNAME=$(az acr credential show --name "$ACR_NAME" --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

# ── 8. Deploy Container App ───────────────────────────────────────────────────
echo ""
echo "[7/8] Deploying Container App..."
az containerapp create \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --environment "$ENVIRONMENT_NAME" \
    --image "$ACR_LOGIN_SERVER/complysphere:latest" \
    --registry-server "$ACR_LOGIN_SERVER" \
    --registry-username "$ACR_USERNAME" \
    --registry-password "$ACR_PASSWORD" \
    --target-port 5000 \
    --ingress external \
    --min-replicas 1 \
    --max-replicas 5 \
    --cpu 1.0 \
    --memory 2.0Gi \
    --env-vars \
        "DATABASE_URL=$DATABASE_URL" \
        "SESSION_SECRET=$SESSION_SECRET" \
        "FLASK_ENV=production" \
        "PYTHONUNBUFFERED=1" \
    --output none

APP_URL=$(az containerapp show \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "properties.configuration.ingress.fqdn" -o tsv)

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "[8/8] Creating Service Principal for GitHub Actions CI/CD..."
SP_JSON=$(az ad sp create-for-rbac \
    --name "complysphere-github-actions" \
    --role contributor \
    --scopes "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP" \
    --sdk-auth 2>/dev/null || echo "{}")

echo ""
echo "=================================================================="
echo "  DEPLOYMENT COMPLETE"
echo "=================================================================="
echo ""
echo "  App URL:    https://$APP_URL"
echo ""
echo "  ── GitHub Secrets (add these at repo → Settings → Secrets) ──"
echo "  AZURE_SUBSCRIPTION_ID  = $SUBSCRIPTION_ID"
echo "  AZURE_TENANT_ID        = $(az account show --query tenantId -o tsv)"
echo "  AZURE_CLIENT_ID        = (from service principal output below)"
echo "  AZURE_CLIENT_SECRET    = (from service principal output below)"
echo "  AZURE_RESOURCE_GROUP   = $RESOURCE_GROUP"
echo "  AZURE_APP_NAME         = $APP_NAME"
echo "  ACR_NAME               = $ACR_NAME"
echo ""
echo "  Service Principal JSON (use as AZURE_CREDENTIALS secret):"
echo "$SP_JSON"
echo ""
echo "  Once secrets are set, every push to main auto-deploys via GitHub Actions."
echo "=================================================================="
