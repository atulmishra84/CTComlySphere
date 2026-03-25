"""
Azure Cloud Scanner — discovers AI/ML agents across Azure services.
Requires: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID
Optional:  AZURE_SUBSCRIPTION_IDS (comma-separated for multi-subscription)
"""
import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AzureScanner:
    """Scans Azure for AI/ML services and returns normalised agent records."""

    def __init__(self):
        self.tenant_id     = os.environ.get("AZURE_TENANT_ID", "")
        self.client_id     = os.environ.get("AZURE_CLIENT_ID", "")
        self.client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
        raw_subs           = os.environ.get("AZURE_SUBSCRIPTION_IDS",
                                            os.environ.get("AZURE_SUBSCRIPTION_ID", ""))
        self.subscriptions = [s.strip() for s in raw_subs.split(",") if s.strip()]

    # ── Credential validation ─────────────────────────────────────────────────
    def is_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret and self.subscriptions)

    def validate_credentials(self) -> Dict[str, Any]:
        if not self.is_configured():
            missing = []
            if not self.tenant_id:     missing.append("AZURE_TENANT_ID")
            if not self.client_id:     missing.append("AZURE_CLIENT_ID")
            if not self.client_secret: missing.append("AZURE_CLIENT_SECRET")
            if not self.subscriptions: missing.append("AZURE_SUBSCRIPTION_ID")
            return {"valid": False, "error": f"Missing: {', '.join(missing)}"}
        try:
            cred = self._credential()
            from azure.mgmt.resource import SubscriptionClient
            sc = SubscriptionClient(cred)
            subs = [s.subscription_id for s in sc.subscriptions.list()]
            return {"valid": True, "subscriptions": subs}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    # ── Main entry point ──────────────────────────────────────────────────────
    def scan_all(self, subscriptions: Optional[List[str]] = None) -> Dict[str, Any]:
        scan_subs = subscriptions or self.subscriptions
        results: List[Dict] = []
        errors: List[str]   = []
        for sub in scan_subs:
            try:
                results.extend(self._scan_subscription(sub))
            except Exception as e:
                errors.append(f"{sub}: {e}")
                logger.warning("Azure scan failed in subscription %s: %s", sub, e)
        return {
            "provider": "azure",
            "scan_time": datetime.utcnow().isoformat(),
            "subscriptions_scanned": scan_subs,
            "agents": results,
            "total": len(results),
            "errors": errors,
        }

    # ── Per-subscription scan ─────────────────────────────────────────────────
    def _scan_subscription(self, subscription_id: str) -> List[Dict]:
        agents = []
        agents.extend(self._scan_cognitive_services(subscription_id))
        agents.extend(self._scan_ml_workspaces(subscription_id))
        agents.extend(self._scan_aks_clusters(subscription_id))
        agents.extend(self._scan_container_apps(subscription_id))
        agents.extend(self._scan_bot_services(subscription_id))
        return agents

    # ── Azure Cognitive Services (incl. Azure OpenAI) ─────────────────────────
    def _scan_cognitive_services(self, sub_id: str) -> List[Dict]:
        agents = []
        try:
            from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
            client = CognitiveServicesManagementClient(self._credential(), sub_id)
            for account in client.accounts.list():
                kind = account.kind or ""
                agent_type = self._cognitive_kind_to_type(kind)
                endpoint   = account.properties.endpoint if account.properties else ""
                agents.append({
                    "name": account.name,
                    "service": f"azure-cognitive-{kind.lower()}",
                    "agent_type": agent_type,
                    "cloud_provider": "azure",
                    "region": account.location or "",
                    "protocol": "REST_API",
                    "endpoint": endpoint or "",
                    "status": account.properties.provisioning_state if account.properties else "Unknown",
                    "metadata": {
                        "subscription_id": sub_id,
                        "resource_group": account.id.split("/")[4] if account.id else "",
                        "kind": kind,
                        "sku": account.sku.name if account.sku else "",
                        "tags": dict(account.tags or {}),
                    },
                })
                # If it's Azure OpenAI, enumerate deployments
                if kind == "OpenAI":
                    rg = account.id.split("/")[4] if account.id else ""
                    try:
                        for dep in client.deployments.list(rg, account.name):
                            model = dep.properties.model if dep.properties else None
                            agents.append({
                                "name": f"{account.name}/{dep.name}",
                                "service": "azure-openai-deployment",
                                "agent_type": "GENAI",
                                "cloud_provider": "azure",
                                "region": account.location or "",
                                "protocol": "REST_API",
                                "endpoint": f"{endpoint}openai/deployments/{dep.name}",
                                "status": dep.properties.provisioning_state if dep.properties else "Unknown",
                                "metadata": {
                                    "model_name": model.name if model else "",
                                    "model_version": model.version if model else "",
                                    "model_format": model.format if model else "",
                                    "capacity": dep.sku.capacity if dep.sku else None,
                                    "account": account.name,
                                    "subscription_id": sub_id,
                                },
                            })
                    except Exception:
                        pass
        except Exception as e:
            logger.debug("Azure Cognitive Services scan error: %s", e)
        return agents

    def _cognitive_kind_to_type(self, kind: str) -> str:
        mapping = {
            "OpenAI":              "GENAI",
            "ComputerVision":      "COMPUTER_VISION",
            "Face":                "COMPUTER_VISION",
            "SpeechServices":      "NLP",
            "TextAnalytics":       "NLP",
            "Language":            "NLP",
            "Translator":          "NLP",
            "FormRecognizer":      "NLP",
            "ContentModerator":    "NLP",
            "QnAMaker":            "CONVERSATIONAL_AI",
            "LUIS":                "CONVERSATIONAL_AI",
            "Recommendations":     "RECOMMENDATION",
            "Personalizer":        "RECOMMENDATION",
            "AnomalyDetector":     "PREDICTIVE_ANALYTICS",
            "CustomVision.Training":"COMPUTER_VISION",
            "CustomVision.Prediction":"COMPUTER_VISION",
        }
        return mapping.get(kind, "TRADITIONAL_ML")

    # ── Azure ML Workspaces ───────────────────────────────────────────────────
    def _scan_ml_workspaces(self, sub_id: str) -> List[Dict]:
        agents = []
        try:
            from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
            client = AzureMachineLearningWorkspaces(self._credential(), sub_id)
            for ws in client.workspaces.list_by_subscription():
                rg = ws.id.split("/")[4] if ws.id else ""
                agents.append({
                    "name": ws.name,
                    "service": "azure-ml-workspace",
                    "agent_type": "TRADITIONAL_ML",
                    "cloud_provider": "azure",
                    "region": ws.location or "",
                    "protocol": "REST_API",
                    "endpoint": ws.ml_flow_tracking_uri or "",
                    "status": ws.provisioning_state or "Unknown",
                    "metadata": {
                        "subscription_id": sub_id,
                        "resource_group": rg,
                        "description": ws.description,
                        "hbi_workspace": ws.hbi_workspace,
                        "tags": dict(ws.tags or {}),
                    },
                })
                # Enumerate online endpoints in workspace
                try:
                    for ep in client.online_endpoints.list(rg, ws.name):
                        agents.append({
                            "name": f"{ws.name}/{ep.name}",
                            "service": "azure-ml-online-endpoint",
                            "agent_type": "TRADITIONAL_ML",
                            "cloud_provider": "azure",
                            "region": ws.location or "",
                            "protocol": "REST_API",
                            "endpoint": ep.properties.scoring_uri if ep.properties else "",
                            "status": ep.properties.provisioning_state if ep.properties else "Unknown",
                            "metadata": {
                                "workspace": ws.name,
                                "auth_mode": ep.properties.auth_mode if ep.properties else "",
                                "subscription_id": sub_id,
                                "resource_group": rg,
                            },
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Azure ML scan error: %s", e)
        return agents

    # ── AKS Clusters ──────────────────────────────────────────────────────────
    def _scan_aks_clusters(self, sub_id: str) -> List[Dict]:
        agents = []
        try:
            from azure.mgmt.containerservice import ContainerServiceClient
            client = ContainerServiceClient(self._credential(), sub_id)
            for cluster in client.managed_clusters.list():
                agents.append({
                    "name": cluster.name,
                    "service": "azure-aks-cluster",
                    "agent_type": "AUTONOMOUS_SYSTEM",
                    "cloud_provider": "azure",
                    "region": cluster.location or "",
                    "protocol": "KUBERNETES",
                    "endpoint": cluster.fqdn or "",
                    "status": cluster.provisioning_state or "Unknown",
                    "metadata": {
                        "subscription_id": sub_id,
                        "kubernetes_version": cluster.kubernetes_version,
                        "node_count": sum(
                            p.count for p in (cluster.agent_pool_profiles or []) if p.count
                        ),
                        "resource_group": cluster.node_resource_group,
                        "tags": dict(cluster.tags or {}),
                    },
                })
        except Exception as e:
            logger.debug("AKS scan error: %s", e)
        return agents

    # ── Azure Container Apps ──────────────────────────────────────────────────
    def _scan_container_apps(self, sub_id: str) -> List[Dict]:
        """Use REST API (azure-mgmt-app not always installed)."""
        agents = []
        try:
            import requests
            token = self._credential().get_token("https://management.azure.com/.default").token
            url   = (f"https://management.azure.com/subscriptions/{sub_id}"
                     f"/providers/Microsoft.App/containerApps?api-version=2023-05-01")
            resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
            if resp.status_code == 200:
                for app in resp.json().get("value", []):
                    props = app.get("properties", {})
                    name  = app.get("name", "")
                    if not any(kw in name.lower() for kw in [
                        "ai", "ml", "model", "llm", "gpt", "agent", "bot",
                        "inference", "predict", "nlp", "vision"
                    ]):
                        continue
                    agents.append({
                        "name": name,
                        "service": "azure-container-app",
                        "agent_type": "AGENTIC_AI",
                        "cloud_provider": "azure",
                        "region": app.get("location", ""),
                        "protocol": "REST_API",
                        "endpoint": props.get("configuration", {}).get("ingress", {}).get("fqdn", ""),
                        "status": props.get("provisioningState", "Unknown"),
                        "metadata": {
                            "subscription_id": sub_id,
                            "resource_group": app.get("id", "").split("/")[4],
                            "tags": app.get("tags", {}),
                        },
                    })
        except Exception as e:
            logger.debug("Azure Container Apps scan error: %s", e)
        return agents

    # ── Azure Bot Services ────────────────────────────────────────────────────
    def _scan_bot_services(self, sub_id: str) -> List[Dict]:
        agents = []
        try:
            import requests
            token = self._credential().get_token("https://management.azure.com/.default").token
            url   = (f"https://management.azure.com/subscriptions/{sub_id}"
                     f"/providers/Microsoft.BotService/botServices?api-version=2022-09-15")
            resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
            if resp.status_code == 200:
                for bot in resp.json().get("value", []):
                    props = bot.get("properties", {})
                    agents.append({
                        "name": bot.get("name", ""),
                        "service": "azure-bot-service",
                        "agent_type": "CONVERSATIONAL_AI",
                        "cloud_provider": "azure",
                        "region": bot.get("location", ""),
                        "protocol": "REST_API",
                        "endpoint": props.get("endpoint", ""),
                        "status": props.get("provisioningState", "Unknown"),
                        "metadata": {
                            "subscription_id": sub_id,
                            "resource_group": bot.get("id", "").split("/")[4],
                            "sku": bot.get("sku", {}).get("name"),
                            "kind": bot.get("kind"),
                            "tags": bot.get("tags", {}),
                        },
                    })
        except Exception as e:
            logger.debug("Azure Bot Services scan error: %s", e)
        return agents

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _credential(self):
        from azure.identity import ClientSecretCredential
        return ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
