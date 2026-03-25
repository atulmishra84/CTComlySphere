"""
GCP Cloud Scanner — discovers AI/ML agents across Google Cloud.
Credentials: set GCP_SERVICE_ACCOUNT_JSON (JSON key contents) OR
             GCP_SERVICE_ACCOUNT_FILE (path to JSON key file)
Required:    GCP_PROJECT_IDS (comma-separated project IDs)
"""
import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

AI_KEYWORDS = [
    "ai", "ml", "model", "predict", "llm", "gemini", "vertex", "nlp",
    "inference", "agent", "bot", "classify", "detect", "embed", "recommend",
]


class GCPScanner:
    """Scans GCP for AI/ML services using Google Cloud REST APIs."""

    def __init__(self):
        self.sa_json_str  = os.environ.get("GCP_SERVICE_ACCOUNT_JSON", "")
        self.sa_json_file = os.environ.get("GCP_SERVICE_ACCOUNT_FILE", "")
        raw_projects      = os.environ.get("GCP_PROJECT_IDS", os.environ.get("GCP_PROJECT_ID", ""))
        self.projects     = [p.strip() for p in raw_projects.split(",") if p.strip()]

    # ── Credential validation ─────────────────────────────────────────────────
    def is_configured(self) -> bool:
        has_creds = bool(self.sa_json_str or self.sa_json_file)
        return has_creds and bool(self.projects)

    def validate_credentials(self) -> Dict[str, Any]:
        if not self.is_configured():
            missing = []
            if not (self.sa_json_str or self.sa_json_file):
                missing.append("GCP_SERVICE_ACCOUNT_JSON or GCP_SERVICE_ACCOUNT_FILE")
            if not self.projects:
                missing.append("GCP_PROJECT_IDS")
            return {"valid": False, "error": f"Missing: {', '.join(missing)}"}
        try:
            creds = self._credentials()
            import google.auth.transport.requests as gtr
            req   = gtr.Request()
            creds.refresh(req)
            return {"valid": True, "projects": self.projects, "email": getattr(creds, "service_account_email", "")}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    # ── Main entry point ──────────────────────────────────────────────────────
    def scan_all(self, projects: Optional[List[str]] = None) -> Dict[str, Any]:
        scan_projects = projects or self.projects
        results: List[Dict] = []
        errors: List[str]   = []
        for project in scan_projects:
            try:
                results.extend(self._scan_project(project))
            except Exception as e:
                errors.append(f"{project}: {e}")
                logger.warning("GCP scan failed in project %s: %s", project, e)
        return {
            "provider": "gcp",
            "scan_time": datetime.utcnow().isoformat(),
            "projects_scanned": scan_projects,
            "agents": results,
            "total": len(results),
            "errors": errors,
        }

    # ── Per-project scan ──────────────────────────────────────────────────────
    def _scan_project(self, project_id: str) -> List[Dict]:
        agents = []
        agents.extend(self._scan_vertex_endpoints(project_id))
        agents.extend(self._scan_vertex_models(project_id))
        agents.extend(self._scan_dialogflow(project_id))
        agents.extend(self._scan_cloud_run(project_id))
        agents.extend(self._scan_gke_clusters(project_id))
        return agents

    # ── Vertex AI Endpoints ───────────────────────────────────────────────────
    def _scan_vertex_endpoints(self, project_id: str) -> List[Dict]:
        agents = []
        try:
            svc = self._build("aiplatform", "v1")
            locations = self._vertex_locations(project_id)
            for loc in locations:
                parent = f"projects/{project_id}/locations/{loc}"
                resp   = svc.projects().locations().endpoints().list(parent=parent).execute()
                for ep in resp.get("endpoints", []):
                    ep_name    = ep.get("displayName", ep.get("name", "").split("/")[-1])
                    model_name = ""
                    for dm in ep.get("deployedModels", []):
                        model_name = dm.get("displayName", "")
                        break
                    agents.append({
                        "name": ep_name,
                        "service": "vertex-ai-endpoint",
                        "agent_type": self._vertex_endpoint_type(ep),
                        "cloud_provider": "gcp",
                        "region": loc,
                        "protocol": "REST_API",
                        "endpoint": ep.get("name", ""),
                        "status": "Active",
                        "metadata": {
                            "project_id": project_id,
                            "location": loc,
                            "model_name": model_name,
                            "traffic_split": ep.get("trafficSplit"),
                            "create_time": ep.get("createTime", ""),
                            "update_time": ep.get("updateTime", ""),
                            "labels": ep.get("labels", {}),
                        },
                    })
        except Exception as e:
            logger.debug("Vertex AI endpoints scan error (%s): %s", project_id, e)
        return agents

    def _vertex_endpoint_type(self, ep: Dict) -> str:
        name = ep.get("displayName", "").lower()
        for m in ep.get("deployedModels", []):
            name += " " + m.get("displayName", "").lower()
        if any(k in name for k in ["gemini", "llm", "text-bison", "chat", "code", "palm"]):
            return "GENAI"
        if any(k in name for k in ["vision", "image", "object"]):
            return "COMPUTER_VISION"
        if any(k in name for k in ["nlp", "language", "bert", "text-embed"]):
            return "NLP"
        return "TRADITIONAL_ML"

    # ── Vertex AI Model Registry ──────────────────────────────────────────────
    def _scan_vertex_models(self, project_id: str) -> List[Dict]:
        agents = []
        try:
            svc = self._build("aiplatform", "v1")
            locations = self._vertex_locations(project_id)
            for loc in locations:
                parent = f"projects/{project_id}/locations/{loc}"
                resp   = svc.projects().locations().models().list(parent=parent).execute()
                for m in resp.get("models", []):
                    display = m.get("displayName", m.get("name", "").split("/")[-1])
                    agents.append({
                        "name": display,
                        "service": "vertex-ai-model",
                        "agent_type": "TRADITIONAL_ML",
                        "cloud_provider": "gcp",
                        "region": loc,
                        "protocol": "REST_API",
                        "endpoint": m.get("name", ""),
                        "status": m.get("state", "Unknown"),
                        "metadata": {
                            "project_id": project_id,
                            "location": loc,
                            "version_id": m.get("versionId"),
                            "framework": m.get("metadata", {}).get("framework", ""),
                            "create_time": m.get("createTime", ""),
                            "labels": m.get("labels", {}),
                        },
                    })
        except Exception as e:
            logger.debug("Vertex AI models scan error (%s): %s", project_id, e)
        return agents

    # ── Dialogflow CX Agents ──────────────────────────────────────────────────
    def _scan_dialogflow(self, project_id: str) -> List[Dict]:
        agents = []
        try:
            svc = self._build("dialogflow", "v3")
            locations = ["global", "us-central1", "eu-west1", "asia-east1"]
            for loc in locations:
                parent = f"projects/{project_id}/locations/{loc}"
                try:
                    resp = svc.projects().locations().agents().list(parent=parent).execute()
                    for ag in resp.get("agents", []):
                        agents.append({
                            "name": ag.get("displayName", ""),
                            "service": "dialogflow-cx-agent",
                            "agent_type": "CONVERSATIONAL_AI",
                            "cloud_provider": "gcp",
                            "region": loc,
                            "protocol": "GRPC",
                            "endpoint": f"dialogflow.googleapis.com/v3/{ag.get('name','')}",
                            "status": "Active",
                            "metadata": {
                                "project_id": project_id,
                                "location": loc,
                                "language_code": ag.get("defaultLanguageCode"),
                                "time_zone": ag.get("timeZone"),
                            },
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Dialogflow scan error (%s): %s", project_id, e)
        return agents

    # ── Cloud Run (AI-related services) ──────────────────────────────────────
    def _scan_cloud_run(self, project_id: str) -> List[Dict]:
        agents = []
        try:
            svc = self._build("run", "v2")
            resp = svc.projects().locations().list(name=f"projects/{project_id}").execute()
            locations = [loc["locationId"] for loc in resp.get("locations", [])]
            for loc in locations:
                parent = f"projects/{project_id}/locations/{loc}"
                try:
                    services_resp = svc.projects().locations().services().list(parent=parent).execute()
                    for service in services_resp.get("services", []):
                        svc_name = service.get("name", "").split("/")[-1]
                        if not any(kw in svc_name.lower() for kw in AI_KEYWORDS):
                            continue
                        agents.append({
                            "name": svc_name,
                            "service": "cloud-run-service",
                            "agent_type": "AGENTIC_AI",
                            "cloud_provider": "gcp",
                            "region": loc,
                            "protocol": "REST_API",
                            "endpoint": service.get("uri", ""),
                            "status": service.get("conditions", [{}])[0].get("state", "Unknown"),
                            "metadata": {
                                "project_id": project_id,
                                "location": loc,
                                "create_time": service.get("createTime", ""),
                                "labels": service.get("labels", {}),
                            },
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Cloud Run scan error (%s): %s", project_id, e)
        return agents

    # ── GKE Clusters ─────────────────────────────────────────────────────────
    def _scan_gke_clusters(self, project_id: str) -> List[Dict]:
        agents = []
        try:
            svc = self._build("container", "v1")
            resp = svc.projects().locations().clusters().list(
                parent=f"projects/{project_id}/locations/-"
            ).execute()
            for cluster in resp.get("clusters", []):
                agents.append({
                    "name": cluster.get("name", ""),
                    "service": "gke-cluster",
                    "agent_type": "AUTONOMOUS_SYSTEM",
                    "cloud_provider": "gcp",
                    "region": cluster.get("location", ""),
                    "protocol": "KUBERNETES",
                    "endpoint": cluster.get("endpoint", ""),
                    "status": cluster.get("status", "Unknown"),
                    "metadata": {
                        "project_id": project_id,
                        "zone": cluster.get("zone"),
                        "kubernetes_version": cluster.get("currentMasterVersion"),
                        "node_count": cluster.get("currentNodeCount"),
                        "network": cluster.get("network"),
                        "labels": cluster.get("resourceLabels", {}),
                    },
                })
        except Exception as e:
            logger.debug("GKE clusters scan error (%s): %s", project_id, e)
        return agents

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _vertex_locations(self, project_id: str) -> List[str]:
        try:
            svc = self._build("aiplatform", "v1")
            resp = svc.projects().locations().list(name=f"projects/{project_id}").execute()
            return [loc["locationId"] for loc in resp.get("locations", [])
                    if loc.get("locationId", "").startswith(("us-", "europe-", "asia-"))]
        except Exception:
            return ["us-central1", "us-east1", "europe-west4"]

    def _credentials(self):
        from google.oauth2 import service_account
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        if self.sa_json_str:
            info = json.loads(self.sa_json_str)
            return service_account.Credentials.from_service_account_info(info, scopes=scopes)
        elif self.sa_json_file and os.path.exists(self.sa_json_file):
            return service_account.Credentials.from_service_account_file(self.sa_json_file, scopes=scopes)
        else:
            import google.auth
            creds, _ = google.auth.default(scopes=scopes)
            return creds

    def _build(self, api_name: str, version: str):
        from googleapiclient.discovery import build
        return build(api_name, version, credentials=self._credentials(), cache_discovery=False)
