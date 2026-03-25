"""
Cloud Scan Manager — orchestrates AWS, Azure, and GCP scanners.
Saves discovered agents to the database and returns a unified report.
"""
import logging
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional

from integrations.aws_scanner   import AWSScanner
from integrations.azure_scanner import AzureScanner
from integrations.gcp_scanner   import GCPScanner

logger = logging.getLogger(__name__)

# In-memory scan status store (keyed by scan_id)
_scan_registry: Dict[str, Dict] = {}
_registry_lock = threading.Lock()


class CloudScanManager:
    """Manages multi-cloud scanning and database persistence."""

    def __init__(self):
        self.aws   = AWSScanner()
        self.azure = AzureScanner()
        self.gcp   = GCPScanner()

    # ── Credential status ─────────────────────────────────────────────────────
    def provider_status(self) -> List[Dict[str, Any]]:
        providers = []
        for name, scanner in [("AWS", self.aws), ("Azure", self.azure), ("GCP", self.gcp)]:
            configured = scanner.is_configured()
            providers.append({
                "name":        name,
                "configured":  configured,
                "label":       "Configured" if configured else "Not configured",
                "icon":        {"AWS": "fab fa-aws", "Azure": "fab fa-microsoft", "GCP": "fab fa-google"}[name],
                "color":       {"AWS": "warning",    "Azure": "info",             "GCP": "danger"}[name],
                "env_vars":    _env_hints(name),
            })
        return providers

    def validate_all(self) -> Dict[str, Any]:
        results = {}
        for name, scanner in [("aws", self.aws), ("azure", self.azure), ("gcp", self.gcp)]:
            results[name] = scanner.validate_credentials()
        return results

    # ── Async scan ────────────────────────────────────────────────────────────
    def start_scan(self, providers: Optional[List[str]] = None, scan_id: Optional[str] = None) -> str:
        import secrets
        sid = scan_id or secrets.token_hex(8)
        _update_status(sid, {"status": "running", "started_at": datetime.utcnow().isoformat(),
                              "providers": providers or ["aws", "azure", "gcp"],
                              "progress": 0, "agents_found": 0, "errors": []})
        t = threading.Thread(target=self._run_scan_thread, args=(sid, providers), daemon=True)
        t.start()
        return sid

    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        with _registry_lock:
            return _scan_registry.get(scan_id)

    def list_scans(self) -> List[Dict]:
        with _registry_lock:
            return sorted(_scan_registry.values(), key=lambda x: x.get("started_at", ""), reverse=True)[:20]

    # ── Background scan thread ────────────────────────────────────────────────
    def _run_scan_thread(self, scan_id: str, providers: Optional[List[str]]):
        scan_providers = [p.lower() for p in (providers or ["aws", "azure", "gcp"])]
        all_agents: List[Dict] = []
        errors: List[str]      = []
        steps                  = len(scan_providers)
        done                   = 0

        for provider in scan_providers:
            try:
                _update_status(scan_id, {"progress": int((done / steps) * 80),
                                          "current_provider": provider.upper()})
                if provider == "aws":
                    result = self.aws.scan_all()
                elif provider == "azure":
                    result = self.azure.scan_all()
                elif provider == "gcp":
                    result = self.gcp.scan_all()
                else:
                    continue
                all_agents.extend(result.get("agents", []))
                errors.extend(result.get("errors", []))
            except Exception as e:
                errors.append(f"{provider.upper()}: {str(e)}")
                logger.warning("Cloud scan thread error for %s: %s", provider, e)
            finally:
                done += 1

        # Save to DB
        saved = 0
        try:
            from app import app, db
            from models import AIAgent, AIAgentType, ScanStatus
            import secrets as sec
            _update_status(scan_id, {"progress": 85, "current_provider": "Saving to database"})
            with app.app_context():
                for ag in all_agents:
                    existing = AIAgent.query.filter_by(name=ag["name"],
                                                       cloud_provider=ag["cloud_provider"]).first()
                    if existing:
                        continue
                    try:
                        agent_type = getattr(AIAgentType, ag.get("agent_type", "TRADITIONAL_ML"),
                                             AIAgentType.TRADITIONAL_ML)
                        new_agent  = AIAgent(
                            agent_id          = sec.token_hex(12),
                            name              = ag["name"][:200],
                            agent_type        = agent_type,
                            cloud_provider    = ag.get("cloud_provider", ""),
                            region            = ag.get("region", "")[:100],
                            protocol          = ag.get("protocol", "REST_API")[:50],
                            endpoint_url      = ag.get("endpoint", "")[:500],
                            description       = f"Discovered via {ag.get('service','')} scan",
                            agent_metadata    = {
                                "service":        ag.get("service"),
                                "scan_source":    "cloud_scan",
                                "status":         ag.get("status", "Unknown"),
                                **ag.get("metadata", {}),
                            },
                        )
                        db.session.add(new_agent)
                        saved += 1
                    except Exception as e:
                        logger.debug("Failed to save agent %s: %s", ag.get("name"), e)
                db.session.commit()
        except Exception as e:
            errors.append(f"DB save error: {str(e)}")
            logger.error("DB save error during cloud scan: %s", e)

        _update_status(scan_id, {
            "status":      "complete",
            "progress":    100,
            "completed_at": datetime.utcnow().isoformat(),
            "agents_found": len(all_agents),
            "agents_saved": saved,
            "agents":       all_agents,
            "errors":       errors,
            "current_provider": None,
        })


# ── Helpers ───────────────────────────────────────────────────────────────────
def _update_status(scan_id: str, updates: Dict):
    with _registry_lock:
        current = _scan_registry.get(scan_id, {})
        current.update(updates)
        _scan_registry[scan_id] = current


def _env_hints(provider: str) -> List[str]:
    hints = {
        "AWS":   ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                  "AWS_DEFAULT_REGION", "AWS_REGIONS (optional)"],
        "Azure": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID",
                  "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID"],
        "GCP":   ["GCP_SERVICE_ACCOUNT_JSON (or GCP_SERVICE_ACCOUNT_FILE)",
                  "GCP_PROJECT_IDS"],
    }
    return hints.get(provider, [])
