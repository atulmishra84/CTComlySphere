"""
AWS Cloud Scanner — discovers AI/ML agents across AWS services.
Requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
Optional:  AWS_REGIONS (comma-separated list for multi-region scan)
"""
import os
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class AWSScanner:
    """Scans AWS for AI/ML services and returns normalised agent records."""

    SERVICES = [
        "sagemaker", "bedrock", "lambda", "ecs", "eks",
        "comprehend", "rekognition", "lex-models-v2",
        "transcribe", "polly", "textract",
    ]

    AI_LAMBDA_KEYWORDS = [
        "ai", "ml", "model", "inference", "predict", "llm", "gpt",
        "claude", "bedrock", "sagemaker", "nlp", "vision", "embed",
        "agent", "assistant", "classify", "detect", "recommend",
    ]

    def __init__(self):
        self.access_key    = os.environ.get("AWS_ACCESS_KEY_ID", "")
        self.secret_key    = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        self.session_token = os.environ.get("AWS_SESSION_TOKEN", "")
        self.default_region= os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        raw_regions        = os.environ.get("AWS_REGIONS", self.default_region)
        self.regions       = [r.strip() for r in raw_regions.split(",") if r.strip()]

    # ── Credential validation ─────────────────────────────────────────────────
    def is_configured(self) -> bool:
        return bool(self.access_key and self.secret_key)

    def validate_credentials(self) -> Dict[str, Any]:
        if not self.is_configured():
            return {"valid": False, "error": "AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set."}
        try:
            import boto3, botocore
            sts = self._client("sts", self.default_region)
            identity = sts.get_caller_identity()
            return {
                "valid": True,
                "account_id": identity["Account"],
                "arn": identity["Arn"],
                "regions": self.regions,
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    # ── Main entry point ──────────────────────────────────────────────────────
    def scan_all(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        scan_regions = regions or self.regions
        results: List[Dict] = []
        errors: List[str]   = []
        for region in scan_regions:
            try:
                results.extend(self._scan_region(region))
            except Exception as e:
                errors.append(f"{region}: {e}")
                logger.warning("AWS scan failed in region %s: %s", region, e)
        return {
            "provider": "aws",
            "scan_time": datetime.utcnow().isoformat(),
            "regions_scanned": scan_regions,
            "agents": results,
            "total": len(results),
            "errors": errors,
        }

    # ── Per-region scan ───────────────────────────────────────────────────────
    def _scan_region(self, region: str) -> List[Dict]:
        agents = []
        agents.extend(self._scan_sagemaker(region))
        agents.extend(self._scan_bedrock(region))
        agents.extend(self._scan_lambda(region))
        agents.extend(self._scan_ecs(region))
        agents.extend(self._scan_managed_ai(region))
        return agents

    # ── SageMaker ─────────────────────────────────────────────────────────────
    def _scan_sagemaker(self, region: str) -> List[Dict]:
        agents = []
        try:
            sm = self._client("sagemaker", region)
            # Real-time endpoints
            paginator = sm.get_paginator("list_endpoints")
            for page in paginator.paginate():
                for ep in page.get("Endpoints", []):
                    detail = sm.describe_endpoint(EndpointName=ep["EndpointName"])
                    agents.append(self._sagemaker_endpoint_to_agent(detail, region))
        except Exception as e:
            logger.debug("SageMaker endpoints scan error %s: %s", region, e)

        try:
            sm = self._client("sagemaker", region)
            # Async inference endpoints
            paginator = sm.get_paginator("list_inference_components")
            for page in paginator.paginate():
                for ic in page.get("InferenceComponents", []):
                    agents.append({
                        "name": ic["InferenceComponentName"],
                        "service": "sagemaker-inference-component",
                        "agent_type": "TRADITIONAL_ML",
                        "cloud_provider": "aws",
                        "region": region,
                        "protocol": "REST_API",
                        "endpoint": f"sagemaker.{region}.amazonaws.com",
                        "status": ic.get("InferenceComponentStatus", "Unknown"),
                        "metadata": {"endpoint_name": ic.get("EndpointName")},
                    })
        except Exception:
            pass

        return agents

    def _sagemaker_endpoint_to_agent(self, detail: Dict, region: str) -> Dict:
        name   = detail["EndpointName"]
        status = detail.get("EndpointStatus", "Unknown")
        # Try to detect model type from config
        agent_type = "TRADITIONAL_ML"
        config_name = detail.get("EndpointConfigName", "")
        if any(k in config_name.lower() for k in ["llm", "gpt", "bert", "bloom", "falcon", "llama", "mistral"]):
            agent_type = "GENAI"
        elif any(k in config_name.lower() for k in ["vision", "image", "detect", "rekognition"]):
            agent_type = "COMPUTER_VISION"
        elif any(k in config_name.lower() for k in ["nlp", "text", "ner", "sentiment"]):
            agent_type = "NLP"
        return {
            "name": name,
            "service": "sagemaker-endpoint",
            "agent_type": agent_type,
            "cloud_provider": "aws",
            "region": region,
            "protocol": "REST_API",
            "endpoint": f"runtime.sagemaker.{region}.amazonaws.com/endpoints/{name}/invocations",
            "status": status,
            "metadata": {
                "endpoint_config": config_name,
                "creation_time": str(detail.get("CreationTime", "")),
                "last_modified": str(detail.get("LastModifiedTime", "")),
                "failure_reason": detail.get("FailureReason"),
            },
        }

    # ── Amazon Bedrock ────────────────────────────────────────────────────────
    def _scan_bedrock(self, region: str) -> List[Dict]:
        agents = []
        try:
            br = self._client("bedrock", region)
            # List custom models
            resp = br.list_custom_models()
            for m in resp.get("modelSummaries", []):
                agents.append({
                    "name": m.get("modelName", "UnknownBedrockModel"),
                    "service": "bedrock-custom-model",
                    "agent_type": "GENAI",
                    "cloud_provider": "aws",
                    "region": region,
                    "protocol": "REST_API",
                    "endpoint": f"bedrock.{region}.amazonaws.com",
                    "status": m.get("modelStatus", "Unknown"),
                    "metadata": {
                        "model_id": m.get("modelArn"),
                        "base_model_id": m.get("baseModelId"),
                        "creation_time": str(m.get("creationTime", "")),
                    },
                })
        except Exception as e:
            logger.debug("Bedrock custom models scan error %s: %s", region, e)

        try:
            br = self._client("bedrock", region)
            # List Bedrock Agents
            resp = br.list_agents()
            for ag in resp.get("agentSummaries", []):
                agents.append({
                    "name": ag.get("agentName", "UnknownAgent"),
                    "service": "bedrock-agent",
                    "agent_type": "AGENTIC_AI",
                    "cloud_provider": "aws",
                    "region": region,
                    "protocol": "REST_API",
                    "endpoint": f"bedrock-agent.{region}.amazonaws.com",
                    "status": ag.get("agentStatus", "Unknown"),
                    "metadata": {
                        "agent_id": ag.get("agentId"),
                        "description": ag.get("description"),
                        "last_updated": str(ag.get("lastUpdatedAt", "")),
                    },
                })
        except Exception as e:
            logger.debug("Bedrock agents scan error %s: %s", region, e)

        return agents

    # ── AWS Lambda (AI-related functions) ─────────────────────────────────────
    def _scan_lambda(self, region: str) -> List[Dict]:
        agents = []
        try:
            lm = self._client("lambda", region)
            paginator = lm.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page.get("Functions", []):
                    fn_name = fn.get("FunctionName", "")
                    if not self._is_ai_lambda(fn):
                        continue
                    agents.append({
                        "name": fn_name,
                        "service": "lambda-function",
                        "agent_type": "AGENTIC_AI",
                        "cloud_provider": "aws",
                        "region": region,
                        "protocol": "REST_API",
                        "endpoint": fn.get("FunctionArn", ""),
                        "status": "Active",
                        "metadata": {
                            "runtime": fn.get("Runtime"),
                            "handler": fn.get("Handler"),
                            "memory_mb": fn.get("MemorySize"),
                            "timeout_sec": fn.get("Timeout"),
                            "last_modified": fn.get("LastModified"),
                            "description": fn.get("Description"),
                        },
                    })
        except Exception as e:
            logger.debug("Lambda scan error %s: %s", region, e)
        return agents

    def _is_ai_lambda(self, fn: Dict) -> bool:
        name = (fn.get("FunctionName", "") + " " + fn.get("Description", "")).lower()
        env_vars = fn.get("Environment", {}).get("Variables", {})
        env_str = " ".join(f"{k} {v}" for k, v in env_vars.items()).lower()
        text = name + " " + env_str
        return any(kw in text for kw in self.AI_LAMBDA_KEYWORDS)

    # ── ECS (containerised AI services) ──────────────────────────────────────
    def _scan_ecs(self, region: str) -> List[Dict]:
        agents = []
        try:
            ecs = self._client("ecs", region)
            clusters_resp = ecs.list_clusters()
            for cluster_arn in clusters_resp.get("clusterArns", []):
                try:
                    services_resp = ecs.list_services(cluster=cluster_arn)
                    if not services_resp.get("serviceArns"):
                        continue
                    details = ecs.describe_services(
                        cluster=cluster_arn,
                        services=services_resp["serviceArns"][:10],
                    )
                    for svc in details.get("services", []):
                        svc_name = svc.get("serviceName", "")
                        if not any(kw in svc_name.lower() for kw in self.AI_LAMBDA_KEYWORDS):
                            continue
                        agents.append({
                            "name": svc_name,
                            "service": "ecs-service",
                            "agent_type": "AGENTIC_AI",
                            "cloud_provider": "aws",
                            "region": region,
                            "protocol": "REST_API",
                            "endpoint": cluster_arn,
                            "status": svc.get("status", "Unknown"),
                            "metadata": {
                                "cluster": cluster_arn.split("/")[-1],
                                "task_definition": svc.get("taskDefinition", ""),
                                "desired_count": svc.get("desiredCount"),
                                "running_count": svc.get("runningCount"),
                                "launch_type": svc.get("launchType"),
                            },
                        })
                except Exception:
                    pass
        except Exception as e:
            logger.debug("ECS scan error %s: %s", region, e)
        return agents

    # ── Managed AI services (Comprehend, Rekognition, Lex, etc.) ─────────────
    def _scan_managed_ai(self, region: str) -> List[Dict]:
        agents = []
        # Comprehend — custom classifiers
        try:
            cp = self._client("comprehend", region)
            resp = cp.list_document_classifiers(Filter={"Status": "TRAINED"})
            for clf in resp.get("DocumentClassifierPropertiesList", []):
                agents.append({
                    "name": clf.get("DocumentClassifierArn", "").split("/")[-1],
                    "service": "comprehend-classifier",
                    "agent_type": "NLP",
                    "cloud_provider": "aws",
                    "region": region,
                    "protocol": "REST_API",
                    "endpoint": f"comprehend.{region}.amazonaws.com",
                    "status": clf.get("Status", "Unknown"),
                    "metadata": {"language": clf.get("LanguageCode"), "mode": clf.get("Mode")},
                })
        except Exception:
            pass

        # Lex V2 — bots
        try:
            lex = self._client("lexv2-models", region)
            resp = lex.list_bots()
            for bot in resp.get("botSummaries", []):
                agents.append({
                    "name": bot.get("botName", "UnknownBot"),
                    "service": "lex-bot",
                    "agent_type": "CONVERSATIONAL_AI",
                    "cloud_provider": "aws",
                    "region": region,
                    "protocol": "REST_API",
                    "endpoint": f"models-v2-lex.{region}.amazonaws.com",
                    "status": bot.get("botStatus", "Unknown"),
                    "metadata": {"bot_id": bot.get("botId"), "description": bot.get("description")},
                })
        except Exception:
            pass

        return agents

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _client(self, service: str, region: str):
        import boto3
        kwargs = dict(region_name=region)
        if self.access_key:
            kwargs["aws_access_key_id"]     = self.access_key
            kwargs["aws_secret_access_key"] = self.secret_key
        if self.session_token:
            kwargs["aws_session_token"]     = self.session_token
        return boto3.client(service, **kwargs)
