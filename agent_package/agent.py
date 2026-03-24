#!/usr/bin/env python3
"""
CT ComplySphere Collector Agent
================================
Lightweight scanner agent that runs inside a customer's network, discovers
AI agents across multiple protocols, and reports findings back to the
CT ComplySphere Visibility & Governance Platform.

Usage
-----
    python agent.py --platform https://complysphere.example.com \
                    --token YOUR_API_TOKEN \
                    [--interval 3600]

Environment variables (override CLI flags):
    PLATFORM_URL        Base URL of the CT ComplySphere platform
    API_TOKEN           API token issued by the platform
    SCAN_INTERVAL       Scan interval in seconds (default: 3600)
    ENABLED_SCANNERS    Comma-separated scanner names (default: all)
    SCAN_TARGETS        Comma-separated CIDRs / hostnames to scan
    LOG_LEVEL           DEBUG / INFO / WARNING  (default: INFO)
"""

import os
import sys
import time
import json
import socket
import logging
import argparse
import platform
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package is required. Run: pip install requests")
    sys.exit(1)

# ── Logging ────────────────────────────────────────────────────────────────

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("complysphere-agent")

AGENT_VERSION = "1.0.0"


# ── Configuration ──────────────────────────────────────────────────────────

def load_config(args) -> Dict[str, Any]:
    platform_url = (args.platform or os.environ.get("PLATFORM_URL", "")).rstrip("/")
    api_token    = args.token    or os.environ.get("API_TOKEN", "")
    interval     = int(args.interval or os.environ.get("SCAN_INTERVAL", 3600))
    raw_scanners = args.scanners or os.environ.get("ENABLED_SCANNERS", "")
    raw_targets  = args.targets  or os.environ.get("SCAN_TARGETS", "")

    enabled_scanners = [s.strip() for s in raw_scanners.split(",") if s.strip()] or None
    scan_targets     = [t.strip() for t in raw_targets.split(",")  if t.strip()] or []

    if not platform_url:
        logger.error("PLATFORM_URL is required (--platform or env var PLATFORM_URL)")
        sys.exit(1)
    if not api_token:
        logger.error("API_TOKEN is required (--token or env var API_TOKEN)")
        sys.exit(1)

    return {
        "platform_url":      platform_url,
        "api_token":         api_token,
        "scan_interval":     interval,
        "enabled_scanners":  enabled_scanners,
        "scan_targets":      scan_targets,
    }


# ── Platform API client ────────────────────────────────────────────────────

class PlatformClient:
    def __init__(self, platform_url: str, api_token: str):
        self.base = platform_url
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type":  "application/json",
            "User-Agent":    f"CT-ComplySphere-Agent/{AGENT_VERSION}",
        })

    def _post(self, path: str, data: dict) -> Optional[dict]:
        url = f"{self.base}{path}"
        try:
            resp = self.session.post(url, json=data, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot reach platform at {url}")
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP {e.response.status_code} from {url}: {e.response.text[:200]}")
        except Exception as e:
            logger.error(f"Request failed {url}: {e}")
        return None

    def register(self) -> Optional[dict]:
        payload = {
            "hostname":      socket.gethostname(),
            "ip_address":    _get_local_ip(),
            "os_info":       f"{platform.system()} {platform.release()}",
            "agent_version": AGENT_VERSION,
        }
        logger.info("Registering agent with platform …")
        result = self._post("/api/collector/register", payload)
        if result:
            logger.info(f"Registered. Platform config: scan_interval={result.get('scan_interval_minutes')}m "
                        f"scanners={result.get('enabled_scanners')}")
        return result

    def heartbeat(self) -> bool:
        result = self._post("/api/collector/heartbeat", {})
        return result is not None and result.get("status") == "ok"

    def report(self, discovered_agents: List[dict]) -> Optional[dict]:
        if not discovered_agents:
            return {"saved": 0, "skipped": 0}
        payload = {"discovered_agents": discovered_agents}
        result = self._post("/api/collector/report", payload)
        if result:
            logger.info(f"Report accepted — saved={result.get('saved')} skipped={result.get('skipped')}")
        return result

    def get_config(self) -> Optional[dict]:
        url = f"{self.base}/api/collector/config"
        try:
            resp = self.session.get(url, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"Could not fetch remote config: {e}")
        return None


# ── Discovery modules ──────────────────────────────────────────────────────

class DockerDiscovery:
    """Discover AI-related containers running in the local Docker daemon"""

    AI_IMAGE_KEYWORDS = [
        "ollama", "llama", "openai", "anthropic", "hugging", "transformers",
        "pytorch", "tensorflow", "triton", "mlflow", "ray", "vllm",
        "langchain", "autogen", "crewai", "mistral", "gpt", "claude",
        "clawbot", "ros", "robotic",
    ]

    def discover(self) -> List[dict]:
        agents = []
        try:
            import docker
            client = docker.from_env(timeout=5)
            containers = client.containers.list()
            for c in containers:
                image = (c.image.tags[0] if c.image.tags else c.image.id or "").lower()
                name  = c.name.lower()
                combined = image + " " + name
                if any(kw in combined for kw in self.AI_IMAGE_KEYWORDS):
                    ports = c.ports or {}
                    endpoint = _first_port_endpoint(ports) or f"docker://{c.name}"
                    agents.append({
                        "name":     f"docker-{c.name}",
                        "type":     "Docker Container AI Agent",
                        "protocol": "docker",
                        "endpoint": endpoint,
                        "risk_level": "MEDIUM",
                        "metadata": {
                            "container_id":   c.id[:12],
                            "image":          image,
                            "status":         c.status,
                            "discovery_method": "docker_sdk",
                        },
                    })
        except ImportError:
            logger.debug("docker SDK not installed — skipping Docker discovery")
        except Exception as e:
            logger.warning(f"Docker discovery error: {e}")
        return agents


class MCPDiscovery:
    """Detect Model Context Protocol endpoints on common ports"""

    MCP_PATHS = ["/mcp/v1/capabilities", "/api/mcp/status", "/context/protocol", "/agent/mcp"]
    PORTS = [11434, 8080, 3000, 5000, 7860]

    def discover(self, targets: List[str] = None) -> List[dict]:
        agents = []
        hosts = targets or ["localhost", "127.0.0.1"]
        for host in hosts:
            for port in self.PORTS:
                for path in self.MCP_PATHS:
                    url = f"http://{host}:{port}{path}"
                    try:
                        resp = requests.get(url, timeout=2)
                        if resp.status_code in (200, 401, 403):
                            agents.append({
                                "name":     f"mcp-{host}-{port}",
                                "type":     "MCP Protocol Agent",
                                "protocol": "mcp",
                                "endpoint": url,
                                "risk_level": "MEDIUM",
                                "metadata": {
                                    "discovery_method": "mcp_port_scan",
                                    "http_status": resp.status_code,
                                },
                            })
                            break
                    except Exception:
                        pass
        return agents


class ProcessDiscovery:
    """Detect AI-related processes running on the local machine"""

    AI_PROCESS_KEYWORDS = [
        "ollama", "llama", "python", "uvicorn", "gunicorn",
        "triton", "vllm", "ray", "mlflow", "ros", "roscore",
    ]
    AI_SCRIPT_KEYWORDS = [
        "llm", "llama", "gpt", "claude", "ai", "agent", "model",
        "inference", "transformers", "langchain", "ros",
    ]

    def discover(self) -> List[dict]:
        agents = []
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "cmdline", "connections"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    cmdline = " ".join(proc.info["cmdline"] or []).lower()
                    if any(kw in name for kw in self.AI_PROCESS_KEYWORDS) or \
                       any(kw in cmdline for kw in self.AI_SCRIPT_KEYWORDS):
                        conns = proc.info.get("connections") or []
                        port  = conns[0].laddr.port if conns else None
                        endpoint = f"process://{proc.info['pid']}"
                        if port:
                            endpoint = f"http://localhost:{port}"
                        agents.append({
                            "name":     f"process-{name}-{proc.info['pid']}",
                            "type":     "Local AI Process",
                            "protocol": "process",
                            "endpoint": endpoint,
                            "risk_level": "LOW",
                            "metadata": {
                                "pid":  proc.info["pid"],
                                "name": proc.info["name"],
                                "cmdline": cmdline[:200],
                                "discovery_method": "process_scan",
                            },
                        })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
        except ImportError:
            logger.debug("psutil not installed — skipping process discovery")
        except Exception as e:
            logger.warning(f"Process discovery error: {e}")
        return agents


class ClawbotDiscovery:
    """Detect Clawbot robotic agents via ROS and MQTT port probing"""

    ROS_PORTS  = [11311]
    MQTT_PORTS = [1883, 8883]
    ROBOT_PATHS = ["/robot/status", "/clawbot/capabilities", "/api/v1/robot/info"]

    def discover(self, targets: List[str] = None) -> List[dict]:
        agents = []
        hosts = targets or ["localhost", "127.0.0.1"]
        for host in hosts:
            for port in self.ROS_PORTS + self.MQTT_PORTS:
                if _port_open(host, port, timeout=1):
                    protocol = "ros" if port in self.ROS_PORTS else "mqtt"
                    agents.append({
                        "name":     f"clawbot-{protocol}-{host}-{port}",
                        "type":     "Clawbot Robotic Agent",
                        "protocol": protocol,
                        "endpoint": f"{protocol}://{host}:{port}",
                        "risk_level": "HIGH",
                        "metadata": {
                            "discovery_method": "port_probe",
                            "host": host,
                            "port": port,
                        },
                    })
            for path in self.ROBOT_PATHS:
                for port in [8080, 5000, 7000]:
                    url = f"http://{host}:{port}{path}"
                    try:
                        resp = requests.get(url, timeout=2)
                        if resp.status_code in (200, 401):
                            agents.append({
                                "name":     f"clawbot-rest-{host}-{port}",
                                "type":     "Clawbot REST Agent",
                                "protocol": "rest_api",
                                "endpoint": url,
                                "risk_level": "HIGH",
                                "metadata": {"discovery_method": "http_probe", "status": resp.status_code},
                            })
                    except Exception:
                        pass
        return agents


class KubernetesDiscovery:
    """Discover AI workloads in the local Kubernetes cluster"""

    AI_KEYWORDS = [
        "llm", "gpt", "claude", "llama", "ollama", "triton",
        "mlflow", "ray", "vllm", "ai", "ml", "model",
    ]

    def discover(self) -> List[dict]:
        agents = []
        try:
            from kubernetes import client as k8s_client, config as k8s_config
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config()
            v1  = k8s_client.CoreV1Api()
            pods = v1.list_pod_for_all_namespaces(watch=False)
            for pod in pods.items:
                name = pod.metadata.name.lower()
                if any(kw in name for kw in self.AI_KEYWORDS):
                    ns = pod.metadata.namespace
                    agents.append({
                        "name":     f"k8s-{ns}-{pod.metadata.name}",
                        "type":     "Kubernetes AI Workload",
                        "protocol": "kubernetes",
                        "endpoint": f"k8s://{ns}/{pod.metadata.name}",
                        "risk_level": "MEDIUM",
                        "metadata": {
                            "namespace": ns,
                            "pod_name":  pod.metadata.name,
                            "phase":     pod.status.phase,
                            "discovery_method": "kubernetes_api",
                        },
                    })
        except ImportError:
            logger.debug("kubernetes SDK not installed — skipping K8s discovery")
        except Exception as e:
            logger.debug(f"Kubernetes discovery: {e}")
        return agents


# ── Scanner orchestrator ───────────────────────────────────────────────────

SCANNER_MAP = {
    "docker":       DockerDiscovery,
    "mcp_protocol": MCPDiscovery,
    "process":      ProcessDiscovery,
    "clawbot":      ClawbotDiscovery,
    "kubernetes":   KubernetesDiscovery,
}


def run_all_scanners(enabled: Optional[List[str]], targets: List[str]) -> List[dict]:
    all_agents = []
    names = enabled if enabled else list(SCANNER_MAP.keys())
    for name in names:
        cls = SCANNER_MAP.get(name)
        if not cls:
            logger.warning(f"Unknown scanner: {name}")
            continue
        try:
            scanner = cls()
            if name in ("mcp_protocol", "clawbot"):
                discovered = scanner.discover(targets or None)
            else:
                discovered = scanner.discover()
            logger.info(f"[{name}] Found {len(discovered)} agent(s)")
            all_agents.extend(discovered)
        except Exception as e:
            logger.error(f"Scanner '{name}' failed: {e}")

    # De-duplicate by endpoint
    seen = set()
    unique = []
    for a in all_agents:
        key = (a.get("name"), a.get("endpoint"))
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique


# ── Helpers ────────────────────────────────────────────────────────────────

def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _first_port_endpoint(ports: dict) -> Optional[str]:
    for container_port, bindings in ports.items():
        if bindings:
            host_port = bindings[0].get("HostPort")
            if host_port:
                return f"http://localhost:{host_port}"
    return None


# ── Main loop ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CT ComplySphere Collector Agent")
    parser.add_argument("--platform",  help="Platform base URL")
    parser.add_argument("--token",     help="API token")
    parser.add_argument("--interval",  type=int, help="Scan interval in seconds", default=None)
    parser.add_argument("--scanners",  help="Comma-separated list of scanners to enable")
    parser.add_argument("--targets",   help="Comma-separated scan targets (CIDRs / hosts)")
    args = parser.parse_args()

    cfg    = load_config(args)
    client = PlatformClient(cfg["platform_url"], cfg["api_token"])

    # ── Register ──
    reg = client.register()
    if reg:
        # Use platform-configured values if not locally overridden
        if not cfg["enabled_scanners"]:
            cfg["enabled_scanners"] = reg.get("enabled_scanners")
        if not cfg["scan_targets"]:
            cfg["scan_targets"] = reg.get("scan_targets", [])
        cfg["scan_interval"] = reg.get("scan_interval_minutes", cfg["scan_interval"] // 60) * 60

    logger.info(f"Agent ready. Scan interval: {cfg['scan_interval']}s | "
                f"Scanners: {cfg['enabled_scanners'] or 'all'}")

    scan_count = 0

    while True:
        scan_count += 1
        logger.info(f"─── Scan #{scan_count} starting ───────────────────")

        # Heartbeat
        if not client.heartbeat():
            logger.warning("Heartbeat failed — platform may be unreachable")

        # Re-fetch config every 10 scans
        if scan_count % 10 == 0:
            remote_cfg = client.get_config()
            if remote_cfg:
                cfg["enabled_scanners"] = remote_cfg.get("enabled_scanners", cfg["enabled_scanners"])
                cfg["scan_targets"]     = remote_cfg.get("scan_targets", cfg["scan_targets"])

        # Run discovery
        discovered = run_all_scanners(cfg["enabled_scanners"], cfg["scan_targets"])
        logger.info(f"Discovery complete — {len(discovered)} unique agent(s) found")

        # Report
        client.report(discovered)

        logger.info(f"─── Scan #{scan_count} complete. Sleeping {cfg['scan_interval']}s ─")
        time.sleep(cfg["scan_interval"])


if __name__ == "__main__":
    main()
