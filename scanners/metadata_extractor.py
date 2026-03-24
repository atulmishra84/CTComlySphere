"""
CT ComplySphere — AI Agent Metadata Extractor
===============================================
Deep-probes a discovered AI agent endpoint to extract rich, structured metadata
that fills the AIAgent model's typed fields (model_family, capabilities, etc.)
and enriches the agent_metadata JSON blob.

Supported probe strategies (selected by protocol):
  - rest_api / https / http  : OpenAI-compat /v1/models, /info, headers, auth detection
  - docker                   : Docker labels, env vars, image manifest, healthcheck
  - kubernetes               : Pod labels, annotations, resource limits, env, service mesh
  - mcp / mcp_protocol       : MCP capabilities handshake
  - mqtt / ros               : MQTT topic enumeration, ROS parameter server probe
  - grpc                     : gRPC server reflection
  - websocket / ws           : WebSocket handshake and banner
  - graphql                  : GraphQL introspection query
  - process                  : /proc cmdline / psutil environ inspection
  - generic                  : Fallback HTTP HEAD + pattern matching
"""

import re
import json
import socket
import logging
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import requests
    from requests.exceptions import RequestException
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    RequestException = Exception

logger = logging.getLogger("MetadataExtractor")

# ── Keyword / pattern libraries ────────────────────────────────────────────

MODEL_FAMILY_PATTERNS = [
    (re.compile(r'gpt-?4o?', re.I), 'GPT-4'),
    (re.compile(r'gpt-?3\.?5', re.I), 'GPT-3.5'),
    (re.compile(r'claude-?3', re.I), 'Claude 3'),
    (re.compile(r'claude-?2', re.I), 'Claude 2'),
    (re.compile(r'\bclaude\b', re.I), 'Claude'),
    (re.compile(r'llama-?3', re.I), 'LLaMA-3'),
    (re.compile(r'llama-?2', re.I), 'LLaMA-2'),
    (re.compile(r'\bllama\b', re.I), 'LLaMA'),
    (re.compile(r'\bmistral\b', re.I), 'Mistral'),
    (re.compile(r'\bgemma\b', re.I), 'Gemma'),
    (re.compile(r'\bgemini\b', re.I), 'Gemini'),
    (re.compile(r'\bphi-?[23]\b', re.I), 'Phi'),
    (re.compile(r'\bfalcon\b', re.I), 'Falcon'),
    (re.compile(r'\bvicuna\b', re.I), 'Vicuna'),
    (re.compile(r'\balpaca\b', re.I), 'Alpaca'),
    (re.compile(r'\bollama\b', re.I), 'Ollama/Local'),
    (re.compile(r'\bhugging\b', re.I), 'HuggingFace'),
    (re.compile(r'\bstable.?diffusion\b', re.I), 'Stable Diffusion'),
    (re.compile(r'\bwhisper\b', re.I), 'Whisper'),
    (re.compile(r'\bclinical\b', re.I), 'Clinical AI'),
    (re.compile(r'\bbiobert\b', re.I), 'BioBERT'),
    (re.compile(r'\bmedical\b', re.I), 'Medical AI'),
]

MODEL_SIZE_PATTERNS = [
    (re.compile(r'(\d+\.?\d*)b\b', re.I), '{n}B'),
    (re.compile(r'(\d+)x(\d+)b\b', re.I), '{n1}x{n2}B (MoE)'),
    (re.compile(r'\b(small|medium|large|xl|xxl|huge)\b', re.I), '{n}'),
    (re.compile(r'(\d+)k\b', re.I), '{n}K context'),
]

AGENT_FRAMEWORK_PATTERNS = [
    (re.compile(r'langchain', re.I), 'LangChain'),
    (re.compile(r'langgraph', re.I), 'LangGraph'),
    (re.compile(r'autogpt', re.I), 'AutoGPT'),
    (re.compile(r'crewai', re.I), 'CrewAI'),
    (re.compile(r'autogen', re.I), 'AutoGen'),
    (re.compile(r'semantic.?kernel', re.I), 'Semantic Kernel'),
    (re.compile(r'llamaindex', re.I), 'LlamaIndex'),
    (re.compile(r'haystack', re.I), 'Haystack'),
    (re.compile(r'dspy', re.I), 'DSPy'),
    (re.compile(r'openai.?swarm', re.I), 'OpenAI Swarm'),
    (re.compile(r'a2a', re.I), 'Agent-to-Agent (A2A)'),
    (re.compile(r'mcp', re.I), 'Model Context Protocol (MCP)'),
    (re.compile(r'ray\b', re.I), 'Ray/RLlib'),
    (re.compile(r'mlflow', re.I), 'MLflow'),
    (re.compile(r'triton', re.I), 'NVIDIA Triton'),
    (re.compile(r'vllm', re.I), 'vLLM'),
    (re.compile(r'torchserve', re.I), 'TorchServe'),
    (re.compile(r'bentoml', re.I), 'BentoML'),
    (re.compile(r'seldon', re.I), 'Seldon'),
    (re.compile(r'kserve', re.I), 'KServe'),
]

CAPABILITY_SIGNALS = {
    'text_generation': ['completion', 'generate', 'chat', 'llm', 'language', 'gpt', 'claude', 'llama'],
    'embeddings': ['embed', 'vector', 'semantic', 'similarity', 'encoding'],
    'image_generation': ['diffusion', 'image', 'dalle', 'midjourney', 'stable', 'flux'],
    'speech_to_text': ['whisper', 'transcribe', 'asr', 'speech', 'audio'],
    'vision': ['vision', 'vqa', 'ocr', 'image_understanding', 'multimodal'],
    'code_generation': ['code', 'codex', 'copilot', 'starcoder', 'deepseek-coder'],
    'function_calling': ['tool', 'function_call', 'tool_use', 'actions'],
    'planning': ['plan', 'reason', 'cot', 'chain_of_thought', 'reflection'],
    'memory': ['memory', 'recall', 'remember', 'context_store', 'persist'],
    'phi_processing': ['patient', 'clinical', 'ehr', 'fhir', 'hipaa', 'medical', 'diagnosis'],
    'rag': ['retrieval', 'rag', 'vector_db', 'knowledge_base', 'semantic_search'],
    'robotics': ['ros', 'robot', 'clawbot', 'motor', 'sensor', 'actuator', 'mqtt'],
}

AUTH_METHOD_SIGNALS = {
    'api_key': ['api-key', 'x-api-key', 'authorization: bearer', 'apikey'],
    'oauth2': ['oauth', 'bearer', 'access_token', 'jwt'],
    'basic_auth': ['basic ', 'www-authenticate: basic'],
    'certificate': ['client-cert', 'mtls', 'x-client-cert', 'certificate'],
    'none': [],
}

AUTONOMY_SIGNALS = {
    'full': ['autonomous', 'self-directed', 'unsupervised', 'agentic', 'auto-execute'],
    'high': ['agent', 'planning', 'tool_use', 'multi-step', 'orchestrat'],
    'medium': ['assist', 'copilot', 'suggest', 'recommend', 'help'],
    'low': ['predict', 'classify', 'inference', 'score', 'detect'],
}

WELL_KNOWN_PROBE_PATHS = [
    '/v1/models',
    '/api/tags',
    '/api/v1/models',
    '/v1/info',
    '/info',
    '/_info',
    '/api/info',
    '/health',
    '/healthz',
    '/ready',
    '/metrics',
    '/version',
    '/api/version',
    '/api/v1/status',
    '/openapi.json',
    '/swagger.json',
    '/docs',
    '/api',
    '/mcp/v1/capabilities',
    '/agent/info',
    '/agent/capabilities',
    '/robots.txt',
]


# ── Main extractor class ───────────────────────────────────────────────────

class MetadataExtractor:
    """
    Protocol-aware metadata extractor for discovered AI agents.
    Call `extract(agent_data)` with the raw scanner output dict.
    Returns an `EnrichedMetadata` dict ready to merge into the AIAgent model.
    """

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    # ── Public API ─────────────────────────────────────────────────────────

    def extract(self, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point.  `agent_data` is the raw dict produced by any scanner.
        Returns a dict whose keys correspond to AIAgent model columns + a
        rich `extracted_metadata` sub-dict.
        """
        protocol  = (agent_data.get('protocol') or '').lower()
        endpoint  = agent_data.get('endpoint') or ''
        raw_meta  = agent_data.get('agent_metadata') or agent_data.get('metadata') or {}
        name      = agent_data.get('name') or ''
        agent_type = agent_data.get('type') or ''

        result: Dict[str, Any] = {
            'extracted_metadata': {
                'extraction_timestamp': datetime.utcnow().isoformat(),
                'protocol_used': protocol,
                'probe_results': {},
            }
        }

        # Dispatch to protocol-specific extractor
        dispatch = {
            'rest_api':      self._probe_rest,
            'http':          self._probe_rest,
            'https':         self._probe_rest,
            'docker':        self._probe_docker,
            'kubernetes':    self._probe_kubernetes,
            'mcp':           self._probe_mcp,
            'mcp_protocol':  self._probe_mcp,
            'mqtt':          self._probe_mqtt,
            'ros':           self._probe_ros,
            'grpc':          self._probe_grpc,
            'websocket':     self._probe_websocket,
            'ws':            self._probe_websocket,
            'graphql':       self._probe_graphql,
            'process':       self._probe_process,
        }
        probe_fn = dispatch.get(protocol, self._probe_generic)
        try:
            probe_result = probe_fn(endpoint, raw_meta)
            result['extracted_metadata']['probe_results'] = probe_result
        except Exception as e:
            logger.debug(f"Protocol probe failed for {endpoint}: {e}")
            probe_result = {}

        # ── Combine all text for pattern matching ──────────────────────────
        searchable = self._build_searchable(name, agent_type, endpoint, raw_meta, probe_result)

        # ── Extract structured fields ──────────────────────────────────────
        result['model_family']    = self._extract_model_family(searchable)
        result['model_size']      = self._extract_model_size(searchable)
        result['capabilities']    = self._extract_capabilities(searchable)
        result['agent_framework'] = self._extract_agent_framework(searchable)
        result['autonomy_level']  = self._extract_autonomy_level(searchable)
        result['tool_access']     = self._extract_tool_access(searchable, probe_result)
        result['authentication_method'] = self._extract_auth_method(searchable, probe_result)

        # Version
        result['version'] = (
            probe_result.get('version') or
            raw_meta.get('version') or
            raw_meta.get('app_version') or
            self._extract_version_from_text(searchable)
        )

        # Deployment details
        result['deployment_method'] = self._map_protocol_to_deployment(protocol)

        # Remove None values for cleanliness (keep existing DB values)
        result = {k: v for k, v in result.items() if v is not None and v != [] and v != {}}

        return result

    # ── Protocol-specific probes ───────────────────────────────────────────

    def _probe_rest(self, endpoint: str, raw_meta: dict) -> dict:
        """Probe REST / HTTP(S) endpoint across well-known paths"""
        if not REQUESTS_AVAILABLE or not endpoint.startswith('http'):
            return {}

        out = {}
        base = self._base_url(endpoint)
        headers_collected = {}

        for path in WELL_KNOWN_PROBE_PATHS:
            url = base + path
            try:
                resp = requests.get(url, timeout=self.timeout,
                                    headers={'Accept': 'application/json'},
                                    allow_redirects=True)
                headers_collected.update(dict(resp.headers))

                if resp.status_code == 200:
                    content_type = resp.headers.get('content-type', '')
                    if 'json' in content_type:
                        try:
                            data = resp.json()
                            out[path] = data
                            # OpenAI-compat /v1/models response
                            if path == '/v1/models' and 'data' in data:
                                models = [m.get('id', '') for m in data['data']]
                                out['available_models'] = models
                                out['model_count'] = len(models)
                            # Ollama /api/tags
                            if path == '/api/tags' and 'models' in data:
                                models = [m.get('name', '') for m in data['models']]
                                out['available_models'] = models
                                out['model_count'] = len(models)
                                out['runtime'] = 'ollama'
                            # Version / info endpoints
                            if path in ('/info', '/_info', '/api/info', '/version', '/api/version'):
                                out['version'] = (data.get('version') or data.get('app_version')
                                                  or data.get('build_version') or data.get('v'))
                                out['service_info'] = data
                            # Health check
                            if path in ('/health', '/healthz', '/ready'):
                                out['health_status'] = data.get('status', 'ok')
                        except Exception:
                            out[path] = resp.text[:500]
                    elif path in ('/health', '/healthz', '/ready'):
                        out['health_status'] = 'up'

                # Detect auth from 401/403
                if resp.status_code in (401, 403):
                    www_auth = resp.headers.get('WWW-Authenticate', '')
                    out['auth_challenge'] = www_auth or f'HTTP {resp.status_code}'
                    out['requires_auth'] = True

            except RequestException:
                pass
            except Exception:
                pass

        # Security headers
        sec_headers = {}
        for h in ['server', 'x-powered-by', 'x-frame-options', 'strict-transport-security',
                  'content-security-policy', 'x-content-type-options']:
            if h.lower() in {k.lower(): v for k, v in headers_collected.items()}:
                sec_headers[h] = headers_collected.get(h) or headers_collected.get(h.title())
        if sec_headers:
            out['security_headers'] = sec_headers

        # TLS / encryption
        out['uses_tls'] = endpoint.startswith('https://')
        return out

    def _probe_docker(self, endpoint: str, raw_meta: dict) -> dict:
        """Extract metadata from Docker container info already in raw_meta"""
        out = {}
        labels  = raw_meta.get('labels') or {}
        env     = raw_meta.get('environment') or {}
        image   = raw_meta.get('image') or raw_meta.get('image_name') or ''
        ports   = raw_meta.get('ports') or {}

        out['image']          = image
        out['container_labels'] = labels
        out['exposed_ports']  = list(ports.keys()) if ports else []
        out['uses_latest_tag'] = image.endswith(':latest') or ':' not in image

        # Extract env vars that reveal AI details (mask secrets)
        ai_env = {}
        secret_keys = {'key', 'token', 'secret', 'password', 'pass', 'pwd', 'credential'}
        for k, v in env.items():
            if any(s in k.lower() for s in secret_keys):
                ai_env[k] = '***redacted***'
            else:
                ai_env[k] = v
        out['environment_vars'] = ai_env

        # Well-known labels
        for label_key in ['ai.model', 'ai.framework', 'ai.type', 'ai.version',
                          'org.opencontainers.image.version', 'version',
                          'com.opencontainers.image.title']:
            if label_key in labels:
                out.setdefault('version', labels[label_key])

        # Model from image name
        out['image_runtime'] = self._identify_image_runtime(image)
        out['uses_tls'] = False
        out['requires_auth'] = bool(env.get('API_KEY') or env.get('AUTH_TOKEN') or env.get('SECRET'))
        return out

    def _probe_kubernetes(self, endpoint: str, raw_meta: dict) -> dict:
        """Extract metadata from Kubernetes pod/service info in raw_meta"""
        out = {}
        labels      = raw_meta.get('labels') or {}
        annotations = raw_meta.get('annotations') or {}
        resources   = raw_meta.get('resource_limits') or {}
        containers  = raw_meta.get('containers') or []

        out['k8s_labels']      = labels
        out['k8s_annotations'] = {k: v for k, v in annotations.items() if len(v) < 300}
        out['resource_limits'] = resources
        out['container_count'] = len(containers)
        out['namespace']       = raw_meta.get('namespace', 'default')

        # Extract images
        images = [c.get('image', '') for c in containers if isinstance(c, dict)]
        out['container_images'] = images
        if images:
            out['image_runtime'] = self._identify_image_runtime(images[0])

        # Common k8s AI annotations
        for key in ['ai.kubernetes.io/model', 'serving.kserve.io/inferenceservice',
                    'seldon.io/model', 'ml.platform', 'ai.framework']:
            if key in annotations:
                out['k8s_ai_annotation'] = annotations[key]
                break

        # Service mesh
        out['service_mesh'] = any('istio' in str(k).lower() or 'linkerd' in str(k).lower()
                                  for k in list(labels.keys()) + list(annotations.keys()))
        return out

    def _probe_mcp(self, endpoint: str, raw_meta: dict) -> dict:
        """Probe MCP capabilities endpoint"""
        out = {'protocol_version': 'mcp/1.0'}
        if not REQUESTS_AVAILABLE:
            return out

        cap_paths = ['/mcp/v1/capabilities', '/capabilities', '/context/protocol', '/agent/capabilities']
        base = self._base_url(endpoint) if endpoint.startswith('http') else f'http://{endpoint}'

        for path in cap_paths:
            try:
                resp = requests.get(base + path, timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        out['capabilities'] = data.get('capabilities') or data.get('tools') or data
                        out['tools_count'] = len(out['capabilities']) if isinstance(out['capabilities'], list) else None
                        out['mcp_version'] = data.get('protocolVersion') or data.get('version')
                        out['server_name'] = data.get('serverInfo', {}).get('name')
                        break
                    except Exception:
                        pass
            except Exception:
                pass

        out['requires_auth'] = raw_meta.get('requires_auth', False)
        return out

    def _probe_mqtt(self, endpoint: str, raw_meta: dict) -> dict:
        """Probe MQTT broker metadata"""
        out = {
            'broker_address': raw_meta.get('broker_host') or self._extract_host(endpoint),
            'port':           raw_meta.get('port') or self._extract_port(endpoint) or 1883,
            'topics':         raw_meta.get('topics') or [],
            'qos_level':      raw_meta.get('qos', 0),
            'uses_tls':       raw_meta.get('uses_tls') or self._extract_port(endpoint) == 8883,
            'requires_auth':  raw_meta.get('requires_auth', False),
        }
        # Clawbot-specific topic structure
        topics = out['topics']
        if any('/robot/' in str(t) or '/clawbot/' in str(t) for t in topics):
            out['is_clawbot'] = True
            out['robot_topics'] = [t for t in topics if 'robot' in str(t) or 'clawbot' in str(t)]
        return out

    def _probe_ros(self, endpoint: str, raw_meta: dict) -> dict:
        """Probe ROS master API"""
        out = {
            'ros_master': raw_meta.get('ros_master_uri') or endpoint,
            'ros_version': raw_meta.get('ros_version', 'ROS 1'),
            'nodes': raw_meta.get('nodes') or [],
            'topics': raw_meta.get('topics') or [],
            'services': raw_meta.get('services') or [],
            'packages': raw_meta.get('packages') or [],
        }
        # Attempt xmlrpc probe for node list
        host = self._extract_host(endpoint)
        port = self._extract_port(endpoint) or 11311
        if _port_open(host, port, timeout=1):
            out['ros_master_reachable'] = True
            try:
                import xmlrpc.client
                proxy = xmlrpc.client.ServerProxy(f'http://{host}:{port}/')
                code, msg, nodes = proxy.getSystemState('/complysphere')
                publishers, subscribers, services = nodes
                out['topic_count']   = len(publishers)
                out['service_count'] = len(services)
                out['nodes'] = list({n for pub in publishers for n in pub[1]})[:20]
            except Exception as e:
                out['ros_probe_error'] = str(e)
        else:
            out['ros_master_reachable'] = False
        return out

    def _probe_grpc(self, endpoint: str, raw_meta: dict) -> dict:
        """Probe gRPC service via reflection or known health protocol"""
        host = self._extract_host(endpoint)
        port = self._extract_port(endpoint) or 443
        out  = {
            'grpc_server': f'{host}:{port}',
            'uses_tls': raw_meta.get('uses_tls', port in (443, 8443)),
            'services': raw_meta.get('services') or [],
        }
        # Check if port is open
        out['reachable'] = _port_open(host, port, timeout=2)
        return out

    def _probe_websocket(self, endpoint: str, raw_meta: dict) -> dict:
        """Probe WebSocket endpoint"""
        out = {
            'uses_tls': endpoint.startswith('wss://'),
            'ws_url': endpoint,
            'protocol_hints': raw_meta.get('subprotocol') or [],
        }
        # Try HTTP upgrade probe
        http_url = endpoint.replace('wss://', 'https://').replace('ws://', 'http://')
        if REQUESTS_AVAILABLE:
            try:
                resp = requests.get(http_url, timeout=self.timeout,
                                    headers={'Upgrade': 'websocket', 'Connection': 'Upgrade'})
                out['http_response_code'] = resp.status_code
                out['server_header'] = resp.headers.get('Server')
            except Exception:
                pass
        return out

    def _probe_graphql(self, endpoint: str, raw_meta: dict) -> dict:
        """Run GraphQL introspection to extract schema info"""
        out = {'uses_tls': endpoint.startswith('https://')}
        if not REQUESTS_AVAILABLE:
            return out

        introspection = {
            "query": "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind}}}"
        }
        try:
            resp = requests.post(endpoint, json=introspection, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                schema = data.get('data', {}).get('__schema', {})
                types = [t['name'] for t in schema.get('types', []) if not t['name'].startswith('__')]
                out['schema_types'] = types[:30]
                out['type_count'] = len(types)
                # Look for AI-related types
                out['ai_types'] = [t for t in types if any(
                    kw in t.lower() for kw in ['model', 'agent', 'predict', 'infer', 'llm', 'chat'])]
        except Exception as e:
            out['introspection_error'] = str(e)
        return out

    def _probe_process(self, endpoint: str, raw_meta: dict) -> dict:
        """Extract metadata from local process info"""
        out = {
            'pid':     raw_meta.get('pid'),
            'cmdline': raw_meta.get('cmdline') or '',
            'process_name': raw_meta.get('name') or '',
        }
        try:
            import psutil
            pid = raw_meta.get('pid')
            if pid:
                proc = psutil.Process(pid)
                out['process_status'] = proc.status()
                out['cpu_percent']    = proc.cpu_percent(interval=0.1)
                out['memory_mb']      = round(proc.memory_info().rss / 1024 / 1024, 1)
                out['open_files']     = len(proc.open_files())
                env_vars = {}
                for k, v in proc.environ().items():
                    if any(s in k.lower() for s in ('model', 'llm', 'ai', 'cuda', 'gpu', 'port')):
                        env_vars[k] = v[:200]
                out['ai_env_vars'] = env_vars
        except Exception:
            pass
        return out

    def _probe_generic(self, endpoint: str, raw_meta: dict) -> dict:
        """Generic HTTP HEAD + text probe fallback"""
        out = {}
        if REQUESTS_AVAILABLE and endpoint.startswith('http'):
            try:
                resp = requests.head(endpoint, timeout=self.timeout, allow_redirects=True)
                out['http_status']  = resp.status_code
                out['server']       = resp.headers.get('server') or resp.headers.get('Server')
                out['content_type'] = resp.headers.get('content-type')
                out['uses_tls']     = endpoint.startswith('https://')
                out['requires_auth'] = resp.status_code in (401, 403)
            except Exception:
                pass
        return out

    # ── Structured field extractors ────────────────────────────────────────

    def _extract_model_family(self, searchable: str) -> Optional[str]:
        for pattern, family in MODEL_FAMILY_PATTERNS:
            if pattern.search(searchable):
                return family
        return None

    def _extract_model_size(self, searchable: str) -> Optional[str]:
        for pattern, template in MODEL_SIZE_PATTERNS:
            m = pattern.search(searchable)
            if m:
                groups = m.groups()
                if len(groups) == 1:
                    size = template.replace('{n}', groups[0])
                elif len(groups) == 2:
                    size = template.replace('{n1}', groups[0]).replace('{n2}', groups[1])
                else:
                    size = m.group(0)
                return size
        return None

    def _extract_capabilities(self, searchable: str) -> List[str]:
        found = []
        sl = searchable.lower()
        for cap, keywords in CAPABILITY_SIGNALS.items():
            if any(kw in sl for kw in keywords):
                found.append(cap)
        return found or None

    def _extract_agent_framework(self, searchable: str) -> Optional[str]:
        for pattern, framework in AGENT_FRAMEWORK_PATTERNS:
            if pattern.search(searchable):
                return framework
        return None

    def _extract_autonomy_level(self, searchable: str) -> Optional[str]:
        sl = searchable.lower()
        for level, signals in AUTONOMY_SIGNALS.items():
            if any(s in sl for s in signals):
                return level
        return None

    def _extract_tool_access(self, searchable: str, probe_result: dict) -> Optional[List[str]]:
        tools = []
        # From MCP capabilities
        caps = probe_result.get('capabilities')
        if isinstance(caps, list):
            tools.extend([str(c.get('name', c)) for c in caps[:20]])
        elif isinstance(caps, dict):
            tools.extend(list(caps.keys())[:20])

        # From GraphQL types
        ai_types = probe_result.get('ai_types', [])
        tools.extend(ai_types[:10])

        # Pattern-based tool detection
        sl = searchable.lower()
        tool_patterns = {
            'web_search': ['search', 'browse', 'web'],
            'code_execution': ['exec', 'sandbox', 'code_run', 'repl'],
            'file_access': ['file', 'filesystem', 'read_file', 'write_file'],
            'database': ['sql', 'query', 'database', 'postgres', 'mysql'],
            'api_calls': ['http', 'rest', 'api', 'webhook'],
            'email': ['email', 'smtp', 'sendgrid'],
            'calendar': ['calendar', 'schedule', 'event'],
        }
        for tool_name, keywords in tool_patterns.items():
            if any(kw in sl for kw in keywords):
                if tool_name not in tools:
                    tools.append(tool_name)

        return tools if tools else None

    def _extract_auth_method(self, searchable: str, probe_result: dict) -> Optional[str]:
        challenge = probe_result.get('auth_challenge', '')
        sl = searchable.lower() + ' ' + challenge.lower()

        if not probe_result.get('requires_auth'):
            return 'none'
        if 'bearer' in sl or 'jwt' in sl or 'oauth' in sl:
            return 'OAuth2/Bearer Token'
        if 'api-key' in sl or 'x-api-key' in sl or 'apikey' in sl:
            return 'API Key'
        if 'basic' in sl:
            return 'HTTP Basic Auth'
        if 'cert' in sl or 'mtls' in sl:
            return 'mTLS Certificate'
        if probe_result.get('requires_auth'):
            return 'Unknown (Auth Required)'
        return None

    def _extract_version_from_text(self, searchable: str) -> Optional[str]:
        patterns = [
            re.compile(r'\bv(\d+\.\d+[\.\d]*)\b'),
            re.compile(r'"version"\s*:\s*"([^"]+)"'),
            re.compile(r'version[:\s]+(\d+\.\d+[\.\d]*)', re.I),
        ]
        for p in patterns:
            m = p.search(searchable)
            if m:
                return m.group(1)
        return None

    # ── Helper methods ─────────────────────────────────────────────────────

    def _build_searchable(self, name, agent_type, endpoint, raw_meta, probe_result) -> str:
        parts = [name, agent_type, endpoint, json.dumps(raw_meta), json.dumps(probe_result)]
        return ' '.join(str(p) for p in parts if p)

    def _base_url(self, endpoint: str) -> str:
        parsed = urllib.parse.urlparse(endpoint)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _extract_host(self, endpoint: str) -> str:
        parsed = urllib.parse.urlparse(endpoint)
        return parsed.hostname or endpoint.split(':')[0] or 'localhost'

    def _extract_port(self, endpoint: str) -> Optional[int]:
        parsed = urllib.parse.urlparse(endpoint)
        if parsed.port:
            return parsed.port
        try:
            parts = endpoint.rsplit(':', 1)
            return int(parts[-1].split('/')[0])
        except Exception:
            return None

    def _map_protocol_to_deployment(self, protocol: str) -> Optional[str]:
        mapping = {
            'docker':     'docker',
            'kubernetes': 'kubernetes',
            'rest_api':   'serverless_or_vm',
            'http':       'serverless_or_vm',
            'https':      'serverless_or_vm',
            'grpc':       'serverless_or_vm',
            'mqtt':       'iot_edge',
            'ros':        'robotic_platform',
            'process':    'bare_metal',
            'mcp':        'model_context_protocol',
            'mcp_protocol': 'model_context_protocol',
        }
        return mapping.get(protocol)

    def _identify_image_runtime(self, image: str) -> Optional[str]:
        image_l = image.lower()
        for keyword, runtime in [
            ('ollama', 'Ollama'), ('vllm', 'vLLM'), ('triton', 'NVIDIA Triton'),
            ('mlflow', 'MLflow'), ('torchserve', 'TorchServe'), ('ray', 'Ray Serve'),
            ('bentoml', 'BentoML'), ('seldon', 'Seldon Core'),
            ('tensorflow', 'TensorFlow Serving'), ('pytorch', 'PyTorch'),
            ('hugging', 'HuggingFace'), ('langchain', 'LangChain'),
            ('ros', 'ROS'), ('clawbot', 'Clawbot'),
        ]:
            if keyword in image_l:
                return runtime
        return None


# ── Module-level helpers ───────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def enrich_agent(agent_data: dict, timeout: int = 5) -> dict:
    """
    Convenience wrapper: instantiate MetadataExtractor, run extraction,
    return merged dict.
    """
    extractor = MetadataExtractor(timeout=timeout)
    return extractor.extract(agent_data)
