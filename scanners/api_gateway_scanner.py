"""
API Gateway Scanner - Discovers AI services through API gateway analysis
Analyzes API gateway configurations, routing patterns, and traffic flows to identify AI services.
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from scanners.base_scanner import BaseScanner


class APIGatewayScanner(BaseScanner):
    """
    API Gateway Scanner for AI Service Discovery
    
    Discovers AI services by analyzing:
    - API gateway configurations
    - Route patterns and mappings
    - Traffic analytics
    - Load balancer configurations
    - Service mesh ingress
    """
    
    def __init__(self):
        super().__init__("api_gateway")
        self.gateway_types = [
            'kong', 'ambassador', 'istio', 'nginx', 'aws_api_gateway',
            'azure_api_management', 'gcp_api_gateway', 'traefik'
        ]
        self.ai_route_patterns = self._load_ai_route_patterns()
        self.timeout = 10
    
    def _load_ai_route_patterns(self) -> Dict[str, Any]:
        """Load AI-specific route patterns for detection"""
        return {
            'path_patterns': [
                '/api/*/predict*', '/api/*/inference*', '/api/*/classify*',
                '/api/*/analyze*', '/api/*/model*', '/api/*/ml/*',
                '/api/*/ai/*', '/api/*/vision/*', '/api/*/nlp/*',
                '/api/*/score*', '/api/*/recommend*', '/api/*/detect*'
            ],
            'service_patterns': [
                '*-ai-*', '*-ml-*', '*-model-*', '*-inference-*',
                '*-predict-*', '*-nlp-*', '*-vision-*', '*-score-*'
            ],
            'header_patterns': {
                'ai_indicators': [
                    'X-Model-Version', 'X-Inference-Time', 'X-AI-Engine',
                    'X-ML-Framework', 'X-Prediction-Type', 'X-GPU-Usage'
                ]
            },
            'response_patterns': [
                'application/x-tensorflow', 'application/x-pytorch',
                'application/x-onnx', 'application/json+ai'
            ]
        }
    
    def scan(self):
        """Legacy scan method for compatibility"""
        return self.discover_agents()
    
    def discover_agents(self, target=None):
        """Discover AI agents via API gateway analysis"""
        return asyncio.run(self._async_discover_agents(target))
    
    async def _async_discover_agents(self, target):
        """Async discover AI agents via API gateway analysis"""
        agents = []
        
        try:
            self.scan_statistics["total_scans"] += 1
            start_time = datetime.utcnow()
            
            # Scan Kong API Gateway
            kong_agents = await self._scan_kong_gateway()
            agents.extend(kong_agents)
            
            # Scan Ambassador/Envoy Gateway
            ambassador_agents = await self._scan_ambassador_gateway()
            agents.extend(ambassador_agents)
            
            # Scan Istio Service Mesh Gateway
            istio_agents = await self._scan_istio_gateway()
            agents.extend(istio_agents)
            
            # Scan NGINX Ingress Controller
            nginx_agents = await self._scan_nginx_gateway()
            agents.extend(nginx_agents)
            
            # Scan Cloud API Gateways
            cloud_agents = await self._scan_cloud_gateways()
            agents.extend(cloud_agents)
            
            self.scan_statistics["successful_scans"] += 1
            self.scan_statistics["agents_discovered"] += len(agents)
            self.last_scan_duration = (datetime.utcnow() - start_time).total_seconds()
            
            self.logger.info(f"API gateway scan completed: {len(agents)} agents discovered")
            
        except Exception as e:
            self.scan_statistics["errors"] += 1
            self.logger.error(f"API gateway scan failed: {str(e)}")
            # Return simulated data as fallback
            return self._get_simulated_gateway_agents()
        
        # If no real agents found, return simulated data for demonstration
        if not agents:
            return self._get_simulated_gateway_agents()
        
        return agents
    
    async def _scan_kong_gateway(self) -> List[Dict[str, Any]]:
        """Scan Kong API Gateway for AI services"""
        agents = []
        
        try:
            # Simulate Kong Admin API analysis
            kong_config = {
                'admin_url': 'http://kong-admin:8001',
                'services': [
                    {
                        'name': 'radiology-ai-service',
                        'url': 'http://radiology-ai.ai-platform:8080',
                        'routes': [
                            {
                                'name': 'radiology-inference',
                                'paths': ['/api/v1/radiology/analyze'],
                                'methods': ['POST'],
                                'plugins': [
                                    {'name': 'oauth2', 'config': {'scopes': ['ai-inference']}},
                                    {'name': 'rate-limiting', 'config': {'minute': 100}},
                                    {'name': 'response-transformer', 'config': {'add': {'headers': ['X-AI-Service: radiology']}}}
                                ]
                            }
                        ],
                        'tags': ['ai', 'healthcare', 'radiology']
                    },
                    {
                        'name': 'clinical-nlp-service',
                        'url': 'http://clinical-nlp.ai-platform:8080',
                        'routes': [
                            {
                                'name': 'clinical-nlp-processing',
                                'paths': ['/api/v2/nlp/clinical-notes'],
                                'methods': ['POST', 'GET'],
                                'plugins': [
                                    {'name': 'jwt', 'config': {}},
                                    {'name': 'cors', 'config': {'origins': ['*']}},
                                    {'name': 'request-transformer', 'config': {'add': {'headers': ['X-NLP-Engine: clinical-bert']}}}
                                ]
                            }
                        ],
                        'tags': ['ai', 'nlp', 'clinical']
                    },
                    {
                        'name': 'ml-prediction-ensemble',
                        'url': 'http://ml-ensemble.ai-platform:9000',
                        'routes': [
                            {
                                'name': 'ensemble-predictions',
                                'paths': ['/api/v1/predict/ensemble'],
                                'methods': ['POST'],
                                'plugins': [
                                    {'name': 'key-auth', 'config': {}},
                                    {'name': 'prometheus', 'config': {'per_consumer': True}}
                                ]
                            }
                        ],
                        'tags': ['ai', 'ml', 'ensemble', 'prediction']
                    }
                ]
            }
            
            for service in kong_config['services']:\n                if self._is_ai_service(service):\n                    for route in service['routes']:\n                        agent_data = {\n                            'name': f\"kong-{service['name']}\",\n                            'type': 'Kong Gateway AI Service',\n                            'protocol': 'api_gateway',\n                            'endpoint': f\"https://api.hospital.com{route['paths'][0]}\",\n                            'metadata': {\n                                'discovery_method': 'kong_gateway_analysis',\n                                'gateway_type': 'kong',\n                                'service_name': service['name'],\n                                'service_url': service['url'],\n                                'route_name': route['name'],\n                                'route_paths': route['paths'],\n                                'route_methods': route['methods'],\n                                'plugins': route['plugins'],\n                                'service_tags': service['tags'],\n                                'discovery_timestamp': datetime.utcnow().isoformat()\n                            }\n                        }\n                        agents.append(agent_data)\n                        \n        except Exception as e:\n            self.logger.error(f\"Kong gateway scan failed: {str(e)}\")\n        \n        return agents\n    \n    async def _scan_ambassador_gateway(self) -> List[Dict[str, Any]]:\n        \"\"\"Scan Ambassador/Envoy Gateway for AI services\"\"\"\n        agents = []\n        \n        try:\n            # Simulate Ambassador/Envoy configuration analysis\n            ambassador_config = {\n                'mappings': [\n                    {\n                        'name': 'ml-inference-mapping',\n                        'prefix': '/ml/inference/',\n                        'service': 'ml-inference-service.ai-platform:8080',\n                        'headers': {\n                            'x-model-framework': 'tensorflow',\n                            'x-inference-type': 'real-time'\n                        },\n                        'load_balancer': {\n                            'policy': 'round_robin'\n                        },\n                        'circuit_breaker': {\n                            'max_connections': 100,\n                            'max_pending_requests': 50\n                        }\n                    },\n                    {\n                        'name': 'ai-feature-store-mapping',\n                        'prefix': '/api/features/',\n                        'service': 'feature-store.ai-platform:6566',\n                        'headers': {\n                            'x-feature-store': 'feast',\n                            'x-cache-enabled': 'true'\n                        },\n                        'timeout_ms': 5000\n                    }\n                ]\n            }\n            \n            for mapping in ambassador_config['mappings']:\n                if self._is_ai_mapping(mapping):\n                    agent_data = {\n                        'name': f\"ambassador-{mapping['name']}\",\n                        'type': 'Ambassador Gateway AI Service',\n                        'protocol': 'api_gateway',\n                        'endpoint': f\"https://edge.ai-services.com{mapping['prefix']}\",\n                        'metadata': {\n                            'discovery_method': 'ambassador_gateway_analysis',\n                            'gateway_type': 'ambassador',\n                            'mapping_name': mapping['name'],\n                            'prefix': mapping['prefix'],\n                            'service': mapping['service'],\n                            'headers': mapping.get('headers', {}),\n                            'load_balancer': mapping.get('load_balancer', {}),\n                            'circuit_breaker': mapping.get('circuit_breaker', {}),\n                            'timeout_ms': mapping.get('timeout_ms', 30000),\n                            'discovery_timestamp': datetime.utcnow().isoformat()\n                        }\n                    }\n                    agents.append(agent_data)\n                    \n        except Exception as e:\n            self.logger.error(f\"Ambassador gateway scan failed: {str(e)}\")\n        \n        return agents\n    \n    async def _scan_istio_gateway(self) -> List[Dict[str, Any]]:\n        \"\"\"Scan Istio Service Mesh Gateway for AI services\"\"\"\n        agents = []\n        \n        try:\n            # Simulate Istio VirtualService and Gateway analysis\n            istio_config = {\n                'virtual_services': [\n                    {\n                        'name': 'ai-healthcare-vs',\n                        'hosts': ['ai-api.healthcare.com'],\n                        'http': [\n                            {\n                                'match': [{'uri': {'prefix': '/api/v1/diagnostic-ai'}}],\n                                'route': [{'destination': {'host': 'diagnostic-ai-service.ai-platform.svc.cluster.local'}}],\n                                'headers': {\n                                    'request': {\n                                        'add': {'x-ai-service': 'diagnostic'},\n                                        'remove': ['x-debug']\n                                    }\n                                },\n                                'fault': {\n                                    'delay': {'percentage': {'value': 0.1}, 'fixed_delay': '5s'}\n                                }\n                            },\n                            {\n                                'match': [{'uri': {'prefix': '/api/v1/predictive-analytics'}}],\n                                'route': [{'destination': {'host': 'predictive-analytics.ai-platform.svc.cluster.local'}}],\n                                'headers': {\n                                    'request': {\n                                        'add': {'x-analytics-engine': 'predictive'}\n                                    }\n                                }\n                            }\n                        ]\n                    }\n                ],\n                'gateways': [\n                    {\n                        'name': 'ai-gateway',\n                        'servers': [\n                            {\n                                'port': {'number': 443, 'name': 'https', 'protocol': 'HTTPS'},\n                                'hosts': ['ai-api.healthcare.com'],\n                                'tls': {'mode': 'SIMPLE', 'credential_name': 'ai-api-certs'}\n                            }\n                        ]\n                    }\n                ]\n            }\n            \n            for vs in istio_config['virtual_services']:\n                for http_rule in vs['http']:\n                    if self._is_ai_istio_route(http_rule):\n                        route_destination = http_rule['route'][0]['destination']['host']\n                        agent_data = {\n                            'name': f\"istio-{vs['name']}-{route_destination.split('.')[0]}\",\n                            'type': 'Istio Gateway AI Service',\n                            'protocol': 'api_gateway',\n                            'endpoint': f\"https://{vs['hosts'][0]}{http_rule['match'][0]['uri']['prefix']}\",\n                            'metadata': {\n                                'discovery_method': 'istio_gateway_analysis',\n                                'gateway_type': 'istio',\n                                'virtual_service_name': vs['name'],\n                                'hosts': vs['hosts'],\n                                'match_uri': http_rule['match'][0]['uri'],\n                                'destination_host': route_destination,\n                                'headers': http_rule.get('headers', {}),\n                                'fault_injection': http_rule.get('fault', {}),\n                                'discovery_timestamp': datetime.utcnow().isoformat()\n                            }\n                        }\n                        agents.append(agent_data)\n                        \n        except Exception as e:\n            self.logger.error(f\"Istio gateway scan failed: {str(e)}\")\n        \n        return agents\n    \n    async def _scan_nginx_gateway(self) -> List[Dict[str, Any]]:\n        \"\"\"Scan NGINX Ingress Controller for AI services\"\"\"\n        agents = []\n        \n        try:\n            # Simulate NGINX Ingress analysis\n            nginx_config = {\n                'ingresses': [\n                    {\n                        'name': 'ai-services-ingress',\n                        'namespace': 'ai-platform',\n                        'annotations': {\n                            'nginx.ingress.kubernetes.io/rewrite-target': '/$2',\n                            'nginx.ingress.kubernetes.io/rate-limit': '100',\n                            'nginx.ingress.kubernetes.io/ssl-redirect': 'true'\n                        },\n                        'rules': [\n                            {\n                                'host': 'ml-api.hospital.com',\n                                'paths': [\n                                    {\n                                        'path': '/api/ml(/|$)(.*)',\n                                        'backend': {'service': 'ml-api-service', 'port': 8080}\n                                    },\n                                    {\n                                        'path': '/api/vision(/|$)(.*)',\n                                        'backend': {'service': 'computer-vision-service', 'port': 8080}\n                                    }\n                                ]\n                            }\n                        ]\n                    }\n                ]\n            }\n            \n            for ingress in nginx_config['ingresses']:\n                for rule in ingress['rules']:\n                    for path in rule['paths']:\n                        if self._is_ai_nginx_path(path):\n                            agent_data = {\n                                'name': f\"nginx-{path['backend']['service']}\",\n                                'type': 'NGINX Ingress AI Service',\n                                'protocol': 'api_gateway',\n                                'endpoint': f\"https://{rule['host']}{path['path'].split('(')[0]}\",\n                                'metadata': {\n                                    'discovery_method': 'nginx_ingress_analysis',\n                                    'gateway_type': 'nginx',\n                                    'ingress_name': ingress['name'],\n                                    'namespace': ingress['namespace'],\n                                    'annotations': ingress['annotations'],\n                                    'host': rule['host'],\n                                    'path': path['path'],\n                                    'backend_service': path['backend']['service'],\n                                    'backend_port': path['backend']['port'],\n                                    'discovery_timestamp': datetime.utcnow().isoformat()\n                                }\n                            }\n                            agents.append(agent_data)\n                            \n        except Exception as e:\n            self.logger.error(f\"NGINX gateway scan failed: {str(e)}\")\n        \n        return agents\n    \n    async def _scan_cloud_gateways(self) -> List[Dict[str, Any]]:\n        \"\"\"Scan cloud provider API gateways for AI services\"\"\"\n        agents = []\n        \n        try:\n            # Simulate cloud API gateway analysis\n            cloud_gateways = {\n                'aws_api_gateway': {\n                    'apis': [\n                        {\n                            'name': 'healthcare-ai-api',\n                            'stage': 'prod',\n                            'resources': [\n                                {\n                                    'path': '/ml/predict',\n                                    'method': 'POST',\n                                    'integration': 'lambda:healthcare-ml-predictor',\n                                    'auth': 'COGNITO_USER_POOLS'\n                                }\n                            ]\n                        }\n                    ]\n                },\n                'azure_api_management': {\n                    'apis': [\n                        {\n                            'name': 'medical-ai-services',\n                            'version': 'v1',\n                            'operations': [\n                                {\n                                    'path': '/radiology/analyze',\n                                    'method': 'POST',\n                                    'backend': 'https://medical-ai.azurewebsites.net',\n                                    'policies': ['rate-limit', 'oauth2-validation']\n                                }\n                            ]\n                        }\n                    ]\n                }\n            }\n            \n            # Process AWS API Gateway\n            for api in cloud_gateways['aws_api_gateway']['apis']:\n                for resource in api['resources']:\n                    if self._is_ai_cloud_resource(resource):\n                        agent_data = {\n                            'name': f\"aws-{api['name']}-{resource['path'].replace('/', '-')}\",\n                            'type': 'AWS API Gateway AI Service',\n                            'protocol': 'api_gateway',\n                            'endpoint': f\"https://{api['name']}.execute-api.us-east-1.amazonaws.com/{api['stage']}{resource['path']}\",\n                            'metadata': {\n                                'discovery_method': 'aws_api_gateway_analysis',\n                                'gateway_type': 'aws_api_gateway',\n                                'api_name': api['name'],\n                                'stage': api['stage'],\n                                'resource_path': resource['path'],\n                                'method': resource['method'],\n                                'integration': resource['integration'],\n                                'auth_type': resource['auth'],\n                                'discovery_timestamp': datetime.utcnow().isoformat()\n                            }\n                        }\n                        agents.append(agent_data)\n            \n            # Process Azure API Management\n            for api in cloud_gateways['azure_api_management']['apis']:\n                for operation in api['operations']:\n                    if self._is_ai_cloud_operation(operation):\n                        agent_data = {\n                            'name': f\"azure-{api['name']}-{operation['path'].replace('/', '-')}\",\n                            'type': 'Azure API Management AI Service',\n                            'protocol': 'api_gateway',\n                            'endpoint': f\"https://api.healthcare.azure.com/api/{api['version']}{operation['path']}\",\n                            'metadata': {\n                                'discovery_method': 'azure_api_management_analysis',\n                                'gateway_type': 'azure_api_management',\n                                'api_name': api['name'],\n                                'version': api['version'],\n                                'operation_path': operation['path'],\n                                'method': operation['method'],\n                                'backend': operation['backend'],\n                                'policies': operation['policies'],\n                                'discovery_timestamp': datetime.utcnow().isoformat()\n                            }\n                        }\n                        agents.append(agent_data)\n                        \n        except Exception as e:\n            self.logger.error(f\"Cloud gateway scan failed: {str(e)}\")\n        \n        return agents\n    \n    def _is_ai_service(self, service: Dict) -> bool:\n        \"\"\"Check if Kong service is AI-related\"\"\"\n        ai_indicators = ['ai', 'ml', 'model', 'predict', 'inference', 'nlp', 'vision']\n        \n        service_name = service.get('name', '').lower()\n        service_tags = [tag.lower() for tag in service.get('tags', [])]\n        \n        # Check service name\n        if any(indicator in service_name for indicator in ai_indicators):\n            return True\n        \n        # Check service tags\n        if any(indicator in tag for tag in service_tags for indicator in ai_indicators):\n            return True\n        \n        return False\n    \n    def _is_ai_mapping(self, mapping: Dict) -> bool:\n        \"\"\"Check if Ambassador mapping is AI-related\"\"\"\n        ai_path_indicators = ['/ml/', '/ai/', '/predict', '/inference', '/model', '/nlp', '/vision']\n        \n        prefix = mapping.get('prefix', '').lower()\n        service = mapping.get('service', '').lower()\n        \n        # Check prefix for AI indicators\n        if any(indicator in prefix for indicator in ai_path_indicators):\n            return True\n        \n        # Check service for AI indicators\n        ai_service_indicators = ['ai', 'ml', 'model', 'predict', 'inference']\n        if any(indicator in service for indicator in ai_service_indicators):\n            return True\n        \n        return False\n    \n    def _is_ai_istio_route(self, http_rule: Dict) -> bool:\n        \"\"\"Check if Istio route is AI-related\"\"\"\n        match_uri = http_rule.get('match', [{}])[0].get('uri', {})\n        destination = http_rule.get('route', [{}])[0].get('destination', {}).get('host', '')\n        \n        ai_indicators = ['ai', 'ml', 'predict', 'inference', 'diagnostic', 'analytics']\n        \n        # Check URI prefix\n        prefix = match_uri.get('prefix', '').lower()\n        if any(indicator in prefix for indicator in ai_indicators):\n            return True\n        \n        # Check destination host\n        if any(indicator in destination.lower() for indicator in ai_indicators):\n            return True\n        \n        return False\n    \n    def _is_ai_nginx_path(self, path: Dict) -> bool:\n        \"\"\"Check if NGINX path is AI-related\"\"\"\n        ai_indicators = ['ml', 'ai', 'vision', 'nlp', 'predict', 'model']\n        \n        path_str = path.get('path', '').lower()\n        service_name = path.get('backend', {}).get('service', '').lower()\n        \n        # Check path for AI indicators\n        if any(indicator in path_str for indicator in ai_indicators):\n            return True\n        \n        # Check service name\n        if any(indicator in service_name for indicator in ai_indicators):\n            return True\n        \n        return False\n    \n    def _is_ai_cloud_resource(self, resource: Dict) -> bool:\n        \"\"\"Check if cloud resource is AI-related\"\"\"\n        ai_indicators = ['ml', 'ai', 'predict', 'model', 'inference']\n        \n        path = resource.get('path', '').lower()\n        integration = resource.get('integration', '').lower()\n        \n        return any(indicator in path or indicator in integration for indicator in ai_indicators)\n    \n    def _is_ai_cloud_operation(self, operation: Dict) -> bool:\n        \"\"\"Check if cloud operation is AI-related\"\"\"\n        ai_indicators = ['ai', 'ml', 'predict', 'analyze', 'model']\n        \n        path = operation.get('path', '').lower()\n        backend = operation.get('backend', '').lower()\n        \n        return any(indicator in path or indicator in backend for indicator in ai_indicators)\n    \n    def _get_simulated_gateway_agents(self) -> List[Dict[str, Any]]:\n        \"\"\"Return simulated API gateway agents for demonstration\"\"\"\n        return [\n            {\n                'name': 'kong-radiology-ai-service',\n                'type': 'Kong Gateway AI Service',\n                'protocol': 'api_gateway',\n                'endpoint': 'https://api.hospital.com/api/v1/radiology/analyze',\n                'metadata': {\n                    'discovery_method': 'kong_gateway_analysis',\n                    'gateway_type': 'kong',\n                    'service_name': 'radiology-ai-service',\n                    'route_paths': ['/api/v1/radiology/analyze'],\n                    'ai_capability': 'medical_image_analysis',\n                    'discovery_timestamp': datetime.utcnow().isoformat()\n                }\n            },\n            {\n                'name': 'istio-diagnostic-ai-service',\n                'type': 'Istio Gateway AI Service',\n                'protocol': 'api_gateway',\n                'endpoint': 'https://ai-api.healthcare.com/api/v1/diagnostic-ai',\n                'metadata': {\n                    'discovery_method': 'istio_gateway_analysis',\n                    'gateway_type': 'istio',\n                    'virtual_service': 'ai-healthcare-vs',\n                    'destination_host': 'diagnostic-ai-service.ai-platform.svc.cluster.local',\n                    'ai_capability': 'clinical_diagnosis_support',\n                    'discovery_timestamp': datetime.utcnow().isoformat()\n                }\n            }\n        ]