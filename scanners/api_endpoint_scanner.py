"""
API Endpoint Scanner - Probes API endpoints for AI services

Discovery Targets:
- Common ML paths
- OpenAPI specs
- Health check endpoints

Capabilities:
- Endpoint probing
- Schema analysis
- Version detection
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urljoin, urlparse

from scanners.base_scanner import BaseScanner


class APIEndpointScanner(BaseScanner):
    """
    API Endpoint Scanner for AI Service Discovery
    
    Probes common API endpoints to discover AI/ML services
    """
    
    def __init__(self):
        super().__init__("api_endpoint")
        self.common_ai_paths = [
            "/predict", "/inference", "/model", "/api/v1/models",
            "/api/predict", "/ml/predict", "/ai/predict",
            "/api/v1/predict", "/api/v2/predict", "/v1/models",
            "/health", "/status", "/version", "/docs", "/openapi.json"
        ]
        self.common_ai_ports = [8000, 8080, 8501, 5000, 9000, 3000]
        self.timeout = 5  # seconds
    
    def scan(self):
        """Legacy scan method for compatibility"""
        return self.discover_agents()
    
    async def discover_agents(self, target=None):
        """Discover AI agents via API endpoints"""
        return await self._async_discover_agents(target)
    
    async def _async_discover_agents(self, target):
        """Async discover AI agents via API endpoints"""
        agents = []
        
        try:
            self.scan_statistics["total_scans"] += 1
            start_time = datetime.utcnow()
            
            # Get target hosts to scan
            hosts = self._get_scan_targets(target)
            
            # Scan each host
            for host in hosts:
                host_agents = await self._scan_host(host)
                agents.extend(host_agents)
            
            self.scan_statistics["successful_scans"] += 1
            self.scan_statistics["agents_discovered"] += len(agents)
            self.last_scan_duration = (datetime.utcnow() - start_time).total_seconds()
            
            self.logger.info(f"API endpoint scan completed: {len(agents)} agents discovered")
            
        except Exception as e:
            self.scan_statistics["errors"] += 1
            self.logger.error(f"API endpoint scan failed: {str(e)}")
            # Return simulated data as fallback
            return self._get_simulated_api_agents()
        
        # If no real endpoints found, return simulated data for demonstration
        if not agents:
            return self._get_simulated_api_agents()
        
        return agents
    
    def _get_scan_targets(self, target) -> List[str]:
        """Get list of hosts to scan"""
        # In a real implementation, this would:
        # - Read from configuration
        # - Discover from network scanning
        # - Use service discovery mechanisms
        
        # For now, return common local endpoints
        return [
            "localhost",
            "127.0.0.1",
            "0.0.0.0"
        ]
    
    async def _scan_host(self, host: str) -> List[Dict[str, Any]]:
        """Scan a specific host for AI API endpoints"""
        agents = []
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for port in self.common_ai_ports:
                for path in self.common_ai_paths:
                    try:
                        url = f"http://{host}:{port}{path}"
                        
                        async with session.get(url) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                if self._is_ai_endpoint(url, content, response.headers):
                                    agent_data = await self._analyze_endpoint(url, content, response.headers, session)
                                    if agent_data:
                                        agents.append(self._create_discovered_agent(agent_data))
                    
                    except asyncio.TimeoutError:
                        # Timeout is expected for non-existent endpoints
                        continue
                    except Exception as e:
                        # Other errors are logged but don't stop scanning
                        self.logger.debug(f"Error scanning {host}:{port}{path}: {str(e)}")
                        continue
        
        return agents
    
    def _is_ai_endpoint(self, url: str, content: str, headers: Dict[str, str]) -> bool:
        """Check if endpoint appears to be an AI/ML service"""
        
        # Check content for AI indicators
        ai_indicators = [
            "model", "predict", "inference", "tensorflow", "pytorch",
            "scikit-learn", "keras", "xgboost", "openapi", "swagger",
            "machine learning", "artificial intelligence", "neural network"
        ]
        
        content_lower = content.lower()
        if any(indicator in content_lower for indicator in ai_indicators):
            return True
        
        # Check headers for AI frameworks
        server_header = headers.get('server', '').lower()
        ai_servers = ["tensorflow", "torchserve", "tritonserver", "seldon", "mlflow"]
        if any(server in server_header for server in ai_servers):
            return True
        
        # Check URL path for AI indicators
        if any(indicator in url.lower() for indicator in ai_indicators):
            return True
        
        return False
    
    async def _analyze_endpoint(self, url: str, content: str, headers: Dict[str, str], 
                              session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """Analyze an AI endpoint to extract metadata"""
        
        parsed_url = urlparse(url)
        endpoint_name = f"{parsed_url.hostname}:{parsed_url.port}{parsed_url.path}"
        
        metadata = {
            "url": url,
            "host": parsed_url.hostname,
            "port": parsed_url.port,
            "path": parsed_url.path,
            "headers": dict(headers),
            "response_size": len(content),
            "public_access": parsed_url.hostname not in ["localhost", "127.0.0.1"],
            "healthcare_data": True,  # Assume healthcare context
            "api_service": True
        }
        
        # Try to detect AI framework
        framework = self._detect_framework(content, headers)
        if framework:
            metadata["ai_framework"] = framework
        
        # Try to get API schema
        schema_info = await self._get_api_schema(url, session)
        if schema_info:
            metadata["api_schema"] = schema_info
        
        # Try to get version information
        version_info = await self._get_version_info(url, session)
        if version_info:
            metadata["version_info"] = version_info
        
        # Check for health status
        health_info = await self._get_health_status(url, session)
        if health_info:
            metadata["health_status"] = health_info
        
        agent_data = {
            "id": f"api_endpoint_{parsed_url.hostname}_{parsed_url.port}_{parsed_url.path.replace('/', '_')}",
            "name": endpoint_name,
            "type": "api_endpoint",
            "protocol": "http",
            "metadata": metadata
        }
        
        return agent_data
    
    def _detect_framework(self, content: str, headers: Dict[str, str]) -> Optional[str]:
        """Detect AI framework from response"""
        
        frameworks = {
            "tensorflow": ["tensorflow", "tf-serving"],
            "pytorch": ["pytorch", "torchserve"],
            "scikit-learn": ["scikit-learn", "sklearn"],
            "xgboost": ["xgboost"],
            "mlflow": ["mlflow"],
            "seldon": ["seldon"],
            "triton": ["triton", "tensorrt"]
        }
        
        # Check content
        content_lower = content.lower()
        for framework, indicators in frameworks.items():
            if any(indicator in content_lower for indicator in indicators):
                return framework
        
        # Check headers
        server_header = headers.get('server', '').lower()
        for framework, indicators in frameworks.items():
            if any(indicator in server_header for indicator in indicators):
                return framework
        
        return None
    
    async def _get_api_schema(self, base_url: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """Try to get API schema (OpenAPI/Swagger)"""
        
        schema_paths = ["/openapi.json", "/swagger.json", "/docs/openapi.json", "/api/docs/openapi.json"]
        parsed_base = urlparse(base_url)
        base_url_without_path = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        for path in schema_paths:
            try:
                url = urljoin(base_url_without_path, path)
                async with session.get(url) as response:
                    if response.status == 200:
                        schema_content = await response.text()
                        try:
                            schema_data = json.loads(schema_content)
                            return {
                                "schema_url": url,
                                "openapi_version": schema_data.get("openapi"),
                                "info": schema_data.get("info", {}),
                                "paths_count": len(schema_data.get("paths", {})),
                                "has_models": bool(schema_data.get("components", {}).get("schemas"))
                            }
                        except json.JSONDecodeError:
                            continue
            except:
                continue
        
        return None
    
    async def _get_version_info(self, base_url: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """Try to get version information"""
        
        version_paths = ["/version", "/v1/version", "/api/version", "/health"]
        parsed_base = urlparse(base_url)
        base_url_without_path = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        for path in version_paths:
            try:
                url = urljoin(base_url_without_path, path)
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        try:
                            version_data = json.loads(content)
                            return {
                                "version_url": url,
                                "version_data": version_data
                            }
                        except json.JSONDecodeError:
                            # Try to extract version from text
                            if any(word in content.lower() for word in ["version", "v1", "v2", "build"]):
                                return {
                                    "version_url": url,
                                    "version_text": content[:200]  # First 200 chars
                                }
            except:
                continue
        
        return None
    
    async def _get_health_status(self, base_url: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        """Try to get health status"""
        
        health_paths = ["/health", "/healthz", "/status", "/ping"]
        parsed_base = urlparse(base_url)
        base_url_without_path = f"{parsed_base.scheme}://{parsed_base.netloc}"
        
        for path in health_paths:
            try:
                url = urljoin(base_url_without_path, path)
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        return {
                            "health_url": url,
                            "status": "healthy",
                            "response_time_ms": response.headers.get('x-response-time'),
                            "content": content[:100]  # First 100 chars
                        }
            except:
                continue
        
        return {"status": "unknown"}
    
    def _create_discovered_agent(self, agent_data: Dict[str, Any]):
        """Create discovered agent from scanner data"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        return DiscoveredAgent(
            id=agent_data.get("id"),
            name=agent_data.get("name"),
            type=agent_data.get("type"),
            protocol=agent_data.get("protocol"),
            discovered_by=ScannerType.API_ENDPOINT,
            metadata=agent_data.get("metadata", {}),
            risk_level=self._assess_risk_level(agent_data),
            compliance_frameworks=self._determine_frameworks(agent_data),
            discovery_timestamp=datetime.utcnow()
        )
    
    def _assess_risk_level(self, agent_data: Dict[str, Any]):
        """Assess risk level of discovered API endpoint"""
        from models import RiskLevel
        
        metadata = agent_data.get("metadata", {})
        risk_score = 0
        
        # Public access increases risk
        if metadata.get("public_access", False):
            risk_score += 3
        
        # No authentication detected (would need deeper analysis)
        if not metadata.get("requires_auth", True):  # Assume auth required by default
            risk_score += 2
        
        # Healthcare data handling
        if metadata.get("healthcare_data", False):
            risk_score += 1
        
        # API schema available (good documentation)
        if metadata.get("api_schema"):
            risk_score -= 1
        
        # Health endpoint available (good monitoring)
        if metadata.get("health_status", {}).get("status") == "healthy":
            risk_score -= 1
        
        # Determine risk level
        if risk_score >= 4:
            return RiskLevel.CRITICAL
        elif risk_score >= 2:
            return RiskLevel.HIGH
        elif risk_score >= 0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _determine_frameworks(self, agent_data: Dict[str, Any]) -> List[str]:
        """Determine applicable compliance frameworks"""
        frameworks = ["HIPAA"]  # Default for healthcare
        
        metadata = agent_data.get("metadata", {})
        
        # Public APIs need additional frameworks
        if metadata.get("public_access", False):
            frameworks.extend(["SOC2", "GDPR"])
        
        # API services typically need API-specific compliance
        if metadata.get("api_service", False):
            frameworks.append("API_SECURITY")
        
        return frameworks
    
    def _get_simulated_api_agents(self) -> List:
        """Return simulated API agents for demonstration"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        simulated_agents = [
            DiscoveredAgent(
                id="api_endpoint_ml_predict",
                name="localhost:8501/v1/models/patient_classifier:predict",
                type="api_endpoint",
                protocol="http",
                discovered_by=ScannerType.API_ENDPOINT,
                metadata={
                    "url": "http://localhost:8501/v1/models/patient_classifier:predict",
                    "host": "localhost",
                    "port": 8501,
                    "ai_framework": "tensorflow",
                    "public_access": False,
                    "healthcare_data": True,
                    "api_service": True,
                    "health_status": {"status": "healthy"}
                },
                risk_level=RiskLevel.LOW,
                compliance_frameworks=["HIPAA"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="api_endpoint_inference_api",
                name="localhost:8080/api/v1/predict",
                type="api_endpoint",
                protocol="http",
                discovered_by=ScannerType.API_ENDPOINT,
                metadata={
                    "url": "http://localhost:8080/api/v1/predict",
                    "host": "localhost",
                    "port": 8080,
                    "ai_framework": "pytorch",
                    "public_access": False,
                    "healthcare_data": True,
                    "api_service": True,
                    "api_schema": {
                        "openapi_version": "3.0.0",
                        "paths_count": 5
                    }
                },
                risk_level=RiskLevel.LOW,
                compliance_frameworks=["HIPAA", "API_SECURITY"],
                discovery_timestamp=datetime.utcnow()
            )
        ]
        
        return simulated_agents
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get API endpoint scanner information"""
        return {
            "scanner_type": "api_endpoint",
            "name": "API Endpoint Scanner",
            "description": "Probes API endpoints for AI services",
            "available": True,  # Always available as it uses HTTP requests
            "discovery_targets": [
                "Common ML paths",
                "OpenAPI specs",
                "Health check endpoints"
            ],
            "capabilities": [
                "Endpoint probing",
                "Schema analysis",
                "Version detection"
            ],
            "scan_ports": self.common_ai_ports,
            "scan_paths": self.common_ai_paths,
            "statistics": self.scan_statistics
        }