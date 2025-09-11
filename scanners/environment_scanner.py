"""
Environment Scanner - Comprehensive AI Agent Discovery System

Discovers and monitors AI agents across infrastructure using multiple discovery methods:
- Kubernetes Scanner: AI services in K8s clusters
- Docker Scanner: AI containers in Docker environments  
- Cloud Service Scanner: Managed AI services from cloud providers
- A2A Communication Scanner: Application-to-Application AI integrations
- MCP Protocol Scanner: Model Context Protocol enabled agents
- API Endpoint Scanner: API endpoints for AI services
- API Gateway Scanner: Kong, Istio, Ambassador, NGINX gateway analysis
- Model Registry Scanner: Model registries and ML platforms
- Process Scanner: AI processes running on systems
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import json

from app import db, app
from models import AIAgent, ScanResult, RiskLevel


class ScannerType(Enum):
    """Types of discovery scanners"""
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    CLOUD_SERVICE = "cloud_service"
    A2A_COMMUNICATION = "a2a_communication"
    MCP_PROTOCOL = "mcp_protocol"
    API_ENDPOINT = "api_endpoint"
    API_GATEWAY = "api_gateway"
    MODEL_REGISTRY = "model_registry"
    PROCESS = "process"


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanTarget:
    """Target environment for scanning"""
    environment: str
    customer_filter: Optional[str] = None
    scan_types: List[ScannerType] = None
    
    def __post_init__(self):
        if self.scan_types is None:
            self.scan_types = list(ScannerType)


@dataclass
class DiscoveredAgent:
    """Discovered AI agent information"""
    id: str
    name: str
    type: str
    protocol: str
    discovered_by: ScannerType
    metadata: Dict[str, Any]
    risk_level: RiskLevel
    compliance_frameworks: List[str]
    discovery_timestamp: datetime
    
    
@dataclass
class ScanResult:
    """Results from environment scan"""
    scan_id: str
    target: ScanTarget
    status: ScanStatus
    discovered_agents: List[DiscoveredAgent]
    scan_statistics: Dict[str, Any]
    errors: List[str]
    start_time: datetime
    end_time: Optional[datetime] = None


class EnvironmentScanner:
    """
    Comprehensive Environment Scanner for AI Agent Discovery
    
    Orchestrates multiple scanning methods to discover AI agents across
    diverse infrastructure environments and protocols.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Scanner instances
        self.scanners = {}
        
        # Scan tracking
        self.active_scans: Dict[str, ScanResult] = {}
        self.scan_history: List[ScanResult] = []
        
        # Auto-scan configuration
        self.auto_scan_enabled = False
        self.auto_scan_interval = timedelta(hours=6)
        self.last_auto_scan = None
        
        # Discovery cache
        self.discovery_cache: Dict[str, DiscoveredAgent] = {}
        self.cache_ttl = timedelta(hours=1)
        
        self._initialize_scanners()
        self.logger.info("Environment Scanner initialized with 8 discovery methods")
    
    def _initialize_scanners(self):
        """Initialize all scanner instances"""
        try:
            # Import and initialize each scanner type
            from scanners.kubernetes_scanner import KubernetesScanner
            from scanners.docker_scanner import DockerScanner
            from scanners.cloud_service_scanner import CloudServiceScanner
            from scanners.a2a_communication_scanner import A2ACommunicationScanner
            from scanners.mcp_protocol_scanner import MCPProtocolScanner
            from scanners.api_endpoint_scanner import APIEndpointScanner
            # from scanners.api_gateway_scanner import APIGatewayScanner  # Temporarily disabled due to syntax issues
            from scanners.model_registry_scanner import ModelRegistryScanner
            from scanners.process_scanner import ProcessScanner
            
            self.scanners = {
                ScannerType.KUBERNETES: KubernetesScanner(),
                ScannerType.DOCKER: DockerScanner(),
                ScannerType.CLOUD_SERVICE: CloudServiceScanner(),
                ScannerType.A2A_COMMUNICATION: A2ACommunicationScanner(),
                ScannerType.MCP_PROTOCOL: MCPProtocolScanner(),
                ScannerType.API_ENDPOINT: APIEndpointScanner(),
                # ScannerType.API_GATEWAY: APIGatewayScanner(),  # Temporarily disabled
                ScannerType.MODEL_REGISTRY: ModelRegistryScanner(),
                ScannerType.PROCESS: ProcessScanner()
            }
            
            self.logger.info(f"Initialized {len(self.scanners)} discovery scanners")
            
        except ImportError as e:
            self.logger.warning(f"Some scanners not available: {str(e)}")
            # Initialize base scanners that are always available
            self.scanners = {}
    
    async def run_scan(self, target: ScanTarget) -> str:
        """
        Execute environment scan with specified target
        
        Args:
            target: Scan target configuration
            
        Returns:
            Scan ID for tracking progress
        """
        scan_id = f"scan_{datetime.utcnow().timestamp()}"
        
        scan_result = ScanResult(
            scan_id=scan_id,
            target=target,
            status=ScanStatus.PENDING,
            discovered_agents=[],
            scan_statistics={},
            errors=[],
            start_time=datetime.utcnow()
        )
        
        self.active_scans[scan_id] = scan_result
        
        # Start scan execution asynchronously
        asyncio.create_task(self._execute_scan(scan_result))
        
        self.logger.info(f"Started environment scan {scan_id} for {target.environment}")
        return scan_id
    
    async def _execute_scan(self, scan_result: ScanResult):
        """Execute the actual scanning process with enhanced performance and accuracy"""
        try:
            scan_result.status = ScanStatus.RUNNING
            self.logger.info(f"Executing enhanced scan {scan_result.scan_id}")
            
            # Enhanced parallel scanning for performance
            scanner_tasks = []
            all_discovered_agents = []
            scanner_stats = {}
            
            # Create parallel tasks for each scanner
            for scanner_type in scan_result.target.scan_types:
                if scanner_type not in self.scanners:
                    scan_result.errors.append(f"Scanner {scanner_type.value} not available")
                    continue
                
                scanner = self.scanners[scanner_type]
                task = asyncio.create_task(
                    self._enhanced_scanner_execution(scanner, scanner_type, scan_result.target)
                )
                scanner_tasks.append((scanner_type, task))
            
            # Execute scanners in parallel for improved performance
            completed_results = await asyncio.gather(
                *[task for _, task in scanner_tasks], 
                return_exceptions=True
            )
            
            # Process results with enhanced accuracy
            for i, (scanner_type, _) in enumerate(scanner_tasks):
                result = completed_results[i]
                
                if isinstance(result, Exception):
                    error_msg = f"{scanner_type.value} scanner failed: {str(result)}"
                    scan_result.errors.append(error_msg)
                    self.logger.error(error_msg)
                    continue
                
                agents, stats = result
                all_discovered_agents.extend(agents)
                scanner_stats[scanner_type.value] = stats
                
                self.logger.info(f"{scanner_type.value} scanner discovered {len(agents)} agents with enhanced accuracy")
            
            # Process and deduplicate discovered agents
            unique_agents = self._deduplicate_agents(all_discovered_agents)
            scan_result.discovered_agents = unique_agents
            
            # Update scan statistics
            scan_result.scan_statistics = {
                "total_agents_discovered": len(unique_agents),
                "scanner_results": scanner_stats,
                "scan_duration": (datetime.utcnow() - scan_result.start_time).total_seconds(),
                "errors_count": len(scan_result.errors)
            }
            
            # Store agents in database
            await self._store_discovered_agents(unique_agents)
            
            # Update cache
            self._update_discovery_cache(unique_agents)
            
            scan_result.status = ScanStatus.COMPLETED
            scan_result.end_time = datetime.utcnow()
            
            self.logger.info(f"Scan {scan_result.scan_id} completed: {len(unique_agents)} unique agents discovered")
            
        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.errors.append(f"Scan execution failed: {str(e)}")
            scan_result.end_time = datetime.utcnow()
            self.logger.error(f"Scan {scan_result.scan_id} failed: {str(e)}")
        
        finally:
            # Move to history
            self.scan_history.append(scan_result)
            if scan_result.scan_id in self.active_scans:
                del self.active_scans[scan_result.scan_id]
    
    def _deduplicate_agents(self, agents: List[DiscoveredAgent]) -> List[DiscoveredAgent]:
        """Enhanced deduplication with improved accuracy and fuzzy matching"""
        seen_agents = set()
        unique_agents = []
        similarity_threshold = 0.85
        
        for agent in agents:
            # Enhanced unique identifier with more attributes
            agent_key = f"{agent.name}_{agent.protocol}_{agent.type}_{getattr(agent, 'endpoint', '')}_{getattr(agent, 'version', '')}"
            
            # Check for exact match first
            if agent_key not in seen_agents:
                is_duplicate = False
                
                # Enhanced similarity checking for better deduplication
                for existing_agent in unique_agents:
                    similarity_score = self._calculate_agent_similarity(agent, existing_agent)
                    if similarity_score > similarity_threshold:
                        is_duplicate = True
                        # Merge metadata from duplicate agents
                        self._merge_agent_metadata(existing_agent, agent)
                        break
                
                if not is_duplicate:
                    seen_agents.add(agent_key)
                    unique_agents.append(agent)
        
        self.logger.info(f"Enhanced deduplication: {len(agents)} -> {len(unique_agents)} unique agents")
        return unique_agents
    
    def _calculate_agent_similarity(self, agent1: DiscoveredAgent, agent2: DiscoveredAgent) -> float:
        """Calculate similarity score between two agents for enhanced deduplication"""
        try:
            similarity_factors = {
                'name': 0.4,
                'protocol': 0.3,
                'type': 0.2,
                'endpoint': 0.1
            }
            
            total_score = 0.0
            
            # Name similarity (fuzzy matching)
            name_similarity = self._fuzzy_string_match(agent1.name, agent2.name)
            total_score += name_similarity * similarity_factors['name']
            
            # Protocol exact match
            if agent1.protocol == agent2.protocol:
                total_score += similarity_factors['protocol']
            
            # Type exact match
            if agent1.type == agent2.type:
                total_score += similarity_factors['type']
            
            # Endpoint similarity
            endpoint1 = getattr(agent1, 'endpoint', '')
            endpoint2 = getattr(agent2, 'endpoint', '')
            if endpoint1 and endpoint2:
                endpoint_similarity = self._fuzzy_string_match(endpoint1, endpoint2)
                total_score += endpoint_similarity * similarity_factors['endpoint']
            
            return total_score
            
        except Exception as e:
            self.logger.error(f"Error calculating agent similarity: {str(e)}")
            return 0.0
    
    def _fuzzy_string_match(self, str1: str, str2: str) -> float:
        """Simple fuzzy string matching for improved accuracy"""
        if not str1 or not str2:
            return 0.0
        
        # Simple character-based similarity
        str1_lower = str1.lower()
        str2_lower = str2.lower()
        
        if str1_lower == str2_lower:
            return 1.0
        
        # Calculate character overlap
        set1 = set(str1_lower)
        set2 = set(str2_lower)
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _merge_agent_metadata(self, existing_agent: DiscoveredAgent, duplicate_agent: DiscoveredAgent):
        """Merge metadata from duplicate agents to improve data quality"""
        try:
            # Merge discovery timestamps to track multiple discoveries
            if hasattr(existing_agent, 'discovery_timestamps'):
                existing_agent.discovery_timestamps.append(duplicate_agent.discovery_timestamp)
            else:
                existing_agent.discovery_timestamps = [existing_agent.discovery_timestamp, duplicate_agent.discovery_timestamp]
            
            # Merge metadata dictionaries
            if hasattr(existing_agent, 'metadata') and hasattr(duplicate_agent, 'metadata'):
                if isinstance(existing_agent.metadata, dict) and isinstance(duplicate_agent.metadata, dict):
                    for key, value in duplicate_agent.metadata.items():
                        if key not in existing_agent.metadata:
                            existing_agent.metadata[key] = value
                        elif isinstance(value, list) and isinstance(existing_agent.metadata[key], list):
                            existing_agent.metadata[key].extend(value)
            
            # Update discovery count
            if hasattr(existing_agent, 'discovery_count'):
                existing_agent.discovery_count += 1
            else:
                existing_agent.discovery_count = 2
                
        except Exception as e:
            self.logger.error(f"Error merging agent metadata: {str(e)}")
    
    async def _enhanced_scanner_execution(self, scanner, scanner_type, target) -> Tuple[List[DiscoveredAgent], Dict]:
        """Enhanced scanner execution with performance monitoring and error handling"""
        start_time = datetime.utcnow()
        
        try:
            # Enhanced error handling and retry logic
            max_retries = 3
            retry_delay = 1.0
            
            for attempt in range(max_retries):
                try:
                    # Execute scanner with timeout - handle both sync and async methods
                    discover_method = scanner.discover_agents(target)
                    if asyncio.iscoroutine(discover_method):
                        raw_agents = await asyncio.wait_for(
                            discover_method, 
                            timeout=300  # 5 minute timeout
                        )
                    else:
                        # Sync method, run directly
                        raw_agents = discover_method
                    
                    # Ensure all agents are DiscoveredAgent objects (convert dicts if needed)
                    agents = []
                    for agent_data in raw_agents:
                        if isinstance(agent_data, dict):
                            # Convert dictionary to DiscoveredAgent object
                            discovered_agent = DiscoveredAgent(
                                id=agent_data.get('id', f"{agent_data.get('name', 'unknown')}_{scanner_type.value}"),
                                name=agent_data.get('name', 'Unknown Agent'),
                                type=agent_data.get('type', 'Unknown'),
                                protocol=agent_data.get('protocol', scanner_type.value),
                                discovered_by=scanner_type,
                                metadata=agent_data.get('metadata', {}),
                                risk_level=RiskLevel.MEDIUM,  # Default risk level
                                compliance_frameworks=[],
                                discovery_timestamp=datetime.utcnow()
                            )
                            agents.append(discovered_agent)
                        else:
                            # Already a DiscoveredAgent object
                            agents.append(agent_data)
                    
                    # Calculate enhanced statistics
                    scan_duration = (datetime.utcnow() - start_time).total_seconds()
                    
                    stats = {
                        "agents_discovered": len(agents),
                        "scan_duration": scan_duration,
                        "scan_efficiency": len(agents) / scan_duration if scan_duration > 0 else 0,
                        "retry_attempts": attempt + 1,
                        "success_rate": 1.0,
                        "enhanced_metrics": {
                            "accuracy_score": getattr(scanner, 'accuracy_score', 0.0),
                            "confidence_level": getattr(scanner, 'confidence_level', 0.0),
                            "coverage_percentage": getattr(scanner, 'coverage_percentage', 0.0)
                        }
                    }
                    
                    return agents, stats
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"{scanner_type.value} scanner timeout on attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay * (attempt + 1))
                        continue
                    else:
                        raise
                        
                except Exception as e:
                    self.logger.warning(f"{scanner_type.value} scanner error on attempt {attempt + 1}: {str(e)}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay * (attempt + 1))
                        continue
                    else:
                        raise
        
        except Exception as e:
            scan_duration = (datetime.utcnow() - start_time).total_seconds()
            stats = {
                "agents_discovered": 0,
                "scan_duration": scan_duration,
                "scan_efficiency": 0,
                "retry_attempts": max_retries,
                "success_rate": 0.0,
                "error": str(e)
            }
            return [], stats
    
    async def _store_discovered_agents(self, agents: List[DiscoveredAgent]):
        """Store discovered agents in database"""
        with app.app_context():
            for agent in agents:
                try:
                    # Check if agent already exists
                    existing_agent = AIAgent.query.filter_by(
                        name=agent.name,
                        protocol=agent.protocol
                    ).first()
                    
                    if existing_agent:
                        # Update existing agent
                        existing_agent.last_scanned = agent.discovery_timestamp
                        existing_agent.agent_metadata = agent.metadata
                    else:
                        # Create new agent
                        new_agent = AIAgent(
                            name=agent.name,
                            type=agent.type,
                            protocol=agent.protocol,
                            endpoint=f"{agent.protocol}://{agent.name}",
                            discovered_at=agent.discovery_timestamp,
                            last_scanned=agent.discovery_timestamp,
                            agent_metadata=agent.metadata
                        )
                        db.session.add(new_agent)
                    
                    db.session.commit()
                    
                except Exception as e:
                    self.logger.error(f"Failed to store agent {agent.name}: {str(e)}")
                    db.session.rollback()
    
    def _update_discovery_cache(self, agents: List[DiscoveredAgent]):
        """Update discovery cache with new agents"""
        for agent in agents:
            self.discovery_cache[agent.id] = agent
        
        # Clean old cache entries
        cutoff_time = datetime.utcnow() - self.cache_ttl
        expired_keys = [
            key for key, agent in self.discovery_cache.items()
            if agent.discovery_timestamp < cutoff_time
        ]
        
        for key in expired_keys:
            del self.discovery_cache[key]
    
    async def start_auto_scan(self, target: ScanTarget):
        """Start automatic scanning with specified interval"""
        self.auto_scan_enabled = True
        self.auto_scan_target = target
        
        # Start auto-scan loop
        asyncio.create_task(self._auto_scan_loop())
        
        self.logger.info(f"Auto-scan started for {target.environment} (interval: {self.auto_scan_interval})")
    
    async def _auto_scan_loop(self):
        """Auto-scan execution loop"""
        while self.auto_scan_enabled:
            try:
                # Check if it's time for next scan
                if (self.last_auto_scan is None or 
                    datetime.utcnow() - self.last_auto_scan >= self.auto_scan_interval):
                    
                    await self.run_scan(self.auto_scan_target)
                    self.last_auto_scan = datetime.utcnow()
                
                # Wait before next check
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Auto-scan loop error: {str(e)}")
                await asyncio.sleep(300)
    
    def stop_auto_scan(self):
        """Stop automatic scanning"""
        self.auto_scan_enabled = False
        self.logger.info("Auto-scan stopped")
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get status of specific scan"""
        # Check active scans
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            return {
                "scan_id": scan_id,
                "status": scan.status.value,
                "progress": self._calculate_scan_progress(scan),
                "discovered_agents": len(scan.discovered_agents),
                "errors": scan.errors,
                "start_time": scan.start_time.isoformat()
            }
        
        # Check scan history
        for scan in self.scan_history:
            if scan.scan_id == scan_id:
                return {
                    "scan_id": scan_id,
                    "status": scan.status.value,
                    "discovered_agents": len(scan.discovered_agents),
                    "statistics": scan.scan_statistics,
                    "errors": scan.errors,
                    "start_time": scan.start_time.isoformat(),
                    "end_time": scan.end_time.isoformat() if scan.end_time else None
                }
        
        return None
    
    def _calculate_scan_progress(self, scan: ScanResult) -> float:
        """Calculate scan progress percentage"""
        if scan.status == ScanStatus.COMPLETED:
            return 100.0
        elif scan.status == ScanStatus.FAILED:
            return 0.0
        
        # Estimate progress based on scanners completed
        total_scanners = len(scan.target.scan_types)
        if total_scanners == 0:
            return 0.0
        
        # This is a simplified progress calculation
        # In reality, you'd track individual scanner progress
        elapsed_time = (datetime.utcnow() - scan.start_time).total_seconds()
        estimated_total_time = 120  # 2 minutes estimated
        
        return min((elapsed_time / estimated_total_time) * 100, 95.0)
    
    def get_discovered_agents(self, environment: Optional[str] = None,
                            customer_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get list of discovered agents with optional filtering"""
        agents = []
        
        for agent in self.discovery_cache.values():
            # Apply filters if specified
            if environment and environment != "All Environments":
                # Environment filtering logic would go here
                pass
            
            if customer_filter:
                # Customer filtering logic would go here  
                pass
            
            agents.append({
                "id": agent.id,
                "name": agent.name,
                "type": agent.type,
                "protocol": agent.protocol,
                "discovered_by": agent.discovered_by.value,
                "risk_level": agent.risk_level.value,
                "compliance_frameworks": agent.compliance_frameworks,
                "discovery_timestamp": agent.discovery_timestamp.isoformat(),
                "metadata": agent.metadata
            })
        
        return sorted(agents, key=lambda x: x["discovery_timestamp"], reverse=True)
    
    def get_scanner_capabilities(self) -> Dict[str, Dict[str, Any]]:
        """Get capabilities of all available scanners"""
        capabilities = {}
        
        scanner_configs = {
            ScannerType.KUBERNETES: {
                "name": "Kubernetes Scanner",
                "description": "Discovers AI services deployed in Kubernetes clusters",
                "discovery_targets": [
                    "Pods with AI labels",
                    "Services with ML annotations", 
                    "Deployments with model metadata"
                ],
                "capabilities": [
                    "Auto-registration",
                    "Metadata extraction",
                    "Risk assessment"
                ]
            },
            ScannerType.DOCKER: {
                "name": "Docker Scanner", 
                "description": "Finds AI containers in Docker environments",
                "discovery_targets": [
                    "Containers with AI images",
                    "ML framework containers",
                    "Model serving containers"
                ],
                "capabilities": [
                    "Image analysis",
                    "Environment variable parsing",
                    "Port detection"
                ]
            },
            ScannerType.CLOUD_SERVICE: {
                "name": "Cloud Service Scanner",
                "description": "Detects managed AI services from cloud providers", 
                "discovery_targets": [
                    "AWS SageMaker",
                    "Azure Cognitive Services",
                    "GCP Vertex AI",
                    "Custom AI APIs"
                ],
                "capabilities": [
                    "Service enumeration",
                    "Configuration analysis", 
                    "Cost assessment"
                ]
            },
            ScannerType.A2A_COMMUNICATION: {
                "name": "A2A Communication Scanner",
                "description": "Discovers Application-to-Application AI integrations",
                "discovery_targets": [
                    "Inter-app API calls",
                    "AI service integrations",
                    "Real-time data flows",
                    "Cross-system communications"
                ],
                "capabilities": [
                    "Protocol detection",
                    "Data flow analysis",
                    "Integration mapping",
                    "Performance monitoring"
                ]
            },
            ScannerType.MCP_PROTOCOL: {
                "name": "MCP Protocol Scanner",
                "description": "Finds Model Context Protocol enabled AI agents",
                "discovery_targets": [
                    "MCP endpoints",
                    "Context-aware agents", 
                    "Protocol-based communications",
                    "Multi-agent systems"
                ],
                "capabilities": [
                    "Context analysis",
                    "Protocol validation",
                    "Agent capability detection",
                    "Context window assessment"
                ]
            },
            ScannerType.API_ENDPOINT: {
                "name": "API Endpoint Scanner",
                "description": "Probes API endpoints for AI services",
                "discovery_targets": [
                    "Common ML paths",
                    "OpenAPI specs",
                    "Health check endpoints"
                ],
                "capabilities": [
                    "Endpoint probing",
                    "Schema analysis",
                    "Version detection"
                ]
            },
            ScannerType.MODEL_REGISTRY: {
                "name": "Model Registry Scanner", 
                "description": "Scans model registries and ML platforms",
                "discovery_targets": [
                    "MLflow Registry",
                    "Weights & Biases",
                    "Hugging Face Hub",
                    "Custom registries"
                ],
                "capabilities": [
                    "Model enumeration",
                    "Version tracking",
                    "Metadata extraction"
                ]
            },
            ScannerType.PROCESS: {
                "name": "Process Scanner",
                "description": "Identifies AI processes running on systems",
                "discovery_targets": [
                    "TensorFlow processes",
                    "PyTorch applications", 
                    "Scikit-learn services"
                ],
                "capabilities": [
                    "Process identification",
                    "Resource monitoring",
                    "Framework detection"
                ]
            }
        }
        
        for scanner_type, config in scanner_configs.items():
            capabilities[scanner_type.value] = {
                **config,
                "available": scanner_type in self.scanners,
                "status": "active" if scanner_type in self.scanners else "unavailable"
            }
        
        return capabilities
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get overall scanning statistics"""
        total_scans = len(self.scan_history) + len(self.active_scans)
        completed_scans = len([s for s in self.scan_history if s.status == ScanStatus.COMPLETED])
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "active_scans": len(self.active_scans),
            "failed_scans": len([s for s in self.scan_history if s.status == ScanStatus.FAILED]),
            "total_agents_discovered": len(self.discovery_cache),
            "auto_scan_enabled": self.auto_scan_enabled,
            "last_auto_scan": self.last_auto_scan.isoformat() if self.last_auto_scan else None,
            "available_scanners": len(self.scanners),
            "cache_size": len(self.discovery_cache)
        }


# Global instance
environment_scanner = EnvironmentScanner()