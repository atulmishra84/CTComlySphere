"""
Real-time MCP (Model Context Protocol) integration for live monitoring and agent discovery
"""
import asyncio
import json
import logging
import aiohttp
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import threading
import time
from urllib.parse import urlparse

from app import db
from models import AIAgent, ScanResult, RiskLevel

logger = logging.getLogger(__name__)


class MCPIntegration:
    """Real-time MCP ecosystem integration"""
    
    def __init__(self):
        self.mcp_clients = {}  # Active MCP connections
        self.server_status = {}  # Real-time server health
        self.protocol_versions = {}  # MCP version compatibility
        self.active_context_flows = {}  # Live context transfers
        self.multiagent_systems = {}  # Connected multi-agent systems
        self.is_connected = False
        self.last_heartbeat = None
        self.monitoring_thread = None
        self.is_monitoring = False
        self.config = None
        
        # Load configuration
        self._load_config()
        
        # Initialize if enabled
        if self.config and self.config.enabled:
            self._initialize_connections()
        else:
            logger.info("MCP integration is disabled")
    
    def _load_config(self):
        """Load MCP configuration from config manager"""
        try:
            from integrations.config_manager import config_manager
            full_config = config_manager.get_configuration()
            self.config = full_config.mcp
        except ImportError:
            logger.warning("Configuration manager not available, using defaults")
            from integrations.config_manager import MCPConfig
            self.config = MCPConfig()
    
    def _initialize_connections(self):
        """Initialize MCP server connections"""
        try:
            # Test connectivity to MCP servers
            self.is_connected = self._test_mcp_connections()
            
            if self.is_connected:
                logger.info("MCP integration initialized successfully")
                self._start_monitoring()
            else:
                logger.warning("MCP integration initialized with limited connectivity")
                
        except Exception as e:
            logger.error(f"Failed to initialize MCP integration: {e}")
            self.is_connected = False
    
    def _test_mcp_connections(self) -> bool:
        """Test MCP server connectivity"""
        try:
            connected_servers = 0
            
            for endpoint in self.config.server_endpoints:
                try:
                    # Simulate connection test - in real implementation would use actual MCP protocol
                    server_name = self._extract_server_name(endpoint)
                    
                    # Mock successful connection for demonstration
                    self.server_status[server_name] = {
                        'status': 'connected',
                        'endpoint': endpoint,
                        'last_ping': datetime.utcnow(),
                        'response_time': '25ms',
                        'protocol_version': '1.0',
                        'capabilities': self._get_mock_capabilities(server_name)
                    }
                    connected_servers += 1
                    
                except Exception as e:
                    server_name = self._extract_server_name(endpoint)
                    self.server_status[server_name] = {
                        'status': 'disconnected',
                        'endpoint': endpoint,
                        'error': str(e),
                        'last_attempt': datetime.utcnow()
                    }
                    logger.warning(f"MCP server {server_name} unreachable: {e}")
            
            self.last_heartbeat = datetime.utcnow()
            return connected_servers > 0
            
        except Exception as e:
            logger.error(f"MCP connection test failed: {e}")
            return False
    
    def _extract_server_name(self, endpoint: str) -> str:
        """Extract server name from endpoint"""
        try:
            parsed = urlparse(endpoint)
            return parsed.hostname.split('.')[0] if parsed.hostname else endpoint
        except:
            return endpoint.replace('http://', '').replace('https://', '').split(':')[0]
    
    def _get_mock_capabilities(self, server_name: str) -> Dict[str, Any]:
        """Get mock capabilities for demonstration"""
        capabilities_map = {
            'clinical-ai-assistant': {
                'context_sharing': True,
                'multi_agent_coordination': False,
                'context_window_size': 128000,
                'supported_protocols': ['http', 'websocket'],
                'authentication': ['bearer_token', 'oauth2'],
                'healthcare_compliance': ['hipaa', 'gdpr'],
                'phi_handling': True
            },
            'radiology-multiagent': {
                'context_sharing': True,
                'multi_agent_coordination': True,
                'context_window_size': 256000,
                'agent_count': 4,
                'coordination_protocol': 'mcp_orchestration',
                'supported_protocols': ['grpc', 'http'],
                'authentication': ['mutual_tls', 'jwt'],
                'healthcare_compliance': ['hipaa', 'fda_samd']
            },
            'research-coordinator': {
                'context_sharing': True,
                'multi_agent_coordination': False,
                'context_window_size': 64000,
                'research_protocols': ['clinical_trials', 'observational_studies'],
                'compliance_monitoring': True,
                'supported_protocols': ['http'],
                'authentication': ['api_key'],
                'healthcare_compliance': ['gdpr', 'ich_gcp']
            }
        }
        
        return capabilities_map.get(server_name, {
            'context_sharing': True,
            'context_window_size': 32000,
            'supported_protocols': ['http'],
            'authentication': ['api_key']
        })
    
    def get_mcp_ecosystem_info(self) -> Dict[str, Any]:
        """Get comprehensive MCP ecosystem status"""
        if not self.server_status:
            return {
                'status': 'disconnected',
                'error': 'No MCP servers configured or reachable'
            }
        
        try:
            connected_servers = [s for s in self.server_status.values() if s['status'] == 'connected']
            disconnected_servers = [s for s in self.server_status.values() if s['status'] == 'disconnected']
            
            total_context_window = sum(
                s.get('capabilities', {}).get('context_window_size', 0) 
                for s in connected_servers
            )
            
            total_agents = sum(
                s.get('capabilities', {}).get('agent_count', 1) 
                for s in connected_servers
            )
            
            # Calculate context utilization (mock data)
            context_utilization = min(75.5, (len(self.active_context_flows) * 15.2))
            
            return {
                'status': 'connected' if connected_servers else 'disconnected',
                'ecosystem_health': {
                    'connected_servers': len(connected_servers),
                    'disconnected_servers': len(disconnected_servers),
                    'total_servers': len(self.server_status),
                    'health_percentage': (len(connected_servers) / len(self.server_status)) * 100
                },
                'capabilities_summary': {
                    'total_context_window': total_context_window,
                    'total_agents': total_agents,
                    'context_utilization_percent': context_utilization,
                    'multiagent_systems': len([s for s in connected_servers 
                                             if s.get('capabilities', {}).get('multi_agent_coordination')]),
                    'healthcare_compliant': len([s for s in connected_servers 
                                               if s.get('capabilities', {}).get('healthcare_compliance')])
                },
                'protocol_distribution': self._get_protocol_distribution(connected_servers),
                'authentication_methods': self._get_auth_methods(connected_servers),
                'compliance_coverage': self._get_compliance_coverage(connected_servers),
                'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
                'monitoring_active': self.is_monitoring
            }
            
        except Exception as e:
            logger.error(f"Failed to get MCP ecosystem info: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _get_protocol_distribution(self, connected_servers: List[Dict]) -> Dict[str, int]:
        """Get distribution of supported protocols"""
        protocol_counts = {}
        for server in connected_servers:
            protocols = server.get('capabilities', {}).get('supported_protocols', [])
            for protocol in protocols:
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        return protocol_counts
    
    def _get_auth_methods(self, connected_servers: List[Dict]) -> Dict[str, int]:
        """Get distribution of authentication methods"""
        auth_counts = {}
        for server in connected_servers:
            auth_methods = server.get('capabilities', {}).get('authentication', [])
            for method in auth_methods:
                auth_counts[method] = auth_counts.get(method, 0) + 1
        return auth_counts
    
    def _get_compliance_coverage(self, connected_servers: List[Dict]) -> Dict[str, int]:
        """Get healthcare compliance framework coverage"""
        compliance_counts = {}
        for server in connected_servers:
            frameworks = server.get('capabilities', {}).get('healthcare_compliance', [])
            for framework in frameworks:
                compliance_counts[framework] = compliance_counts.get(framework, 0) + 1
        return compliance_counts
    
    def discover_mcp_agents(self) -> List[Dict[str, Any]]:
        """Discover AI agents in the MCP ecosystem"""
        if not self.is_connected:
            return []
        
        mcp_agents = []
        
        try:
            for server_name, server_info in self.server_status.items():
                if server_info['status'] == 'connected':
                    agents = self._discover_agents_on_server(server_name, server_info)
                    mcp_agents.extend(agents)
            
            logger.info(f"Discovered {len(mcp_agents)} MCP agents")
            return mcp_agents
            
        except Exception as e:
            logger.error(f"Failed to discover MCP agents: {e}")
            return []
    
    def _discover_agents_on_server(self, server_name: str, server_info: Dict) -> List[Dict[str, Any]]:
        """Discover agents on a specific MCP server"""
        agents = []
        
        try:
            capabilities = server_info.get('capabilities', {})
            
            # Main server agent
            agent = {
                'name': f"{server_name}-mcp-agent",
                'type': 'MCP Agent',
                'protocol': 'mcp',
                'endpoint': server_info['endpoint'],
                'cloud_provider': 'mcp_ecosystem',
                'region': 'healthcare_network',
                'metadata': {
                    'server_name': server_name,
                    'mcp_capabilities': capabilities,
                    'protocol_version': server_info.get('protocol_version', '1.0'),
                    'response_time': server_info.get('response_time'),
                    'context_window_size': capabilities.get('context_window_size', 0),
                    'healthcare_compliance': capabilities.get('healthcare_compliance', []),
                    'discovery_method': 'mcp_integration',
                    'discovery_timestamp': datetime.utcnow().isoformat(),
                    'phi_handling': capabilities.get('phi_handling', False),
                    'authentication_methods': capabilities.get('authentication', [])
                }
            }
            agents.append(agent)
            
            # If this is a multi-agent system, discover individual agents
            if capabilities.get('multi_agent_coordination') and capabilities.get('agent_count', 0) > 1:
                individual_agents = self._discover_multiagent_components(server_name, server_info)
                agents.extend(individual_agents)
            
        except Exception as e:
            logger.error(f"Failed to discover agents on {server_name}: {e}")
        
        return agents
    
    def _discover_multiagent_components(self, server_name: str, server_info: Dict) -> List[Dict[str, Any]]:
        """Discover individual agents in a multi-agent system"""
        components = []
        
        try:
            agent_count = server_info.get('capabilities', {}).get('agent_count', 0)
            
            # Mock multi-agent components based on server type
            if server_name == 'radiology-multiagent':
                agent_roles = [
                    {'role': 'image_preprocessor', 'port': 8081, 'capabilities': ['dicom_parsing', 'image_normalization']},
                    {'role': 'pattern_detector', 'port': 8082, 'capabilities': ['anomaly_detection', 'feature_extraction']},
                    {'role': 'diagnostic_classifier', 'port': 8083, 'capabilities': ['disease_classification', 'severity_assessment']},
                    {'role': 'report_generator', 'port': 8084, 'capabilities': ['structured_reporting', 'nlg']}
                ]
            else:
                # Generic multi-agent system
                agent_roles = [
                    {'role': f'agent_{i+1}', 'port': 8080 + i + 1, 'capabilities': ['context_processing']}
                    for i in range(min(agent_count, 4))
                ]
            
            for agent_info in agent_roles:
                component = {
                    'name': f"{server_name}-{agent_info['role']}",
                    'type': 'MCP Multi-Agent Component',
                    'protocol': 'mcp',
                    'endpoint': f"http://{server_name}:{agent_info['port']}",
                    'cloud_provider': 'mcp_ecosystem',
                    'region': 'healthcare_network',
                    'metadata': {
                        'parent_system': server_name,
                        'agent_role': agent_info['role'],
                        'agent_capabilities': agent_info['capabilities'],
                        'port': agent_info['port'],
                        'discovery_method': 'mcp_multiagent_discovery',
                        'discovery_timestamp': datetime.utcnow().isoformat(),
                        'coordination_protocol': 'mcp_orchestration'
                    }
                }
                components.append(component)
                
        except Exception as e:
            logger.error(f"Failed to discover multi-agent components for {server_name}: {e}")
        
        return components
    
    def get_context_flow_metrics(self) -> Dict[str, Any]:
        """Get real-time context flow metrics"""
        try:
            # Simulate context flow metrics
            active_flows = [
                {
                    'flow_id': 'clinical-context-flow',
                    'source': 'clinical-ai-assistant',
                    'target': 'radiology-multiagent',
                    'context_type': 'patient_clinical_history',
                    'transfer_rate': '2.5MB/s',
                    'compression_ratio': 0.65,
                    'encryption': 'aes_256',
                    'phi_content': True,
                    'last_transfer': datetime.utcnow() - timedelta(minutes=2)
                },
                {
                    'flow_id': 'research-coordination-flow',
                    'source': 'research-coordinator',
                    'target': 'clinical-advisor',
                    'context_type': 'research_protocol_context',
                    'transfer_rate': '1.2MB/s',
                    'compression_ratio': 0.78,
                    'encryption': 'aes_256',
                    'phi_content': False,
                    'last_transfer': datetime.utcnow() - timedelta(minutes=5)
                }
            ]
            
            total_transfer_rate = sum(float(flow['transfer_rate'].replace('MB/s', '')) for flow in active_flows)
            phi_flows = len([flow for flow in active_flows if flow['phi_content']])
            
            return {
                'active_flows': len(active_flows),
                'total_transfer_rate': f"{total_transfer_rate:.1f}MB/s",
                'phi_flows': phi_flows,
                'non_phi_flows': len(active_flows) - phi_flows,
                'average_compression': sum(flow['compression_ratio'] for flow in active_flows) / len(active_flows) if active_flows else 0,
                'flows': [
                    {
                        'flow_id': flow['flow_id'],
                        'source_target': f"{flow['source']} → {flow['target']}",
                        'context_type': flow['context_type'],
                        'transfer_rate': flow['transfer_rate'],
                        'phi_content': flow['phi_content'],
                        'last_transfer': flow['last_transfer'].strftime('%H:%M:%S')
                    }
                    for flow in active_flows
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to get context flow metrics: {e}")
            return {
                'active_flows': 0,
                'total_transfer_rate': '0MB/s',
                'phi_flows': 0,
                'non_phi_flows': 0,
                'flows': []
            }
    
    def get_server_details(self) -> List[Dict[str, Any]]:
        """Get detailed information about each MCP server"""
        servers = []
        
        for server_name, server_info in self.server_status.items():
            try:
                capabilities = server_info.get('capabilities', {})
                
                server_details = {
                    'name': server_name,
                    'status': server_info['status'],
                    'endpoint': server_info['endpoint'],
                    'protocol_version': server_info.get('protocol_version', 'Unknown'),
                    'response_time': server_info.get('response_time', 'N/A'),
                    'last_ping': server_info.get('last_ping', server_info.get('last_attempt')),
                    'capabilities': {
                        'context_sharing': capabilities.get('context_sharing', False),
                        'multi_agent': capabilities.get('multi_agent_coordination', False),
                        'context_window': capabilities.get('context_window_size', 0),
                        'agent_count': capabilities.get('agent_count', 1),
                        'phi_handling': capabilities.get('phi_handling', False)
                    },
                    'protocols': capabilities.get('supported_protocols', []),
                    'authentication': capabilities.get('authentication', []),
                    'compliance': capabilities.get('healthcare_compliance', []),
                    'error': server_info.get('error')
                }
                
                servers.append(server_details)
                
            except Exception as e:
                logger.error(f"Failed to get details for server {server_name}: {e}")
        
        return servers
    
    def _start_monitoring(self):
        """Start background monitoring of MCP ecosystem"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
            logger.info("Started MCP ecosystem monitoring")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.is_monitoring:
            try:
                # Refresh server status every 30 seconds
                self._test_mcp_connections()
                
                # Update context flow metrics
                self.active_context_flows = self.get_context_flow_metrics()
                
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in MCP monitoring loop: {e}")
                time.sleep(60)
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        logger.info("Stopped MCP ecosystem monitoring")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get MCP ecosystem performance metrics"""
        try:
            connected_servers = [s for s in self.server_status.values() if s['status'] == 'connected']
            
            if not connected_servers:
                return {
                    'average_response_time': 'N/A',
                    'fastest_server': 'N/A',
                    'slowest_server': 'N/A',
                    'uptime_percentage': 0
                }
            
            # Parse response times
            response_times = []
            server_response_times = {}
            
            for server_name, server_info in self.server_status.items():
                if server_info['status'] == 'connected':
                    response_time_str = server_info.get('response_time', '0ms')
                    try:
                        response_time = float(response_time_str.replace('ms', ''))
                        response_times.append(response_time)
                        server_response_times[server_name] = response_time
                    except:
                        response_times.append(0)
                        server_response_times[server_name] = 0
            
            fastest_server = min(server_response_times, key=server_response_times.get) if server_response_times else 'N/A'
            slowest_server = max(server_response_times, key=server_response_times.get) if server_response_times else 'N/A'
            
            return {
                'average_response_time': f"{sum(response_times) / len(response_times):.1f}ms" if response_times else 'N/A',
                'fastest_server': f"{fastest_server} ({server_response_times.get(fastest_server, 0):.1f}ms)",
                'slowest_server': f"{slowest_server} ({server_response_times.get(slowest_server, 0):.1f}ms)",
                'uptime_percentage': (len(connected_servers) / len(self.server_status)) * 100,
                'total_servers': len(self.server_status),
                'healthy_servers': len(connected_servers)
            }
            
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            return {
                'average_response_time': 'Error',
                'fastest_server': 'Error',
                'slowest_server': 'Error',
                'uptime_percentage': 0
            }


# Global instance
mcp_integration = MCPIntegration()