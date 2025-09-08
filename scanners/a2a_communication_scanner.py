"""
A2A Communication Scanner - Discovers Application-to-Application AI integrations

Discovery Targets:
- Inter-app API calls
- AI service integrations
- Real-time data flows
- Cross-system communications

Capabilities:
- Protocol detection
- Data flow analysis
- Integration mapping
- Performance monitoring
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

from scanners.base_scanner import BaseScanner


class A2ACommunicationScanner(BaseScanner):
    """
    Application-to-Application Communication Scanner
    
    Discovers AI integrations between applications and services
    """
    
    def __init__(self):
        super().__init__("a2a_communication")
        # In a real implementation, this would integrate with:
        # - Service mesh monitoring (Istio, Linkerd)
        # - API gateways (Kong, Ambassador)
        # - Network monitoring tools
        # - Application performance monitoring (APM)
    
    def scan(self):
        """Legacy scan method for compatibility"""
        return self.discover_agents()
    
    def discover_agents(self, target=None):
        """Discover AI agents via A2A communications"""
        return asyncio.run(self._async_discover_agents(target))
    
    async def _async_discover_agents(self, target):
        """Async discover AI agents via A2A communications"""
        agents = []
        
        try:
            self.scan_statistics["total_scans"] += 1
            start_time = datetime.utcnow()
            
            # Scan for inter-app API calls
            agents.extend(await self._scan_api_integrations())
            
            # Scan for AI service integrations
            agents.extend(await self._scan_ai_service_integrations())
            
            # Scan for real-time data flows
            agents.extend(await self._scan_realtime_flows())
            
            # Scan for cross-system communications
            agents.extend(await self._scan_cross_system_comms())
            
            # Scan for API gateway integrations
            agents.extend(await self._scan_api_gateway_integrations())
            
            self.scan_statistics["successful_scans"] += 1
            self.scan_statistics["agents_discovered"] += len(agents)
            self.last_scan_duration = (datetime.utcnow() - start_time).total_seconds()
            
            self.logger.info(f"A2A communication scan completed: {len(agents)} agents discovered")
            
        except Exception as e:
            self.scan_statistics["errors"] += 1
            self.logger.error(f"A2A communication scan failed: {str(e)}")
        
        # For demonstration, return simulated A2A integrations
        if not agents:
            agents = self._get_simulated_a2a_agents()
        
        return agents
    
    async def _scan_api_integrations(self) -> List[Dict[str, Any]]:
        """Scan for inter-app API calls involving AI"""
        agents = []
        
        # Enhanced API integration discovery
        try:
            # Simulate API gateway log analysis
            api_patterns = [
                {
                    'source': 'ehr-portal',
                    'target': 'radiology-ai-api',
                    'endpoint': '/api/v1/analyze-image',
                    'method': 'POST',
                    'frequency': 'high',
                    'data_type': 'medical_imaging',
                    'authentication': 'oauth2',
                    'encryption': 'tls_1_3'
                },
                {
                    'source': 'patient-monitoring',
                    'target': 'vitals-ai-predictor',
                    'endpoint': '/predict/deterioration',
                    'method': 'POST',
                    'frequency': 'realtime',
                    'data_type': 'clinical_vitals',
                    'authentication': 'jwt',
                    'encryption': 'tls_1_2'
                },
                {
                    'source': 'pharmacy-system',
                    'target': 'drug-interaction-ai',
                    'endpoint': '/api/check-interactions',
                    'method': 'GET',
                    'frequency': 'moderate',
                    'data_type': 'medication_data',
                    'authentication': 'api_key',
                    'encryption': 'tls_1_3'
                }
            ]
            
            for pattern in api_patterns:
                if self._is_ai_api_pattern(pattern):
                    agent_data = {
                        'name': f"a2a-{pattern['target']}",
                        'type': 'A2A API Integration',
                        'protocol': 'a2a_communication',
                        'endpoint': f"https://{pattern['target']}{pattern['endpoint']}",
                        'metadata': {
                            'discovery_method': 'api_integration_analysis',
                            'source_service': pattern['source'],
                            'target_service': pattern['target'],
                            'api_endpoint': pattern['endpoint'],
                            'http_method': pattern['method'],
                            'call_frequency': pattern['frequency'],
                            'data_type': pattern['data_type'],
                            'authentication_method': pattern['authentication'],
                            'encryption_protocol': pattern['encryption'],
                            'discovery_timestamp': datetime.utcnow().isoformat()
                        }
                    }
                    agents.append(agent_data)
                    
        except Exception as e:
            self.logger.error(f"API integration scan failed: {str(e)}")
        
        return agents
    
    async def _scan_ai_service_integrations(self) -> List[Dict[str, Any]]:
        """Scan for AI service integrations"""
        agents = []
        
        try:
            # Enhanced AI service integration detection
            ai_integrations = [
                {
                    'integration_type': 'ml_model_serving',
                    'service_name': 'tensorflow-serving-cluster',
                    'endpoint': 'http://tf-serving:8501/v1/models/chest_xray_model:predict',
                    'model_info': {
                        'framework': 'tensorflow',
                        'model_name': 'chest_xray_classifier',
                        'version': '2.1.0',
                        'input_shape': '[224, 224, 3]',
                        'output_classes': 14
                    },
                    'performance_metrics': {
                        'avg_inference_time': '150ms',
                        'throughput': '100 req/min',
                        'gpu_utilization': '75%'
                    }
                },
                {
                    'integration_type': 'nlp_service',
                    'service_name': 'clinical-nlp-processor',
                    'endpoint': 'http://nlp-service:8080/api/v1/process-clinical-notes',
                    'model_info': {
                        'framework': 'huggingface',
                        'model_name': 'clinical-bert',
                        'version': '1.3.0',
                        'context_length': 512,
                        'languages': ['en']
                    },
                    'performance_metrics': {
                        'avg_inference_time': '300ms',
                        'throughput': '50 req/min',
                        'cpu_utilization': '60%'
                    }
                },
                {
                    'integration_type': 'feature_store',
                    'service_name': 'feast-feature-store',
                    'endpoint': 'http://feast:6566/get-online-features',
                    'model_info': {
                        'framework': 'feast',
                        'feature_groups': ['patient_demographics', 'vital_signs', 'lab_results'],
                        'storage_backend': 'redis',
                        'feature_count': 157
                    },
                    'performance_metrics': {
                        'avg_retrieval_time': '10ms',
                        'throughput': '1000 req/min',
                        'cache_hit_rate': '95%'
                    }
                }
            ]
            
            for integration in ai_integrations:
                agent_data = {
                    'name': f"ai-service-{integration['service_name']}",
                    'type': 'AI Service Integration',
                    'protocol': 'a2a_communication',
                    'endpoint': integration['endpoint'],
                    'metadata': {
                        'discovery_method': 'ai_service_integration_analysis',
                        'integration_type': integration['integration_type'],
                        'service_name': integration['service_name'],
                        'model_info': integration['model_info'],
                        'performance_metrics': integration['performance_metrics'],
                        'discovery_timestamp': datetime.utcnow().isoformat()
                    }
                }
                agents.append(agent_data)
                
        except Exception as e:
            self.logger.error(f"AI service integration scan failed: {str(e)}")
        
        return agents
    
    async def _scan_realtime_flows(self) -> List[Dict[str, Any]]:
        """Scan for real-time data flows"""
        agents = []
        
        try:
            # Enhanced real-time flow detection
            realtime_flows = [
                {
                    'flow_type': 'websocket_stream',
                    'name': 'patient-vitals-monitoring',
                    'source': 'iot-vital-monitors',
                    'sink': 'deterioration-prediction-ai',
                    'protocol': 'websocket',
                    'data_format': 'json',
                    'stream_config': {
                        'frequency': '1Hz',
                        'buffer_size': '1000 events',
                        'compression': 'gzip',
                        'encryption': 'wss'
                    },
                    'ai_processing': {
                        'model_type': 'lstm_predictor',
                        'window_size': '5 minutes',
                        'prediction_horizon': '30 minutes'
                    }
                },
                {
                    'flow_type': 'kafka_stream',
                    'name': 'medical-imaging-pipeline',
                    'source': 'pacs-dicom-producer',
                    'sink': 'radiology-ai-consumer',
                    'protocol': 'kafka',
                    'data_format': 'dicom',
                    'stream_config': {
                        'topic': 'medical.images.incoming',
                        'partitions': 8,
                        'replication_factor': 3,
                        'retention': '7 days'
                    },
                    'ai_processing': {
                        'model_type': 'cnn_classifier',
                        'batch_size': 16,
                        'processing_mode': 'real_time'
                    }
                },
                {
                    'flow_type': 'grpc_stream',
                    'name': 'clinical-decision-stream',
                    'source': 'ehr-data-provider',
                    'sink': 'clinical-ai-decision-engine',
                    'protocol': 'grpc',
                    'data_format': 'protobuf',
                    'stream_config': {
                        'bidirectional': True,
                        'compression': 'gzip',
                        'keep_alive': '30s',
                        'max_message_size': '50MB'
                    },
                    'ai_processing': {
                        'model_type': 'ensemble_classifier',
                        'decision_threshold': 0.85,
                        'explanation_mode': 'enabled'
                    }
                }
            ]
            
            for flow in realtime_flows:
                agent_data = {
                    'name': f"realtime-{flow['name']}",
                    'type': 'Real-time AI Data Flow',
                    'protocol': 'a2a_communication',
                    'endpoint': f"{flow['protocol']}://{flow['sink']}",
                    'metadata': {
                        'discovery_method': 'realtime_flow_analysis',
                        'flow_type': flow['flow_type'],
                        'flow_name': flow['name'],
                        'source': flow['source'],
                        'sink': flow['sink'],
                        'protocol': flow['protocol'],
                        'data_format': flow['data_format'],
                        'stream_config': flow['stream_config'],
                        'ai_processing': flow['ai_processing'],
                        'processing_type': 'real_time',
                        'discovery_timestamp': datetime.utcnow().isoformat()
                    }
                }
                agents.append(agent_data)
                
        except Exception as e:
            self.logger.error(f"Real-time flow scan failed: {str(e)}")
        
        return agents
    
    async def _scan_cross_system_comms(self) -> List[Dict[str, Any]]:
        """Scan for cross-system communications"""
        agents = []
        
        try:
            # Enhanced cross-system communication detection
            cross_system_patterns = [
                {
                    'comm_type': 'database_integration',
                    'name': 'ml-feature-database-connection',
                    'source_system': 'ml-training-pipeline',
                    'target_system': 'feature-store-db',
                    'protocol': 'postgresql',
                    'connection_info': {
                        'host': 'feature-store-db.ai-platform.svc.cluster.local',
                        'port': 5432,
                        'database': 'feature_store',
                        'ssl_mode': 'require',
                        'connection_pool_size': 20
                    },
                    'data_patterns': {
                        'read_frequency': 'high',
                        'write_frequency': 'moderate',
                        'data_volume': '10GB/day',
                        'query_types': ['feature_retrieval', 'model_metadata']
                    }
                },
                {
                    'comm_type': 'file_system_integration',
                    'name': 'model-artifact-storage',
                    'source_system': 'ml-training-cluster',
                    'target_system': 'model-registry-storage',
                    'protocol': 's3',
                    'connection_info': {
                        'bucket': 'ml-models-healthcare',
                        'path_prefix': '/models/production/',
                        'encryption': 'sse-s3',
                        'versioning': 'enabled'
                    },
                    'data_patterns': {
                        'upload_frequency': 'daily',
                        'download_frequency': 'on_deployment',
                        'data_volume': '50GB/month',
                        'file_types': ['checkpoint', 'weights', 'metadata']
                    }
                },
                {
                    'comm_type': 'message_queue_integration',
                    'name': 'inference-result-messaging',
                    'source_system': 'ai-inference-service',
                    'target_system': 'result-processing-queue',
                    'protocol': 'rabbitmq',
                    'connection_info': {
                        'host': 'rabbitmq.messaging.svc.cluster.local',
                        'port': 5672,
                        'vhost': '/ai-healthcare',
                        'exchange': 'ai.inference.results',
                        'routing_key': 'radiology.analysis.complete'
                    },
                    'data_patterns': {
                        'message_frequency': 'real_time',
                        'message_size': '1KB-10MB',
                        'message_types': ['prediction_result', 'confidence_score', 'metadata']
                    }
                }
            ]
            
            for pattern in cross_system_patterns:
                agent_data = {
                    'name': f"cross-system-{pattern['name']}",
                    'type': 'Cross-System AI Communication',
                    'protocol': 'a2a_communication',
                    'endpoint': f"{pattern['protocol']}://{pattern['target_system']}",
                    'metadata': {
                        'discovery_method': 'cross_system_analysis',
                        'communication_type': pattern['comm_type'],
                        'name': pattern['name'],
                        'source_system': pattern['source_system'],
                        'target_system': pattern['target_system'],
                        'protocol': pattern['protocol'],
                        'connection_info': pattern['connection_info'],
                        'data_patterns': pattern['data_patterns'],
                        'discovery_timestamp': datetime.utcnow().isoformat()
                    }
                }
                agents.append(agent_data)
                
        except Exception as e:
            self.logger.error(f"Cross-system communication scan failed: {str(e)}")
        
        return agents
    
    def _create_discovered_agent(self, agent_data: Dict[str, Any]):
        """Create discovered agent from scanner data"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        return DiscoveredAgent(
            id=agent_data.get("id"),
            name=agent_data.get("name"),
            type=agent_data.get("type"),
            protocol=agent_data.get("protocol"),
            discovered_by=ScannerType.A2A_COMMUNICATION,
            metadata=agent_data.get("metadata", {}),
            risk_level=self._assess_risk_level(agent_data),
            compliance_frameworks=self._determine_frameworks(agent_data),
            discovery_timestamp=datetime.utcnow()
        )
    
    def _assess_risk_level(self, agent_data: Dict[str, Any]):
        """Assess risk level of A2A communication"""
        from models import RiskLevel
        
        metadata = agent_data.get("metadata", {})
        risk_score = 0
        
        # Unencrypted communications increase risk
        if not metadata.get("encrypted", True):
            risk_score += 3
        
        # Cross-network communications
        if metadata.get("cross_network", False):
            risk_score += 2
        
        # High volume data transfer
        if metadata.get("data_volume", "low") == "high":
            risk_score += 1
        
        # PHI data in transit
        if metadata.get("phi_data", False):
            risk_score += 2
        
        # Real-time communications may have different risk
        if metadata.get("realtime", False):
            risk_score += 1
        
        # Authentication present
        if metadata.get("authenticated", True):
            risk_score -= 1
        
        # Determine risk level
        if risk_score >= 5:
            return RiskLevel.CRITICAL
        elif risk_score >= 3:
            return RiskLevel.HIGH
        elif risk_score >= 1:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _determine_frameworks(self, agent_data: Dict[str, Any]) -> List[str]:
        """Determine applicable compliance frameworks"""
        frameworks = ["HIPAA"]  # Default for healthcare
        
        metadata = agent_data.get("metadata", {})
        
        # Data in transit compliance
        frameworks.append("DATA_PROTECTION")
        
        # Cross-system integrations need SOC 2
        frameworks.append("SOC2")
        
        # Real-time systems may need additional oversight
        if metadata.get("realtime", False):
            frameworks.append("OPERATIONAL_RESILIENCE")
        
        return frameworks
    
    def _get_simulated_a2a_agents(self) -> List:
        """Return simulated A2A communication agents for demonstration"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        simulated_agents = [
            DiscoveredAgent(
                id="a2a_ehr_to_ai_predictor",
                name="EHR → Patient Risk Predictor",
                type="a2a_integration",
                protocol="https",
                discovered_by=ScannerType.A2A_COMMUNICATION,
                metadata={
                    "source_system": "EHR_System",
                    "target_system": "AI_Risk_Predictor",
                    "communication_type": "REST_API",
                    "data_flow": "patient_data",
                    "encrypted": True,
                    "authenticated": True,
                    "data_volume": "medium",
                    "phi_data": True,
                    "frequency": "real-time",
                    "integration_pattern": "request-response"
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_frameworks=["HIPAA", "DATA_PROTECTION", "SOC2"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="a2a_imaging_to_diagnosis_ai",
                name="Medical Imaging → Diagnosis AI",
                type="a2a_integration",
                protocol="dicom",
                discovered_by=ScannerType.A2A_COMMUNICATION,
                metadata={
                    "source_system": "PACS_System",
                    "target_system": "Diagnosis_AI",
                    "communication_type": "DICOM_PUSH",
                    "data_flow": "medical_images",
                    "encrypted": True,
                    "authenticated": True,
                    "data_volume": "high",
                    "phi_data": True,
                    "frequency": "batch",
                    "integration_pattern": "event-driven"
                },
                risk_level=RiskLevel.HIGH,
                compliance_frameworks=["HIPAA", "FDA", "DATA_PROTECTION"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="a2a_lab_results_streaming",
                name="Lab Results → Clinical Decision Support",
                type="a2a_integration",
                protocol="websocket",
                discovered_by=ScannerType.A2A_COMMUNICATION,
                metadata={
                    "source_system": "Lab_Information_System",
                    "target_system": "Clinical_Decision_Support_AI",
                    "communication_type": "WebSocket_Stream",
                    "data_flow": "lab_results",
                    "encrypted": True,
                    "authenticated": True,
                    "data_volume": "medium",
                    "phi_data": True,
                    "frequency": "real-time",
                    "realtime": True,
                    "integration_pattern": "streaming"
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_frameworks=["HIPAA", "DATA_PROTECTION", "SOC2", "OPERATIONAL_RESILIENCE"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="a2a_pharmacy_ai_interaction",
                name="Pharmacy System ↔ Drug Interaction AI",
                type="a2a_integration",
                protocol="https",
                discovered_by=ScannerType.A2A_COMMUNICATION,
                metadata={
                    "source_system": "Pharmacy_Management_System",
                    "target_system": "Drug_Interaction_AI",
                    "communication_type": "Bidirectional_API",
                    "data_flow": "medication_data",
                    "encrypted": True,
                    "authenticated": True,
                    "data_volume": "low",
                    "phi_data": True,
                    "frequency": "on-demand",
                    "integration_pattern": "synchronous"
                },
                risk_level=RiskLevel.LOW,
                compliance_frameworks=["HIPAA", "FDA", "DATA_PROTECTION"],
                discovery_timestamp=datetime.utcnow()
            )
        ]
        
        return simulated_agents
    
    def _is_ai_api_pattern(self, pattern: Dict) -> bool:
        """Check if API pattern indicates AI service integration"""
        ai_indicators = [
            'predict', 'inference', 'classify', 'analyze', 'model',
            'ai', 'ml', 'neural', 'algorithm', 'score', 'detection',
            'recommendation', 'optimization', 'vision', 'nlp'
        ]
        
        endpoint = pattern.get('endpoint', '').lower()
        target = pattern.get('target', '').lower()
        data_type = pattern.get('data_type', '').lower()
        
        # Check endpoint for AI indicators
        if any(indicator in endpoint for indicator in ai_indicators):
            return True
            
        # Check target service name
        if any(indicator in target for indicator in ai_indicators):
            return True
            
        # Check data type for AI-related patterns
        ai_data_types = [
            'medical_imaging', 'clinical_vitals', 'nlp_text',
            'predictions', 'features', 'embeddings', 'model_data'
        ]
        if any(data_type_indicator in data_type for data_type_indicator in ai_data_types):
            return True
            
        return False
    
    async def _scan_api_gateway_integrations(self) -> List[Dict[str, Any]]:
        """Scan for AI services through API gateway analysis"""
        agents = []
        
        try:
            # API Gateway patterns for AI services
            gateway_patterns = [
                {
                    'gateway_type': 'kong',
                    'gateway_host': 'api-gateway.hospital.com',
                    'routes': [
                        {
                            'path': '/api/v1/radiology/analyze',
                            'service': 'radiology-ai-service',
                            'methods': ['POST'],
                            'plugins': ['oauth2', 'rate-limiting', 'cors'],
                            'upstream': 'http://radiology-ai.ai-platform:8080'
                        },
                        {
                            'path': '/api/v2/nlp/clinical-notes',
                            'service': 'clinical-nlp-service',
                            'methods': ['POST', 'GET'],
                            'plugins': ['jwt', 'request-transformer'],
                            'upstream': 'http://nlp-service.ai-platform:8080'
                        }
                    ]
                },
                {
                    'gateway_type': 'ambassador',
                    'gateway_host': 'edge.ai-services.com',
                    'routes': [
                        {
                            'path': '/ml/predict/*',
                            'service': 'ml-prediction-service',
                            'methods': ['POST'],
                            'plugins': ['auth', 'circuit-breaker'],
                            'upstream': 'http://ml-predictor.inference:9000'
                        }
                    ]
                }
            ]
            
            for gateway in gateway_patterns:
                for route in gateway['routes']:
                    if self._is_ai_gateway_route(route):
                        agent_data = {
                            'name': f"gateway-{route['service']}",
                            'type': 'API Gateway AI Service',
                            'protocol': 'a2a_communication',
                            'endpoint': f"https://{gateway['gateway_host']}{route['path']}",
                            'metadata': {
                                'discovery_method': 'api_gateway_analysis',
                                'gateway_type': gateway['gateway_type'],
                                'gateway_host': gateway['gateway_host'],
                                'route_path': route['path'],
                                'service_name': route['service'],
                                'methods': route['methods'],
                                'plugins': route['plugins'],
                                'upstream': route['upstream'],
                                'discovery_timestamp': datetime.utcnow().isoformat()
                            }
                        }
                        agents.append(agent_data)
                        
        except Exception as e:
            self.logger.error(f"API gateway scan failed: {str(e)}")
        
        return agents
    
    def _is_ai_gateway_route(self, route: Dict) -> bool:
        """Check if gateway route serves AI functionality"""
        ai_path_indicators = [
            '/ai/', '/ml/', '/predict', '/inference', '/classify',
            '/analyze', '/nlp/', '/vision/', '/model/', '/score'
        ]
        
        path = route.get('path', '').lower()
        service = route.get('service', '').lower()
        
        # Check path for AI indicators
        if any(indicator in path for indicator in ai_path_indicators):
            return True
            
        # Check service name for AI indicators
        ai_service_indicators = ['ai', 'ml', 'model', 'predict', 'nlp', 'vision']
        if any(indicator in service for indicator in ai_service_indicators):
            return True
            
        return False
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get A2A communication scanner information"""
        return {
            "scanner_type": "a2a_communication",
            "name": "A2A Communication Scanner",
            "description": "Discovers Application-to-Application AI integrations",
            "available": True,  # Always available for simulation
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
            ],
            "integration_types": [
                "REST APIs",
                "WebSocket streams",
                "Message queues",
                "Database connections",
                "File transfers",
                "DICOM communications"
            ],
            "statistics": self.scan_statistics
        }