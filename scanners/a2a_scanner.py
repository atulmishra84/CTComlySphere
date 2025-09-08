from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel, DataFlowMap
import json
import os
import re
from datetime import datetime
import requests

class A2ACommunicationScanner(BaseScanner):
    """Scanner for Application-to-Application AI integrations"""
    
    def __init__(self):
        super().__init__()
        self.timeout = 10
        self.discovery_protocols = ['http', 'https', 'grpc', 'websocket', 'amqp', 'kafka']
    
    def scan(self):
        """Scan for A2A AI communications and integrations"""
        self.start_scan()
        
        try:
            agents = self.discover_agents()
            results = []
            
            # Also discover data flows between agents
            data_flows = self.discover_data_flows()
            
            for agent_data in agents:
                agent = self.create_or_update_agent(agent_data)
                scan_result = self.perform_security_scan(agent, agent_data)
                results.append(scan_result)
            
            duration = self.end_scan()
            return {
                'status': 'completed',
                'agents_found': len(agents),
                'data_flows_found': len(data_flows),
                'scan_duration': duration,
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"A2A communication scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover A2A AI integrations and communications"""
        agents = []
        
        # Discover inter-app API calls
        api_integrations = self.discover_inter_app_api_calls()
        agents.extend(api_integrations)
        
        # Discover AI service integrations
        service_integrations = self.discover_ai_service_integrations()
        agents.extend(service_integrations)
        
        # Discover real-time data flows
        realtime_flows = self.discover_realtime_data_flows()
        agents.extend(realtime_flows)
        
        # Discover cross-system communications
        cross_system_comms = self.discover_cross_system_communications()
        agents.extend(cross_system_comms)
        
        self.logger.info(f"Discovered {len(agents)} A2A AI integrations")
        return agents
    
    def discover_inter_app_api_calls(self):
        """Discover inter-application API calls involving AI"""
        api_integrations = []
        
        # Mock inter-app API discovery
        mock_api_calls = [
            {
                'integration_name': 'ehr-to-ai-diagnosis',
                'source_app': 'Epic EHR System',
                'target_app': 'AI Diagnosis Engine',
                'api_endpoint': 'https://ai-diagnosis.hospital.com/api/v2/diagnose',
                'method': 'POST',
                'data_flow': {
                    'input_data': ['patient_symptoms', 'medical_history', 'lab_results'],
                    'output_data': ['diagnosis_suggestions', 'confidence_scores', 'recommended_tests'],
                    'data_classification': 'PHI',
                    'encryption': 'TLS_1.3'
                },
                'communication_pattern': {
                    'frequency': 'real-time',
                    'volume': '~2000 calls/day',
                    'peak_hours': '08:00-18:00',
                    'authentication': 'OAuth2_mTLS'
                },
                'integration_type': 'synchronous',
                'performance_metrics': {
                    'average_response_time': '850ms',
                    'success_rate': '99.2%',
                    'error_rate': '0.8%'
                }
            },
            {
                'integration_name': 'pharmacy-drug-interaction-check',
                'source_app': 'Pharmacy Management System',
                'target_app': 'Drug Interaction AI',
                'api_endpoint': 'https://drug-ai.pharma.com/api/v1/check-interactions',
                'method': 'POST',
                'data_flow': {
                    'input_data': ['medication_list', 'patient_allergies', 'current_prescriptions'],
                    'output_data': ['interaction_warnings', 'severity_levels', 'alternative_medications'],
                    'data_classification': 'PHI',
                    'encryption': 'TLS_1.2'
                },
                'communication_pattern': {
                    'frequency': 'on-demand',
                    'volume': '~5000 calls/day',
                    'peak_hours': '09:00-17:00',
                    'authentication': 'API_Key_HMAC'
                },
                'integration_type': 'synchronous',
                'performance_metrics': {
                    'average_response_time': '320ms',
                    'success_rate': '99.8%',
                    'error_rate': '0.2%'
                }
            },
            {
                'integration_name': 'radiology-ai-image-analysis',
                'source_app': 'PACS Radiology System',
                'target_app': 'Medical Imaging AI',
                'api_endpoint': 'https://imaging-ai.radiology.com/api/v3/analyze',
                'method': 'POST',
                'data_flow': {
                    'input_data': ['dicom_images', 'study_metadata', 'patient_demographics'],
                    'output_data': ['abnormality_detection', 'region_annotations', 'diagnostic_confidence'],
                    'data_classification': 'PHI',
                    'encryption': 'AES_256_GCM'
                },
                'communication_pattern': {
                    'frequency': 'batch_processing',
                    'volume': '~800 studies/day',
                    'peak_hours': '24/7',
                    'authentication': 'SAML_SSO'
                },
                'integration_type': 'asynchronous',
                'performance_metrics': {
                    'average_response_time': '15.2s',
                    'success_rate': '98.5%',
                    'error_rate': '1.5%'
                }
            }
        ]
        
        for api_call in mock_api_calls:
            agent_data = {
                'name': api_call['integration_name'],
                'type': 'A2A API Integration',
                'protocol': 'rest-api',
                'endpoint': api_call['api_endpoint'],
                'cloud_provider': 'hybrid',
                'region': 'on-premise',
                'metadata': {
                    'source_app': api_call['source_app'],
                    'target_app': api_call['target_app'],
                    'method': api_call['method'],
                    'data_flow': api_call['data_flow'],
                    'communication_pattern': api_call['communication_pattern'],
                    'integration_type': api_call['integration_type'],
                    'performance_metrics': api_call['performance_metrics'],
                    'discovery_method': 'inter-app-api-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat()
                }
            }
            api_integrations.append(agent_data)
        
        return api_integrations
    
    def discover_ai_service_integrations(self):
        """Discover AI service integrations between systems"""
        service_integrations = []
        
        # Mock AI service integration discovery
        mock_integrations = [
            {
                'integration_name': 'clinical-nlp-pipeline',
                'services': [
                    {
                        'name': 'Text Extraction Service',
                        'endpoint': 'https://text-extract.clinic.com/api/extract',
                        'role': 'extractor'
                    },
                    {
                        'name': 'Clinical NER Service',
                        'endpoint': 'https://ner.clinic.com/api/entities',
                        'role': 'processor'
                    },
                    {
                        'name': 'PHI Redaction Service',
                        'endpoint': 'https://phi-redact.clinic.com/api/redact',
                        'role': 'privacy'
                    },
                    {
                        'name': 'Clinical Summary Service',
                        'endpoint': 'https://summary.clinic.com/api/summarize',
                        'role': 'aggregator'
                    }
                ],
                'data_pipeline': {
                    'flow_direction': 'sequential',
                    'data_transformation': 'clinical_notes -> entities -> redacted_text -> summary',
                    'error_handling': 'retry_with_fallback',
                    'monitoring': 'comprehensive'
                },
                'integration_patterns': {
                    'choreography': True,
                    'orchestration': False,
                    'event_driven': True
                }
            },
            {
                'integration_name': 'medical-imaging-workflow',
                'services': [
                    {
                        'name': 'DICOM Preprocessing',
                        'endpoint': 'https://dicom-prep.imaging.com/api/preprocess',
                        'role': 'preprocessor'
                    },
                    {
                        'name': 'AI Anomaly Detection',
                        'endpoint': 'https://anomaly-ai.imaging.com/api/detect',
                        'role': 'analyzer'
                    },
                    {
                        'name': 'Report Generation',
                        'endpoint': 'https://report-gen.imaging.com/api/generate',
                        'role': 'reporter'
                    },
                    {
                        'name': 'Quality Assurance',
                        'endpoint': 'https://qa.imaging.com/api/validate',
                        'role': 'validator'
                    }
                ],
                'data_pipeline': {
                    'flow_direction': 'parallel_sequential',
                    'data_transformation': 'raw_dicom -> processed_images -> analysis_results -> reports',
                    'error_handling': 'circuit_breaker',
                    'monitoring': 'real_time'
                },
                'integration_patterns': {
                    'choreography': False,
                    'orchestration': True,
                    'event_driven': True
                }
            }
        ]
        
        for integration in mock_integrations:
            agent_data = {
                'name': integration['integration_name'],
                'type': 'AI Service Integration Pipeline',
                'protocol': 'multi-service',
                'endpoint': f"pipeline://{integration['integration_name']}",
                'cloud_provider': 'hybrid',
                'region': 'multi-region',
                'metadata': {
                    'services': integration['services'],
                    'data_pipeline': integration['data_pipeline'],
                    'integration_patterns': integration['integration_patterns'],
                    'service_count': len(integration['services']),
                    'discovery_method': 'ai-service-integration-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat()
                }
            }
            service_integrations.append(agent_data)
        
        return service_integrations
    
    def discover_realtime_data_flows(self):
        """Discover real-time data flows involving AI systems"""
        realtime_flows = []
        
        # Mock real-time data flow discovery\n        mock_flows = [\n            {\n                'flow_name': 'icu-monitoring-stream',\n                'source': 'ICU Patient Monitors',\n                'target': 'Real-time Risk Assessment AI',\n                'protocol': 'websocket',\n                'endpoint': 'wss://icu-ai.hospital.com/stream/risk-assessment',\n                'data_characteristics': {\n                    'data_types': ['vitals', 'ecg', 'respiratory_rate', 'blood_pressure'],\n                    'frequency': '1Hz',\n                    'latency_requirement': '< 100ms',\n                    'data_volume': '~50MB/hour per patient'\n                },\n                'ai_processing': {\n                    'model_type': 'lstm_ensemble',\n                    'prediction_window': '30_minutes',\n                    'alert_thresholds': {\n                        'deterioration_risk': 0.7,\n                        'sepsis_risk': 0.8,\n                        'cardiac_event_risk': 0.85\n                    }\n                },\n                'reliability': {\n                    'uptime': '99.99%',\n                    'failover': 'automatic',\n                    'backup_systems': 2\n                }\n            },\n            {\n                'flow_name': 'pharmacy-inventory-optimization',\n                'source': 'Pharmacy Inventory System',\n                'target': 'Demand Prediction AI',\n                'protocol': 'kafka',\n                'endpoint': 'kafka://pharmacy-cluster.hospital.com/inventory-events',\n                'data_characteristics': {\n                    'data_types': ['medication_usage', 'stock_levels', 'expiry_dates', 'supplier_data'],\n                    'frequency': 'event_driven',\n                    'latency_requirement': '< 5s',\n                    'data_volume': '~10GB/day'\n                },\n                'ai_processing': {\n                    'model_type': 'time_series_forecasting',\n                    'prediction_horizon': '30_days',\n                    'optimization_criteria': ['cost_minimization', 'stockout_prevention', 'waste_reduction']\n                },\n                'reliability': {\n                    'uptime': '99.9%',\n                    'failover': 'manual',\n                    'backup_systems': 1\n                }\n            }\n        ]\n        \n        for flow in mock_flows:\n            agent_data = {\n                'name': flow['flow_name'],\n                'type': 'Real-time AI Data Flow',\n                'protocol': flow['protocol'],\n                'endpoint': flow['endpoint'],\n                'cloud_provider': 'hybrid',\n                'region': 'on-premise',\n                'metadata': {\n                    'source': flow['source'],\n                    'target': flow['target'],\n                    'data_characteristics': flow['data_characteristics'],\n                    'ai_processing': flow['ai_processing'],\n                    'reliability': flow['reliability'],\n                    'discovery_method': 'realtime-flow-scan',\n                    'discovery_timestamp': datetime.utcnow().isoformat()\n                }\n            }\n            realtime_flows.append(agent_data)\n        \n        return realtime_flows\n    \n    def discover_cross_system_communications(self):\n        \"\"\"Discover cross-system communications involving AI\"\"\"\n        cross_system_comms = []\n        \n        # Mock cross-system communication discovery\n        mock_comms = [\n            {\n                'communication_name': 'multi-hospital-ai-consortium',\n                'participants': [\n                    {\n                        'system': 'Hospital A - Cancer Center',\n                        'endpoint': 'https://cancer-ai.hospital-a.com/api/consortium',\n                        'role': 'data_contributor',\n                        'ai_models': ['oncology_outcome_predictor', 'treatment_response_model']\n                    },\n                    {\n                        'system': 'Hospital B - Research Institute',\n                        'endpoint': 'https://research-ai.hospital-b.com/api/consortium',\n                        'role': 'model_trainer',\n                        'ai_models': ['federated_learning_coordinator', 'privacy_preserving_aggregator']\n                    },\n                    {\n                        'system': 'Hospital C - Teaching Hospital',\n                        'endpoint': 'https://teaching-ai.hospital-c.com/api/consortium',\n                        'role': 'validation_center',\n                        'ai_models': ['model_validator', 'bias_detector']\n                    }\n                ],\n                'communication_protocol': 'federated_learning',\n                'data_sharing': {\n                    'privacy_technique': 'differential_privacy',\n                    'encryption': 'homomorphic',\n                    'governance': 'blockchain_based'\n                },\n                'coordination': {\n                    'orchestrator': 'Hospital B - Research Institute',\n                    'consensus_mechanism': 'weighted_voting',\n                    'update_frequency': 'weekly'\n                }\n            },\n            {\n                'communication_name': 'regional-health-ai-network',\n                'participants': [\n                    {\n                        'system': 'Regional Health Authority',\n                        'endpoint': 'https://health-authority.region.gov/ai-hub',\n                        'role': 'coordinator',\n                        'ai_models': ['population_health_analytics', 'outbreak_detection']\n                    },\n                    {\n                        'system': 'Public Health Laboratory',\n                        'endpoint': 'https://lab.public-health.region.gov/ai-api',\n                        'role': 'diagnostics_provider',\n                        'ai_models': ['pathogen_identification', 'antimicrobial_resistance_predictor']\n                    },\n                    {\n                        'system': 'Emergency Response System',\n                        'endpoint': 'https://emergency.region.gov/ai-dispatch',\n                        'role': 'response_optimizer',\n                        'ai_models': ['resource_allocation_optimizer', 'emergency_severity_classifier']\n                    }\n                ],\n                'communication_protocol': 'rest_api_mesh',\n                'data_sharing': {\n                    'privacy_technique': 'k_anonymity',\n                    'encryption': 'aes_256',\n                    'governance': 'policy_based_access_control'\n                },\n                'coordination': {\n                    'orchestrator': 'Regional Health Authority',\n                    'consensus_mechanism': 'authority_based',\n                    'update_frequency': 'daily'\n                }\n            }\n        ]\n        \n        for comm in mock_comms:\n            agent_data = {\n                'name': comm['communication_name'],\n                'type': 'Cross-System AI Communication',\n                'protocol': comm['communication_protocol'],\n                'endpoint': f\"network://{comm['communication_name']}\",\n                'cloud_provider': 'multi-cloud',\n                'region': 'multi-region',\n                'metadata': {\n                    'participants': comm['participants'],\n                    'data_sharing': comm['data_sharing'],\n                    'coordination': comm['coordination'],\n                    'participant_count': len(comm['participants']),\n                    'discovery_method': 'cross-system-scan',\n                    'discovery_timestamp': datetime.utcnow().isoformat()\n                }\n            }\n            cross_system_comms.append(agent_data)\n        \n        return cross_system_comms\n    \n    def discover_data_flows(self):\n        \"\"\"Discover and map data flows between AI agents\"\"\"\n        data_flows = []\n        \n        # Mock data flow mapping\n        mock_data_flows = [\n            {\n                'source_agent': 'ehr-to-ai-diagnosis',\n                'destination_agent': 'clinical-decision-support',\n                'data_type': 'diagnostic_recommendations',\n                'flow_volume': 2.5,  # GB per day\n                'encryption_status': 'encrypted',\n                'compliance_status': 'hipaa_compliant'\n            },\n            {\n                'source_agent': 'medical-imaging-ai',\n                'destination_agent': 'radiology-report-generator',\n                'data_type': 'image_analysis_results',\n                'flow_volume': 8.7,  # GB per day\n                'encryption_status': 'encrypted',\n                'compliance_status': 'fda_cleared'\n            }\n        ]\n        \n        for flow_data in mock_data_flows:\n            # Find or create source and destination agents\n            source_agent = AIAgent.query.filter_by(name=flow_data['source_agent']).first()\n            dest_agent = AIAgent.query.filter_by(name=flow_data['destination_agent']).first()\n            \n            if source_agent and dest_agent:\n                data_flow = DataFlowMap(\n                    source_agent_id=source_agent.id,\n                    destination_agent_id=dest_agent.id,\n                    data_type=flow_data['data_type'],\n                    flow_volume=flow_data['flow_volume'],\n                    encryption_status=flow_data['encryption_status'],\n                    compliance_status=flow_data['compliance_status'],\n                    flow_metadata={\n                        'discovered_by': 'a2a_scanner',\n                        'discovery_timestamp': datetime.utcnow().isoformat()\n                    }\n                )\n                db.session.add(data_flow)\n                data_flows.append(data_flow)\n        \n        if data_flows:\n            db.session.commit()\n        \n        return data_flows\n    \n    def create_or_update_agent(self, agent_data):\n        \"\"\"Create or update AI agent in database\"\"\"\n        agent = AIAgent.query.filter_by(\n            name=agent_data['name'],\n            endpoint=agent_data['endpoint']\n        ).first()\n        \n        if not agent:\n            agent = AIAgent(\n                name=agent_data['name'],\n                type=agent_data['type'],\n                protocol=agent_data['protocol'],\n                endpoint=agent_data['endpoint'],\n                cloud_provider=agent_data['cloud_provider'],\n                region=agent_data['region'],\n                agent_metadata=agent_data['metadata']\n            )\n            db.session.add(agent)\n        else:\n            agent.agent_metadata = agent_data['metadata']\n            agent.last_scanned = datetime.utcnow()\n        \n        db.session.commit()\n        return agent\n    \n    def perform_security_scan(self, agent, agent_data):\n        \"\"\"Perform security scan on A2A communication\"\"\"\n        vulnerabilities = 0\n        phi_exposure = False\n        encryption_status = 'unknown'\n        \n        metadata = agent_data['metadata']\n        \n        # Check for PHI in data flows\n        if 'data_flow' in metadata:\n            data_types = metadata['data_flow'].get('input_data', []) + metadata['data_flow'].get('output_data', [])\n            phi_indicators = ['patient', 'medical', 'clinical', 'phi', 'health', 'diagnosis']\n            if any(indicator in ' '.join(data_types).lower() for indicator in phi_indicators):\n                phi_exposure = True\n        \n        # Check encryption\n        if 'data_flow' in metadata and metadata['data_flow'].get('encryption'):\n            encryption = metadata['data_flow']['encryption']\n            if 'TLS_1.3' in encryption or 'AES_256' in encryption:\n                encryption_status = 'strong'\n            elif 'TLS' in encryption:\n                encryption_status = 'moderate'\n            else:\n                encryption_status = 'weak'\n        \n        # Check authentication\n        if 'communication_pattern' in metadata:\n            auth = metadata['communication_pattern'].get('authentication', '')\n            if not auth or 'API_Key' in auth:\n                vulnerabilities += 1\n        \n        # Check performance issues\n        if 'performance_metrics' in metadata:\n            metrics = metadata['performance_metrics']\n            if float(metrics.get('error_rate', '0%').replace('%', '')) > 5.0:\n                vulnerabilities += 1\n            if float(metrics.get('success_rate', '100%').replace('%', '')) < 95.0:\n                vulnerabilities += 1\n        \n        # Check real-time requirements\n        if agent_data['type'] == 'Real-time AI Data Flow':\n            latency_req = metadata.get('data_characteristics', {}).get('latency_requirement', '')\n            if '< 100ms' in latency_req and encryption_status != 'strong':\n                vulnerabilities += 1  # Real-time + PHI needs strong encryption\n        \n        # Calculate risk\n        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)\n        risk_level = self.determine_risk_level(risk_score)\n        \n        # Create scan result\n        scan_result = ScanResult(\n            ai_agent_id=agent.id,\n            scan_type='a2a_communication_security',\n            status='COMPLETED',\n            risk_score=risk_score,\n            risk_level=getattr(RiskLevel, risk_level),\n            vulnerabilities_found=vulnerabilities,\n            phi_exposure_detected=phi_exposure,\n            scan_data={\n                'encryption_status': encryption_status,\n                'integration_type': metadata.get('integration_type'),\n                'communication_protocol': agent_data['protocol'],\n                'performance_metrics': metadata.get('performance_metrics', {}),\n                'data_volume': metadata.get('data_characteristics', {}).get('data_volume', 'unknown')\n            },\n            recommendations=self.generate_a2a_recommendations(vulnerabilities, phi_exposure, agent_data['type'])\n        )\n        \n        db.session.add(scan_result)\n        agent.last_scanned = scan_result.created_at\n        db.session.commit()\n        \n        return scan_result\n    \n    def generate_a2a_recommendations(self, vulnerabilities, phi_exposure, agent_type):\n        \"\"\"Generate A2A communication specific recommendations\"\"\"\n        recommendations = []\n        \n        if phi_exposure:\n            recommendations.append({\n                'priority': 'critical',\n                'category': 'data_protection',\n                'description': 'PHI detected in A2A communication',\n                'action': 'Implement end-to-end encryption and access controls for PHI data flows'\n            })\n        \n        if vulnerabilities > 2:\n            recommendations.append({\n                'priority': 'high',\n                'category': 'integration_security',\n                'description': 'Multiple security issues in A2A integration',\n                'action': 'Review authentication, authorization, and monitoring for all integration points'\n            })\n        \n        if agent_type == 'Real-time AI Data Flow':\n            recommendations.append({\n                'priority': 'medium',\n                'category': 'performance_monitoring',\n                'description': 'Real-time AI system requires continuous monitoring',\n                'action': 'Implement real-time performance monitoring and alerting'\n            })\n        \n        recommendations.append({\n            'priority': 'low',\n            'category': 'integration_mapping',\n            'description': 'Document A2A integration architecture',\n            'action': 'Maintain comprehensive documentation of all AI system integrations'\n        })\n        \n        return recommendations