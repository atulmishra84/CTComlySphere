from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
import re
from datetime import datetime

class CloudServiceScanner(BaseScanner):
    """Scanner for managed AI services from cloud providers"""
    
    def __init__(self):
        super().__init__()
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.azure_region = os.getenv('AZURE_REGION', 'eastus')
        self.gcp_region = os.getenv('GCP_REGION', 'us-central1')
    
    def scan(self):
        """Scan cloud providers for managed AI services"""
        self.start_scan()
        
        try:
            agents = self.discover_agents()
            results = []
            
            for agent_data in agents:
                agent = self.create_or_update_agent(agent_data)
                scan_result = self.perform_security_scan(agent, agent_data)
                results.append(scan_result)
            
            duration = self.end_scan()
            return {
                'status': 'completed',
                'agents_found': len(agents),
                'scan_duration': duration,
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"Cloud service scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover managed AI services across cloud providers"""
        agents = []
        
        # Discover AWS AI services
        aws_services = self.discover_aws_ai_services()
        agents.extend(aws_services)
        
        # Discover Azure AI services
        azure_services = self.discover_azure_ai_services()
        agents.extend(azure_services)
        
        # Discover GCP AI services
        gcp_services = self.discover_gcp_ai_services()
        agents.extend(gcp_services)
        
        # Discover Custom AI APIs
        custom_apis = self.discover_custom_ai_apis()
        agents.extend(custom_apis)
        
        self.logger.info(f"Discovered {len(agents)} cloud AI services")
        return agents
    
    def discover_aws_ai_services(self):
        """Discover AWS AI/ML services"""
        aws_services = []
        
        # Mock AWS service discovery - in real implementation would use boto3
        mock_aws_services = [
            {
                'service_name': 'medical-imaging-sagemaker',
                'service_type': 'SageMaker',
                'endpoint_name': 'chest-xray-classifier-endpoint',
                'region': 'us-east-1',
                'instance_type': 'ml.g4dn.xlarge',
                'model_name': 'chest-xray-classifier-v2',
                'configuration': {
                    'auto_scaling': True,
                    'min_capacity': 1,
                    'max_capacity': 10,
                    'encryption_at_rest': True,
                    'data_capture': True
                },
                'tags': {
                    'Environment': 'production',
                    'Application': 'healthcare-ai',
                    'DataClassification': 'PHI',
                    'Compliance': 'HIPAA'
                },
                'cost_tracking': {
                    'monthly_cost_estimate': 2340.50,
                    'currency': 'USD'
                }
            },
            {
                'service_name': 'clinical-comprehend-medical',
                'service_type': 'ComprehendMedical',
                'region': 'us-east-1',
                'job_name': 'phi-detection-batch-job',
                'configuration': {
                    'input_data_format': 'ONE_DOC_PER_LINE',
                    'output_data_format': 'ONE_DOC_PER_LINE',
                    'language_code': 'en',
                    'phi_detection': True
                },
                'tags': {
                    'Environment': 'production',
                    'DataType': 'clinical-notes',
                    'PHIProcessing': 'true'
                },
                'cost_tracking': {
                    'monthly_cost_estimate': 1250.00,
                    'currency': 'USD'
                }
            },
            {
                'service_name': 'drug-discovery-bedrock',
                'service_type': 'Bedrock',
                'model_id': 'anthropic.claude-v2',
                'region': 'us-west-2',
                'configuration': {
                    'model_customization': True,
                    'fine_tuning_job': 'drug-interaction-ft-001',
                    'guardrails': {
                        'content_policy': 'STRICT',
                        'word_policy': 'MEDICAL_TERMS',
                        'topic_policy': 'HEALTHCARE'
                    }
                },
                'tags': {
                    'UseCase': 'drug-discovery',
                    'Compliance': 'FDA-ready'
                }
            }
        ]
        
        for service in mock_aws_services:
            agent_data = {
                'name': service['service_name'],
                'type': f"AWS {service['service_type']}",
                'protocol': 'cloud-api',
                'endpoint': self.build_aws_endpoint(service),
                'cloud_provider': 'aws',
                'region': service['region'],
                'metadata': {
                    'service_type': service['service_type'],
                    'configuration': service['configuration'],
                    'tags': service['tags'],
                    'cost_tracking': service.get('cost_tracking', {}),
                    'discovery_method': 'aws-api-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat(),
                    'compliance_tags': self.extract_compliance_info(service['tags'])
                }
            }
            aws_services.append(agent_data)
        
        return aws_services
    
    def discover_azure_ai_services(self):
        """Discover Azure Cognitive Services and AI services"""
        azure_services = []
        
        # Mock Azure service discovery
        mock_azure_services = [
            {
                'resource_name': 'healthcare-vision-cognitive',
                'service_type': 'CognitiveServices',
                'kind': 'ComputerVision',
                'resource_group': 'healthcare-ai-rg',
                'location': 'eastus',
                'sku': {
                    'name': 'S1',
                    'tier': 'Standard'
                },
                'properties': {
                    'custom_subdomain': 'healthcare-vision-api',
                    'public_network_access': 'Disabled',
                    'private_endpoint_connections': ['pe-healthcare-vision'],
                    'encryption': {
                        'key_source': 'Microsoft.CognitiveServices',
                        'customer_managed_key': True
                    }
                },
                'tags': {
                    'Environment': 'production',
                    'Application': 'medical-imaging',
                    'DataClassification': 'sensitive',
                    'Compliance': 'HIPAA,GDPR'
                }
            },
            {
                'resource_name': 'clinical-text-analytics',
                'service_type': 'CognitiveServices',
                'kind': 'TextAnalytics',
                'resource_group': 'nlp-healthcare-rg',
                'location': 'westeurope',
                'sku': {
                    'name': 'S',
                    'tier': 'Standard'
                },
                'properties': {
                    'custom_subdomain': 'clinical-text-api',
                    'capabilities': [
                        'healthcare-entities',
                        'phi-detection',
                        'clinical-trial-matching'
                    ]
                },
                'tags': {
                    'Environment': 'production',
                    'UseCase': 'clinical-nlp',
                    'DataType': 'clinical-notes'
                }
            },
            {
                'resource_name': 'ml-workspace-pharma',
                'service_type': 'MachineLearningServices',
                'kind': 'Workspace',
                'resource_group': 'pharma-ml-rg',
                'location': 'northeurope',
                'properties': {
                    'storage_account': 'pharmamltoragesaccount',
                    'key_vault': 'pharma-ml-kv',
                    'application_insights': 'pharma-ml-insights',
                    'container_registry': 'pharmamlacrregisty.azurecr.io',
                    'compute_instances': [
                        {
                            'name': 'drug-discovery-compute',
                            'vm_size': 'Standard_NC6s_v3',
                            'state': 'Running'
                        }
                    ]
                },
                'tags': {
                    'Project': 'drug-discovery',
                    'Compliance': 'GxP,FDA-21CFR11'
                }
            }
        ]
        
        for service in mock_azure_services:
            agent_data = {
                'name': service['resource_name'],
                'type': f"Azure {service['service_type']}",
                'protocol': 'cloud-api',
                'endpoint': self.build_azure_endpoint(service),
                'cloud_provider': 'azure',
                'region': service['location'],
                'metadata': {
                    'service_type': service['service_type'],
                    'kind': service['kind'],
                    'resource_group': service['resource_group'],
                    'sku': service.get('sku', {}),
                    'properties': service['properties'],
                    'tags': service['tags'],
                    'discovery_method': 'azure-api-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat(),
                    'compliance_tags': self.extract_compliance_info(service['tags'])
                }
            }
            azure_services.append(agent_data)
        
        return azure_services
    
    def discover_gcp_ai_services(self):
        """Discover GCP Vertex AI and AI Platform services"""
        gcp_services = []
        
        # Mock GCP service discovery
        mock_gcp_services = [
            {
                'display_name': 'medical-diagnosis-vertex-ai',
                'service_type': 'VertexAI',
                'project_id': 'healthcare-ai-project',
                'location': 'us-central1',
                'model_display_name': 'medical-diagnosis-model-v3',
                'endpoint_id': '1234567890123456789',
                'deployed_models': [
                    {
                        'id': '8765432109876543210',
                        'display_name': 'medical-diagnosis-v3',
                        'model_version_id': '3',
                        'machine_type': 'n1-standard-4',
                        'min_replica_count': 1,
                        'max_replica_count': 5,
                        'dedicated_resources': {
                            'machine_spec': {
                                'machine_type': 'n1-standard-4',
                                'accelerator_type': 'NVIDIA_TESLA_K80',
                                'accelerator_count': 1
                            }
                        }
                    }
                ],
                'labels': {
                    'environment': 'production',
                    'team': 'healthcare-ai',
                    'model-type': 'diagnosis',
                    'data-classification': 'phi',
                    'compliance': 'hipaa'
                },
                'encryption_spec': {
                    'kms_key_name': 'projects/healthcare-ai-project/locations/us-central1/keyRings/healthcare/cryptoKeys/vertex-ai'
                }
            },
            {
                'display_name': 'healthcare-automl-tables',
                'service_type': 'AutoMLTables',
                'project_id': 'healthcare-ai-project',
                'location': 'us-central1',
                'dataset_id': 'clinical_data_v2',
                'model_id': 'TBL_4567890123456789',
                'prediction_service': {
                    'online_prediction': True,
                    'batch_prediction': True
                },
                'labels': {
                    'environment': 'production',
                    'use-case': 'clinical-prediction',
                    'data-type': 'structured'
                }
            },
            {
                'display_name': 'medical-document-ai',
                'service_type': 'DocumentAI',
                'project_id': 'healthcare-ai-project',
                'location': 'us',
                'processor_type': 'FORM_PARSER_PROCESSOR',
                'processor_version': '1.0.0',
                'capabilities': [
                    'medical-form-extraction',
                    'phi-redaction',
                    'structured-data-extraction'
                ],
                'labels': {
                    'environment': 'production',
                    'document-type': 'medical-forms',
                    'phi-processing': 'true'
                }
            }
        ]
        
        for service in mock_gcp_services:
            agent_data = {
                'name': service['display_name'],
                'type': f"GCP {service['service_type']}",
                'protocol': 'cloud-api',
                'endpoint': self.build_gcp_endpoint(service),
                'cloud_provider': 'gcp',
                'region': service['location'],
                'metadata': {
                    'service_type': service['service_type'],
                    'project_id': service['project_id'],
                    'labels': service.get('labels', {}),
                    'service_config': {k: v for k, v in service.items() 
                                    if k not in ['display_name', 'service_type', 'project_id', 'location', 'labels']},
                    'discovery_method': 'gcp-api-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat(),
                    'compliance_tags': self.extract_compliance_info(service.get('labels', {}))
                }
            }
            gcp_services.append(agent_data)
        
        return gcp_services
    
    def discover_custom_ai_apis(self):
        """Discover custom AI APIs and third-party services"""
        custom_apis = []
        
        # Mock custom API discovery
        mock_custom_apis = [
            {
                'name': 'epic-fhir-ai-insights',
                'provider': 'Epic Systems',
                'api_version': 'R4',
                'base_url': 'https://fhir.epic.com/interconnect-fhir-oauth',
                'capabilities': [
                    'clinical-decision-support',
                    'risk-stratification',
                    'medication-reconciliation'
                ],
                'authentication': 'OAuth2',
                'data_types': ['ehr', 'fhir', 'clinical-notes'],
                'compliance': ['HIPAA', 'HL7-FHIR'],
                'sla': {
                    'availability': '99.9%',
                    'response_time': '< 200ms'
                }
            },
            {
                'name': 'pathology-ai-service',
                'provider': 'PathAI Inc',
                'api_version': 'v2.1',
                'base_url': 'https://api.pathai.com/v2',
                'capabilities': [
                    'pathology-image-analysis',
                    'cancer-detection',
                    'biomarker-identification'
                ],
                'authentication': 'API-Key',
                'data_types': ['histopathology-images', 'slide-annotations'],
                'compliance': ['FDA-510k', 'CE-IVD', 'CLIA'],
                'regulatory_status': 'FDA-cleared'
            }
        ]
        
        for api in mock_custom_apis:
            agent_data = {
                'name': api['name'],
                'type': f"Custom AI API - {api['provider']}",
                'protocol': 'rest-api',
                'endpoint': api['base_url'],
                'cloud_provider': 'third-party',
                'region': 'external',
                'metadata': {
                    'provider': api['provider'],
                    'api_version': api['api_version'],
                    'capabilities': api['capabilities'],
                    'authentication': api['authentication'],
                    'data_types': api['data_types'],
                    'compliance': api['compliance'],
                    'sla': api.get('sla', {}),
                    'regulatory_status': api.get('regulatory_status'),
                    'discovery_method': 'custom-api-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat()
                }
            }
            custom_apis.append(agent_data)
        
        return custom_apis
    
    def build_aws_endpoint(self, service):
        """Build AWS service endpoint URL"""
        service_type = service['service_type'].lower()
        region = service['region']
        
        if service_type == 'sagemaker':
            return f"https://runtime.sagemaker.{region}.amazonaws.com/endpoints/{service.get('endpoint_name', 'unknown')}"
        elif service_type == 'comprehendmedical':
            return f"https://comprehendmedical.{region}.amazonaws.com"
        elif service_type == 'bedrock':
            return f"https://bedrock-runtime.{region}.amazonaws.com/model/{service.get('model_id', 'unknown')}"
        else:
            return f"https://{service_type}.{region}.amazonaws.com"
    
    def build_azure_endpoint(self, service):
        """Build Azure service endpoint URL"""
        properties = service.get('properties', {})
        custom_subdomain = properties.get('custom_subdomain')
        
        if custom_subdomain:
            return f"https://{custom_subdomain}.cognitiveservices.azure.com"
        else:
            return f"https://{service['resource_name']}.cognitiveservices.azure.com"
    
    def build_gcp_endpoint(self, service):
        """Build GCP service endpoint URL"""
        project_id = service['project_id']
        location = service['location']
        service_type = service['service_type'].lower()
        
        if service_type == 'vertexai':
            endpoint_id = service.get('endpoint_id', 'unknown')
            return f"https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/endpoints/{endpoint_id}"
        elif service_type == 'automltables':
            model_id = service.get('model_id', 'unknown')
            return f"https://automl.googleapis.com/v1/projects/{project_id}/locations/{location}/models/{model_id}"
        elif service_type == 'documentai':
            return f"https://{location}-documentai.googleapis.com/v1/projects/{project_id}/locations/{location}/processors"
        else:
            return f"https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}"
    
    def extract_compliance_info(self, tags):
        """Extract compliance information from service tags"""
        compliance_tags = []
        
        for key, value in tags.items():
            if any(compliance_term in key.lower() or compliance_term in str(value).lower() 
                   for compliance_term in ['compliance', 'hipaa', 'gdpr', 'fda', 'sox', 'pci']):
                compliance_tags.append(f"{key}:{value}")
        
        return compliance_tags
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        agent = AIAgent.query.filter_by(
            name=agent_data['name'],
            endpoint=agent_data['endpoint']
        ).first()
        
        if not agent:
            agent = AIAgent(
                name=agent_data['name'],
                type=agent_data['type'],
                protocol=agent_data['protocol'],
                endpoint=agent_data['endpoint'],
                cloud_provider=agent_data['cloud_provider'],
                region=agent_data['region'],
                agent_metadata=agent_data['metadata']
            )
            db.session.add(agent)
        else:
            agent.agent_metadata = agent_data['metadata']
            agent.last_scanned = datetime.utcnow()
        
        db.session.commit()
        return agent
    
    def perform_security_scan(self, agent, agent_data):
        """Perform security scan on cloud AI service"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'unknown'
        
        metadata = agent_data['metadata']
        tags = metadata.get('tags', {}) or metadata.get('labels', {})
        
        # Check for PHI processing
        phi_indicators = ['phi', 'sensitive', 'medical', 'clinical', 'patient']
        for key, value in tags.items():
            if any(indicator in key.lower() or indicator in str(value).lower() 
                   for indicator in phi_indicators):
                phi_exposure = True
                break
        
        # Check encryption
        if 'encryption' in str(metadata).lower():
            encryption_status = 'strong'
        elif phi_exposure:
            vulnerabilities += 2  # PHI without encryption
            
        # Check compliance tags
        compliance_tags = metadata.get('compliance_tags', [])
        if phi_exposure and not compliance_tags:
            vulnerabilities += 1
            
        # Cloud-specific security checks
        cloud_provider = agent_data['cloud_provider']
        if cloud_provider == 'aws':
            vulnerabilities += self.check_aws_security(metadata)
        elif cloud_provider == 'azure':
            vulnerabilities += self.check_azure_security(metadata)
        elif cloud_provider == 'gcp':
            vulnerabilities += self.check_gcp_security(metadata)
        
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='cloud_service_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'cloud_provider': cloud_provider,
                'service_type': metadata.get('service_type'),
                'compliance_tags': compliance_tags,
                'cost_estimate': metadata.get('cost_tracking', {}).get('monthly_cost_estimate', 0)
            },
            recommendations=self.generate_cloud_recommendations(vulnerabilities, phi_exposure, cloud_provider)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def check_aws_security(self, metadata):
        """AWS-specific security checks"""
        vulnerabilities = 0
        config = metadata.get('configuration', {})
        
        if not config.get('encryption_at_rest'):
            vulnerabilities += 1
        if not config.get('data_capture'):
            vulnerabilities += 1
        if config.get('auto_scaling') is False:
            vulnerabilities += 1
            
        return vulnerabilities
    
    def check_azure_security(self, metadata):
        """Azure-specific security checks"""
        vulnerabilities = 0
        properties = metadata.get('properties', {})
        
        if properties.get('public_network_access') != 'Disabled':
            vulnerabilities += 1
        if not properties.get('encryption', {}).get('customer_managed_key'):
            vulnerabilities += 1
        if not properties.get('private_endpoint_connections'):
            vulnerabilities += 1
            
        return vulnerabilities
    
    def check_gcp_security(self, metadata):
        """GCP-specific security checks"""
        vulnerabilities = 0
        
        if not metadata.get('encryption_spec'):
            vulnerabilities += 1
        if metadata.get('service_type') == 'VertexAI':
            deployed_models = metadata.get('service_config', {}).get('deployed_models', [])
            if not deployed_models:
                vulnerabilities += 1
                
        return vulnerabilities
    
    def generate_cloud_recommendations(self, vulnerabilities, phi_exposure, cloud_provider):
        """Generate cloud-specific security recommendations"""
        recommendations = []
        
        if phi_exposure:
            recommendations.append({
                'priority': 'critical',
                'category': 'data_protection',
                'description': f'PHI processing detected in {cloud_provider} service',
                'action': f'Implement {cloud_provider}-native encryption and access controls for PHI data'
            })
        
        if vulnerabilities > 2:
            recommendations.append({
                'priority': 'high',
                'category': 'cloud_security',
                'description': f'Multiple security issues in {cloud_provider} configuration',
                'action': f'Review and implement {cloud_provider} security best practices'
            })
        
        recommendations.append({
            'priority': 'medium',
            'category': 'cost_optimization',
            'description': f'Monitor {cloud_provider} AI service costs',
            'action': 'Implement cost monitoring and alerts for AI service usage'
        })
        
        return recommendations