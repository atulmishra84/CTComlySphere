from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
import re
from datetime import datetime

class KubernetesScanner(BaseScanner):
    """Scanner for Kubernetes-deployed AI agents"""
    
    def __init__(self):
        super().__init__()
        self.namespace = os.getenv('K8S_NAMESPACE', 'default')
        self.cluster_endpoint = os.getenv('K8S_CLUSTER_ENDPOINT', 'https://kubernetes.default.svc')
    
    def scan(self):
        """Scan Kubernetes cluster for AI agents"""
        self.start_scan()
        
        try:
            agents = self.discover_agents()
            results = []
            
            for agent_data in agents:
                # Create or update AI agent
                agent = self.create_or_update_agent(agent_data)
                
                # Perform security scan
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
            self.logger.error(f"Kubernetes scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self, target=None):
        """Discover AI agents in Kubernetes cluster with advanced detection"""
        agents = []
        
        # Discover Pods with AI labels
        ai_pods = self.discover_ai_pods()
        agents.extend(ai_pods)
        
        # Discover Services with ML annotations
        ml_services = self.discover_ml_services()
        agents.extend(ml_services)
        
        # Discover Deployments with model metadata
        model_deployments = self.discover_model_deployments()
        agents.extend(model_deployments)
        
        self.logger.info(f"Discovered {len(agents)} AI agents in Kubernetes cluster")
        return agents
    
    def discover_ai_pods(self):
        """Discover Pods with AI-specific labels and annotations"""
        ai_pods = []
        
        # Mock Pod discovery with AI labels
        mock_pods = [
            {
                'name': 'medical-imaging-ai-pod',
                'namespace': 'ai-healthcare',
                'labels': {
                    'app.kubernetes.io/component': 'ai-inference',
                    'ai.framework': 'tensorflow',
                    'ai.model-type': 'medical-imaging',
                    'healthcare.phi-processing': 'true',
                    'version': 'v2.1.0'
                },
                'annotations': {
                    'ai.model.name': 'chest-xray-classifier',
                    'ai.model.version': '2.1.0',
                    'ai.framework.version': 'tensorflow-2.13',
                    'healthcare.compliance': 'hipaa,fda-510k'
                },
                'containers': [
                    {
                        'name': 'inference-server',
                        'image': 'tensorflow/serving:2.13.0-gpu',
                        'ports': [{'containerPort': 8501, 'name': 'rest-api'}],
                        'resources': {'requests': {'memory': '4Gi', 'cpu': '2', 'nvidia.com/gpu': '1'}}
                    }
                ],
                'environment': {
                    'MODEL_NAME': 'chest_xray_classifier',
                    'MODEL_VERSION': '2',
                    'PHI_PROCESSING_MODE': 'secure',
                    'ENCRYPTION_AT_REST': 'aes-256'
                }
            },
            {
                'name': 'clinical-nlp-processor',
                'namespace': 'ai-healthcare', 
                'labels': {
                    'app.kubernetes.io/component': 'ai-nlp',
                    'ai.framework': 'transformers',
                    'ai.model-type': 'clinical-nlp',
                    'healthcare.data-classification': 'phi'
                },
                'annotations': {
                    'ai.model.name': 'clinical-bert',
                    'ai.model.source': 'huggingface',
                    'ai.input.types': 'clinical-notes,discharge-summaries'
                },
                'containers': [
                    {
                        'name': 'nlp-processor',
                        'image': 'huggingface/transformers:4.21-gpu',
                        'ports': [{'containerPort': 8080, 'name': 'grpc'}]
                    }
                ],
                'environment': {
                    'MODEL_TYPE': 'clinical-bert',
                    'TOKENIZER': 'bert-base-clinical',
                    'PHI_DETECTION': 'enabled'
                }
            }
        ]

        for pod in mock_pods:
            if self.is_ai_pod(pod):
                agent_data = {
                    'name': pod['name'],
                    'type': self.determine_ai_type_from_pod(pod),
                    'protocol': 'kubernetes',
                    'endpoint': self.build_pod_endpoint(pod),
                    'cloud_provider': 'kubernetes',
                    'region': self.get_cluster_region(),
                    'metadata': {
                        'resource_type': 'pod',
                        'namespace': pod['namespace'],
                        'labels': pod['labels'],
                        'annotations': pod.get('annotations', {}),
                        'containers': pod['containers'],
                        'environment': pod.get('environment', {}),
                        'auto_registered': True,
                        'discovery_timestamp': datetime.utcnow().isoformat()
                    }
                }
                ai_pods.append(agent_data)
        
        return ai_pods
    
    def discover_ml_services(self):
        """Discover Services with ML annotations"""
        ml_services = []
        
        # Mock Service discovery with ML annotations
        mock_services = [
            {
                'name': 'model-serving-service',
                'namespace': 'ml-platform',
                'annotations': {
                    'ml.serving.framework': 'tensorflow-serving',
                    'ml.model.registry': 'mlflow',
                    'ml.auto-scaling': 'enabled',
                    'healthcare.compliance.level': 'hipaa-ready'
                },
                'labels': {
                    'app': 'ml-inference',
                    'tier': 'serving'
                },
                'ports': [{'port': 8501, 'protocol': 'TCP', 'name': 'http-api'}],
                'selector': {'app': 'tensorflow-serving'}
            },
            {
                'name': 'ensemble-predictor',
                'namespace': 'ai-ops',
                'annotations': {
                    'ml.ensemble.models': 'xgboost,lightgbm,catboost',
                    'ml.prediction.type': 'classification',
                    'healthcare.data.types': 'ehr,imaging,genomics'
                },
                'labels': {
                    'app': 'ensemble-ai',
                    'model-type': 'ensemble'
                },
                'ports': [{'port': 8080, 'protocol': 'TCP', 'name': 'grpc'}]
            }
        ]
        
        for service in mock_services:
            if self.has_ml_annotations(service):
                agent_data = {
                    'name': service['name'],
                    'type': self.determine_ai_type_from_service(service),
                    'protocol': 'kubernetes',
                    'endpoint': self.build_service_endpoint(service),
                    'cloud_provider': 'kubernetes',
                    'region': self.get_cluster_region(),
                    'metadata': {
                        'resource_type': 'service',
                        'namespace': service['namespace'],
                        'annotations': service.get('annotations', {}),
                        'labels': service['labels'],
                        'ports': service['ports'],
                        'selector': service.get('selector', {}),
                        'discovery_method': 'ml-annotations',
                        'discovery_timestamp': datetime.utcnow().isoformat()
                    }
                }
                ml_services.append(agent_data)
        
        return ml_services
    
    def discover_model_deployments(self):
        """Discover Deployments with model metadata"""
        model_deployments = []
        
        # Mock Deployment discovery with model metadata
        mock_deployments = [
            {
                'name': 'drug-interaction-classifier',
                'namespace': 'pharma-ai',
                'metadata': {
                    'labels': {
                        'app': 'drug-interaction-ai',
                        'model.source': 'custom-trained',
                        'deployment.type': 'canary'
                    },
                    'annotations': {
                        'model.registry.url': 'https://mlflow.company.com/models/drug-interaction/latest',
                        'model.training.dataset': 'fda-approved-drugs-v3',
                        'model.accuracy': '0.94',
                        'model.deployment.strategy': 'blue-green',
                        'healthcare.regulatory.approval': 'fda-cleared'
                    }
                },
                'spec': {
                    'replicas': 3,
                    'template': {
                        'metadata': {
                            'labels': {'app': 'drug-interaction-ai'}
                        },
                        'spec': {
                            'containers': [
                                {
                                    'name': 'model-server',
                                    'image': 'custom-registry/drug-interaction:v1.2.3',
                                    'ports': [{'containerPort': 8000}],
                                    'env': [
                                        {'name': 'MODEL_VERSION', 'value': 'v1.2.3'},
                                        {'name': 'BATCH_SIZE', 'value': '32'},
                                        {'name': 'GPU_MEMORY_FRACTION', 'value': '0.7'}
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        ]
        
        for deployment in mock_deployments:
            if self.has_model_metadata(deployment):
                agent_data = {
                    'name': deployment['name'],
                    'type': self.determine_ai_type_from_deployment(deployment),
                    'protocol': 'kubernetes',
                    'endpoint': self.build_deployment_endpoint(deployment),
                    'cloud_provider': 'kubernetes',
                    'region': self.get_cluster_region(),
                    'metadata': {
                        'resource_type': 'deployment',
                        'namespace': deployment['namespace'],
                        'deployment_metadata': deployment['metadata'],
                        'spec': deployment['spec'],
                        'model_info': self.extract_model_info(deployment),
                        'auto_registered': True,
                        'discovery_timestamp': datetime.utcnow().isoformat()
                    }
                }
                model_deployments.append(agent_data)
        
        return model_deployments
    
    def is_ai_pod(self, pod):
        """Check if pod contains AI/ML workloads"""
        labels = pod.get('labels', {})
        annotations = pod.get('annotations', {})
        
        # Check for AI-specific labels
        ai_indicators = [
            'ai.framework', 'ai.model-type', 'ml.', 'tensorflow', 'pytorch', 
            'huggingface', 'model', 'inference', 'serving'
        ]
        
        for label_key, label_value in labels.items():
            if any(indicator in label_key.lower() or indicator in str(label_value).lower() 
                   for indicator in ai_indicators):
                return True
        
        # Check annotations
        for annotation_key in annotations.keys():
            if any(indicator in annotation_key.lower() for indicator in ai_indicators):
                return True
                
        return False
    
    def has_ml_annotations(self, service):
        """Check if service has ML-related annotations"""
        annotations = service.get('annotations', {})
        ml_indicators = ['ml.', 'model.', 'ai.', 'tensorflow', 'pytorch']
        
        return any(indicator in key.lower() for key in annotations.keys() 
                  for indicator in ml_indicators)
    
    def has_model_metadata(self, deployment):
        """Check if deployment has model metadata"""
        metadata = deployment.get('metadata', {})
        annotations = metadata.get('annotations', {})
        
        model_indicators = ['model.registry', 'model.training', 'model.accuracy']
        return any(indicator in key for key in annotations.keys() 
                  for indicator in model_indicators)
    
    def determine_ai_type_from_pod(self, pod):
        """Determine AI type from pod metadata"""
        labels = pod.get('labels', {})
        annotations = pod.get('annotations', {})
        
        model_type = labels.get('ai.model-type', '')
        framework = labels.get('ai.framework', '')
        
        if 'medical-imaging' in model_type:
            return 'Medical Imaging AI'
        elif 'clinical-nlp' in model_type:
            return 'Clinical NLP AI'
        elif 'tensorflow' in framework:
            return 'TensorFlow AI Agent'
        elif 'transformers' in framework:
            return 'Transformer AI Agent'
        else:
            return 'Healthcare AI Agent'
    
    def determine_ai_type_from_service(self, service):
        """Determine AI type from service annotations"""
        annotations = service.get('annotations', {})
        
        if 'ensemble' in annotations.get('ml.ensemble.models', ''):
            return 'Ensemble AI Model'
        elif 'tensorflow-serving' in annotations.get('ml.serving.framework', ''):
            return 'TensorFlow Serving'
        else:
            return 'ML Service'
    
    def determine_ai_type_from_deployment(self, deployment):
        """Determine AI type from deployment metadata"""
        annotations = deployment.get('metadata', {}).get('annotations', {})
        
        if 'drug-interaction' in deployment['name']:
            return 'Drug Interaction AI'
        elif 'fda-cleared' in annotations.get('healthcare.regulatory.approval', ''):
            return 'FDA-Cleared AI Device'
        else:
            return 'Healthcare AI Deployment'
    
    def build_pod_endpoint(self, pod):
        """Build endpoint URL for pod"""
        namespace = pod['namespace']
        name = pod['name']
        
        # Find the main service port
        containers = pod.get('containers', [])
        port = 8080  # default
        
        for container in containers:
            ports = container.get('ports', [])
            if ports:
                port = ports[0].get('containerPort', 8080)
                break
        
        return f"http://{name}.{namespace}.svc.cluster.local:{port}"
    
    def build_service_endpoint(self, service):
        """Build endpoint URL for service"""
        namespace = service['namespace']
        name = service['name']
        ports = service.get('ports', [])
        
        port = 80  # default
        if ports:
            port = ports[0].get('port', 80)
        
        return f"http://{name}.{namespace}.svc.cluster.local:{port}"
    
    def build_deployment_endpoint(self, deployment):
        """Build endpoint URL for deployment"""
        namespace = deployment['namespace']
        name = deployment['name']
        
        # Extract port from container spec
        containers = deployment.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
        port = 8000  # default
        
        if containers:
            container_ports = containers[0].get('ports', [])
            if container_ports:
                port = container_ports[0].get('containerPort', 8000)
        
        return f"http://{name}.{namespace}.svc.cluster.local:{port}"
    
    def get_cluster_region(self):
        """Get cluster region from environment or default"""
        return os.getenv('K8S_CLUSTER_REGION', 'us-central1')
    
    def extract_model_info(self, deployment):
        """Extract model information from deployment metadata"""
        annotations = deployment.get('metadata', {}).get('annotations', {})
        
        return {
            'registry_url': annotations.get('model.registry.url'),
            'training_dataset': annotations.get('model.training.dataset'),
            'accuracy': annotations.get('model.accuracy'),
            'deployment_strategy': annotations.get('model.deployment.strategy'),
            'regulatory_approval': annotations.get('healthcare.regulatory.approval')
        }
    
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
            agent.last_scanned = None  # Will be updated after scan
        
        db.session.commit()
        return agent
    
    def perform_security_scan(self, agent, agent_data):
        """Perform security scan on discovered agent"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'tls'
        
        # Enhanced security scanning based on metadata
        metadata = agent_data['agent_metadata']
        env = metadata.get('environment', {})
        labels = metadata.get('labels', {})
        annotations = metadata.get('annotations', {})
        
        # Check for PHI processing
        if (env.get('PHI_PROCESSING') == 'true' or 
            env.get('PHI_PROCESSING_MODE') == 'secure' or
            labels.get('healthcare.phi-processing') == 'true'):
            phi_exposure = True
            
        # Enhanced compliance checks
        if env.get('HIPAA_MODE') != 'enabled':
            vulnerabilities += 1
            
        # Check encryption
        if env.get('ENCRYPTION_AT_REST') == 'aes-256':
            encryption_status = 'strong'
        elif env.get('ENCRYPTION_AT_REST'):
            encryption_status = 'weak'
            
        # Check compliance annotations
        compliance_level = annotations.get('healthcare.compliance')
        if phi_exposure and not compliance_level:
            vulnerabilities += 2
            
        # Check for security contexts and resource limits
        containers = metadata.get('containers', [])
        for container in containers:
            if 'securityContext' not in container:
                vulnerabilities += 1
            if 'resources' not in container:
                vulnerabilities += 1
                
        # Check for regulatory approval
        if 'fda' in annotations.get('healthcare.compliance', '').lower():
            # FDA regulated - higher security standards
            if vulnerabilities > 0:
                vulnerabilities += 1
                
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='kubernetes_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'containers_scanned': len(containers),
                'namespace': metadata['namespace'],
                'resource_type': metadata.get('resource_type'),
                'discovery_method': metadata.get('discovery_method', 'standard'),
                'compliance_annotations': annotations.get('healthcare.compliance'),
                'model_info': metadata.get('model_info', {})
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def generate_recommendations(self, vulnerabilities, phi_exposure):
        """Generate security recommendations"""
        recommendations = []
        
        if phi_exposure:
            recommendations.append({
                'priority': 'high',
                'category': 'data_protection',
                'description': 'Implement additional PHI protection measures',
                'action': 'Enable field-level encryption for PHI data processing'
            })
            
        if vulnerabilities > 0:
            recommendations.append({
                'priority': 'medium',
                'category': 'security_hardening',
                'description': 'Address security configuration gaps',
                'action': 'Review and implement Kubernetes security best practices'
            })
            
        recommendations.append({
            'priority': 'low',
            'category': 'monitoring',
            'description': 'Enhance monitoring and logging',
            'action': 'Implement comprehensive audit logging for all AI operations'
        })
        
        return recommendations
