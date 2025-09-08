"""
Enhanced Model Metadata Extraction Service

Expands beyond basic Kubernetes annotations to provide comprehensive
model metadata extraction from multiple sources:
- MLflow Registry
- Container environments
- API endpoints
- Configuration files
- Cloud services metadata
"""

import json
import os
import re
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import requests
import yaml
from urllib.parse import urlparse

from app import db
from models import AIAgent
from model_registry.mlflow_integration import MLflowRegistryIntegration

import logging

logger = logging.getLogger(__name__)

class EnhancedModelMetadataExtractor:
    """Enhanced service for extracting comprehensive model metadata"""
    
    def __init__(self):
        self.mlflow_integration = MLflowRegistryIntegration()
        self.logger = logger
        self.metadata_sources = {
            'kubernetes': self._extract_k8s_metadata,
            'docker': self._extract_docker_metadata,
            'api': self._extract_api_metadata,
            'config': self._extract_config_metadata,
            'mlflow': self._extract_mlflow_metadata,
            'environment': self._extract_environment_metadata
        }
    
    def extract_comprehensive_metadata(self, agent: AIAgent) -> Dict[str, Any]:
        """
        Extract comprehensive metadata from all available sources
        
        Args:
            agent: AI agent to extract metadata for
            
        Returns:
            Comprehensive metadata dictionary
        """
        comprehensive_metadata = {
            'agent_id': agent.id,
            'agent_name': agent.name,
            'extraction_timestamp': datetime.utcnow().isoformat(),
            'sources_checked': [],
            'metadata_by_source': {},
            'consolidated_metadata': {},
            'model_information': {},
            'compliance_indicators': {},
            'deployment_information': {},
            'lineage_information': {}
        }
        
        # Extract from all available sources
        agent_metadata = agent.agent_metadata or {}
        
        for source_name, extractor_func in self.metadata_sources.items():
            try:
                self.logger.debug(f"Extracting metadata from source: {source_name}")
                source_metadata = extractor_func(agent, agent_metadata)
                
                if source_metadata:
                    comprehensive_metadata['sources_checked'].append(source_name)
                    comprehensive_metadata['metadata_by_source'][source_name] = source_metadata
                    
            except Exception as e:
                self.logger.warning(f"Failed to extract metadata from {source_name}: {e}")
        
        # Consolidate metadata from all sources
        comprehensive_metadata['consolidated_metadata'] = self._consolidate_metadata(
            comprehensive_metadata['metadata_by_source']
        )
        
        # Extract specific information categories
        comprehensive_metadata['model_information'] = self._extract_model_information(
            comprehensive_metadata['consolidated_metadata']
        )
        
        comprehensive_metadata['compliance_indicators'] = self._extract_compliance_indicators(
            comprehensive_metadata['consolidated_metadata']
        )
        
        comprehensive_metadata['deployment_information'] = self._extract_deployment_information(
            comprehensive_metadata['consolidated_metadata']
        )
        
        comprehensive_metadata['lineage_information'] = self._extract_lineage_information(
            comprehensive_metadata['consolidated_metadata']
        )
        
        return comprehensive_metadata
    
    def _extract_k8s_metadata(self, agent: AIAgent, agent_metadata: Dict) -> Dict[str, Any]:
        """Extract metadata from Kubernetes annotations and labels"""
        k8s_metadata = {}
        
        # Basic Kubernetes metadata from existing implementation
        annotations = agent_metadata.get('annotations', {})
        labels = agent_metadata.get('labels', {})
        
        # Model registry information
        k8s_metadata['model_registry'] = {
            'registry_url': annotations.get('model.registry.url'),
            'model_name': annotations.get('model.name'),
            'model_version': annotations.get('model.version'),
            'model_stage': annotations.get('model.stage'),
            'training_dataset': annotations.get('model.training.dataset'),
            'accuracy': annotations.get('model.accuracy'),
            'deployment_strategy': annotations.get('model.deployment.strategy')
        }
        
        # Healthcare-specific annotations
        k8s_metadata['healthcare'] = {
            'regulatory_approval': annotations.get('healthcare.regulatory.approval'),
            'phi_access': annotations.get('healthcare.phi.access', 'false').lower() == 'true',
            'compliance_frameworks': annotations.get('healthcare.compliance.frameworks', '').split(','),
            'data_classification': annotations.get('healthcare.data.classification'),
            'audit_required': annotations.get('healthcare.audit.required', 'false').lower() == 'true'
        }
        
        # AI/ML specific metadata
        k8s_metadata['ml_metadata'] = {
            'framework': labels.get('ml.framework') or annotations.get('ml.framework'),
            'model_type': labels.get('ml.model.type'),
            'input_schema': annotations.get('ml.input.schema'),
            'output_schema': annotations.get('ml.output.schema'),
            'serving_runtime': labels.get('ml.serving.runtime'),
            'resource_requirements': annotations.get('ml.resources.requirements')
        }
        
        # Performance and monitoring
        k8s_metadata['monitoring'] = {
            'metrics_enabled': annotations.get('monitoring.enabled', 'false').lower() == 'true',
            'logging_level': annotations.get('monitoring.logging.level'),
            'health_check_path': annotations.get('monitoring.health.path'),
            'alerting_config': annotations.get('monitoring.alerting.config')
        }
        
        return k8s_metadata
    
    def _extract_docker_metadata(self, agent: AIAgent, agent_metadata: Dict) -> Dict[str, Any]:
        """Extract metadata from Docker container environment and labels"""
        docker_metadata = {}
        
        # Container information
        image = agent_metadata.get('image', '')
        environment = agent_metadata.get('environment', {})
        labels = agent_metadata.get('labels', {})
        
        # Model information from environment variables
        docker_metadata['model_environment'] = {
            'model_path': environment.get('MODEL_PATH'),
            'model_name': environment.get('MODEL_NAME'),
            'model_version': environment.get('MODEL_VERSION'),
            'serving_port': environment.get('SERVING_PORT'),
            'batch_size': environment.get('BATCH_SIZE'),
            'max_memory': environment.get('MAX_MEMORY')
        }
        
        # MLflow specific environment
        docker_metadata['mlflow_config'] = {
            'tracking_uri': environment.get('MLFLOW_TRACKING_URI'),
            'experiment_id': environment.get('MLFLOW_EXPERIMENT_ID'),
            'run_id': environment.get('MLFLOW_RUN_ID'),
            'model_uri': environment.get('MLFLOW_MODEL_URI'),
            'registry_uri': environment.get('MLFLOW_REGISTRY_URI')
        }
        
        # Healthcare compliance from environment
        docker_metadata['compliance_config'] = {
            'phi_access': environment.get('PHI_ACCESS', 'false').lower() == 'true',
            'encryption_enabled': environment.get('ENCRYPTION_ENABLED', 'false').lower() == 'true',
            'audit_logging': environment.get('AUDIT_LOGGING', 'false').lower() == 'true',
            'data_retention_days': environment.get('DATA_RETENTION_DAYS')
        }
        
        # Image analysis
        docker_metadata['image_info'] = self._analyze_container_image(image)
        
        return docker_metadata
    
    def _extract_api_metadata(self, agent: AIAgent, agent_metadata: Dict) -> Dict[str, Any]:
        """Extract metadata from API endpoints and responses"""
        api_metadata = {}
        
        try:
            endpoint = agent.endpoint
            if not endpoint:
                return api_metadata
            
            # Try common model serving endpoints
            model_endpoints = [
                f"{endpoint}/model/metadata",
                f"{endpoint}/api/model/info", 
                f"{endpoint}/health",
                f"{endpoint}/metrics",
                f"{endpoint}/info"
            ]
            
            for model_endpoint in model_endpoints:
                try:
                    response = requests.get(model_endpoint, timeout=10)
                    if response.status_code == 200:
                        endpoint_data = response.json()
                        api_metadata[f"endpoint_{model_endpoint.split('/')[-1]}"] = endpoint_data
                        
                        # Extract model information if available
                        if 'model' in endpoint_data or 'name' in endpoint_data:
                            api_metadata['model_info_from_api'] = {
                                'model_name': endpoint_data.get('model_name') or endpoint_data.get('name'),
                                'model_version': endpoint_data.get('model_version') or endpoint_data.get('version'),
                                'framework': endpoint_data.get('framework'),
                                'input_schema': endpoint_data.get('input_schema'),
                                'output_schema': endpoint_data.get('output_schema')
                            }
                        
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"Failed to extract API metadata: {e}")
        
        return api_metadata
    
    def _extract_config_metadata(self, agent: AIAgent, agent_metadata: Dict) -> Dict[str, Any]:
        """Extract metadata from configuration files and manifests"""
        config_metadata = {}
        
        # Look for configuration in agent metadata
        config_files = agent_metadata.get('config_files', {})
        
        for config_name, config_content in config_files.items():
            try:
                if isinstance(config_content, str):
                    # Try to parse as YAML or JSON
                    if config_name.endswith(('.yaml', '.yml')):
                        parsed_config = yaml.safe_load(config_content)
                    elif config_name.endswith('.json'):
                        parsed_config = json.loads(config_content)
                    else:
                        continue
                    
                    config_metadata[config_name] = parsed_config
                    
                    # Extract model-specific configuration
                    if 'model' in parsed_config:
                        config_metadata['model_config'] = parsed_config['model']
                    
                elif isinstance(config_content, dict):
                    config_metadata[config_name] = config_content
                    
            except Exception as e:
                self.logger.debug(f"Failed to parse config {config_name}: {e}")
        
        return config_metadata
    
    def _extract_mlflow_metadata(self, agent: AIAgent, agent_metadata: Dict) -> Dict[str, Any]:
        """Extract metadata from MLflow registry"""
        mlflow_metadata = {}
        
        try:
            # Check if this agent is associated with an MLflow model
            model_name = None
            
            # Try to extract model name from various sources
            if agent.protocol == 'mlflow':
                model_name = agent_metadata.get('model_name')
            else:
                # Look in annotations, environment, etc.
                for source_data in agent_metadata.values():
                    if isinstance(source_data, dict):
                        model_name = (source_data.get('model_name') or 
                                    source_data.get('MODEL_NAME') or
                                    source_data.get('mlflow_model_name'))
                        if model_name:
                            break
            
            if model_name:
                # Get comprehensive model information from MLflow
                models = self.mlflow_integration.get_registered_models()
                matching_model = next((m for m in models if m['name'] == model_name), None)
                
                if matching_model:
                    mlflow_metadata['registry_model'] = matching_model
                    
                    # Get model versions
                    versions = self.mlflow_integration.get_model_versions(model_name)
                    mlflow_metadata['model_versions'] = versions
                    
                    # Get lineage for latest version
                    if versions:
                        latest_version = max(versions, key=lambda v: int(v.get('version', 0)))
                        lineage = self.mlflow_integration.get_model_lineage(
                            model_name, latest_version['version']
                        )
                        mlflow_metadata['model_lineage'] = lineage
                        
        except Exception as e:
            self.logger.warning(f"Failed to extract MLflow metadata: {e}")
        
        return mlflow_metadata
    
    def _extract_environment_metadata(self, agent: AIAgent, agent_metadata: Dict) -> Dict[str, Any]:
        """Extract metadata from environment and system information"""
        env_metadata = {}
        
        # Check for model-related environment variables
        environment = agent_metadata.get('environment', {})
        
        # Model serving frameworks
        env_metadata['serving_framework'] = self._detect_serving_framework(environment)
        
        # Hardware requirements
        env_metadata['hardware_requirements'] = {
            'gpu_required': any(key for key in environment.keys() if 'gpu' in key.lower()),
            'memory_limit': environment.get('MEMORY_LIMIT'),
            'cpu_limit': environment.get('CPU_LIMIT'),
            'storage_required': environment.get('STORAGE_REQUIRED')
        }
        
        # Security configuration
        env_metadata['security_config'] = {
            'tls_enabled': environment.get('TLS_ENABLED', 'false').lower() == 'true',
            'auth_required': environment.get('AUTH_REQUIRED', 'false').lower() == 'true',
            'cors_enabled': environment.get('CORS_ENABLED', 'false').lower() == 'true',
            'rate_limiting': environment.get('RATE_LIMITING', 'false').lower() == 'true'
        }
        
        return env_metadata
    
    def _consolidate_metadata(self, metadata_by_source: Dict[str, Any]) -> Dict[str, Any]:
        """Consolidate metadata from multiple sources with priority"""
        consolidated = {}
        
        # Priority order for metadata sources (highest to lowest)
        source_priority = ['mlflow', 'kubernetes', 'config', 'api', 'docker', 'environment']
        
        # Categories to consolidate
        categories = [
            'model_name', 'model_version', 'model_type', 'framework',
            'registry_url', 'training_dataset', 'accuracy', 'phi_access',
            'compliance_frameworks', 'regulatory_approval'
        ]
        
        for category in categories:
            for source in source_priority:
                if source in metadata_by_source:
                    value = self._extract_value_from_source(
                        metadata_by_source[source], category
                    )
                    if value is not None:
                        consolidated[category] = value
                        consolidated[f"{category}_source"] = source
                        break
        
        return consolidated
    
    def _extract_model_information(self, consolidated_metadata: Dict) -> Dict[str, Any]:
        """Extract structured model information"""
        return {
            'name': consolidated_metadata.get('model_name'),
            'version': consolidated_metadata.get('model_version'),
            'type': consolidated_metadata.get('model_type'),
            'framework': consolidated_metadata.get('framework'),
            'registry_url': consolidated_metadata.get('registry_url'),
            'training_dataset': consolidated_metadata.get('training_dataset'),
            'accuracy': consolidated_metadata.get('accuracy'),
            'deployment_stage': consolidated_metadata.get('model_stage'),
            'serving_runtime': consolidated_metadata.get('serving_runtime')
        }
    
    def _extract_compliance_indicators(self, consolidated_metadata: Dict) -> Dict[str, Any]:
        """Extract healthcare compliance indicators"""
        return {
            'phi_access': consolidated_metadata.get('phi_access', False),
            'regulatory_approval': consolidated_metadata.get('regulatory_approval'),
            'compliance_frameworks': consolidated_metadata.get('compliance_frameworks', []),
            'audit_required': consolidated_metadata.get('audit_required', False),
            'encryption_enabled': consolidated_metadata.get('encryption_enabled', False),
            'data_classification': consolidated_metadata.get('data_classification')
        }
    
    def _extract_deployment_information(self, consolidated_metadata: Dict) -> Dict[str, Any]:
        """Extract deployment-specific information"""
        return {
            'deployment_strategy': consolidated_metadata.get('deployment_strategy'),
            'serving_port': consolidated_metadata.get('serving_port'),
            'health_check_path': consolidated_metadata.get('health_check_path'),
            'resource_requirements': consolidated_metadata.get('resource_requirements'),
            'scaling_config': consolidated_metadata.get('scaling_config'),
            'monitoring_enabled': consolidated_metadata.get('monitoring_enabled', False)
        }
    
    def _extract_lineage_information(self, consolidated_metadata: Dict) -> Dict[str, Any]:
        """Extract model lineage and provenance information"""
        return {
            'training_run_id': consolidated_metadata.get('training_run_id'),
            'experiment_id': consolidated_metadata.get('experiment_id'),
            'parent_model': consolidated_metadata.get('parent_model'),
            'data_sources': consolidated_metadata.get('data_sources', []),
            'feature_dependencies': consolidated_metadata.get('feature_dependencies', []),
            'model_dependencies': consolidated_metadata.get('model_dependencies', [])
        }
    
    def _analyze_container_image(self, image: str) -> Dict[str, Any]:
        """Analyze container image for model framework indicators"""
        image_info = {'image': image}
        
        # Common ML framework indicators in image names
        framework_indicators = {
            'tensorflow': ['tensorflow', 'tf'],
            'pytorch': ['pytorch', 'torch'],
            'sklearn': ['sklearn', 'scikit'],
            'xgboost': ['xgboost', 'xgb'],
            'lightgbm': ['lightgbm', 'lgb'],
            'onnx': ['onnx'],
            'triton': ['triton', 'trtis'],
            'mlflow': ['mlflow']
        }
        
        image_lower = image.lower()
        for framework, indicators in framework_indicators.items():
            if any(indicator in image_lower for indicator in indicators):
                image_info['detected_framework'] = framework
                break
        
        return image_info
    
    def _detect_serving_framework(self, environment: Dict[str, str]) -> str:
        """Detect model serving framework from environment variables"""
        serving_indicators = {
            'tensorflow_serving': ['TF_SERVING', 'TENSORFLOW_SERVING'],
            'torchserve': ['TORCH_SERVE', 'TORCHSERVE'],
            'mlflow': ['MLFLOW_TRACKING_URI', 'MLFLOW_MODEL_URI'],
            'triton': ['TRITON_MODEL_REPOSITORY', 'TRITON_SERVER'],
            'seldon': ['SELDON_DEPLOYMENT'],
            'kfserving': ['KFSERVING_CONTAINER'],
            'bentoml': ['BENTOML_CONFIG']
        }
        
        for framework, indicators in serving_indicators.items():
            if any(indicator in environment for indicator in indicators):
                return framework
        
        return 'unknown'
    
    def _extract_value_from_source(self, source_data: Dict, key: str) -> Any:
        """Extract a specific value from nested source data"""
        # Try direct access
        if key in source_data:
            return source_data[key]
        
        # Try nested access for common patterns
        nested_paths = [
            ['model_registry', key],
            ['healthcare', key], 
            ['ml_metadata', key],
            ['model_environment', key],
            ['model_config', key],
            ['registry_model', key]
        ]
        
        for path in nested_paths:
            try:
                value = source_data
                for part in path:
                    value = value[part]
                if value is not None:
                    return value
            except (KeyError, TypeError):
                continue
        
        return None