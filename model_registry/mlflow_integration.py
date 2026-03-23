"""
MLflow Integration Service for CT ComplySphere Visibility & Governance Platform

Provides comprehensive model registry integration with MLflow, including:
- Model tracking and versioning
- Experiment management
- Model lineage tracking
- Registry API integration
- Healthcare compliance annotations
"""

import os
import json
import requests
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from urllib.parse import urljoin
import logging

from app import db
from models import AIAgent, ComplianceFramework, RiskLevel

# Configure logging
logger = logging.getLogger(__name__)

class MLflowRegistryIntegration:
    """Comprehensive MLflow registry integration service"""
    
    def __init__(self, mlflow_tracking_uri: Optional[str] = None):
        """
        Initialize MLflow integration
        
        Args:
            mlflow_tracking_uri: MLflow tracking server URI (optional, uses env var if not provided)
        """
        self.tracking_uri = mlflow_tracking_uri or os.getenv('MLFLOW_TRACKING_URI', 'http://localhost:5000')
        self.api_base_url = urljoin(self.tracking_uri, '/api/2.0/mlflow/')
        self.timeout = 30
        self.logger = logger
        
    def validate_connection(self) -> bool:
        """Validate connection to MLflow tracking server"""
        try:
            response = requests.get(
                urljoin(self.api_base_url, 'experiments/list'),
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Failed to connect to MLflow server: {e}")
            return False
    
    def get_registered_models(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve all registered models from MLflow
        
        Args:
            max_results: Maximum number of models to retrieve
            
        Returns:
            List of model metadata dictionaries
        """
        try:
            endpoint = urljoin(self.api_base_url, 'registered-models/list')
            params = {'max_results': max_results}
            
            response = requests.get(endpoint, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            models = data.get('registered_models', [])
            
            # Enrich model data with additional information
            enriched_models = []
            for model in models:
                enriched_model = self._enrich_model_metadata(model)
                enriched_models.append(enriched_model)
            
            return enriched_models
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve registered models: {e}")
            return []
    
    def get_model_versions(self, model_name: str) -> List[Dict[str, Any]]:
        """
        Get all versions of a specific model
        
        Args:
            model_name: Name of the model
            
        Returns:
            List of model version metadata
        """
        try:
            endpoint = urljoin(self.api_base_url, 'registered-models/get-latest-versions')
            data = {
                'name': model_name,
                'stages': ['None', 'Staging', 'Production', 'Archived']
            }
            
            response = requests.post(endpoint, json=data, timeout=self.timeout)
            response.raise_for_status()
            
            result = response.json()
            versions = result.get('model_versions', [])
            
            # Enrich version data
            for version in versions:
                version.update(self._get_version_details(model_name, version['version']))
            
            return versions
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve model versions for {model_name}: {e}")
            return []
    
    def get_model_lineage(self, model_name: str, version: str) -> Dict[str, Any]:
        """
        Get model lineage including training runs and data sources
        
        Args:
            model_name: Name of the model
            version: Model version
            
        Returns:
            Model lineage information
        """
        try:
            # Get model version details
            endpoint = urljoin(self.api_base_url, 'model-versions/get')
            data = {'name': model_name, 'version': version}
            
            response = requests.get(endpoint, params=data, timeout=self.timeout)
            response.raise_for_status()
            
            version_data = response.json()['model_version']
            run_id = version_data.get('run_id')
            
            if not run_id:
                return {'error': 'No run ID found for model version'}
            
            # Get run details
            run_data = self._get_run_details(run_id)
            
            # Build lineage information
            lineage = {
                'model_name': model_name,
                'version': version,
                'run_id': run_id,
                'experiment_id': run_data.get('experiment_id'),
                'created_by': version_data.get('user_id'),
                'created_at': version_data.get('creation_timestamp'),
                'source_path': version_data.get('source'),
                'training_data': self._extract_training_data_info(run_data),
                'parameters': run_data.get('params', {}),
                'metrics': run_data.get('metrics', {}),
                'tags': run_data.get('tags', {}),
                'artifacts': self._get_model_artifacts(run_id),
                'dependencies': self._extract_dependencies(run_data)
            }
            
            return lineage
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve model lineage for {model_name}:{version}: {e}")
            return {'error': str(e)}
    
    def track_model_compliance(self, model_name: str, version: str, 
                             compliance_data: Dict[str, Any]) -> bool:
        """
        Add healthcare compliance tracking tags to a model version
        
        Args:
            model_name: Name of the model
            version: Model version
            compliance_data: Dictionary containing compliance information
            
        Returns:
            Success status
        """
        try:
            # Prepare compliance tags
            compliance_tags = {
                'healthcare.compliance.hipaa_compliant': str(compliance_data.get('hipaa_compliant', False)),
                'healthcare.compliance.fda_cleared': str(compliance_data.get('fda_cleared', False)),
                'healthcare.compliance.gdpr_compliant': str(compliance_data.get('gdpr_compliant', False)),
                'healthcare.compliance.risk_level': compliance_data.get('risk_level', 'unknown'),
                'healthcare.compliance.last_audit': datetime.utcnow().isoformat(),
                'healthcare.data.phi_processed': str(compliance_data.get('phi_processed', False)),
                'healthcare.data.encryption_required': str(compliance_data.get('encryption_required', True)),
                'healthcare.deployment.environment': compliance_data.get('environment', 'unknown')
            }
            
            # Add regulatory framework tags
            frameworks = compliance_data.get('applicable_frameworks', [])
            for framework in frameworks:
                compliance_tags[f'healthcare.framework.{framework.lower()}'] = 'true'
            
            # Set tags on model version
            endpoint = urljoin(self.api_base_url, 'model-versions/set-tag')
            
            for key, value in compliance_tags.items():
                data = {
                    'name': model_name,
                    'version': version,
                    'key': key,
                    'value': value
                }
                
                response = requests.post(endpoint, json=data, timeout=self.timeout)
                response.raise_for_status()
            
            self.logger.info(f"Successfully updated compliance tags for {model_name}:{version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to track compliance for {model_name}:{version}: {e}")
            return False
    
    def create_model_deployment_record(self, model_name: str, version: str,
                                     deployment_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a deployment record for a model version
        
        Args:
            model_name: Name of the model
            version: Model version
            deployment_info: Deployment metadata
            
        Returns:
            Deployment record
        """
        deployment_record = {
            'model_name': model_name,
            'model_version': version,
            'deployment_id': f"{model_name}-v{version}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            'deployed_at': datetime.utcnow().isoformat(),
            'deployment_target': deployment_info.get('target', 'kubernetes'),
            'endpoint_url': deployment_info.get('endpoint'),
            'environment': deployment_info.get('environment', 'production'),
            'deployment_config': deployment_info.get('config', {}),
            'health_check_url': deployment_info.get('health_check_url'),
            'compliance_status': deployment_info.get('compliance_status', 'pending'),
            'security_scan_status': 'pending',
            'monitoring_enabled': deployment_info.get('monitoring_enabled', False)
        }
        
        # Track deployment in MLflow tags
        try:
            self._add_deployment_tags(model_name, version, deployment_record)
        except Exception as e:
            self.logger.warning(f"Failed to add deployment tags: {e}")
        
        return deployment_record
    
    def sync_models_with_agents(self) -> Dict[str, Any]:
        """
        Synchronize MLflow models with AI agents in the platform
        
        Returns:
            Synchronization results
        """
        sync_results = {
            'total_models': 0,
            'synced_agents': 0,
            'new_agents': 0,
            'errors': [],
            'started_at': datetime.utcnow().isoformat()
        }
        
        try:
            # Get all registered models from MLflow
            models = self.get_registered_models()
            sync_results['total_models'] = len(models)
            
            for model in models:
                try:
                    # Create or update AI agent for each model
                    agent_result = self._sync_model_to_agent(model)
                    
                    if agent_result['created']:
                        sync_results['new_agents'] += 1
                    else:
                        sync_results['synced_agents'] += 1
                        
                except Exception as e:
                    error_msg = f"Failed to sync model {model.get('name', 'unknown')}: {e}"
                    sync_results['errors'].append(error_msg)
                    self.logger.error(error_msg)
            
            sync_results['completed_at'] = datetime.utcnow().isoformat()
            return sync_results
            
        except Exception as e:
            sync_results['errors'].append(f"Sync operation failed: {e}")
            self.logger.error(f"Model sync operation failed: {e}")
            return sync_results
    
    def _enrich_model_metadata(self, model: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich model metadata with additional information"""
        try:
            # Get latest version details
            latest_versions = self.get_model_versions(model['name'])
            if latest_versions:
                latest_version = max(latest_versions, key=lambda v: int(v.get('version', 0)))
                model['latest_version'] = latest_version
                model['latest_version_number'] = latest_version.get('version')
                model['current_stage'] = latest_version.get('current_stage', 'None')
            
            # Extract healthcare-specific tags
            tags = model.get('tags', [])
            healthcare_tags = {tag['key']: tag['value'] for tag in tags if tag['key'].startswith('healthcare.')}
            model['healthcare_metadata'] = healthcare_tags
            
            # Determine if model processes PHI
            model['processes_phi'] = healthcare_tags.get('healthcare.data.phi_processed', 'false').lower() == 'true'
            
            # Extract compliance information
            model['compliance_status'] = {
                'hipaa_compliant': healthcare_tags.get('healthcare.compliance.hipaa_compliant', 'unknown'),
                'fda_cleared': healthcare_tags.get('healthcare.compliance.fda_cleared', 'unknown'),
                'risk_level': healthcare_tags.get('healthcare.compliance.risk_level', 'unknown')
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to enrich metadata for model {model.get('name')}: {e}")
        
        return model
    
    def _get_version_details(self, model_name: str, version: str) -> Dict[str, Any]:
        """Get detailed information about a specific model version"""
        try:
            endpoint = urljoin(self.api_base_url, 'model-versions/get')
            params = {'name': model_name, 'version': version}
            
            response = requests.get(endpoint, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()['model_version']
            
        except Exception as e:
            self.logger.error(f"Failed to get version details for {model_name}:{version}: {e}")
            return {}
    
    def _get_run_details(self, run_id: str) -> Dict[str, Any]:
        """Get details about a training run"""
        try:
            endpoint = urljoin(self.api_base_url, 'runs/get')
            params = {'run_id': run_id}
            
            response = requests.get(endpoint, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json()['run']
            
        except Exception as e:
            self.logger.error(f"Failed to get run details for {run_id}: {e}")
            return {}
    
    def _extract_training_data_info(self, run_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract training data information from run data"""
        tags = run_data.get('tags', {})
        params = run_data.get('params', {})
        
        return {
            'dataset_name': tags.get('mlflow.source.name') or params.get('dataset'),
            'dataset_version': tags.get('mlflow.source.version') or params.get('dataset_version'),
            'training_samples': params.get('training_samples'),
            'validation_samples': params.get('validation_samples'),
            'data_source': tags.get('healthcare.data.source'),
            'phi_included': tags.get('healthcare.data.phi_included', 'false').lower() == 'true'
        }
    
    def _get_model_artifacts(self, run_id: str) -> List[Dict[str, Any]]:
        """Get artifacts associated with a training run"""
        try:
            endpoint = urljoin(self.api_base_url, 'artifacts/list')
            params = {'run_id': run_id}
            
            response = requests.get(endpoint, params=params, timeout=self.timeout)
            response.raise_for_status()
            
            return response.json().get('files', [])
            
        except Exception as e:
            self.logger.error(f"Failed to get artifacts for run {run_id}: {e}")
            return []
    
    def _extract_dependencies(self, run_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract model dependencies from run data"""
        tags = run_data.get('tags', {})
        
        return {
            'python_version': tags.get('mlflow.source.python_version'),
            'mlflow_version': tags.get('mlflow.version'),
            'framework': tags.get('framework') or self._detect_framework_from_tags(tags),
            'requirements': tags.get('requirements') or tags.get('mlflow.source.requirements')
        }
    
    def _detect_framework_from_tags(self, tags: Dict[str, str]) -> str:
        """Detect ML framework from tags"""
        frameworks = ['tensorflow', 'pytorch', 'sklearn', 'xgboost', 'lightgbm']
        
        for framework in frameworks:
            if any(framework in key.lower() or framework in value.lower() 
                   for key, value in tags.items()):
                return framework
        
        return 'unknown'
    
    def _add_deployment_tags(self, model_name: str, version: str, 
                           deployment_record: Dict[str, Any]) -> None:
        """Add deployment tracking tags to model version"""
        deployment_tags = {
            'deployment.id': deployment_record['deployment_id'],
            'deployment.target': deployment_record['deployment_target'],
            'deployment.environment': deployment_record['environment'],
            'deployment.endpoint': deployment_record.get('endpoint_url', ''),
            'deployment.deployed_at': deployment_record['deployed_at']
        }
        
        endpoint = urljoin(self.api_base_url, 'model-versions/set-tag')
        
        for key, value in deployment_tags.items():
            data = {
                'name': model_name,
                'version': version,
                'key': key,
                'value': str(value)
            }
            
            response = requests.post(endpoint, json=data, timeout=self.timeout)
            response.raise_for_status()
    
    def _sync_model_to_agent(self, model: Dict[str, Any]) -> Dict[str, Any]:
        """Sync an MLflow model to an AI agent record"""
        # Determine endpoint URL
        latest_version = model.get('latest_version', {})
        model_name = model['name']
        
        # Try to extract endpoint from deployment tags
        endpoint = self._extract_endpoint_from_model(model)
        
        # Create agent data
        agent_data = {
            'name': f"MLflow Model: {model_name}",
            'type': 'ML Model',
            'protocol': 'mlflow',
            'endpoint': endpoint,
            'cloud_provider': 'mlflow',
            'region': 'model-registry',
            'metadata': {
                'model_name': model_name,
                'model_version': model.get('latest_version_number'),
                'model_stage': model.get('current_stage', 'None'),
                'model_description': model.get('description', ''),
                'healthcare_metadata': model.get('healthcare_metadata', {}),
                'compliance_status': model.get('compliance_status', {}),
                'processes_phi': model.get('processes_phi', False),
                'registry_url': f"{self.tracking_uri}/#/models/{model_name}",
                'discovery_method': 'mlflow-registry-sync',
                'discovery_timestamp': datetime.utcnow().isoformat()
            }
        }
        
        # Check if agent already exists
        existing_agent = AIAgent.query.filter_by(
            name=agent_data['name'],
            protocol='mlflow'
        ).first()
        
        if existing_agent:
            # Update existing agent
            existing_agent.agent_metadata = agent_data['metadata']
            existing_agent.last_scanned = None  # Mark for re-scanning
            db.session.commit()
            return {'created': False, 'agent_id': existing_agent.id}
        else:
            # Create new agent
            new_agent = AIAgent(
                name=agent_data['name'],
                type=agent_data['type'],
                protocol=agent_data['protocol'],
                endpoint=agent_data['endpoint'],
                cloud_provider=agent_data['cloud_provider'],
                region=agent_data['region'],
                agent_metadata=agent_data['metadata']
            )
            
            db.session.add(new_agent)
            db.session.commit()
            return {'created': True, 'agent_id': new_agent.id}
    
    def _extract_endpoint_from_model(self, model: Dict[str, Any]) -> str:
        """Extract deployment endpoint from model metadata"""
        healthcare_metadata = model.get('healthcare_metadata', {})
        
        # Check for deployment endpoint in tags
        endpoint = (healthcare_metadata.get('deployment.endpoint') or
                   healthcare_metadata.get('serving.endpoint') or
                   f"{self.tracking_uri}/model/{model['name']}/latest")
        
        return endpoint


class ModelRegistryManager:
    """High-level model registry management service"""
    
    def __init__(self):
        self.mlflow_integration = MLflowRegistryIntegration()
        self.logger = logger
    
    def initialize_registry_connection(self) -> Dict[str, Any]:
        """Initialize and validate model registry connection"""
        connection_status = {
            'connected': False,
            'tracking_uri': self.mlflow_integration.tracking_uri,
            'validated_at': datetime.utcnow().isoformat(),
            'error': None
        }
        
        try:
            if self.mlflow_integration.validate_connection():
                connection_status['connected'] = True
                self.logger.info("Successfully connected to MLflow registry")
            else:
                connection_status['error'] = "Failed to validate MLflow connection"
                
        except Exception as e:
            connection_status['error'] = str(e)
            self.logger.error(f"Registry connection failed: {e}")
        
        return connection_status
    
    def get_registry_overview(self) -> Dict[str, Any]:
        """Get comprehensive overview of model registry"""
        overview = {
            'total_models': 0,
            'models_by_stage': {'Production': 0, 'Staging': 0, 'Archived': 0, 'None': 0},
            'healthcare_models': 0,
            'phi_processing_models': 0,
            'compliant_models': 0,
            'recent_deployments': [],
            'compliance_summary': {},
            'generated_at': datetime.utcnow().isoformat()
        }
        
        try:
            models = self.mlflow_integration.get_registered_models()
            overview['total_models'] = len(models)
            
            for model in models:
                # Count by stage
                stage = model.get('current_stage', 'None')
                overview['models_by_stage'][stage] += 1
                
                # Count healthcare-specific models
                if model.get('healthcare_metadata'):
                    overview['healthcare_models'] += 1
                
                # Count PHI processing models
                if model.get('processes_phi'):
                    overview['phi_processing_models'] += 1
                
                # Count compliant models
                compliance = model.get('compliance_status', {})
                if compliance.get('hipaa_compliant') == 'true':
                    overview['compliant_models'] += 1
            
            # Calculate compliance summary
            total_healthcare = overview['healthcare_models']
            if total_healthcare > 0:
                overview['compliance_summary'] = {
                    'total_healthcare_models': total_healthcare,
                    'compliance_rate': round((overview['compliant_models'] / total_healthcare) * 100, 1),
                    'phi_processing_rate': round((overview['phi_processing_models'] / total_healthcare) * 100, 1)
                }
            
        except Exception as e:
            self.logger.error(f"Failed to generate registry overview: {e}")
            overview['error'] = str(e)
        
        return overview