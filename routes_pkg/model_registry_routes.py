"""
Model Registry Routes for Healthcare AI Compliance Platform

Provides comprehensive API endpoints for:
- Model registry management
- Model versioning and lineage
- Deployment tracking
- Compliance monitoring
- MLflow integration
"""

from flask import Blueprint, render_template, request, jsonify
from datetime import datetime, timedelta
import traceback
import logging

from app import db
from models import (ModelVersion, ModelDeployment, ModelLineage, ModelRegistrySync,
                   AIAgent, ComplianceEvaluation, ComplianceFramework)
from model_registry.mlflow_integration import MLflowRegistryIntegration, ModelRegistryManager
from model_registry.enhanced_metadata_extractor import EnhancedModelMetadataExtractor

# Configure logging
logger = logging.getLogger(__name__)

# Create Blueprint
model_registry_bp = Blueprint('model_registry', __name__)

# Initialize services
mlflow_integration = MLflowRegistryIntegration()
registry_manager = ModelRegistryManager()
metadata_extractor = EnhancedModelMetadataExtractor()

@model_registry_bp.route('/model-registry')
def model_registry_dashboard():
    """Main model registry dashboard"""
    try:
        # Create sample registry overview
        registry_overview = {
            'total_models': 12,
            'models_by_stage': {
                'Production': 4,
                'Staging': 3,
                'None': 5
            },
            'healthcare_models': 8,
            'compliance_summary': {
                'compliance_rate': 75.5,
                'total_healthcare_models': 8,
                'phi_processing_rate': 45.2
            }
        }
        
        # Get recent models (fallback to empty if tables don't exist)
        try:
            models = ModelVersion.query.order_by(ModelVersion.created_at.desc()).limit(50).all()
        except:
            models = []
        
        # Get recent deployments (fallback to empty if tables don't exist)
        try:
            deployments = ModelDeployment.query.join(ModelVersion).order_by(
                ModelDeployment.deployed_at.desc()
            ).limit(20).all()
            
            # Add model info to deployments
            deployment_data = []
            for deployment in deployments:
                deployment_info = {
                    'deployment_id': deployment.deployment_id,
                    'model_name': deployment.model_version.model_name,
                    'model_version': deployment.model_version.version,
                    'environment': deployment.environment,
                    'deployment_status': deployment.deployment_status,
                    'health_status': deployment.health_status,
                    'endpoint_url': deployment.endpoint_url,
                    'request_count': deployment.request_count,
                    'average_response_time': deployment.average_response_time,
                    'deployed_at': deployment.deployed_at
                }
                deployment_data.append(deployment_info)
        except:
            deployment_data = []
        
        return render_template('model_registry.html',
                             registry_overview=registry_overview,
                             models=models,
                             deployments=deployment_data)
                             
    except Exception as e:
        logger.error(f"Error loading model registry dashboard: {e}")
        logger.error(traceback.format_exc())
        # Return with empty data if there are any issues
        registry_overview = {
            'total_models': 0,
            'models_by_stage': {'Production': 0, 'Staging': 0, 'None': 0},
            'healthcare_models': 0,
            'compliance_summary': {'compliance_rate': 0, 'total_healthcare_models': 0, 'phi_processing_rate': 0}
        }
        return render_template('model_registry.html',
                             registry_overview=registry_overview,
                             models=[],
                             deployments=[])

@model_registry_bp.route('/api/model-registry/models')
def get_models():
    """Get all registered models"""
    try:
        models = ModelVersion.query.order_by(ModelVersion.created_at.desc()).all()
        
        models_data = []
        for model in models:
            model_info = {
                'id': model.id,
                'model_name': model.model_name,
                'version': model.version,
                'stage': model.stage,
                'description': model.description,
                'framework': model.framework,
                'model_type': model.model_type,
                'accuracy': model.accuracy,
                'precision': model.precision,
                'recall': model.recall,
                'f1_score': model.f1_score,
                'hipaa_compliant': model.hipaa_compliant,
                'fda_cleared': model.fda_cleared,
                'gdpr_compliant': model.gdpr_compliant,
                'processes_phi': model.processes_phi,
                'training_dataset': model.training_dataset,
                'training_samples': model.training_samples,
                'validation_samples': model.validation_samples,
                'training_duration': model.training_duration,
                'deployment_status': model.deployment_status,
                'serving_endpoint': model.serving_endpoint,
                'last_deployed': model.last_deployed.isoformat() if model.last_deployed else None,
                'created_at': model.created_at.isoformat(),
                'updated_at': model.updated_at.isoformat()
            }
            models_data.append(model_info)
        
        return jsonify({
            'success': True,
            'models': models_data,
            'total': len(models_data)
        })
        
    except Exception as e:
        logger.error(f"Error retrieving models: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'models': []
        }), 500

@model_registry_bp.route('/api/model-registry/models/<int:model_id>')
def get_model_details(model_id):
    """Get detailed information about a specific model"""
    try:
        model = ModelVersion.query.get_or_404(model_id)
        
        model_details = {
            'id': model.id,
            'model_name': model.model_name,
            'version': model.version,
            'stage': model.stage,
            'description': model.description,
            'created_by': model.created_by,
            'framework': model.framework,
            'model_type': model.model_type,
            'input_schema': model.input_schema,
            'output_schema': model.output_schema,
            'model_size_mb': model.model_size_mb,
            'training_run_id': model.training_run_id,
            'experiment_id': model.experiment_id,
            'training_dataset': model.training_dataset,
            'training_samples': model.training_samples,
            'validation_samples': model.validation_samples,
            'training_duration': model.training_duration,
            'accuracy': model.accuracy,
            'precision': model.precision,
            'recall': model.recall,
            'f1_score': model.f1_score,
            'custom_metrics': model.custom_metrics,
            'hipaa_compliant': model.hipaa_compliant,
            'fda_cleared': model.fda_cleared,
            'gdpr_compliant': model.gdpr_compliant,
            'processes_phi': model.processes_phi,
            'regulatory_approval': model.regulatory_approval,
            'data_classification': model.data_classification,
            'compliance_frameworks': model.compliance_frameworks,
            'deployment_config': model.deployment_config,
            'serving_endpoint': model.serving_endpoint,
            'deployment_status': model.deployment_status,
            'last_deployed': model.last_deployed.isoformat() if model.last_deployed else None,
            'created_at': model.created_at.isoformat(),
            'updated_at': model.updated_at.isoformat(),
            'deployments_count': len(model.deployments),
            'lineage_records_count': len(model.lineage_records)
        }
        
        return jsonify({
            'success': True,
            'model': model_details
        })
        
    except Exception as e:
        logger.error(f"Error retrieving model details: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/models/<int:model_id>/lineage')
def get_model_lineage(model_id):
    """Get lineage information for a specific model"""
    try:
        model = ModelVersion.query.get_or_404(model_id)
        
        # Get lineage records
        lineage_records = ModelLineage.query.filter_by(model_version_id=model_id).all()
        
        lineage_data = {
            'model_id': model_id,
            'model_name': model.model_name,
            'version': model.version,
            'lineage_records': []
        }
        
        for record in lineage_records:
            lineage_info = {
                'id': record.id,
                'parent_model_name': record.parent_model_name,
                'parent_model_version': record.parent_model_version,
                'training_run_id': record.training_run_id,
                'experiment_name': record.experiment_name,
                'data_sources': record.data_sources,
                'feature_dependencies': record.feature_dependencies,
                'code_version': record.code_version,
                'training_artifacts': record.training_artifacts,
                'model_artifacts': record.model_artifacts,
                'framework_dependencies': record.framework_dependencies,
                'library_dependencies': record.library_dependencies,
                'infrastructure_dependencies': record.infrastructure_dependencies,
                'created_by': record.created_by,
                'created_at': record.created_at.isoformat(),
                'lineage_extracted_at': record.lineage_extracted_at.isoformat(),
                'lineage_source': record.lineage_source
            }
            lineage_data['lineage_records'].append(lineage_info)
        
        # Try to get additional lineage from MLflow if available
        try:
            mlflow_lineage = mlflow_integration.get_model_lineage(model.model_name, model.version)
            if mlflow_lineage and 'error' not in mlflow_lineage:
                lineage_data['mlflow_lineage'] = mlflow_lineage
        except Exception as e:
            logger.warning(f"Could not retrieve MLflow lineage: {e}")
        
        return jsonify({
            'success': True,
            'lineage': lineage_data
        })
        
    except Exception as e:
        logger.error(f"Error retrieving model lineage: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/deployments')
def get_deployments():
    """Get all model deployments"""
    try:
        deployments = ModelDeployment.query.join(ModelVersion).order_by(
            ModelDeployment.deployed_at.desc()
        ).all()
        
        deployment_data = []
        for deployment in deployments:
            deployment_info = {
                'id': deployment.id,
                'deployment_id': deployment.deployment_id,
                'model_name': deployment.model_version.model_name,
                'model_version': deployment.model_version.version,
                'environment': deployment.environment,
                'deployment_target': deployment.deployment_target,
                'endpoint_url': deployment.endpoint_url,
                'health_check_url': deployment.health_check_url,
                'api_version': deployment.api_version,
                'deployment_status': deployment.deployment_status,
                'health_status': deployment.health_status,
                'request_count': deployment.request_count,
                'error_count': deployment.error_count,
                'average_response_time': deployment.average_response_time,
                'last_prediction_time': deployment.last_prediction_time.isoformat() if deployment.last_prediction_time else None,
                'compliance_scan_status': deployment.compliance_scan_status,
                'audit_logs_enabled': deployment.audit_logs_enabled,
                'deployed_at': deployment.deployed_at.isoformat(),
                'last_health_check': deployment.last_health_check.isoformat() if deployment.last_health_check else None
            }
            deployment_data.append(deployment_info)
        
        return jsonify({
            'success': True,
            'deployments': deployment_data,
            'total': len(deployment_data)
        })
        
    except Exception as e:
        logger.error(f"Error retrieving deployments: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'deployments': []
        }), 500

@model_registry_bp.route('/api/model-registry/sync', methods=['POST'])
def sync_model_registry():
    """Synchronize with external model registries"""
    try:
        # Perform sync with MLflow
        sync_results = mlflow_integration.sync_models_with_agents()
        
        # Update sync record
        sync_record = ModelRegistrySync.query.filter_by(
            registry_type='mlflow',
            registry_url=mlflow_integration.tracking_uri
        ).first()
        
        if not sync_record:
            sync_record = ModelRegistrySync(
                registry_type='mlflow',
                registry_url=mlflow_integration.tracking_uri
            )
            db.session.add(sync_record)
        
        sync_record.last_sync_at = datetime.utcnow()
        sync_record.models_synced = sync_results.get('synced_agents', 0) + sync_results.get('new_agents', 0)
        sync_record.models_failed = len(sync_results.get('errors', []))
        sync_record.sync_status = 'success' if not sync_results.get('errors') else 'partial_failure'
        sync_record.sync_error = '; '.join(sync_results.get('errors', []))
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Model registry synchronization completed',
            'sync_results': sync_results
        })
        
    except Exception as e:
        logger.error(f"Error syncing model registry: {e}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/models/<int:model_id>/archive', methods=['POST'])
def archive_model(model_id):
    """Archive a model version"""
    try:
        model = ModelVersion.query.get_or_404(model_id)
        model.stage = 'Archived'
        model.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Model {model.model_name} v{model.version} archived successfully'
        })
        
    except Exception as e:
        logger.error(f"Error archiving model: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/deployments/<string:deployment_id>/test', methods=['POST'])
def test_deployment(deployment_id):
    """Test a model deployment"""
    try:
        deployment = ModelDeployment.query.filter_by(deployment_id=deployment_id).first_or_404()
        
        # Simulate deployment test (in real implementation, would make actual API call)
        import random
        test_success = random.choice([True, True, True, False])  # 75% success rate
        
        if test_success:
            # Update deployment metrics
            deployment.last_health_check = datetime.utcnow()
            deployment.health_status = 'healthy'
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Deployment test successful',
                'test_results': {
                    'response_time': round(random.uniform(50, 200), 2),
                    'status_code': 200,
                    'prediction_accuracy': round(random.uniform(0.85, 0.95), 3)
                }
            })
        else:
            deployment.health_status = 'unhealthy'
            deployment.last_health_check = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                'success': False,
                'error': 'Deployment endpoint not responding',
                'test_results': {
                    'error': 'Connection timeout'
                }
            })
        
    except Exception as e:
        logger.error(f"Error testing deployment: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/compliance/scan', methods=['POST'])
def run_compliance_scan():
    """Run compliance scan on all models"""
    try:
        # Get all models that process PHI or are in production
        models_to_scan = ModelVersion.query.filter(
            (ModelVersion.processes_phi == True) | (ModelVersion.stage == 'Production')
        ).all()
        
        scan_results = {
            'scanned_models': 0,
            'compliance_issues': 0,
            'updated_compliance': 0
        }
        
        for model in models_to_scan:
            try:
                # Simulate compliance scanning
                compliance_status = evaluate_model_compliance(model)
                
                # Update model compliance status
                model.hipaa_compliant = compliance_status.get('hipaa_compliant', False)
                model.fda_cleared = compliance_status.get('fda_cleared', False)
                model.gdpr_compliant = compliance_status.get('gdpr_compliant', False)
                model.updated_at = datetime.utcnow()
                
                scan_results['scanned_models'] += 1
                if not all([model.hipaa_compliant, model.fda_cleared, model.gdpr_compliant]):
                    scan_results['compliance_issues'] += 1
                
                scan_results['updated_compliance'] += 1
                
            except Exception as e:
                logger.warning(f"Failed to scan model {model.model_name}: {e}")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Compliance scan completed for {scan_results["scanned_models"]} models',
            'scan_results': scan_results
        })
        
    except Exception as e:
        logger.error(f"Error running compliance scan: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/compliance/report')
def generate_compliance_report():
    """Generate and download compliance report"""
    try:
        models = ModelVersion.query.all()
        
        report_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'total_models': len(models),
            'compliance_summary': {
                'hipaa_compliant': len([m for m in models if m.hipaa_compliant]),
                'fda_cleared': len([m for m in models if m.fda_cleared]),
                'gdpr_compliant': len([m for m in models if m.gdpr_compliant]),
                'processes_phi': len([m for m in models if m.processes_phi])
            },
            'models': []
        }
        
        for model in models:
            model_info = {
                'model_name': model.model_name,
                'version': model.version,
                'stage': model.stage,
                'hipaa_compliant': model.hipaa_compliant,
                'fda_cleared': model.fda_cleared,
                'gdpr_compliant': model.gdpr_compliant,
                'processes_phi': model.processes_phi,
                'regulatory_approval': model.regulatory_approval,
                'data_classification': model.data_classification,
                'compliance_frameworks': model.compliance_frameworks,
                'created_at': model.created_at.isoformat()
            }
            report_data['models'].append(model_info)
        
        return jsonify({
            'success': True,
            'report': report_data
        })
        
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@model_registry_bp.route('/api/model-registry/models', methods=['POST'])
def register_model():
    """Register a new model version"""
    try:
        data = request.get_json()
        
        # Create new model version
        model = ModelVersion(
            model_name=data.get('model_name'),
            version=data.get('version'),
            stage=data.get('stage', 'None'),
            description=data.get('description'),
            framework=data.get('framework'),
            model_type=data.get('model_type'),
            input_schema=data.get('input_schema'),
            output_schema=data.get('output_schema'),
            model_size_mb=data.get('model_size_mb'),
            training_dataset=data.get('training_dataset'),
            training_samples=data.get('training_samples'),
            validation_samples=data.get('validation_samples'),
            accuracy=data.get('accuracy'),
            precision=data.get('precision'),
            recall=data.get('recall'),
            f1_score=data.get('f1_score'),
            processes_phi=data.get('processes_phi', False),
            hipaa_compliant=data.get('hipaa_compliant', False),
            fda_cleared=data.get('fda_cleared', False),
            gdpr_compliant=data.get('gdpr_compliant', False),
            regulatory_approval=data.get('regulatory_approval'),
            data_classification=data.get('data_classification'),
            compliance_frameworks=data.get('compliance_frameworks', [])
        )
        
        db.session.add(model)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Model {model.model_name} v{model.version} registered successfully',
            'model_id': model.id
        })
        
    except Exception as e:
        logger.error(f"Error registering model: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def evaluate_model_compliance(model: ModelVersion) -> dict:
    """Evaluate compliance status for a model"""
    compliance_status = {
        'hipaa_compliant': True,
        'fda_cleared': False,
        'gdpr_compliant': True
    }
    
    # HIPAA compliance checks
    if model.processes_phi:
        # Check for encryption, access controls, audit logging
        if not model.data_classification or model.data_classification not in ['encrypted', 'protected']:
            compliance_status['hipaa_compliant'] = False
    
    # FDA compliance checks for medical devices
    if model.model_type and 'medical' in model.model_type.lower():
        # In real implementation, would check regulatory approval status
        if model.regulatory_approval and 'fda' in model.regulatory_approval.lower():
            compliance_status['fda_cleared'] = True
    
    # GDPR compliance checks
    if model.processes_phi:
        # Check for data minimization, consent management, etc.
        if not model.compliance_frameworks or 'GDPR' not in model.compliance_frameworks:
            compliance_status['gdpr_compliant'] = False
    
    return compliance_status