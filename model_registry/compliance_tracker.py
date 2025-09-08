"""
Model-Specific Compliance and Governance Tracking Service

Provides comprehensive compliance tracking for AI/ML models including:
- Healthcare regulatory framework compliance (HIPAA, FDA, GDPR)
- Model governance and audit trails
- Automated compliance assessments
- Risk scoring for model compliance
- Compliance reporting and alerts
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import json

from app import db
from models import (ModelVersion, ModelDeployment, ComplianceEvaluation, 
                   ComplianceFramework, RiskLevel, AIAgent)

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class ComplianceRequirement:
    """Represents a specific compliance requirement"""
    framework: str
    requirement_id: str
    description: str
    severity: str  # critical, high, medium, low
    applicable_models: List[str]  # model types this applies to
    validation_criteria: Dict[str, Any]

@dataclass
class ComplianceAssessment:
    """Results of a compliance assessment"""
    model_id: int
    framework: str
    compliant: bool
    compliance_score: float  # 0.0 to 100.0
    violations: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    assessment_date: datetime
    next_assessment_due: datetime

class ModelComplianceTracker:
    """Service for tracking model-specific compliance and governance"""
    
    def __init__(self):
        self.logger = logger
        self.compliance_frameworks = self._initialize_frameworks()
        self.compliance_requirements = self._load_compliance_requirements()
    
    def _initialize_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize compliance framework configurations"""
        return {
            'HIPAA': {
                'full_name': 'Health Insurance Portability and Accountability Act',
                'applicable_to': ['healthcare', 'medical', 'phi_processing'],
                'key_requirements': ['access_controls', 'audit_logging', 'encryption', 'data_minimization'],
                'assessment_frequency_days': 90,
                'mandatory_for_phi': True
            },
            'FDA_SAMD': {
                'full_name': 'FDA Software as Medical Device',
                'applicable_to': ['medical_device', 'diagnostic', 'therapeutic'],
                'key_requirements': ['clinical_validation', 'risk_management', 'quality_system', 'change_control'],
                'assessment_frequency_days': 180,
                'mandatory_for_medical': True
            },
            'GDPR': {
                'full_name': 'General Data Protection Regulation',
                'applicable_to': ['personal_data', 'eu_data', 'phi_processing'],
                'key_requirements': ['consent_management', 'data_minimization', 'right_to_erasure', 'privacy_by_design'],
                'assessment_frequency_days': 90,
                'mandatory_for_personal_data': True
            },
            'SOC2_TYPE_II': {
                'full_name': 'SOC 2 Type II',
                'applicable_to': ['cloud_services', 'saas', 'data_processing'],
                'key_requirements': ['security', 'availability', 'processing_integrity', 'confidentiality'],
                'assessment_frequency_days': 365,
                'mandatory_for_cloud': True
            },
            'HITRUST_CSF': {
                'full_name': 'HITRUST Common Security Framework',
                'applicable_to': ['healthcare', 'regulated_industries'],
                'key_requirements': ['information_security', 'risk_management', 'incident_response', 'business_continuity'],
                'assessment_frequency_days': 180,
                'mandatory_for_healthcare': True
            }
        }
    
    def _load_compliance_requirements(self) -> Dict[str, List[ComplianceRequirement]]:
        """Load detailed compliance requirements for each framework"""
        requirements = {}
        
        # HIPAA Requirements
        requirements['HIPAA'] = [
            ComplianceRequirement(
                framework='HIPAA',
                requirement_id='164.312(a)(1)',
                description='Access control - Unique user identification',
                severity='critical',
                applicable_models=['phi_processing', 'healthcare'],
                validation_criteria={'auth_required': True, 'unique_user_id': True}
            ),
            ComplianceRequirement(
                framework='HIPAA',
                requirement_id='164.312(b)',
                description='Audit controls - Hardware, software, and procedural mechanisms',
                severity='critical',
                applicable_models=['phi_processing', 'healthcare'],
                validation_criteria={'audit_logging': True, 'log_retention_days': 2555}  # 7 years
            ),
            ComplianceRequirement(
                framework='HIPAA',
                requirement_id='164.312(e)(1)',
                description='Transmission security - Guard against unauthorized access',
                severity='critical',
                applicable_models=['phi_processing', 'healthcare'],
                validation_criteria={'encryption_in_transit': True, 'tls_version': '1.2+'}
            )
        ]
        
        # FDA SAMD Requirements
        requirements['FDA_SAMD'] = [
            ComplianceRequirement(
                framework='FDA_SAMD',
                requirement_id='QSR_820.30',
                description='Design controls for medical device software',
                severity='critical',
                applicable_models=['medical_device', 'diagnostic'],
                validation_criteria={'design_documentation': True, 'validation_testing': True}
            ),
            ComplianceRequirement(
                framework='FDA_SAMD',
                requirement_id='SAMD_RISK',
                description='Risk categorization and management',
                severity='high',
                applicable_models=['medical_device', 'diagnostic', 'therapeutic'],
                validation_criteria={'risk_assessment': True, 'clinical_validation': True}
            )
        ]
        
        # GDPR Requirements
        requirements['GDPR'] = [
            ComplianceRequirement(
                framework='GDPR',
                requirement_id='Art_25',
                description='Data protection by design and by default',
                severity='critical',
                applicable_models=['personal_data', 'eu_data'],
                validation_criteria={'privacy_by_design': True, 'data_minimization': True}
            ),
            ComplianceRequirement(
                framework='GDPR',
                requirement_id='Art_17',
                description='Right to erasure (right to be forgotten)',
                severity='high',
                applicable_models=['personal_data', 'eu_data'],
                validation_criteria={'data_deletion_capability': True, 'erasure_log': True}
            )
        ]
        
        return requirements
    
    def assess_model_compliance(self, model: ModelVersion, 
                               frameworks: Optional[List[str]] = None) -> Dict[str, ComplianceAssessment]:
        """
        Perform comprehensive compliance assessment for a model
        
        Args:
            model: Model version to assess
            frameworks: List of frameworks to assess (None for all applicable)
            
        Returns:
            Dictionary mapping framework names to assessment results
        """
        assessments = {}
        
        # Determine applicable frameworks
        if frameworks is None:
            frameworks = self._get_applicable_frameworks(model)
        
        for framework in frameworks:
            try:
                assessment = self._assess_framework_compliance(model, framework)
                assessments[framework] = assessment
                
                # Store assessment in database
                self._store_compliance_assessment(assessment)
                
            except Exception as e:
                self.logger.error(f"Failed to assess {framework} compliance for model {model.model_name}: {e}")
        
        return assessments
    
    def _get_applicable_frameworks(self, model: ModelVersion) -> List[str]:
        """Determine which compliance frameworks apply to a model"""
        applicable_frameworks = []
        
        model_characteristics = {
            'processes_phi': model.processes_phi,
            'model_type': (model.model_type or '').lower(),
            'data_classification': (model.data_classification or '').lower(),
            'healthcare_related': self._is_healthcare_model(model),
            'medical_device': self._is_medical_device_model(model),
            'personal_data': self._processes_personal_data(model)
        }
        
        for framework, config in self.compliance_frameworks.items():
            if self._framework_applies_to_model(framework, config, model_characteristics):
                applicable_frameworks.append(framework)
        
        return applicable_frameworks
    
    def _assess_framework_compliance(self, model: ModelVersion, framework: str) -> ComplianceAssessment:
        """Assess compliance for a specific framework"""
        requirements = self.compliance_requirements.get(framework, [])
        
        violations = []
        compliance_checks_passed = 0
        total_checks = 0
        recommendations = []
        
        for requirement in requirements:
            if self._requirement_applies_to_model(requirement, model):
                total_checks += 1
                
                # Perform compliance check
                check_result = self._check_requirement_compliance(model, requirement)
                
                if not check_result['compliant']:
                    violations.append({
                        'requirement_id': requirement.requirement_id,
                        'description': requirement.description,
                        'severity': requirement.severity,
                        'finding': check_result['finding'],
                        'evidence': check_result.get('evidence', {})
                    })
                    
                    # Generate remediation recommendation
                    recommendation = self._generate_remediation_recommendation(requirement, check_result)
                    recommendations.append(recommendation)
                else:
                    compliance_checks_passed += 1
        
        # Calculate compliance score
        compliance_score = (compliance_checks_passed / total_checks * 100) if total_checks > 0 else 100.0
        
        # Determine next assessment date
        framework_config = self.compliance_frameworks[framework]
        next_assessment = datetime.utcnow() + timedelta(days=framework_config['assessment_frequency_days'])
        
        return ComplianceAssessment(
            model_id=model.id,
            framework=framework,
            compliant=len(violations) == 0,
            compliance_score=compliance_score,
            violations=violations,
            recommendations=recommendations,
            assessment_date=datetime.utcnow(),
            next_assessment_due=next_assessment
        )
    
    def _check_requirement_compliance(self, model: ModelVersion, 
                                    requirement: ComplianceRequirement) -> Dict[str, Any]:
        """Check if a model meets a specific compliance requirement"""
        validation_criteria = requirement.validation_criteria
        
        # Get model deployment information for security checks
        latest_deployment = None
        if model.deployments:
            latest_deployment = max(model.deployments, key=lambda d: d.deployed_at)
        
        compliance_check = {
            'compliant': True,
            'finding': '',
            'evidence': {}
        }
        
        # Check based on requirement type
        if requirement.requirement_id == '164.312(a)(1)':  # HIPAA Access Control
            if not model.processes_phi:
                compliance_check['compliant'] = True
            else:
                # Check if authentication is enabled
                auth_enabled = self._check_authentication_enabled(model, latest_deployment)
                if not auth_enabled:
                    compliance_check['compliant'] = False
                    compliance_check['finding'] = 'Model processes PHI but lacks proper access controls'
                    compliance_check['evidence'] = {'auth_enabled': False}
        
        elif requirement.requirement_id == '164.312(b)':  # HIPAA Audit Controls
            if model.processes_phi:
                audit_enabled = self._check_audit_logging(model, latest_deployment)
                if not audit_enabled:
                    compliance_check['compliant'] = False
                    compliance_check['finding'] = 'Audit logging not properly configured for PHI processing'
                    compliance_check['evidence'] = {'audit_enabled': False}
        
        elif requirement.requirement_id == '164.312(e)(1)':  # HIPAA Transmission Security
            if model.processes_phi and latest_deployment:
                tls_enabled = self._check_encryption_in_transit(latest_deployment)
                if not tls_enabled:
                    compliance_check['compliant'] = False
                    compliance_check['finding'] = 'Encryption in transit not properly configured'
                    compliance_check['evidence'] = {'tls_enabled': False}
        
        elif requirement.requirement_id == 'QSR_820.30':  # FDA Design Controls
            if self._is_medical_device_model(model):
                design_docs = self._check_design_documentation(model)
                if not design_docs:
                    compliance_check['compliant'] = False
                    compliance_check['finding'] = 'Medical device model lacks required design documentation'
                    compliance_check['evidence'] = {'design_docs_complete': False}
        
        elif requirement.requirement_id == 'Art_25':  # GDPR Privacy by Design
            if self._processes_personal_data(model):
                privacy_by_design = self._check_privacy_by_design(model)
                if not privacy_by_design:
                    compliance_check['compliant'] = False
                    compliance_check['finding'] = 'Model lacks privacy by design implementation'
                    compliance_check['evidence'] = {'privacy_by_design': False}
        
        return compliance_check
    
    def _generate_remediation_recommendation(self, requirement: ComplianceRequirement, 
                                           check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate specific remediation recommendations"""
        recommendation = {
            'requirement_id': requirement.requirement_id,
            'priority': requirement.severity,
            'title': f'Address {requirement.framework} Requirement: {requirement.requirement_id}',
            'description': requirement.description,
            'remediation_steps': [],
            'estimated_effort': 'Unknown',
            'compliance_impact': 'High'
        }
        
        # Generate specific remediation steps based on requirement
        if requirement.requirement_id == '164.312(a)(1)':
            recommendation['remediation_steps'] = [
                'Implement user authentication for model endpoints',
                'Configure unique user identification and access controls',
                'Set up role-based access control (RBAC)',
                'Document access control procedures'
            ]
            recommendation['estimated_effort'] = 'Medium (2-4 weeks)'
        
        elif requirement.requirement_id == '164.312(b)':
            recommendation['remediation_steps'] = [
                'Enable comprehensive audit logging',
                'Configure log retention for minimum 7 years',
                'Implement log monitoring and alerting',
                'Establish log review procedures'
            ]
            recommendation['estimated_effort'] = 'Medium (1-3 weeks)'
        
        elif requirement.requirement_id == '164.312(e)(1)':
            recommendation['remediation_steps'] = [
                'Enable TLS 1.2+ for all communications',
                'Implement end-to-end encryption for PHI',
                'Configure secure API endpoints',
                'Validate encryption implementation'
            ]
            recommendation['estimated_effort'] = 'Low (3-7 days)'
        
        elif requirement.requirement_id == 'QSR_820.30':
            recommendation['remediation_steps'] = [
                'Create comprehensive design documentation',
                'Perform design review and validation',
                'Document risk management activities',
                'Establish change control procedures'
            ]
            recommendation['estimated_effort'] = 'High (4-8 weeks)'
        
        elif requirement.requirement_id == 'Art_25':
            recommendation['remediation_steps'] = [
                'Implement data minimization techniques',
                'Add privacy-preserving data processing',
                'Configure data retention policies',
                'Document privacy impact assessment'
            ]
            recommendation['estimated_effort'] = 'Medium (2-4 weeks)'
        
        return recommendation
    
    def generate_compliance_report(self, model_ids: Optional[List[int]] = None,
                                 frameworks: Optional[List[str]] = None,
                                 include_recommendations: bool = True) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        
        # Get models to assess
        if model_ids:
            models = ModelVersion.query.filter(ModelVersion.id.in_(model_ids)).all()
        else:
            models = ModelVersion.query.all()
        
        report = {
            'generated_at': datetime.utcnow().isoformat(),
            'report_scope': {
                'models_assessed': len(models),
                'frameworks_assessed': frameworks or 'all_applicable',
                'include_recommendations': include_recommendations
            },
            'executive_summary': {
                'total_models': len(models),
                'compliant_models': 0,
                'non_compliant_models': 0,
                'compliance_score_average': 0.0,
                'critical_violations': 0,
                'high_violations': 0
            },
            'framework_summary': {},
            'model_assessments': [],
            'recommendations_summary': []
        }
        
        all_assessments = []
        framework_stats = {}
        
        for model in models:
            model_frameworks = frameworks or self._get_applicable_frameworks(model)
            model_assessments = self.assess_model_compliance(model, model_frameworks)
            
            model_report = {
                'model_id': model.id,
                'model_name': model.model_name,
                'version': model.version,
                'stage': model.stage,
                'processes_phi': model.processes_phi,
                'assessments': {}
            }
            
            for framework, assessment in model_assessments.items():
                assessment_data = {
                    'compliant': assessment.compliant,
                    'compliance_score': assessment.compliance_score,
                    'violations_count': len(assessment.violations),
                    'violations': assessment.violations,
                    'assessment_date': assessment.assessment_date.isoformat()
                }
                
                if include_recommendations:
                    assessment_data['recommendations'] = assessment.recommendations
                
                model_report['assessments'][framework] = assessment_data
                all_assessments.append(assessment)
                
                # Update framework statistics
                if framework not in framework_stats:
                    framework_stats[framework] = {
                        'models_assessed': 0,
                        'compliant_models': 0,
                        'average_score': 0.0,
                        'total_violations': 0
                    }
                
                framework_stats[framework]['models_assessed'] += 1
                if assessment.compliant:
                    framework_stats[framework]['compliant_models'] += 1
                framework_stats[framework]['total_violations'] += len(assessment.violations)
            
            report['model_assessments'].append(model_report)
        
        # Calculate executive summary
        if all_assessments:
            compliant_count = sum(1 for a in all_assessments if a.compliant)
            total_assessments = len(all_assessments)
            average_score = sum(a.compliance_score for a in all_assessments) / total_assessments
            
            report['executive_summary'].update({
                'compliant_models': compliant_count,
                'non_compliant_models': total_assessments - compliant_count,
                'compliance_score_average': round(average_score, 2)
            })
            
            # Count violations by severity
            all_violations = [v for assessment in all_assessments for v in assessment.violations]
            report['executive_summary']['critical_violations'] = len([v for v in all_violations if v['severity'] == 'critical'])
            report['executive_summary']['high_violations'] = len([v for v in all_violations if v['severity'] == 'high'])
        
        # Calculate framework summary
        for framework, stats in framework_stats.items():
            if stats['models_assessed'] > 0:
                stats['compliance_rate'] = round((stats['compliant_models'] / stats['models_assessed']) * 100, 1)
            report['framework_summary'][framework] = stats
        
        return report
    
    def _store_compliance_assessment(self, assessment: ComplianceAssessment) -> None:
        """Store compliance assessment in database"""
        try:
            # Create compliance evaluation record
            evaluation = ComplianceEvaluation(
                ai_agent_id=None,  # Model assessments don't directly link to agents
                framework=getattr(ComplianceFramework, assessment.framework),
                compliance_score=assessment.compliance_score,
                compliant=assessment.compliant,
                findings=json.dumps({
                    'violations': assessment.violations,
                    'recommendations': assessment.recommendations,
                    'model_id': assessment.model_id
                }),
                evaluated_at=assessment.assessment_date
            )
            
            db.session.add(evaluation)
            db.session.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to store compliance assessment: {e}")
            db.session.rollback()
    
    # Helper methods for compliance checks
    def _is_healthcare_model(self, model: ModelVersion) -> bool:
        """Determine if model is healthcare-related"""
        healthcare_indicators = ['healthcare', 'medical', 'clinical', 'patient', 'diagnosis', 'treatment']
        model_text = f"{model.model_name} {model.description or ''} {model.model_type or ''}".lower()
        return any(indicator in model_text for indicator in healthcare_indicators)
    
    def _is_medical_device_model(self, model: ModelVersion) -> bool:
        """Determine if model qualifies as medical device software"""
        device_indicators = ['diagnostic', 'therapeutic', 'medical_device', 'fda', 'clinical_decision']
        model_text = f"{model.model_name} {model.description or ''} {model.model_type or ''}".lower()
        return any(indicator in model_text for indicator in device_indicators)
    
    def _processes_personal_data(self, model: ModelVersion) -> bool:
        """Determine if model processes personal data"""
        return model.processes_phi or 'personal' in (model.data_classification or '').lower()
    
    def _framework_applies_to_model(self, framework: str, config: Dict[str, Any], 
                                   characteristics: Dict[str, Any]) -> bool:
        """Determine if a framework applies to a model based on characteristics"""
        applicable_to = config.get('applicable_to', [])
        
        for criterion in applicable_to:
            if criterion == 'healthcare' and characteristics['healthcare_related']:
                return True
            elif criterion == 'medical_device' and characteristics['medical_device']:
                return True
            elif criterion == 'phi_processing' and characteristics['processes_phi']:
                return True
            elif criterion == 'personal_data' and characteristics['personal_data']:
                return True
        
        return False
    
    def _requirement_applies_to_model(self, requirement: ComplianceRequirement, 
                                    model: ModelVersion) -> bool:
        """Determine if a specific requirement applies to a model"""
        model_type = (model.model_type or '').lower()
        
        for applicable_type in requirement.applicable_models:
            if applicable_type == 'phi_processing' and model.processes_phi:
                return True
            elif applicable_type == 'healthcare' and self._is_healthcare_model(model):
                return True
            elif applicable_type == 'medical_device' and self._is_medical_device_model(model):
                return True
            elif applicable_type == 'personal_data' and self._processes_personal_data(model):
                return True
            elif applicable_type in model_type:
                return True
        
        return False
    
    def _check_authentication_enabled(self, model: ModelVersion, 
                                    deployment: Optional[ModelDeployment]) -> bool:
        """Check if authentication is properly enabled"""
        if not deployment:
            return False
        
        security_config = deployment.security_config or {}
        return security_config.get('auth_required', False)
    
    def _check_audit_logging(self, model: ModelVersion, 
                           deployment: Optional[ModelDeployment]) -> bool:
        """Check if audit logging is properly configured"""
        if not deployment:
            return False
        
        return deployment.audit_logs_enabled
    
    def _check_encryption_in_transit(self, deployment: ModelDeployment) -> bool:
        """Check if encryption in transit is properly configured"""
        if deployment.endpoint_url and deployment.endpoint_url.startswith('https://'):
            return True
        
        security_config = deployment.security_config or {}
        return security_config.get('tls_enabled', False)
    
    def _check_design_documentation(self, model: ModelVersion) -> bool:
        """Check if design documentation is complete"""
        # In real implementation, would check for specific documentation artifacts
        return model.description is not None and len(model.description) > 50
    
    def _check_privacy_by_design(self, model: ModelVersion) -> bool:
        """Check if privacy by design principles are implemented"""
        compliance_frameworks = model.compliance_frameworks or []
        return 'GDPR' in compliance_frameworks and model.data_classification is not None