"""
Predefined Remediation Workflow Templates

This module provides predefined workflow templates for common healthcare
compliance and security remediation scenarios.
"""

from models import RemediationTemplate, RemediationActionType, RemediationTriggerType
from app import db
import json


def create_default_templates():
    """Create default remediation workflow templates"""
    templates = [
        {
            'name': 'HIPAA Encryption Enforcement',
            'description': 'Automatically enable encryption when PHI exposure is detected in healthcare AI systems',
            'category': 'compliance',
            'framework': 'HIPAA',
            'template_config': {
                'workflow_type': 'compliance',
                'trigger_type': 'compliance_violation',
                'trigger_conditions': {
                    'framework': 'HIPAA',
                    'phi_exposure_detected': True,
                    'encryption_enabled': False
                },
                'actions': [
                    {
                        'type': 'backup_data',
                        'name': 'Create Pre-Remediation Backup',
                        'backup_location': '/secure/backups/',
                        'continue_on_failure': False,
                        'max_retries': 2
                    },
                    {
                        'type': 'enable_encryption',
                        'name': 'Enable AES-256 Encryption',
                        'encryption_type': 'AES-256',
                        'encryption_scope': 'data_at_rest',
                        'continue_on_failure': False,
                        'max_retries': 3
                    },
                    {
                        'type': 'update_configuration',
                        'name': 'Update Security Configuration',
                        'config_params': {
                            'encryption_enabled': True,
                            'phi_protection': True,
                            'data_classification': 'sensitive'
                        },
                        'continue_on_failure': False
                    },
                    {
                        'type': 'run_compliance_scan',
                        'name': 'Verify HIPAA Compliance',
                        'frameworks': ['HIPAA'],
                        'scan_type': 'encryption_verification',
                        'continue_on_failure': True
                    },
                    {
                        'type': 'notify_stakeholders',
                        'name': 'Notify Compliance Team',
                        'recipients': ['compliance@organization.com', 'security@organization.com'],
                        'message_template': 'HIPAA encryption remediation completed',
                        'continue_on_failure': True
                    }
                ],
                'parallel_execution': False,
                'requires_approval': False,
                'auto_rollback': True,
                'timeout_minutes': 30,
                'retry_attempts': 3,
                'target_frameworks': ['HIPAA'],
                'target_protocols': ['rest_api', 'grpc', 'kubernetes'],
                'target_risk_levels': ['HIGH', 'CRITICAL']
            },
            'required_parameters': ['encryption_type', 'backup_location'],
            'optional_parameters': ['notification_emails', 'compliance_scan_scope']
        },
        
        {
            'name': 'Critical Security Patch Deployment',
            'description': 'Automatically apply critical security patches and restart affected services',
            'category': 'security',
            'framework': 'GENERAL',
            'template_config': {
                'workflow_type': 'security',
                'trigger_type': 'security_alert',
                'trigger_conditions': {
                    'vulnerability_severity': 'CRITICAL',
                    'patch_available': True,
                    'system_uptime_hours': '>=24'
                },
                'actions': [
                    {
                        'type': 'backup_data',
                        'name': 'Create System Backup',
                        'backup_type': 'full_system',
                        'continue_on_failure': False,
                        'max_retries': 2
                    },
                    {
                        'type': 'apply_security_patch',
                        'name': 'Apply Critical Security Patch',
                        'patch_verification': True,
                        'continue_on_failure': False,
                        'max_retries': 2
                    },
                    {
                        'type': 'restart_service',
                        'name': 'Restart Affected Services',
                        'restart_mode': 'graceful',
                        'health_check_timeout': 300,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'run_compliance_scan',
                        'name': 'Post-Patch Security Scan',
                        'scan_type': 'vulnerability_assessment',
                        'continue_on_failure': True
                    },
                    {
                        'type': 'notify_stakeholders',
                        'name': 'Notify Security Team',
                        'recipients': ['security@organization.com', 'ops@organization.com'],
                        'include_scan_results': True,
                        'continue_on_failure': True
                    }
                ],
                'parallel_execution': False,
                'requires_approval': False,
                'auto_rollback': True,
                'timeout_minutes': 45,
                'retry_attempts': 2,
                'target_frameworks': ['SOC2', 'NIST'],
                'target_protocols': ['kubernetes', 'docker', 'rest_api'],
                'target_risk_levels': ['CRITICAL']
            },
            'required_parameters': ['patch_id', 'affected_services'],
            'optional_parameters': ['maintenance_window', 'rollback_strategy']
        },
        
        {
            'name': 'GDPR Data Access Control Update',
            'description': 'Update access controls and audit logs when GDPR violations are detected',
            'category': 'compliance',
            'framework': 'GDPR',
            'template_config': {
                'workflow_type': 'compliance',
                'trigger_type': 'compliance_violation',
                'trigger_conditions': {
                    'framework': 'GDPR',
                    'data_access_violation': True,
                    'personal_data_exposed': True
                },
                'actions': [
                    {
                        'type': 'quarantine_system',
                        'name': 'Isolate Affected System',
                        'quarantine_mode': 'network_isolation',
                        'preserve_data': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'update_access_controls',
                        'name': 'Revoke Unauthorized Access',
                        'access_policy': 'strict_gdpr',
                        'audit_trail': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'backup_data',
                        'name': 'Secure Data Backup',
                        'backup_encryption': True,
                        'retention_policy': 'gdpr_compliant',
                        'continue_on_failure': False
                    },
                    {
                        'type': 'update_monitoring',
                        'name': 'Enhanced Monitoring Setup',
                        'monitoring_scope': 'data_access_audit',
                        'alert_sensitivity': 'high',
                        'continue_on_failure': True
                    },
                    {
                        'type': 'notify_stakeholders',
                        'name': 'GDPR Incident Notification',
                        'recipients': ['dpo@organization.com', 'legal@organization.com'],
                        'notification_type': 'gdpr_breach',
                        'regulatory_reporting': True,
                        'continue_on_failure': True
                    }
                ],
                'parallel_execution': False,
                'requires_approval': True,
                'auto_rollback': False,  # GDPR remediation should not be auto-rolled back
                'timeout_minutes': 60,
                'retry_attempts': 2,
                'target_frameworks': ['GDPR'],
                'target_protocols': ['rest_api', 'grpc', 'websocket'],
                'target_risk_levels': ['HIGH', 'CRITICAL']
            },
            'required_parameters': ['data_protection_officer', 'legal_contact'],
            'optional_parameters': ['regulatory_authority', 'incident_severity']
        },
        
        {
            'name': 'FDA SaMD Validation Remediation',
            'description': 'Ensure FDA Software as Medical Device compliance for healthcare AI systems',
            'category': 'compliance',
            'framework': 'FDA',
            'template_config': {
                'workflow_type': 'compliance',
                'trigger_type': 'audit_finding',
                'trigger_conditions': {
                    'framework': 'FDA',
                    'medical_device_classification': True,
                    'validation_status': 'non_compliant'
                },
                'actions': [
                    {
                        'type': 'backup_data',
                        'name': 'Validation Data Backup',
                        'backup_scope': 'validation_artifacts',
                        'fda_compliant_storage': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'update_configuration',
                        'name': 'FDA SaMD Configuration Update',
                        'config_params': {
                            'fda_compliance_mode': True,
                            'validation_logging': True,
                            'change_control': True,
                            'risk_management': True
                        },
                        'continue_on_failure': False
                    },
                    {
                        'type': 'run_compliance_scan',
                        'name': 'FDA SaMD Validation Scan',
                        'frameworks': ['FDA'],
                        'validation_scope': 'full_samd_requirements',
                        'generate_report': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'update_monitoring',
                        'name': 'FDA Compliance Monitoring',
                        'monitoring_type': 'regulatory_compliance',
                        'adverse_event_monitoring': True,
                        'continue_on_failure': True
                    },
                    {
                        'type': 'notify_stakeholders',
                        'name': 'FDA Compliance Team Notification',
                        'recipients': ['regulatory@organization.com', 'quality@organization.com'],
                        'include_validation_report': True,
                        'continue_on_failure': True
                    }
                ],
                'parallel_execution': False,
                'requires_approval': True,
                'auto_rollback': True,
                'timeout_minutes': 90,
                'retry_attempts': 1,
                'target_frameworks': ['FDA'],
                'target_protocols': ['rest_api', 'grpc'],
                'target_risk_levels': ['HIGH', 'CRITICAL']
            },
            'required_parameters': ['device_classification', 'intended_use'],
            'optional_parameters': ['fda_submission_id', 'clinical_evaluation']
        },
        
        {
            'name': 'SOC 2 Access Control Remediation',
            'description': 'Remediate SOC 2 access control violations and strengthen security controls',
            'category': 'compliance',
            'framework': 'SOC2',
            'template_config': {
                'workflow_type': 'compliance',
                'trigger_type': 'audit_finding',
                'trigger_conditions': {
                    'framework': 'SOC2',
                    'control_failure': 'access_control',
                    'audit_exception': True
                },
                'actions': [
                    {
                        'type': 'update_access_controls',
                        'name': 'Implement SOC 2 Access Controls',
                        'access_control_framework': 'SOC2_TYPE_II',
                        'principle_of_least_privilege': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'rotate_credentials',
                        'name': 'Rotate All System Credentials',
                        'credential_types': ['api_keys', 'passwords', 'certificates'],
                        'rotation_policy': 'soc2_compliant',
                        'continue_on_failure': False
                    },
                    {
                        'type': 'update_monitoring',
                        'name': 'SOC 2 Monitoring Enhancement',
                        'monitoring_controls': ['CC6.1', 'CC6.2', 'CC6.3'],
                        'log_retention': '1_year',
                        'continue_on_failure': True
                    },
                    {
                        'type': 'run_compliance_scan',
                        'name': 'SOC 2 Control Testing',
                        'frameworks': ['SOC2'],
                        'control_testing_scope': 'access_controls',
                        'evidence_collection': True,
                        'continue_on_failure': True
                    },
                    {
                        'type': 'notify_stakeholders',
                        'name': 'SOC 2 Audit Team Notification',
                        'recipients': ['audit@organization.com', 'security@organization.com'],
                        'include_evidence': True,
                        'continue_on_failure': True
                    }
                ],
                'parallel_execution': False,
                'requires_approval': False,
                'auto_rollback': True,
                'timeout_minutes': 60,
                'retry_attempts': 2,
                'target_frameworks': ['SOC2'],
                'target_protocols': ['rest_api', 'grpc', 'kubernetes'],
                'target_risk_levels': ['MEDIUM', 'HIGH', 'CRITICAL']
            },
            'required_parameters': ['audit_period', 'control_objectives'],
            'optional_parameters': ['auditor_contact', 'remediation_deadline']
        },
        
        {
            'name': 'Emergency System Quarantine',
            'description': 'Immediately quarantine systems with critical security threats while preserving evidence',
            'category': 'security',
            'framework': 'GENERAL',
            'template_config': {
                'workflow_type': 'security',
                'trigger_type': 'security_alert',
                'trigger_conditions': {
                    'threat_level': 'CRITICAL',
                    'active_attack': True,
                    'immediate_action_required': True
                },
                'actions': [
                    {
                        'type': 'quarantine_system',
                        'name': 'Emergency System Isolation',
                        'quarantine_mode': 'complete_isolation',
                        'preserve_evidence': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'backup_data',
                        'name': 'Forensic Data Preservation',
                        'backup_type': 'forensic_image',
                        'chain_of_custody': True,
                        'continue_on_failure': False
                    },
                    {
                        'type': 'notify_stakeholders',
                        'name': 'Emergency Security Notification',
                        'recipients': ['security@organization.com', 'incident-response@organization.com'],
                        'notification_priority': 'critical',
                        'escalation_required': True,
                        'continue_on_failure': True
                    },
                    {
                        'type': 'update_monitoring',
                        'name': 'Enhanced Threat Monitoring',
                        'monitoring_scope': 'network_wide',
                        'threat_hunting': True,
                        'continue_on_failure': True
                    }
                ],
                'parallel_execution': True,  # Some actions can run in parallel
                'requires_approval': False,  # Emergency actions should not wait for approval
                'auto_rollback': False,  # Quarantine should not be auto-rolled back
                'timeout_minutes': 15,  # Quick response needed
                'retry_attempts': 1,
                'target_frameworks': ['SOC2', 'NIST', 'ISO27001'],
                'target_protocols': ['rest_api', 'grpc', 'kubernetes', 'docker'],
                'target_risk_levels': ['CRITICAL']
            },
            'required_parameters': ['incident_response_team', 'quarantine_network'],
            'optional_parameters': ['legal_hold_required', 'external_notification']
        }
    ]
    
    # Create templates if they don't exist
    for template_data in templates:
        existing = RemediationTemplate.query.filter_by(name=template_data['name']).first()
        if not existing:
            template = RemediationTemplate(
                name=template_data['name'],
                description=template_data['description'],
                category=template_data['category'],
                framework=template_data['framework'],
                template_config=template_data['template_config'],
                required_parameters=template_data['required_parameters'],
                optional_parameters=template_data['optional_parameters'],
                created_by='system'
            )
            db.session.add(template)
    
    try:
        db.session.commit()
        print(f"Created {len(templates)} remediation workflow templates")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating templates: {str(e)}")


def get_template_by_category(category):
    """Get templates by category"""
    return RemediationTemplate.query.filter_by(category=category).all()


def get_template_by_framework(framework):
    """Get templates by compliance framework"""
    return RemediationTemplate.query.filter_by(framework=framework).all()


def get_most_used_templates(limit=5):
    """Get most frequently used templates"""
    return RemediationTemplate.query.order_by(
        RemediationTemplate.usage_count.desc()
    ).limit(limit).all()


if __name__ == '__main__':
    # Create default templates when script is run directly
    create_default_templates()