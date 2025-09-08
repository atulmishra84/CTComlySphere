"""
Healthcare Compliance Frameworks Configuration
Defines the various compliance frameworks and their requirements
"""

import json
from enum import Enum

class ComplianceFramework(Enum):
    HIPAA = "HIPAA"
    HITRUST_CSF = "HITRUST_CSF"
    FDA_SAMD = "FDA_SAMD"
    GDPR = "GDPR"
    SOC2_TYPE_II = "SOC2_TYPE_II"

class ComplianceFrameworks:
    """Manages compliance framework definitions and requirements"""
    
    def __init__(self):
        self.frameworks = self._load_framework_definitions()
    
    def _load_framework_definitions(self):
        """Load compliance framework definitions"""
        return {
            ComplianceFramework.HIPAA: {
                'name': 'Health Insurance Portability and Accountability Act',
                'description': 'US federal law requiring the protection and confidential handling of PHI',
                'categories': {
                    'administrative_safeguards': {
                        'weight': 0.30,
                        'controls': [
                            'access_management',
                            'workforce_training',
                            'incident_response',
                            'business_associate_agreements',
                            'security_officer_designation'
                        ]
                    },
                    'physical_safeguards': {
                        'weight': 0.25,
                        'controls': [
                            'facility_access_controls',
                            'workstation_use',
                            'device_and_media_controls'
                        ]
                    },
                    'technical_safeguards': {
                        'weight': 0.45,
                        'controls': [
                            'access_control',
                            'audit_controls',
                            'integrity',
                            'person_or_entity_authentication',
                            'transmission_security'
                        ]
                    }
                },
                'minimum_score': 80.0,
                'critical_controls': ['access_control', 'transmission_security', 'audit_controls']
            },
            
            ComplianceFramework.HITRUST_CSF: {
                'name': 'HITRUST Common Security Framework',
                'description': 'Risk-based security framework for healthcare organizations',
                'categories': {
                    'information_security_governance': {
                        'weight': 0.20,
                        'controls': [
                            'security_policies',
                            'risk_management',
                            'security_organization'
                        ]
                    },
                    'access_control': {
                        'weight': 0.25,
                        'controls': [
                            'user_access_management',
                            'privileged_access_management',
                            'application_access_control'
                        ]
                    },
                    'data_protection': {
                        'weight': 0.30,
                        'controls': [
                            'data_classification',
                            'encryption',
                            'data_loss_prevention',
                            'backup_and_recovery'
                        ]
                    },
                    'network_security': {
                        'weight': 0.25,
                        'controls': [
                            'network_segmentation',
                            'intrusion_detection',
                            'vulnerability_management'
                        ]
                    }
                },
                'minimum_score': 85.0,
                'critical_controls': ['encryption', 'user_access_management', 'data_classification']
            },
            
            ComplianceFramework.FDA_SAMD: {
                'name': 'FDA Software as Medical Device',
                'description': 'FDA guidance for AI/ML-based medical devices',
                'categories': {
                    'quality_management': {
                        'weight': 0.30,
                        'controls': [
                            'software_lifecycle_processes',
                            'risk_management',
                            'clinical_evaluation',
                            'post_market_surveillance'
                        ]
                    },
                    'software_verification': {
                        'weight': 0.25,
                        'controls': [
                            'algorithm_validation',
                            'performance_testing',
                            'bias_assessment',
                            'model_explainability'
                        ]
                    },
                    'cybersecurity': {
                        'weight': 0.25,
                        'controls': [
                            'secure_development',
                            'vulnerability_management',
                            'incident_response',
                            'software_bill_of_materials'
                        ]
                    },
                    'clinical_safety': {
                        'weight': 0.20,
                        'controls': [
                            'safety_requirements',
                            'adverse_event_reporting',
                            'clinical_evidence',
                            'human_factors_engineering'
                        ]
                    }
                },
                'minimum_score': 90.0,
                'critical_controls': ['algorithm_validation', 'clinical_evaluation', 'risk_management']
            },
            
            ComplianceFramework.GDPR: {
                'name': 'General Data Protection Regulation',
                'description': 'EU regulation on data protection and privacy',
                'categories': {
                    'lawfulness_and_consent': {
                        'weight': 0.25,
                        'controls': [
                            'legal_basis',
                            'consent_management',
                            'data_subject_rights',
                            'transparency'
                        ]
                    },
                    'data_protection_by_design': {
                        'weight': 0.30,
                        'controls': [
                            'privacy_by_design',
                            'data_minimization',
                            'purpose_limitation',
                            'storage_limitation'
                        ]
                    },
                    'security_measures': {
                        'weight': 0.25,
                        'controls': [
                            'encryption',
                            'pseudonymization',
                            'access_controls',
                            'breach_notification'
                        ]
                    },
                    'accountability': {
                        'weight': 0.20,
                        'controls': [
                            'data_protection_impact_assessment',
                            'records_of_processing',
                            'data_protection_officer',
                            'international_transfers'
                        ]
                    }
                },
                'minimum_score': 75.0,
                'critical_controls': ['consent_management', 'encryption', 'data_subject_rights']
            },
            
            ComplianceFramework.SOC2_TYPE_II: {
                'name': 'SOC 2 Type II',
                'description': 'Security, availability, and confidentiality controls audit',
                'categories': {
                    'security': {
                        'weight': 0.40,
                        'controls': [
                            'logical_access_controls',
                            'network_security',
                            'change_management',
                            'risk_mitigation'
                        ]
                    },
                    'availability': {
                        'weight': 0.20,
                        'controls': [
                            'system_monitoring',
                            'backup_procedures',
                            'disaster_recovery',
                            'capacity_management'
                        ]
                    },
                    'confidentiality': {
                        'weight': 0.25,
                        'controls': [
                            'data_encryption',
                            'access_restrictions',
                            'secure_disposal',
                            'confidentiality_agreements'
                        ]
                    },
                    'processing_integrity': {
                        'weight': 0.15,
                        'controls': [
                            'data_validation',
                            'error_handling',
                            'audit_trails',
                            'authorized_processing'
                        ]
                    }
                },
                'minimum_score': 80.0,
                'critical_controls': ['logical_access_controls', 'data_encryption', 'system_monitoring']
            }
        }
    
    def get_framework(self, framework_type):
        """Get framework definition by type"""
        return self.frameworks.get(framework_type)
    
    def get_all_frameworks(self):
        """Get all framework definitions"""
        return self.frameworks
    
    def get_framework_controls(self, framework_type):
        """Get all controls for a specific framework"""
        framework = self.get_framework(framework_type)
        if not framework:
            return []
        
        controls = []
        for category in framework['categories'].values():
            controls.extend(category['controls'])
        
        return controls
    
    def get_critical_controls(self, framework_type):
        """Get critical controls for a framework"""
        framework = self.get_framework(framework_type)
        if not framework:
            return []
        
        return framework.get('critical_controls', [])
    
    def get_minimum_score(self, framework_type):
        """Get minimum compliance score for a framework"""
        framework = self.get_framework(framework_type)
        if not framework:
            return 0.0
        
        return framework.get('minimum_score', 0.0)
