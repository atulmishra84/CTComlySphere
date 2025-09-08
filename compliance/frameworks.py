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
    NIST_AI_RMF = "NIST_AI_RMF"
    OWASP_AI = "OWASP_AI"
    MITRE_ATLAS = "MITRE_ATLAS"
    DATABRICKS_AI_GOVERNANCE = "DATABRICKS_AI_GOVERNANCE"
    DASF = "DASF"
    SAIF_GOOGLE = "SAIF_GOOGLE"

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
            },
            
            ComplianceFramework.NIST_AI_RMF: {
                'name': 'NIST AI Risk Management Framework',
                'description': 'Framework for managing AI risks throughout the AI lifecycle',
                'categories': {
                    'govern': {
                        'weight': 0.25,
                        'controls': [
                            'ai_governance_structure',
                            'ai_risk_management_policy',
                            'ai_risk_tolerance',
                            'roles_and_responsibilities',
                            'ai_system_inventory'
                        ]
                    },
                    'map': {
                        'weight': 0.20,
                        'controls': [
                            'ai_system_categorization',
                            'impact_assessment',
                            'context_analysis',
                            'stakeholder_identification',
                            'interdependency_mapping'
                        ]
                    },
                    'measure': {
                        'weight': 0.25,
                        'controls': [
                            'performance_monitoring',
                            'bias_detection',
                            'risk_measurement',
                            'testing_and_validation',
                            'human_ai_configuration'
                        ]
                    },
                    'manage': {
                        'weight': 0.30,
                        'controls': [
                            'risk_treatment',
                            'incident_response',
                            'continuous_monitoring',
                            'documentation_maintenance',
                            'third_party_ai_management'
                        ]
                    }
                },
                'minimum_score': 75.0,
                'critical_controls': ['ai_governance_structure', 'bias_detection', 'performance_monitoring', 'incident_response']
            },
            
            ComplianceFramework.OWASP_AI: {
                'name': 'OWASP AI Security and Privacy Guide',
                'description': 'Security guidance for AI/ML systems and applications',
                'categories': {
                    'data_security': {
                        'weight': 0.30,
                        'controls': [
                            'training_data_protection',
                            'data_poisoning_prevention',
                            'sensitive_data_detection',
                            'data_lineage_tracking',
                            'privacy_preservation'
                        ]
                    },
                    'model_security': {
                        'weight': 0.25,
                        'controls': [
                            'model_integrity',
                            'adversarial_attack_protection',
                            'model_extraction_prevention',
                            'backdoor_detection',
                            'model_versioning'
                        ]
                    },
                    'inference_security': {
                        'weight': 0.25,
                        'controls': [
                            'input_validation',
                            'output_filtering',
                            'evasion_attack_mitigation',
                            'membership_inference_protection',
                            'model_inversion_protection'
                        ]
                    },
                    'infrastructure_security': {
                        'weight': 0.20,
                        'controls': [
                            'secure_deployment',
                            'access_controls',
                            'logging_and_monitoring',
                            'secure_communication',
                            'container_security'
                        ]
                    }
                },
                'minimum_score': 80.0,
                'critical_controls': ['training_data_protection', 'model_integrity', 'input_validation', 'access_controls']
            },
            
            ComplianceFramework.MITRE_ATLAS: {
                'name': 'MITRE ATLAS - Adversarial Threat Landscape for AI Systems',
                'description': 'Framework for understanding and mitigating AI/ML adversarial threats',
                'categories': {
                    'initial_access': {
                        'weight': 0.20,
                        'controls': [
                            'ml_supply_chain_compromise',
                            'published_model_compromise',
                            'valid_accounts_protection',
                            'external_remote_services',
                            'public_facing_application_security'
                        ]
                    },
                    'ml_model_access': {
                        'weight': 0.25,
                        'controls': [
                            'ml_artifact_collection',
                            'model_inference_api_access',
                            'full_ml_model_access',
                            'model_repository_discovery',
                            'training_data_access'
                        ]
                    },
                    'ml_attack_staging': {
                        'weight': 0.25,
                        'controls': [
                            'proxy_ml_model_creation',
                            'craft_adversarial_data',
                            'poison_training_data',
                            'backdoor_ml_model',
                            'develop_capabilities'
                        ]
                    },
                    'impact': {
                        'weight': 0.30,
                        'controls': [
                            'evade_ml_model',
                            'skew_ml_model',
                            'erode_ml_model_integrity',
                            'ml_model_corruption',
                            'denial_of_ml_service'
                        ]
                    }
                },
                'minimum_score': 85.0,
                'critical_controls': ['ml_supply_chain_compromise', 'poison_training_data', 'evade_ml_model', 'ml_model_corruption']
            },
            
            ComplianceFramework.DATABRICKS_AI_GOVERNANCE: {
                'name': 'Databricks AI Governance Framework',
                'description': 'Comprehensive AI governance for data and ML lifecycle management',
                'categories': {
                    'data_governance': {
                        'weight': 0.25,
                        'controls': [
                            'data_catalog_management',
                            'data_lineage_tracking',
                            'data_quality_monitoring',
                            'access_control_policies',
                            'sensitive_data_classification'
                        ]
                    },
                    'model_lifecycle_management': {
                        'weight': 0.30,
                        'controls': [
                            'model_registry',
                            'model_versioning',
                            'experiment_tracking',
                            'model_deployment_approval',
                            'model_performance_monitoring'
                        ]
                    },
                    'compliance_and_ethics': {
                        'weight': 0.25,
                        'controls': [
                            'bias_detection_mitigation',
                            'fairness_assessment',
                            'explainability_requirements',
                            'regulatory_compliance_tracking',
                            'ethical_ai_guidelines'
                        ]
                    },
                    'security_and_privacy': {
                        'weight': 0.20,
                        'controls': [
                            'workspace_security',
                            'notebook_access_control',
                            'secrets_management',
                            'privacy_preserving_ml',
                            'audit_logging'
                        ]
                    }
                },
                'minimum_score': 75.0,
                'critical_controls': ['data_catalog_management', 'model_registry', 'bias_detection_mitigation', 'workspace_security']
            },
            
            ComplianceFramework.DASF: {
                'name': 'Data and AI Security Framework',
                'description': 'Comprehensive security framework for data science and AI operations',
                'categories': {
                    'data_security': {
                        'weight': 0.30,
                        'controls': [
                            'data_encryption',
                            'data_masking',
                            'secure_data_storage',
                            'data_access_logging',
                            'data_retention_policies'
                        ]
                    },
                    'ai_model_security': {
                        'weight': 0.25,
                        'controls': [
                            'model_authentication',
                            'model_authorization',
                            'model_integrity_validation',
                            'secure_model_serving',
                            'model_audit_trails'
                        ]
                    },
                    'infrastructure_security': {
                        'weight': 0.25,
                        'controls': [
                            'compute_environment_isolation',
                            'network_segmentation',
                            'container_security',
                            'api_security',
                            'infrastructure_monitoring'
                        ]
                    },
                    'operational_security': {
                        'weight': 0.20,
                        'controls': [
                            'secure_development_lifecycle',
                            'vulnerability_management',
                            'incident_response',
                            'security_training',
                            'third_party_risk_management'
                        ]
                    }
                },
                'minimum_score': 80.0,
                'critical_controls': ['data_encryption', 'model_authentication', 'compute_environment_isolation', 'secure_development_lifecycle']
            },
            
            ComplianceFramework.SAIF_GOOGLE: {
                'name': 'Google Secure AI Framework (SAIF)',
                'description': 'Google\'s framework for securing AI systems throughout their lifecycle',
                'categories': {
                    'secure_foundation': {
                        'weight': 0.20,
                        'controls': [
                            'secure_by_design',
                            'supply_chain_security',
                            'infrastructure_hardening',
                            'identity_and_access_management',
                            'zero_trust_architecture'
                        ]
                    },
                    'secure_development': {
                        'weight': 0.25,
                        'controls': [
                            'secure_coding_practices',
                            'threat_modeling',
                            'security_testing',
                            'code_review_processes',
                            'dependency_management'
                        ]
                    },
                    'secure_deployment': {
                        'weight': 0.25,
                        'controls': [
                            'deployment_verification',
                            'runtime_protection',
                            'monitoring_and_detection',
                            'incident_response_automation',
                            'rollback_capabilities'
                        ]
                    },
                    'secure_operations': {
                        'weight': 0.30,
                        'controls': [
                            'continuous_monitoring',
                            'threat_intelligence',
                            'vulnerability_assessment',
                            'security_metrics',
                            'compliance_reporting'
                        ]
                    }
                },
                'minimum_score': 85.0,
                'critical_controls': ['secure_by_design', 'threat_modeling', 'deployment_verification', 'continuous_monitoring']
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
