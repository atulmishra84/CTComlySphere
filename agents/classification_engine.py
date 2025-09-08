"""
Agent Classification Engine
Automatically classifies AI agents based on functionality and determines applicable regulatory frameworks
"""
import re
import json
from typing import Dict, List, Set, Any, Optional
from datetime import datetime
from models import ComplianceFramework


class AgentClassificationEngine:
    """Classifies AI agents and determines applicable regulatory frameworks"""
    
    def __init__(self):
        self.classification_rules = self._load_classification_rules()
        self.framework_mappings = self._load_framework_mappings()
        
    def _load_classification_rules(self) -> Dict[str, Dict]:
        """Load agent classification rules based on functionality patterns"""
        return {
            'healthcare_ai': {
                'keywords': [
                    'medical', 'clinical', 'healthcare', 'hospital', 'patient', 'phi', 'hipaa',
                    'diagnosis', 'radiology', 'imaging', 'pathology', 'oncology', 'cardiology',
                    'ehr', 'emr', 'fhir', 'hl7', 'dicom', 'icd', 'cpt', 'snomed', 'loinc',
                    'prescription', 'medication', 'drug', 'therapy', 'treatment', 'clinical-trial'
                ],
                'protocols': ['fhir', 'hl7', 'dicom'],
                'data_types': ['phi', 'clinical', 'medical'],
                'frameworks': [ComplianceFramework.HIPAA, ComplianceFramework.FDA_SAMD, ComplianceFramework.HITRUST_CSF],
                'criticality': 'high',
                'description': 'AI systems processing healthcare data or providing medical functionality'
            },
            'financial_ai': {
                'keywords': [
                    'financial', 'banking', 'payment', 'credit', 'loan', 'investment', 'trading',
                    'fraud', 'kyc', 'aml', 'pci', 'sox', 'risk', 'compliance', 'audit',
                    'transaction', 'account', 'portfolio', 'insurance', 'fintech'
                ],
                'protocols': ['rest_api', 'grpc'],
                'data_types': ['pii', 'financial', 'transaction'],
                'frameworks': [ComplianceFramework.SOC2_TYPE_II, ComplianceFramework.GDPR],
                'criticality': 'high',
                'description': 'AI systems processing financial data or providing financial services'
            },
            'personal_data_ai': {
                'keywords': [
                    'personal', 'pii', 'gdpr', 'privacy', 'consent', 'profile', 'user',
                    'biometric', 'location', 'behavioral', 'demographic', 'identity'
                ],
                'protocols': ['rest_api', 'websocket', 'graphql'],
                'data_types': ['pii', 'personal'],
                'frameworks': [ComplianceFramework.GDPR],
                'criticality': 'medium',
                'description': 'AI systems processing personal identifiable information'
            },
            'operational_ai': {
                'keywords': [
                    'monitoring', 'analytics', 'optimization', 'automation', 'workflow',
                    'process', 'operation', 'maintenance', 'performance', 'efficiency'
                ],
                'protocols': ['mqtt', 'websocket', 'amqp'],
                'data_types': ['operational', 'telemetry'],
                'frameworks': [ComplianceFramework.SOC2_TYPE_II],
                'criticality': 'low',
                'description': 'AI systems for operational efficiency and monitoring'
            },
            'research_ai': {
                'keywords': [
                    'research', 'experiment', 'model', 'training', 'development', 'prototype',
                    'academic', 'science', 'analysis', 'discovery', 'innovation'
                ],
                'protocols': ['kubernetes', 'docker'],
                'data_types': ['research', 'experimental'],
                'frameworks': [],
                'criticality': 'low',
                'description': 'AI systems for research and development purposes'
            }
        }
    
    def _load_framework_mappings(self) -> Dict[str, Dict]:
        """Load framework-specific requirements and mappings"""
        return {
            ComplianceFramework.HIPAA.value: {
                'required_controls': [
                    'encryption_at_rest', 'encryption_in_transit', 'access_control',
                    'audit_logging', 'phi_protection', 'authentication'
                ],
                'data_handling': ['phi_detection', 'anonymization', 'consent_management'],
                'risk_threshold': 'medium',
                'mandatory': True
            },
            ComplianceFramework.FDA_SAMD.value: {
                'required_controls': [
                    'model_validation', 'clinical_evaluation', 'risk_management',
                    'quality_assurance', 'version_control', 'documentation'
                ],
                'data_handling': ['clinical_data_validation', 'adverse_event_reporting'],
                'risk_threshold': 'high',
                'mandatory': True
            },
            ComplianceFramework.GDPR.value: {
                'required_controls': [
                    'consent_management', 'data_minimization', 'right_to_erasure',
                    'data_portability', 'privacy_by_design', 'breach_notification'
                ],
                'data_handling': ['anonymization', 'pseudonymization', 'consent_tracking'],
                'risk_threshold': 'medium',
                'mandatory': True
            },
            ComplianceFramework.SOC2_TYPE_II.value: {
                'required_controls': [
                    'access_control', 'system_monitoring', 'change_management',
                    'availability', 'processing_integrity', 'confidentiality'
                ],
                'data_handling': ['data_classification', 'backup_recovery'],
                'risk_threshold': 'low',
                'mandatory': False
            },
            ComplianceFramework.HITRUST_CSF.value: {
                'required_controls': [
                    'information_security_governance', 'endpoint_protection',
                    'portable_media_security', 'mobile_device_security',
                    'wireless_access_management', 'network_protection'
                ],
                'data_handling': ['phi_protection', 'secure_communications'],
                'risk_threshold': 'high',
                'mandatory': True
            }
        }
    
    def classify_agent(self, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an AI agent based on its functionality and metadata
        
        Args:
            agent_data: Dictionary containing agent information (name, type, protocol, metadata, etc.)
            
        Returns:
            Dictionary with classification results and applicable frameworks
        """
        classification_result = {
            'agent_id': agent_data.get('id'),
            'primary_classification': None,
            'secondary_classifications': [],
            'applicable_frameworks': [],
            'required_controls': [],
            'criticality_level': 'low',
            'confidence_score': 0.0,
            'classification_reasons': [],
            'data_types_detected': [],
            'protocols_analyzed': [],
            'classified_at': datetime.utcnow().isoformat()
        }
        
        # Analyze agent characteristics
        agent_text = self._extract_text_for_analysis(agent_data)
        protocol = agent_data.get('protocol', '').lower()
        
        # Score each classification type
        classification_scores = {}
        
        for class_type, rules in self.classification_rules.items():
            score = self._calculate_classification_score(agent_text, protocol, rules)
            if score > 0:
                classification_scores[class_type] = score
        
        # Determine primary and secondary classifications
        if classification_scores:
            sorted_scores = sorted(classification_scores.items(), key=lambda x: x[1], reverse=True)
            
            # Primary classification (highest score)
            primary_class, primary_score = sorted_scores[0]
            classification_result['primary_classification'] = primary_class
            classification_result['confidence_score'] = primary_score
            
            # Secondary classifications (score > threshold)
            secondary_threshold = 0.3
            for class_type, score in sorted_scores[1:]:
                if score > secondary_threshold:
                    classification_result['secondary_classifications'].append({
                        'type': class_type,
                        'score': score
                    })
            
            # Determine applicable frameworks
            frameworks = set()
            controls = set()
            max_criticality = 'low'
            
            # Add frameworks from primary classification
            primary_rules = self.classification_rules[primary_class]
            frameworks.update(primary_rules['frameworks'])
            max_criticality = primary_rules['criticality']
            
            # Add frameworks from secondary classifications
            for secondary in classification_result['secondary_classifications']:
                secondary_rules = self.classification_rules[secondary['type']]
                frameworks.update(secondary_rules['frameworks'])
                if self._criticality_priority(secondary_rules['criticality']) > self._criticality_priority(max_criticality):
                    max_criticality = secondary_rules['criticality']
            
            # Collect required controls
            for framework in frameworks:
                framework_key = framework.value if hasattr(framework, 'value') else str(framework)
                if framework_key in self.framework_mappings:
                    controls.update(self.framework_mappings[framework_key]['required_controls'])
            
            classification_result['applicable_frameworks'] = [f.value for f in frameworks]
            classification_result['required_controls'] = list(controls)
            classification_result['criticality_level'] = max_criticality
            
            # Add reasoning
            classification_result['classification_reasons'] = self._generate_reasoning(
                agent_data, primary_class, primary_rules, classification_scores
            )
        
        return classification_result
    
    def _extract_text_for_analysis(self, agent_data: Dict[str, Any]) -> str:
        """Extract relevant text from agent data for analysis"""
        text_parts = []
        
        # Basic fields
        for field in ['name', 'type', 'endpoint']:
            if field in agent_data and agent_data[field]:
                text_parts.append(str(agent_data[field]))
        
        # Metadata
        if 'agent_metadata' in agent_data and agent_data['agent_metadata']:
            metadata = agent_data['agent_metadata']
            if isinstance(metadata, dict):
                # Extract values from metadata
                for key, value in metadata.items():
                    text_parts.append(f"{key}: {value}")
            else:
                text_parts.append(str(metadata))
        
        # Cloud provider and region
        if 'cloud_provider' in agent_data:
            text_parts.append(agent_data['cloud_provider'])
        if 'region' in agent_data:
            text_parts.append(agent_data['region'])
        
        return ' '.join(text_parts).lower()
    
    def _calculate_classification_score(self, agent_text: str, protocol: str, rules: Dict) -> float:
        """Calculate classification score for a given rule set"""
        score = 0.0
        
        # Keyword matching (weighted heavily)
        keyword_matches = 0
        for keyword in rules['keywords']:
            if keyword.lower() in agent_text:
                keyword_matches += 1
        
        if rules['keywords']:
            keyword_score = (keyword_matches / len(rules['keywords'])) * 0.7
            score += keyword_score
        
        # Protocol matching
        if protocol in rules.get('protocols', []):
            score += 0.2
        
        # Data type inference (if available in metadata)
        data_type_keywords = rules.get('data_types', [])
        for data_type in data_type_keywords:
            if data_type.lower() in agent_text:
                score += 0.1
                break
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _criticality_priority(self, criticality: str) -> int:
        """Convert criticality to priority number for comparison"""
        priorities = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return priorities.get(criticality, 1)
    
    def _generate_reasoning(self, agent_data: Dict, primary_class: str, 
                          primary_rules: Dict, all_scores: Dict) -> List[str]:
        """Generate human-readable reasoning for classification"""
        reasons = []
        
        reasons.append(f"Primary classification: {primary_class.replace('_', ' ').title()}")
        reasons.append(f"Confidence: {all_scores[primary_class]:.2f}")
        reasons.append(f"Criticality: {primary_rules['criticality']}")
        
        # Keyword matches
        agent_text = self._extract_text_for_analysis(agent_data)
        matching_keywords = [kw for kw in primary_rules['keywords'] if kw.lower() in agent_text]
        if matching_keywords:
            reasons.append(f"Matched keywords: {', '.join(matching_keywords[:5])}")
        
        # Protocol match
        protocol = agent_data.get('protocol', '').lower()
        if protocol in primary_rules.get('protocols', []):
            reasons.append(f"Protocol match: {protocol}")
        
        return reasons
    
    def generate_agent_playbook(self, classification_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate automatic registration playbook based on classification"""
        frameworks = classification_result['applicable_frameworks']
        controls = classification_result['required_controls']
        criticality = classification_result['criticality_level']
        
        playbook_config = {
            'name': f"Auto-Generated {classification_result['primary_classification'].replace('_', ' ').title()} Playbook",
            'description': f"Automated registration for {classification_result['primary_classification']} agents",
            'trigger_conditions': {
                'agent_types': [classification_result['primary_classification']],
                'protocols': self._get_protocols_for_class(classification_result['primary_classification']),
                'automatic': True
            },
            'onboarding_steps': self._generate_onboarding_steps(controls, frameworks, criticality),
            'compliance_requirements': frameworks,
            'validation_rules': self._generate_validation_rules(controls),
            'notification_config': self._generate_notification_config(criticality),
            'auto_onboarding_enabled': True
        }
        
        return playbook_config
    
    def _get_protocols_for_class(self, class_type: str) -> List[str]:
        """Get protocols associated with a classification type"""
        if class_type in self.classification_rules:
            return self.classification_rules[class_type].get('protocols', [])
        return []
    
    def _generate_onboarding_steps(self, controls: List[str], frameworks: List[str], criticality: str) -> List[Dict]:
        """Generate onboarding steps based on required controls"""
        steps = [
            {
                'step': 'security_scan',
                'description': 'Perform comprehensive security assessment',
                'required': True,
                'timeout': 300
            },
            {
                'step': 'compliance_evaluation',
                'description': f'Evaluate compliance against {", ".join(frameworks)}',
                'required': True,
                'timeout': 180
            }
        ]
        
        # Add control-specific steps
        if 'encryption_at_rest' in controls:
            steps.append({
                'step': 'encryption_validation',
                'description': 'Verify encryption at rest implementation',
                'required': True,
                'timeout': 60
            })
        
        if 'access_control' in controls:
            steps.append({
                'step': 'access_control_setup',
                'description': 'Configure role-based access controls',
                'required': True,
                'timeout': 120
            })
        
        if 'phi_protection' in controls:
            steps.append({
                'step': 'phi_detection_scan',
                'description': 'Scan for PHI exposure and implement protection',
                'required': True,
                'timeout': 240
            })
        
        # High criticality agents need approval
        if criticality in ['high', 'critical']:
            steps.append({
                'step': 'manual_approval',
                'description': 'Require security team approval for high-criticality agent',
                'required': True,
                'timeout': 86400  # 24 hours
            })
        
        return steps
    
    def _generate_validation_rules(self, controls: List[str]) -> List[Dict]:
        """Generate validation rules based on required controls"""
        rules = [
            {
                'rule': 'endpoint_accessibility',
                'description': 'Verify agent endpoint is accessible',
                'type': 'connectivity'
            },
            {
                'rule': 'metadata_completeness',
                'description': 'Ensure required metadata fields are present',
                'type': 'data_quality'
            }
        ]
        
        if 'encryption_at_rest' in controls:
            rules.append({
                'rule': 'encryption_check',
                'description': 'Verify encryption is properly configured',
                'type': 'security'
            })
        
        if 'authentication' in controls:
            rules.append({
                'rule': 'auth_mechanism',
                'description': 'Validate authentication mechanism is in place',
                'type': 'security'
            })
        
        return rules
    
    def _generate_notification_config(self, criticality: str) -> Dict[str, Any]:
        """Generate notification configuration based on criticality"""
        config = {
            'channels': ['email'],
            'events': ['registration_complete', 'security_scan_complete'],
            'recipients': ['security-team@company.com']
        }
        
        if criticality in ['high', 'critical']:
            config['events'].extend(['high_risk_detected', 'compliance_violation'])
            config['recipients'].append('compliance-team@company.com')
            config['immediate_notify'] = True
        
        return config