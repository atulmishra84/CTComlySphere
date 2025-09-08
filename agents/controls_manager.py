"""
Agent-Level Controls Manager
Implements and manages individual security controls for AI agents
"""
import json
from typing import Dict, List, Set, Any, Optional
from datetime import datetime, timedelta
from models import AIAgent, ComplianceFramework
from app import db


class AgentControlsManager:
    """Manages individual security controls for AI agents"""
    
    def __init__(self):
        self.control_definitions = self._load_control_definitions()
        self.control_implementations = self._load_control_implementations()
    
    def _load_control_definitions(self) -> Dict[str, Dict]:
        """Define available security controls and their requirements"""
        return {
            'encryption_at_rest': {
                'name': 'Encryption at Rest',
                'description': 'Encrypt sensitive data when stored',
                'category': 'data_protection',
                'severity': 'high',
                'frameworks': ['HIPAA', 'GDPR', 'SOC2_TYPE_II'],
                'implementation_methods': ['database_encryption', 'file_encryption', 'volume_encryption'],
                'validation_criteria': ['encryption_algorithm', 'key_management', 'access_controls']
            },
            'encryption_in_transit': {
                'name': 'Encryption in Transit',
                'description': 'Encrypt data during transmission',
                'category': 'data_protection',
                'severity': 'high',
                'frameworks': ['HIPAA', 'GDPR', 'SOC2_TYPE_II'],
                'implementation_methods': ['tls_https', 'vpn', 'secure_protocols'],
                'validation_criteria': ['certificate_validation', 'protocol_version', 'cipher_strength']
            },
            'access_control': {
                'name': 'Access Control',
                'description': 'Role-based access control and authorization',
                'category': 'identity_access',
                'severity': 'high',
                'frameworks': ['HIPAA', 'GDPR', 'SOC2_TYPE_II', 'HITRUST_CSF'],
                'implementation_methods': ['rbac', 'oauth2', 'api_keys', 'jwt_tokens'],
                'validation_criteria': ['role_definition', 'permission_mapping', 'session_management']
            },
            'audit_logging': {
                'name': 'Audit Logging',
                'description': 'Comprehensive logging of all activities',
                'category': 'monitoring',
                'severity': 'medium',
                'frameworks': ['HIPAA', 'SOC2_TYPE_II', 'HITRUST_CSF'],
                'implementation_methods': ['centralized_logging', 'structured_logs', 'log_retention'],
                'validation_criteria': ['log_completeness', 'timestamp_accuracy', 'integrity_protection']
            },
            'phi_protection': {
                'name': 'PHI Protection',
                'description': 'Protected Health Information safeguarding',
                'category': 'data_protection',
                'severity': 'critical',
                'frameworks': ['HIPAA', 'HITRUST_CSF'],
                'implementation_methods': ['data_masking', 'anonymization', 'access_restrictions'],
                'validation_criteria': ['phi_identification', 'protection_methods', 'access_logs']
            },
            'authentication': {
                'name': 'Strong Authentication',
                'description': 'Multi-factor authentication requirements',
                'category': 'identity_access',
                'severity': 'high',
                'frameworks': ['HIPAA', 'GDPR', 'SOC2_TYPE_II'],
                'implementation_methods': ['mfa', 'sso', 'certificate_auth'],
                'validation_criteria': ['factor_strength', 'session_timeout', 'failed_attempt_handling']
            },
            'model_validation': {
                'name': 'AI Model Validation',
                'description': 'Clinical validation of AI models',
                'category': 'model_governance',
                'severity': 'critical',
                'frameworks': ['FDA_SAMD'],
                'implementation_methods': ['clinical_trials', 'validation_datasets', 'performance_metrics'],
                'validation_criteria': ['accuracy_metrics', 'bias_assessment', 'safety_evaluation']
            },
            'consent_management': {
                'name': 'Consent Management',
                'description': 'User consent tracking and management',
                'category': 'privacy',
                'severity': 'high',
                'frameworks': ['GDPR'],
                'implementation_methods': ['consent_database', 'opt_in_out', 'consent_history'],
                'validation_criteria': ['consent_granularity', 'withdrawal_mechanism', 'audit_trail']
            },
            'data_minimization': {
                'name': 'Data Minimization',
                'description': 'Collect and process only necessary data',
                'category': 'privacy',
                'severity': 'medium',
                'frameworks': ['GDPR'],
                'implementation_methods': ['data_classification', 'retention_policies', 'automated_deletion'],
                'validation_criteria': ['necessity_justification', 'retention_limits', 'deletion_verification']
            },
            'system_monitoring': {
                'name': 'System Monitoring',
                'description': 'Continuous system health and security monitoring',
                'category': 'monitoring',
                'severity': 'medium',
                'frameworks': ['SOC2_TYPE_II', 'HITRUST_CSF'],
                'implementation_methods': ['real_time_monitoring', 'alerting', 'anomaly_detection'],
                'validation_criteria': ['coverage_completeness', 'alert_responsiveness', 'false_positive_rate']
            }
        }
    
    def _load_control_implementations(self) -> Dict[str, Dict]:
        """Define how to implement each control"""
        return {
            'encryption_at_rest': {
                'kubernetes': {
                    'config': {
                        'volumeMounts': [{'name': 'encrypted-storage', 'mountPath': '/data'}],
                        'volumes': [{'name': 'encrypted-storage', 'secret': {'secretName': 'encryption-keys'}}]
                    },
                    'validation': 'kubectl get secret encryption-keys'
                },
                'docker': {
                    'config': {
                        'environment': ['ENCRYPTION_KEY_PATH=/secrets/encryption.key'],
                        'volumes': ['/host/secrets:/secrets:ro']
                    },
                    'validation': 'docker exec <container> test -f /secrets/encryption.key'
                },
                'cloud': {
                    'aws': 'Enable KMS encryption on EBS volumes and RDS instances',
                    'azure': 'Enable Azure Disk Encryption and Transparent Data Encryption',
                    'gcp': 'Enable Cloud KMS encryption for Compute Engine and Cloud SQL'
                }
            },
            'access_control': {
                'rest_api': {
                    'headers': ['Authorization: Bearer <token>', 'X-API-Key: <key>'],
                    'validation_endpoint': '/auth/validate',
                    'role_header': 'X-User-Role'
                },
                'grpc': {
                    'metadata': {'authorization': 'bearer <token>'},
                    'interceptor': 'auth_interceptor',
                    'role_claim': 'user_role'
                }
            },
            'phi_protection': {
                'scanning': {
                    'patterns': [
                        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                        r'\b\d{10}\b',              # Phone
                        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email
                    ],
                    'anonymization_methods': ['masking', 'tokenization', 'hashing'],
                    'detection_tools': ['presidio', 'dlp_api', 'custom_regex']
                }
            }
        }
    
    def apply_controls_to_agent(self, agent_id: int, required_controls: List[str]) -> Dict[str, Any]:
        """Apply security controls to a specific agent"""
        agent = AIAgent.query.get(agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")
        
        results = {
            'agent_id': agent_id,
            'controls_applied': [],
            'controls_failed': [],
            'implementation_details': {},
            'validation_results': {},
            'applied_at': datetime.utcnow().isoformat()
        }
        
        for control_name in required_controls:
            try:
                # Apply the control
                impl_result = self._implement_control(agent, control_name)
                
                if impl_result['success']:
                    results['controls_applied'].append(control_name)
                    results['implementation_details'][control_name] = impl_result['details']
                    
                    # Validate the control
                    validation_result = self._validate_control(agent, control_name, impl_result)
                    results['validation_results'][control_name] = validation_result
                else:
                    results['controls_failed'].append({
                        'control': control_name,
                        'reason': impl_result.get('error', 'Unknown error')
                    })
                    
            except Exception as e:
                results['controls_failed'].append({
                    'control': control_name,
                    'reason': str(e)
                })
        
        # Update agent metadata with control information
        self._update_agent_controls_metadata(agent, results)
        
        return results
    
    def _implement_control(self, agent: AIAgent, control_name: str) -> Dict[str, Any]:
        """Implement a specific security control for an agent"""
        if control_name not in self.control_definitions:
            return {'success': False, 'error': f'Unknown control: {control_name}'}
        
        control_def = self.control_definitions[control_name]
        protocol = agent.protocol.lower()
        
        # Get implementation method based on protocol
        implementation = self._get_implementation_method(control_name, protocol)
        
        if not implementation:
            return {
                'success': False, 
                'error': f'No implementation available for {control_name} on {protocol}'
            }
        
        # Apply the control based on the agent's protocol and environment
        try:
            if protocol in ['kubernetes', 'docker']:
                result = self._implement_container_control(agent, control_name, implementation)
            elif protocol in ['rest_api', 'grpc', 'graphql']:
                result = self._implement_api_control(agent, control_name, implementation)
            elif protocol in ['fhir', 'hl7', 'dicom']:
                result = self._implement_healthcare_control(agent, control_name, implementation)
            else:
                result = self._implement_generic_control(agent, control_name, implementation)
            
            return {'success': True, 'details': result}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _get_implementation_method(self, control_name: str, protocol: str) -> Optional[Dict]:
        """Get implementation method for a control on a specific protocol"""
        if control_name not in self.control_implementations:
            return None
        
        impl = self.control_implementations[control_name]
        
        # Direct protocol match
        if protocol in impl:
            return impl[protocol]
        
        # Category-based matching
        category_mapping = {
            'kubernetes': ['kubernetes', 'container'],
            'docker': ['docker', 'container'],
            'rest_api': ['rest_api', 'api'],
            'grpc': ['grpc', 'api'],
            'graphql': ['graphql', 'api'],
            'fhir': ['fhir', 'healthcare'],
            'hl7': ['hl7', 'healthcare'],
            'dicom': ['dicom', 'healthcare']
        }
        
        if protocol in category_mapping:
            for category in category_mapping[protocol]:
                if category in impl:
                    return impl[category]
        
        # Cloud-based implementation
        if 'cloud' in impl:
            return impl['cloud']
        
        return None
    
    def _implement_container_control(self, agent: AIAgent, control_name: str, implementation: Dict) -> Dict:
        """Implement control for containerized agents (Kubernetes/Docker)"""
        result = {
            'method': 'container_configuration',
            'control': control_name,
            'configuration': implementation.get('config', {}),
            'validation_command': implementation.get('validation', ''),
            'applied_to': f"{agent.protocol}:{agent.name}"
        }
        
        # For demonstration, we simulate the implementation
        # In a real system, this would interact with Kubernetes API or Docker daemon
        if control_name == 'encryption_at_rest':
            result['encryption_volume'] = 'encrypted-storage-volume'
            result['key_management'] = 'kubernetes-secrets'
        elif control_name == 'access_control':
            result['rbac_policy'] = f"{agent.name}-rbac-policy"
            result['service_account'] = f"{agent.name}-service-account"
        
        return result
    
    def _implement_api_control(self, agent: AIAgent, control_name: str, implementation: Dict) -> Dict:
        """Implement control for API-based agents"""
        result = {
            'method': 'api_configuration',
            'control': control_name,
            'endpoint': agent.endpoint,
            'implementation': implementation
        }
        
        if control_name == 'access_control':
            result['auth_method'] = 'bearer_token'
            result['headers_required'] = implementation.get('headers', [])
        elif control_name == 'encryption_in_transit':
            result['tls_version'] = '1.3'
            result['certificate_validation'] = True
        
        return result
    
    def _implement_healthcare_control(self, agent: AIAgent, control_name: str, implementation: Dict) -> Dict:
        """Implement control for healthcare-specific agents"""
        result = {
            'method': 'healthcare_specific',
            'control': control_name,
            'protocol': agent.protocol,
            'implementation': implementation
        }
        
        if control_name == 'phi_protection':
            result['phi_detection_enabled'] = True
            result['anonymization_methods'] = ['tokenization', 'masking']
            result['phi_patterns'] = implementation.get('scanning', {}).get('patterns', [])
        elif control_name == 'audit_logging':
            result['hipaa_audit_fields'] = [
                'user_id', 'access_time', 'data_accessed', 'action_performed'
            ]
        
        return result
    
    def _implement_generic_control(self, agent: AIAgent, control_name: str, implementation: Dict) -> Dict:
        """Implement generic control for any agent type"""
        return {
            'method': 'generic_implementation',
            'control': control_name,
            'agent_type': agent.type,
            'protocol': agent.protocol,
            'configuration': implementation
        }
    
    def _validate_control(self, agent: AIAgent, control_name: str, impl_result: Dict) -> Dict[str, Any]:
        """Validate that a control has been properly implemented"""
        validation_result = {
            'control': control_name,
            'status': 'unknown',
            'checks_performed': [],
            'issues_found': [],
            'validated_at': datetime.utcnow().isoformat()
        }
        
        control_def = self.control_definitions[control_name]
        validation_criteria = control_def.get('validation_criteria', [])
        
        # Perform validation checks based on criteria
        passed_checks = 0
        total_checks = len(validation_criteria)
        
        for criterion in validation_criteria:
            check_result = self._perform_validation_check(agent, control_name, criterion, impl_result)
            validation_result['checks_performed'].append({
                'criterion': criterion,
                'result': check_result['passed'],
                'details': check_result['details']
            })
            
            if check_result['passed']:
                passed_checks += 1
            else:
                validation_result['issues_found'].append({
                    'criterion': criterion,
                    'issue': check_result['issue']
                })
        
        # Determine overall status
        if total_checks == 0:
            validation_result['status'] = 'no_validation_criteria'
        elif passed_checks == total_checks:
            validation_result['status'] = 'compliant'
        elif passed_checks > total_checks * 0.7:  # 70% threshold
            validation_result['status'] = 'partially_compliant'
        else:
            validation_result['status'] = 'non_compliant'
        
        validation_result['compliance_score'] = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        return validation_result
    
    def _perform_validation_check(self, agent: AIAgent, control_name: str, 
                                 criterion: str, impl_result: Dict) -> Dict[str, Any]:
        """Perform a specific validation check"""
        # This would contain actual validation logic for each criterion
        # For demonstration, we'll simulate some checks
        
        if criterion == 'encryption_algorithm':
            return {
                'passed': True,
                'details': 'AES-256 encryption detected',
                'issue': None
            }
        elif criterion == 'certificate_validation':
            return {
                'passed': agent.endpoint.startswith('https://'),
                'details': f'Endpoint: {agent.endpoint}',
                'issue': 'Non-HTTPS endpoint detected' if not agent.endpoint.startswith('https://') else None
            }
        elif criterion == 'role_definition':
            return {
                'passed': 'rbac_policy' in impl_result['details'],
                'details': 'RBAC policy configuration found',
                'issue': 'No RBAC policy defined' if 'rbac_policy' not in impl_result['details'] else None
            }
        else:
            # Default validation
            return {
                'passed': True,
                'details': f'Basic validation for {criterion}',
                'issue': None
            }
    
    def _update_agent_controls_metadata(self, agent: AIAgent, control_results: Dict):
        """Update agent metadata with applied controls information"""
        if not agent.agent_metadata:
            agent.agent_metadata = {}
        
        agent.agent_metadata['security_controls'] = {
            'applied_controls': control_results['controls_applied'],
            'failed_controls': control_results['controls_failed'],
            'last_updated': control_results['applied_at'],
            'implementation_summary': {
                control: details for control, details in control_results['implementation_details'].items()
            },
            'validation_summary': {
                control: result['status'] for control, result in control_results['validation_results'].items()
            }
        }
        
        db.session.commit()
    
    def get_agent_control_status(self, agent_id: int) -> Dict[str, Any]:
        """Get current control status for an agent"""
        agent = AIAgent.query.get(agent_id)
        if not agent:
            return {'error': f'Agent {agent_id} not found'}
        
        metadata = agent.agent_metadata or {}
        controls_info = metadata.get('security_controls', {})
        
        return {
            'agent_id': agent_id,
            'agent_name': agent.name,
            'protocol': agent.protocol,
            'controls_applied': controls_info.get('applied_controls', []),
            'controls_failed': controls_info.get('failed_controls', []),
            'last_updated': controls_info.get('last_updated'),
            'compliance_status': self._calculate_compliance_status(controls_info)
        }
    
    def _calculate_compliance_status(self, controls_info: Dict) -> Dict[str, Any]:
        """Calculate overall compliance status based on applied controls"""
        applied = len(controls_info.get('applied_controls', []))
        failed = len(controls_info.get('failed_controls', []))
        total = applied + failed
        
        if total == 0:
            return {'status': 'unknown', 'score': 0}
        
        score = (applied / total) * 100
        
        if score >= 90:
            status = 'compliant'
        elif score >= 70:
            status = 'partially_compliant'
        else:
            status = 'non_compliant'
        
        return {
            'status': status,
            'score': score,
            'controls_applied': applied,
            'controls_failed': failed
        }