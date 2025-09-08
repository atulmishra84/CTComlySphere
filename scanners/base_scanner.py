from abc import ABC, abstractmethod
from datetime import datetime
import logging
from typing import Dict, List, Optional, Any

class BaseScanner(ABC):
    """Abstract base class for all protocol scanners"""
    
    def __init__(self, scanner_type=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.scan_start_time = None
        self.scan_end_time = None
        self.scanner_type = scanner_type
        self.last_scan_duration = 0
        self.scan_statistics = {
            "total_scans": 0,
            "successful_scans": 0,
            "agents_discovered": 0,
            "errors": 0
        }
    
    @abstractmethod
    def scan(self):
        """Perform the actual scanning operation"""
        pass
    
    @abstractmethod
    def discover_agents(self, target=None):
        """Discover AI agents using this protocol"""
        pass
    
    def start_scan(self):
        """Initialize scan timing"""
        self.scan_start_time = datetime.utcnow()
        self.logger.info(f"Starting {self.__class__.__name__} scan")
    
    def end_scan(self):
        """Finalize scan timing"""
        self.scan_end_time = datetime.utcnow()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        self.logger.info(f"Completed {self.__class__.__name__} scan in {duration:.2f} seconds")
        return duration
    
    def calculate_risk_score(self, vulnerabilities, phi_exposure, encryption_status, additional_factors=None):
        """Enhanced risk calculation with advanced threat assessment"""
        base_score = 0
        
        # Enhanced vulnerability scoring with severity weighting
        if isinstance(vulnerabilities, dict):
            critical_vulns = vulnerabilities.get('critical', 0)
            high_vulns = vulnerabilities.get('high', 0)
            medium_vulns = vulnerabilities.get('medium', 0)
            low_vulns = vulnerabilities.get('low', 0)
            
            base_score += min(critical_vulns * 25, 50)  # Critical vulnerabilities
            base_score += min(high_vulns * 15, 30)      # High vulnerabilities
            base_score += min(medium_vulns * 8, 15)     # Medium vulnerabilities
            base_score += min(low_vulns * 3, 5)         # Low vulnerabilities
        else:
            # Legacy numeric vulnerability count
            base_score += min(vulnerabilities * 10, 50)
        
        # Enhanced PHI exposure assessment
        if phi_exposure:
            if isinstance(phi_exposure, dict):
                exposure_level = phi_exposure.get('level', 'unknown')
                if exposure_level == 'direct_access':
                    base_score += 45
                elif exposure_level == 'indirect_access':
                    base_score += 30
                elif exposure_level == 'potential_exposure':
                    base_score += 15
                else:
                    base_score += 40  # Default for unknown exposure
            else:
                base_score += 40  # Legacy boolean PHI exposure
        
        # Enhanced encryption assessment
        if encryption_status == 'none':
            base_score += 25
        elif encryption_status == 'weak':
            base_score += 15
        elif encryption_status == 'deprecated':
            base_score += 20
        elif encryption_status == 'strong':
            base_score += 0  # No penalty for strong encryption
        
        # Additional security factors
        if additional_factors:
            # AI/ML specific risks
            if additional_factors.get('model_poisoning_risk', False):
                base_score += 20
            if additional_factors.get('adversarial_attack_risk', False):
                base_score += 15
            if additional_factors.get('data_poisoning_risk', False):
                base_score += 18
            
            # Compliance specific factors
            if additional_factors.get('regulatory_violations', 0) > 0:
                base_score += min(additional_factors['regulatory_violations'] * 10, 25)
            
            # Network exposure
            if additional_factors.get('internet_exposed', False):
                base_score += 15
            
            # Authentication weaknesses
            if additional_factors.get('weak_authentication', False):
                base_score += 12
        
        # Cap at 100
        return min(base_score, 100)
    
    def determine_risk_level(self, risk_score, context=None):
        """Enhanced risk level determination with contextual awareness"""
        # Base risk level determination
        if risk_score >= 85:
            base_level = 'CRITICAL'
        elif risk_score >= 70:
            base_level = 'HIGH'
        elif risk_score >= 40:
            base_level = 'MEDIUM'
        elif risk_score >= 15:
            base_level = 'LOW'
        else:
            base_level = 'MINIMAL'
        
        # Contextual risk adjustment
        if context:
            # Healthcare-specific context
            if context.get('healthcare_critical', False):
                if base_level == 'HIGH':
                    base_level = 'CRITICAL'
                elif base_level == 'MEDIUM':
                    base_level = 'HIGH'
            
            # Production system context
            if context.get('production_system', False):
                if base_level in ['MEDIUM', 'LOW']:
                    base_level = 'HIGH'
            
            # Regulatory compliance context
            if context.get('regulatory_scope', False):
                if base_level == 'MEDIUM':
                    base_level = 'HIGH'
        
        return base_level
    
    def enhanced_security_scan(self, agent_data):
        """Perform enhanced security scanning with advanced threat detection"""
        security_findings = {
            'vulnerabilities': self._scan_vulnerabilities(agent_data),
            'phi_exposure': self._assess_phi_exposure(agent_data),
            'encryption_status': self._check_encryption(agent_data),
            'authentication': self._analyze_authentication(agent_data),
            'network_exposure': self._assess_network_exposure(agent_data),
            'compliance_violations': self._check_compliance_violations(agent_data),
            'ai_ml_risks': self._assess_ai_ml_risks(agent_data)
        }
        
        return security_findings
    
    def _scan_vulnerabilities(self, agent_data):
        """Advanced vulnerability scanning"""
        vulnerabilities = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'details': []
        }
        
        # Check for common vulnerabilities
        if agent_data.get('api_exposed', False):
            if not agent_data.get('authentication_required', True):
                vulnerabilities['critical'] += 1
                vulnerabilities['details'].append('Unauthenticated API exposure')
        
        if agent_data.get('default_credentials', False):
            vulnerabilities['high'] += 1
            vulnerabilities['details'].append('Default credentials detected')
        
        if agent_data.get('unencrypted_data', False):
            vulnerabilities['high'] += 1
            vulnerabilities['details'].append('Unencrypted sensitive data')
        
        return vulnerabilities
    
    def _assess_phi_exposure(self, agent_data):
        """Enhanced PHI exposure assessment"""
        phi_assessment = {
            'exposed': False,
            'level': 'none',
            'risk_factors': []
        }
        
        # Check for PHI processing indicators
        if agent_data.get('processes_patient_data', False):
            phi_assessment['exposed'] = True
            phi_assessment['level'] = 'direct_access'
            phi_assessment['risk_factors'].append('Direct patient data processing')
        
        if agent_data.get('healthcare_context', False):
            phi_assessment['exposed'] = True
            phi_assessment['level'] = 'potential_exposure'
            phi_assessment['risk_factors'].append('Healthcare context detected')
        
        return phi_assessment
    
    def _check_encryption(self, agent_data):
        """Enhanced encryption status checking"""
        if agent_data.get('encryption_at_rest', False) and agent_data.get('encryption_in_transit', False):
            return 'strong'
        elif agent_data.get('encryption_at_rest', False) or agent_data.get('encryption_in_transit', False):
            return 'partial'
        elif agent_data.get('weak_encryption', False):
            return 'weak'
        else:
            return 'none'
    
    def _analyze_authentication(self, agent_data):
        """Analyze authentication mechanisms"""
        auth_analysis = {
            'strength': 'unknown',
            'multi_factor': False,
            'issues': []
        }
        
        if agent_data.get('no_authentication', False):
            auth_analysis['strength'] = 'none'
            auth_analysis['issues'].append('No authentication required')
        elif agent_data.get('weak_passwords', False):
            auth_analysis['strength'] = 'weak'
            auth_analysis['issues'].append('Weak password requirements')
        elif agent_data.get('strong_authentication', False):
            auth_analysis['strength'] = 'strong'
            auth_analysis['multi_factor'] = agent_data.get('mfa_enabled', False)
        
        return auth_analysis
    
    def _assess_network_exposure(self, agent_data):
        """Assess network exposure risks"""
        exposure = {
            'internet_exposed': agent_data.get('internet_accessible', False),
            'internal_only': agent_data.get('internal_network_only', True),
            'firewall_protected': agent_data.get('firewall_enabled', False),
            'vpn_required': agent_data.get('vpn_access_required', False)
        }
        
        return exposure
    
    def _check_compliance_violations(self, agent_data):
        """Check for regulatory compliance violations"""
        violations = []
        
        # HIPAA checks
        if agent_data.get('healthcare_context', False):
            if not agent_data.get('audit_logging', False):
                violations.append('HIPAA: Missing audit logging')
            if not agent_data.get('access_controls', False):
                violations.append('HIPAA: Insufficient access controls')
        
        # FDA checks for medical devices
        if agent_data.get('medical_device', False):
            if not agent_data.get('clinical_validation', False):
                violations.append('FDA: Missing clinical validation')
        
        return violations
    
    def _assess_ai_ml_risks(self, agent_data):
        """Assess AI/ML specific security risks"""
        ai_risks = {
            'model_poisoning': agent_data.get('model_update_mechanism', False) and not agent_data.get('model_integrity_checks', False),
            'adversarial_attacks': agent_data.get('public_api', False) and not agent_data.get('input_validation', True),
            'data_poisoning': agent_data.get('online_learning', False) and not agent_data.get('data_validation', False),
            'model_extraction': agent_data.get('model_accessible', False) and not agent_data.get('model_protection', False)
        }
        
        return ai_risks
