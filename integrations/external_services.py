"""
External Service Integrations for Healthcare AI Compliance Platform

This module provides integration with external threat intelligence feeds,
compliance validation APIs, cloud security tools, and notification channels
to enhance the platform's capabilities with real-time external data.
"""

import asyncio
import json
import logging
import os
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

import requests


class ServiceType(Enum):
    """Types of external services"""
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE_API = "compliance_api"
    SECURITY_TOOL = "security_tool"
    NOTIFICATION = "notification"
    CLOUD_SECURITY = "cloud_security"


class ServiceStatus(Enum):
    """Service connection status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    UNAUTHORIZED = "unauthorized"


@dataclass
class ExternalService:
    """External service configuration"""
    service_id: str
    name: str
    service_type: ServiceType
    endpoint: str
    api_key_env: str
    enabled: bool = False
    rate_limit: int = 100  # requests per minute
    timeout: int = 30
    retry_attempts: int = 3
    status: ServiceStatus = ServiceStatus.INACTIVE


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    source: str
    threat_id: str
    threat_type: str
    severity: str
    description: str
    indicators: List[str]
    healthcare_relevant: bool
    published_at: datetime
    expires_at: Optional[datetime] = None


@dataclass
class ComplianceValidation:
    """External compliance validation result"""
    validator: str
    framework: str
    agent_id: str
    validation_result: bool
    confidence_score: float
    findings: List[str]
    recommendations: List[str]
    validated_at: datetime


class ExternalServiceIntegrator:
    """
    Manages integration with external services for enhanced platform capabilities
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.services = {}
        self.rate_limiters = {}
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Initialize all external services
        self.initialize_services()
        
        # Background task for service health monitoring
        self.monitoring_enabled = True
        
        self.logger.info("External Service Integrator initialized")
    
    def initialize_services(self):
        """Initialize all external service configurations"""
        
        # Threat Intelligence Services
        self.services["mitre_attack"] = ExternalService(
            service_id="mitre_attack",
            name="MITRE ATT&CK Framework",
            service_type=ServiceType.THREAT_INTELLIGENCE,
            endpoint="https://attack.mitre.org/api/",
            api_key_env="MITRE_API_KEY",
            enabled=True,
            rate_limit=60,
            timeout=15
        )
        
        self.services["cisa_advisories"] = ExternalService(
            service_id="cisa_advisories",
            name="CISA Cybersecurity Advisories",
            service_type=ServiceType.THREAT_INTELLIGENCE,
            endpoint="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            api_key_env="CISA_API_KEY",
            enabled=True,
            rate_limit=30,
            timeout=20
        )
        
        self.services["healthcare_isac"] = ExternalService(
            service_id="healthcare_isac",
            name="Healthcare Cybersecurity Coordination Center",
            service_type=ServiceType.THREAT_INTELLIGENCE,
            endpoint="https://api.healthsectorcouncil.org/threats",
            api_key_env="HEALTH_ISAC_API_KEY",
            enabled=False,  # Requires membership
            rate_limit=50,
            timeout=25
        )
        
        # Compliance Validation APIs
        self.services["hipaa_validator"] = ExternalService(
            service_id="hipaa_validator", 
            name="HIPAA Compliance Validator",
            service_type=ServiceType.COMPLIANCE_API,
            endpoint="https://api.hipaa-compliance.com/validate",
            api_key_env="HIPAA_VALIDATOR_API_KEY",
            enabled=False,
            rate_limit=20,
            timeout=30
        )
        
        self.services["gdpr_validator"] = ExternalService(
            service_id="gdpr_validator",
            name="GDPR Compliance Validator", 
            service_type=ServiceType.COMPLIANCE_API,
            endpoint="https://api.gdpr-compliance.eu/validate",
            api_key_env="GDPR_VALIDATOR_API_KEY",
            enabled=False,
            rate_limit=15,
            timeout=35
        )
        
        self.services["fda_validator"] = ExternalService(
            service_id="fda_validator",
            name="FDA Medical Device Validator",
            service_type=ServiceType.COMPLIANCE_API, 
            endpoint="https://api.fda.gov/device/validation",
            api_key_env="FDA_API_KEY",
            enabled=False,
            rate_limit=10,
            timeout=40
        )
        
        # Cloud Security Tools
        self.services["aws_security_hub"] = ExternalService(
            service_id="aws_security_hub",
            name="AWS Security Hub",
            service_type=ServiceType.CLOUD_SECURITY,
            endpoint="https://securityhub.amazonaws.com/",
            api_key_env="AWS_ACCESS_KEY_ID",
            enabled=False,
            rate_limit=100,
            timeout=20
        )
        
        self.services["azure_security_center"] = ExternalService(
            service_id="azure_security_center", 
            name="Azure Security Center",
            service_type=ServiceType.CLOUD_SECURITY,
            endpoint="https://management.azure.com/",
            api_key_env="AZURE_CLIENT_SECRET",
            enabled=False,
            rate_limit=80,
            timeout=25
        )
        
        self.services["gcp_security_command"] = ExternalService(
            service_id="gcp_security_command",
            name="Google Cloud Security Command Center", 
            service_type=ServiceType.CLOUD_SECURITY,
            endpoint="https://securitycenter.googleapis.com/",
            api_key_env="GOOGLE_APPLICATION_CREDENTIALS",
            enabled=False,
            rate_limit=60,
            timeout=30
        )
        
        # Notification Services
        self.services["slack_notifications"] = ExternalService(
            service_id="slack_notifications",
            name="Slack Notifications",
            service_type=ServiceType.NOTIFICATION,
            endpoint="https://hooks.slack.com/services/",
            api_key_env="SLACK_WEBHOOK_URL",
            enabled=False,
            rate_limit=200,
            timeout=10
        )
        
        self.services["email_notifications"] = ExternalService(
            service_id="email_notifications",
            name="Email Notifications",
            service_type=ServiceType.NOTIFICATION,
            endpoint="smtp://smtp.gmail.com:587",
            api_key_env="EMAIL_PASSWORD",
            enabled=False,
            rate_limit=50,
            timeout=15
        )
        
        # Enable services with available API keys
        self._check_service_availability()
    
    def _check_service_availability(self):
        """Check which services have API keys available and enable them"""
        for service_id, service in self.services.items():
            if os.getenv(service.api_key_env):
                service.enabled = True
                service.status = ServiceStatus.ACTIVE
                self.logger.info(f"Enabled external service: {service.name}")
            else:
                self.logger.debug(f"API key not available for {service.name}, service disabled")
    
    async def get_threat_intelligence(self, source: str = None) -> List[ThreatIntelligence]:
        """Fetch threat intelligence from configured sources"""
        threat_data = []
        
        # Determine which sources to query
        sources = [source] if source else ["mitre_attack", "cisa_advisories", "healthcare_isac"]
        
        for source_id in sources:
            if source_id not in self.services:
                continue
                
            service = self.services[source_id]
            if not service.enabled or service.status != ServiceStatus.ACTIVE:
                continue
            
            try:
                threats = await self._fetch_threat_intelligence(service)
                threat_data.extend(threats)
                
            except Exception as e:
                self.logger.error(f"Failed to fetch threat intelligence from {service.name}: {str(e)}")
        
        # Filter for healthcare-relevant threats
        healthcare_threats = [t for t in threat_data if t.healthcare_relevant]
        
        self.logger.info(f"Retrieved {len(threat_data)} threats, {len(healthcare_threats)} healthcare-relevant")
        return healthcare_threats
    
    async def _fetch_threat_intelligence(self, service: ExternalService) -> List[ThreatIntelligence]:
        """Fetch threat intelligence from specific source"""
        threats = []
        
        if service.service_id == "mitre_attack":
            threats = await self._fetch_mitre_threats(service)
        elif service.service_id == "cisa_advisories":
            threats = await self._fetch_cisa_threats(service)
        elif service.service_id == "healthcare_isac":
            threats = await self._fetch_healthcare_isac_threats(service)
        
        return threats
    
    async def _fetch_mitre_threats(self, service: ExternalService) -> List[ThreatIntelligence]:
        """Fetch threats from MITRE ATT&CK"""
        threats = []
        
        try:
            # Simulated MITRE threat data (in production, would call actual API)
            mock_mitre_threats = [
                {
                    "id": "T1566.001",
                    "name": "Spearphishing Attachment",
                    "description": "Healthcare targeted spearphishing with malicious attachments",
                    "severity": "high",
                    "healthcare_targeted": True,
                    "indicators": ["malicious_email_attachment", "healthcare_domain_spoofing"],
                    "published": "2024-01-15T10:00:00Z"
                },
                {
                    "id": "T1078.004", 
                    "name": "Cloud Accounts",
                    "description": "Compromised cloud accounts in healthcare infrastructure",
                    "severity": "critical",
                    "healthcare_targeted": True,
                    "indicators": ["cloud_account_compromise", "healthcare_cloud_abuse"],
                    "published": "2024-01-20T14:30:00Z"
                }
            ]
            
            for threat_data in mock_mitre_threats:
                threat = ThreatIntelligence(
                    source="MITRE ATT&CK",
                    threat_id=threat_data["id"],
                    threat_type="technique",
                    severity=threat_data["severity"],
                    description=threat_data["description"],
                    indicators=threat_data["indicators"],
                    healthcare_relevant=threat_data["healthcare_targeted"],
                    published_at=datetime.fromisoformat(threat_data["published"].replace('Z', '+00:00'))
                )
                threats.append(threat)
                
        except Exception as e:
            self.logger.error(f"Error fetching MITRE threats: {str(e)}")
        
        return threats
    
    async def _fetch_cisa_threats(self, service: ExternalService) -> List[ThreatIntelligence]:
        """Fetch threats from CISA advisories"""
        threats = []
        
        try:
            # Simulated CISA threat data
            mock_cisa_threats = [
                {
                    "cve_id": "CVE-2024-1234",
                    "title": "Healthcare Management System SQL Injection",
                    "severity": "critical",
                    "description": "SQL injection vulnerability in widely-used healthcare management systems",
                    "healthcare_impact": True,
                    "indicators": ["sql_injection", "healthcare_management_system"],
                    "published": "2024-01-25T09:00:00Z"
                }
            ]
            
            for threat_data in mock_cisa_threats:
                threat = ThreatIntelligence(
                    source="CISA",
                    threat_id=threat_data["cve_id"],
                    threat_type="vulnerability",
                    severity=threat_data["severity"],
                    description=threat_data["description"],
                    indicators=threat_data["indicators"],
                    healthcare_relevant=threat_data["healthcare_impact"],
                    published_at=datetime.fromisoformat(threat_data["published"].replace('Z', '+00:00'))
                )
                threats.append(threat)
                
        except Exception as e:
            self.logger.error(f"Error fetching CISA threats: {str(e)}")
        
        return threats
    
    async def _fetch_healthcare_isac_threats(self, service: ExternalService) -> List[ThreatIntelligence]:
        """Fetch threats from Healthcare ISAC"""
        threats = []
        
        try:
            # Simulated Healthcare ISAC threat data
            mock_healthcare_threats = [
                {
                    "alert_id": "HC-2024-001",
                    "title": "Ransomware Targeting Medical Devices",
                    "severity": "critical",
                    "description": "New ransomware variant specifically targeting connected medical devices",
                    "indicators": ["medical_device_ransomware", "iot_healthcare_compromise"],
                    "published": "2024-01-28T16:00:00Z"
                }
            ]
            
            for threat_data in mock_healthcare_threats:
                threat = ThreatIntelligence(
                    source="Healthcare ISAC",
                    threat_id=threat_data["alert_id"],
                    threat_type="ransomware",
                    severity=threat_data["severity"],
                    description=threat_data["description"],
                    indicators=threat_data["indicators"],
                    healthcare_relevant=True,  # All Healthcare ISAC threats are healthcare relevant
                    published_at=datetime.fromisoformat(threat_data["published"].replace('Z', '+00:00'))
                )
                threats.append(threat)
                
        except Exception as e:
            self.logger.error(f"Error fetching Healthcare ISAC threats: {str(e)}")
        
        return threats
    
    async def validate_compliance_external(self, agent_data: Dict[str, Any], framework: str) -> Optional[ComplianceValidation]:
        """Validate compliance using external validation services"""
        
        # Determine appropriate validator for framework
        validator_mapping = {
            "HIPAA": "hipaa_validator",
            "GDPR": "gdpr_validator", 
            "FDA": "fda_validator"
        }
        
        validator_id = validator_mapping.get(framework)
        if not validator_id or validator_id not in self.services:
            return None
        
        service = self.services[validator_id]
        if not service.enabled or service.status != ServiceStatus.ACTIVE:
            return None
        
        try:
            # Call external validation service
            validation_result = await self._call_compliance_validator(service, agent_data, framework)
            return validation_result
            
        except Exception as e:
            self.logger.error(f"External compliance validation failed for {framework}: {str(e)}")
            return None
    
    async def _call_compliance_validator(self, service: ExternalService, agent_data: Dict[str, Any], framework: str) -> ComplianceValidation:
        """Call external compliance validation service"""
        
        # Simulated external validation (in production, would call actual API)
        mock_validation_result = {
            "compliant": True,
            "confidence": 0.85,
            "findings": [
                "Access controls properly implemented",
                "Encryption standards meet requirements",
                "Audit logging configured correctly"
            ],
            "recommendations": [
                "Consider implementing additional monitoring",
                "Review access permissions quarterly"
            ]
        }
        
        validation = ComplianceValidation(
            validator=service.name,
            framework=framework,
            agent_id=agent_data.get("agent_id", "unknown"),
            validation_result=mock_validation_result["compliant"],
            confidence_score=mock_validation_result["confidence"],
            findings=mock_validation_result["findings"],
            recommendations=mock_validation_result["recommendations"],
            validated_at=datetime.utcnow()
        )
        
        return validation
    
    async def get_cloud_security_findings(self, cloud_provider: str = None) -> List[Dict[str, Any]]:
        """Fetch security findings from cloud security tools"""
        findings = []
        
        # Determine which cloud security services to query
        cloud_services = []
        if cloud_provider == "aws" or cloud_provider is None:
            cloud_services.append("aws_security_hub")
        if cloud_provider == "azure" or cloud_provider is None:
            cloud_services.append("azure_security_center") 
        if cloud_provider == "gcp" or cloud_provider is None:
            cloud_services.append("gcp_security_command")
        
        for service_id in cloud_services:
            if service_id not in self.services:
                continue
                
            service = self.services[service_id]
            if not service.enabled or service.status != ServiceStatus.ACTIVE:
                continue
            
            try:
                service_findings = await self._fetch_cloud_security_findings(service)
                findings.extend(service_findings)
                
            except Exception as e:
                self.logger.error(f"Failed to fetch findings from {service.name}: {str(e)}")
        
        return findings
    
    async def _fetch_cloud_security_findings(self, service: ExternalService) -> List[Dict[str, Any]]:
        """Fetch security findings from specific cloud security service"""
        
        # Simulated cloud security findings
        mock_findings = [
            {
                "finding_id": f"{service.service_id}_001",
                "severity": "high",
                "title": "Unencrypted healthcare data storage",
                "description": "Healthcare data stored without encryption",
                "resource": "s3://healthcare-data-bucket",
                "recommendation": "Enable S3 bucket encryption",
                "compliance_impact": ["HIPAA", "GDPR"]
            },
            {
                "finding_id": f"{service.service_id}_002", 
                "severity": "medium",
                "title": "Overly permissive IAM policy",
                "description": "IAM policy grants excessive permissions to healthcare AI service",
                "resource": "arn:aws:iam::123456789012:policy/HealthcareAIPolicy",
                "recommendation": "Apply principle of least privilege",
                "compliance_impact": ["HIPAA", "SOC2"]
            }
        ]
        
        return mock_findings
    
    async def send_notification(self, channel: str, message: str, severity: str = "info") -> bool:
        """Send notification through configured channels"""
        
        if channel not in self.services:
            self.logger.error(f"Unknown notification channel: {channel}")
            return False
        
        service = self.services[channel]
        if not service.enabled or service.status != ServiceStatus.ACTIVE:
            return False
        
        try:
            if channel == "slack_notifications":
                return await self._send_slack_notification(service, message, severity)
            elif channel == "email_notifications":
                return await self._send_email_notification(service, message, severity)
            
        except Exception as e:
            self.logger.error(f"Failed to send notification via {channel}: {str(e)}")
            return False
        
        return False
    
    async def _send_slack_notification(self, service: ExternalService, message: str, severity: str) -> bool:
        """Send Slack notification"""
        
        # Simulated Slack notification
        self.logger.info(f"[SLACK {severity.upper()}] {message}")
        return True
    
    async def _send_email_notification(self, service: ExternalService, message: str, severity: str) -> bool:
        """Send email notification"""
        
        # Simulated email notification  
        self.logger.info(f"[EMAIL {severity.upper()}] {message}")
        return True
    
    async def start_service_monitoring(self):
        """Start background monitoring of external services"""
        self.monitoring_enabled = True
        
        while self.monitoring_enabled:
            try:
                await self._monitor_service_health()
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Service monitoring error: {str(e)}")
                await asyncio.sleep(60)
    
    async def _monitor_service_health(self):
        """Monitor health of all external services"""
        for service_id, service in self.services.items():
            if not service.enabled:
                continue
            
            try:
                # Perform health check
                is_healthy = await self._health_check_service(service)
                
                if is_healthy:
                    service.status = ServiceStatus.ACTIVE
                else:
                    service.status = ServiceStatus.ERROR
                    self.logger.warning(f"Service {service.name} is not responding")
                    
            except Exception as e:
                service.status = ServiceStatus.ERROR
                self.logger.error(f"Health check failed for {service.name}: {str(e)}")
    
    async def _health_check_service(self, service: ExternalService) -> bool:
        """Perform health check on a service"""
        try:
            # Simple connectivity test (in production, would be more sophisticated)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(service.endpoint.split('/api')[0]) as response:
                    return response.status < 500
                    
        except Exception:
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all external services"""
        status_summary = {
            "total_services": len(self.services),
            "active_services": len([s for s in self.services.values() if s.status == ServiceStatus.ACTIVE]),
            "enabled_services": len([s for s in self.services.values() if s.enabled]),
            "services": {}
        }
        
        for service_id, service in self.services.items():
            status_summary["services"][service_id] = {
                "name": service.name,
                "type": service.service_type.value,
                "enabled": service.enabled,
                "status": service.status.value,
                "rate_limit": service.rate_limit
            }
        
        return status_summary


# Global instance
external_service_integrator = ExternalServiceIntegrator()