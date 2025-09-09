"""
Integration Configuration Manager
Manages custom configuration settings for all integration types based on customer needs
"""
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict, field
from enum import Enum

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    KUBERNETES = "kubernetes"
    DOCKER = "docker"
    MCP = "mcp"


class MonitoringLevel(Enum):
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"


@dataclass
class KubernetesConfig:
    """Kubernetes integration configuration"""
    enabled: bool = True
    cluster_endpoints: List[str] = field(default_factory=lambda: ["default"])
    namespaces_to_monitor: List[str] = field(default_factory=lambda: ["default", "kube-system"])
    exclude_namespaces: List[str] = field(default_factory=lambda: ["kube-public"])
    authentication_method: str = "in_cluster"  # in_cluster, kubeconfig, service_account
    kubeconfig_path: str = "~/.kube/config"
    service_account_token: str = ""
    monitoring_level: str = "standard"
    scan_interval_minutes: int = 15
    ai_labels: List[str] = field(default_factory=lambda: ["ai.framework", "ml.model", "ai.type"])
    ai_annotations: List[str] = field(default_factory=lambda: ["healthcare.compliance", "model.version"])
    resource_monitoring: bool = True
    event_monitoring: bool = True
    custom_selectors: Dict[str, str] = field(default_factory=dict)


@dataclass
class DockerConfig:
    """Docker integration configuration"""
    enabled: bool = True
    daemon_endpoints: List[str] = field(default_factory=lambda: ["unix:///var/run/docker.sock"])
    registries_to_monitor: List[str] = field(default_factory=lambda: ["docker.io", "ghcr.io"])
    container_filters: Dict[str, List[str]] = field(default_factory=lambda: {
        "ai_images": ["tensorflow", "pytorch", "scikit-learn", "huggingface"],
        "exclude_images": ["nginx", "redis", "postgres"]
    })
    monitoring_level: str = "standard"
    scan_interval_minutes: int = 10
    ai_labels: List[str] = field(default_factory=lambda: ["ai.type", "ml.framework", "healthcare.phi"])
    log_monitoring: bool = True
    stats_monitoring: bool = True
    security_scanning: bool = True
    max_log_lines: int = 1000
    custom_image_patterns: List[str] = field(default_factory=list)


@dataclass
class MCPConfig:
    """MCP integration configuration"""
    enabled: bool = True
    server_endpoints: List[str] = field(default_factory=lambda: [
        "http://clinical-ai-assistant:11434/mcp/v1",
        "http://radiology-multiagent:8080/api/mcp",
        "http://research-coordinator:3000/context/protocol"
    ])
    protocol_versions: List[str] = field(default_factory=lambda: ["1.0", "1.1"])
    authentication_methods: List[str] = field(default_factory=lambda: ["bearer_token", "api_key"])
    monitoring_level: str = "comprehensive"
    scan_interval_minutes: int = 5
    context_flow_monitoring: bool = True
    context_window_threshold: int = 50000  # Alert when context usage exceeds this
    phi_monitoring: bool = True
    multiagent_discovery: bool = True
    compression_monitoring: bool = True
    response_time_threshold_ms: int = 200
    custom_capabilities: List[str] = field(default_factory=list)


@dataclass
class GeneralConfig:
    """General integration configuration"""
    auto_discovery: bool = True
    real_time_alerts: bool = True
    security_scanning: bool = True
    compliance_validation: bool = True
    data_retention_days: int = 30
    alert_thresholds: Dict[str, Any] = field(default_factory=lambda: {
        "high_cpu_percent": 80,
        "high_memory_percent": 85,
        "response_time_ms": 1000,
        "error_rate_percent": 5
    })
    notification_channels: List[str] = field(default_factory=lambda: ["email", "webhook"])
    timezone: str = "UTC"
    log_level: str = "INFO"


@dataclass
class IntegrationConfiguration:
    """Complete integration configuration"""
    kubernetes: KubernetesConfig = field(default_factory=KubernetesConfig)
    docker: DockerConfig = field(default_factory=DockerConfig)
    mcp: MCPConfig = field(default_factory=MCPConfig)
    general: GeneralConfig = field(default_factory=GeneralConfig)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "1.0"


class IntegrationConfigManager:
    """Manages integration configuration settings"""
    
    def __init__(self, config_file: str = "config/integrations.json"):
        self.config_file = config_file
        self.config_dir = os.path.dirname(config_file)
        self._ensure_config_dir()
        self._config: Optional[IntegrationConfiguration] = None
        self.load_configuration()
    
    def _ensure_config_dir(self):
        """Ensure configuration directory exists"""
        if self.config_dir and not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, exist_ok=True)
    
    def load_configuration(self) -> IntegrationConfiguration:
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Convert dict to dataclass
                self._config = IntegrationConfiguration(
                    kubernetes=KubernetesConfig(**config_data.get('kubernetes', {})),
                    docker=DockerConfig(**config_data.get('docker', {})),
                    mcp=MCPConfig(**config_data.get('mcp', {})),
                    general=GeneralConfig(**config_data.get('general', {})),
                    created_at=config_data.get('created_at', datetime.utcnow().isoformat()),
                    updated_at=config_data.get('updated_at', datetime.utcnow().isoformat()),
                    version=config_data.get('version', '1.0')
                )
                
                logger.info(f"Loaded integration configuration from {self.config_file}")
            else:
                # Create default configuration
                self._config = IntegrationConfiguration()
                self.save_configuration()
                logger.info("Created default integration configuration")
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self._config = IntegrationConfiguration()
        
        return self._config
    
    def save_configuration(self, config: Optional[IntegrationConfiguration] = None) -> bool:
        """Save configuration to file"""
        try:
            if config:
                self._config = config
            
            if not self._config:
                return False
            
            # Update timestamp
            self._config.updated_at = datetime.utcnow().isoformat()
            
            # Convert to dict
            config_dict = asdict(self._config)
            
            # Save to file
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            logger.info(f"Saved integration configuration to {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get_configuration(self) -> IntegrationConfiguration:
        """Get current configuration"""
        if not self._config:
            self.load_configuration()
        return self._config
    
    def update_kubernetes_config(self, **kwargs) -> bool:
        """Update Kubernetes configuration"""
        try:
            if not self._config:
                self.load_configuration()
            
            for key, value in kwargs.items():
                if hasattr(self._config.kubernetes, key):
                    setattr(self._config.kubernetes, key, value)
            
            return self.save_configuration()
        except Exception as e:
            logger.error(f"Failed to update Kubernetes config: {e}")
            return False
    
    def update_docker_config(self, **kwargs) -> bool:
        """Update Docker configuration"""
        try:
            if not self._config:
                self.load_configuration()
            
            for key, value in kwargs.items():
                if hasattr(self._config.docker, key):
                    setattr(self._config.docker, key, value)
            
            return self.save_configuration()
        except Exception as e:
            logger.error(f"Failed to update Docker config: {e}")
            return False
    
    def update_mcp_config(self, **kwargs) -> bool:
        """Update MCP configuration"""
        try:
            if not self._config:
                self.load_configuration()
            
            for key, value in kwargs.items():
                if hasattr(self._config.mcp, key):
                    setattr(self._config.mcp, key, value)
            
            return self.save_configuration()
        except Exception as e:
            logger.error(f"Failed to update MCP config: {e}")
            return False
    
    def update_general_config(self, **kwargs) -> bool:
        """Update general configuration"""
        try:
            if not self._config:
                self.load_configuration()
            
            for key, value in kwargs.items():
                if hasattr(self._config.general, key):
                    setattr(self._config.general, key, value)
            
            return self.save_configuration()
        except Exception as e:
            logger.error(f"Failed to update general config: {e}")
            return False
    
    def validate_configuration(self, config: IntegrationConfiguration) -> Dict[str, List[str]]:
        """Validate configuration and return errors"""
        errors = {
            'kubernetes': [],
            'docker': [],
            'mcp': [],
            'general': []
        }
        
        # Validate Kubernetes config
        k8s = config.kubernetes
        if k8s.enabled:
            if not k8s.cluster_endpoints:
                errors['kubernetes'].append("At least one cluster endpoint is required")
            if k8s.scan_interval_minutes < 1:
                errors['kubernetes'].append("Scan interval must be at least 1 minute")
            if k8s.authentication_method not in ["in_cluster", "kubeconfig", "service_account"]:
                errors['kubernetes'].append("Invalid authentication method")
        
        # Validate Docker config
        docker = config.docker
        if docker.enabled:
            if not docker.daemon_endpoints:
                errors['docker'].append("At least one daemon endpoint is required")
            if docker.scan_interval_minutes < 1:
                errors['docker'].append("Scan interval must be at least 1 minute")
            if docker.max_log_lines < 10:
                errors['docker'].append("Max log lines must be at least 10")
        
        # Validate MCP config
        mcp = config.mcp
        if mcp.enabled:
            if not mcp.server_endpoints:
                errors['mcp'].append("At least one MCP server endpoint is required")
            if mcp.scan_interval_minutes < 1:
                errors['mcp'].append("Scan interval must be at least 1 minute")
            if mcp.context_window_threshold < 1000:
                errors['mcp'].append("Context window threshold must be at least 1000 tokens")
            if mcp.response_time_threshold_ms < 10:
                errors['mcp'].append("Response time threshold must be at least 10ms")
        
        # Validate General config
        general = config.general
        if general.data_retention_days < 1:
            errors['general'].append("Data retention must be at least 1 day")
        if not general.timezone:
            errors['general'].append("Timezone is required")
        
        return {k: v for k, v in errors.items() if v}
    
    def get_enabled_integrations(self) -> List[str]:
        """Get list of enabled integration types"""
        config = self.get_configuration()
        enabled = []
        
        if config.kubernetes.enabled:
            enabled.append('kubernetes')
        if config.docker.enabled:
            enabled.append('docker')
        if config.mcp.enabled:
            enabled.append('mcp')
        
        return enabled
    
    def get_integration_config(self, integration_type: str) -> Optional[Union[KubernetesConfig, DockerConfig, MCPConfig]]:
        """Get configuration for specific integration type"""
        config = self.get_configuration()
        
        if integration_type == 'kubernetes':
            return config.kubernetes
        elif integration_type == 'docker':
            return config.docker
        elif integration_type == 'mcp':
            return config.mcp
        
        return None
    
    def reset_to_defaults(self, integration_type: Optional[str] = None) -> bool:
        """Reset configuration to defaults"""
        try:
            if integration_type:
                if integration_type == 'kubernetes':
                    self._config.kubernetes = KubernetesConfig()
                elif integration_type == 'docker':
                    self._config.docker = DockerConfig()
                elif integration_type == 'mcp':
                    self._config.mcp = MCPConfig()
                elif integration_type == 'general':
                    self._config.general = GeneralConfig()
            else:
                self._config = IntegrationConfiguration()
            
            return self.save_configuration()
        except Exception as e:
            logger.error(f"Failed to reset configuration: {e}")
            return False
    
    def export_configuration(self) -> Dict[str, Any]:
        """Export configuration as dictionary"""
        config = self.get_configuration()
        return asdict(config)
    
    def import_configuration(self, config_dict: Dict[str, Any]) -> bool:
        """Import configuration from dictionary"""
        try:
            config = IntegrationConfiguration(
                kubernetes=KubernetesConfig(**config_dict.get('kubernetes', {})),
                docker=DockerConfig(**config_dict.get('docker', {})),
                mcp=MCPConfig(**config_dict.get('mcp', {})),
                general=GeneralConfig(**config_dict.get('general', {})),
                created_at=config_dict.get('created_at', datetime.utcnow().isoformat()),
                updated_at=datetime.utcnow().isoformat(),
                version=config_dict.get('version', '1.0')
            )
            
            # Validate before saving
            errors = self.validate_configuration(config)
            if any(errors.values()):
                logger.error(f"Configuration validation failed: {errors}")
                return False
            
            return self.save_configuration(config)
            
        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False


# Global configuration manager instance
config_manager = IntegrationConfigManager()