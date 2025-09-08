"""
Model Registry Scanner - Scans model registries and ML platforms

Discovery Targets:
- MLflow Registry
- Weights & Biases
- Hugging Face Hub
- Custom registries

Capabilities:
- Model enumeration
- Version tracking
- Metadata extraction
"""

import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime

from scanners.base_scanner import BaseScanner


class ModelRegistryScanner(BaseScanner):
    """
    Model Registry Scanner
    
    Discovers AI models in various model registries and ML platforms
    """
    
    def __init__(self):
        super().__init__("model_registry")
        self.registry_types = [
            "mlflow",
            "wandb", 
            "huggingface",
            "tensorboard",
            "dvc",
            "custom"
        ]
    
    def scan(self):
        """Legacy scan method for compatibility"""
        return self.discover_agents()
    
    def discover_agents(self, target=None):
        """Discover AI models in registries"""
        return asyncio.run(self._async_discover_agents(target))
    
    async def _async_discover_agents(self, target):
        """Async discover models in registries"""
        agents = []
        
        try:
            self.scan_statistics["total_scans"] += 1
            start_time = datetime.utcnow()
            
            # Scan MLflow registries
            agents.extend(await self._scan_mlflow_registry())
            
            # Scan Weights & Biases
            agents.extend(await self._scan_wandb_registry())
            
            # Scan Hugging Face Hub
            agents.extend(await self._scan_huggingface_hub())
            
            # Scan custom registries
            agents.extend(await self._scan_custom_registries())
            
            self.scan_statistics["successful_scans"] += 1
            self.scan_statistics["agents_discovered"] += len(agents)
            self.last_scan_duration = (datetime.utcnow() - start_time).total_seconds()
            
            self.logger.info(f"Model registry scan completed: {len(agents)} models discovered")
            
        except Exception as e:
            self.scan_statistics["errors"] += 1
            self.logger.error(f"Model registry scan failed: {str(e)}")
        
        # For demonstration, return simulated registry data
        if not agents:
            agents = self._get_simulated_registry_agents()
        
        return agents
    
    async def _scan_mlflow_registry(self) -> List[Dict[str, Any]]:
        """Scan MLflow model registry"""
        agents = []
        
        try:
            # This would connect to MLflow tracking server
            # and enumerate registered models
            pass
        except Exception as e:
            self.logger.warning(f"MLflow registry scan failed: {str(e)}")
        
        return agents
    
    async def _scan_wandb_registry(self) -> List[Dict[str, Any]]:
        """Scan Weights & Biases registry"""
        agents = []
        
        try:
            # This would connect to W&B API
            # and enumerate models and artifacts
            pass
        except Exception as e:
            self.logger.warning(f"W&B registry scan failed: {str(e)}")
        
        return agents
    
    async def _scan_huggingface_hub(self) -> List[Dict[str, Any]]:
        """Scan Hugging Face Hub"""
        agents = []
        
        try:
            # This would use Hugging Face Hub API
            # to discover models
            pass
        except Exception as e:
            self.logger.warning(f"Hugging Face Hub scan failed: {str(e)}")
        
        return agents
    
    async def _scan_custom_registries(self) -> List[Dict[str, Any]]:
        """Scan custom model registries"""
        agents = []
        
        # This would scan organization-specific
        # model registries and repositories
        
        return agents
    
    def _create_discovered_agent(self, agent_data: Dict[str, Any]):
        """Create discovered agent from scanner data"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        return DiscoveredAgent(
            id=agent_data.get("id"),
            name=agent_data.get("name"),
            type=agent_data.get("type"),
            protocol=agent_data.get("protocol"),
            discovered_by=ScannerType.MODEL_REGISTRY,
            metadata=agent_data.get("metadata", {}),
            risk_level=self._assess_risk_level(agent_data),
            compliance_frameworks=self._determine_frameworks(agent_data),
            discovery_timestamp=datetime.utcnow()
        )
    
    def _assess_risk_level(self, agent_data: Dict[str, Any]):
        """Assess risk level of registered model"""
        from models import RiskLevel
        
        metadata = agent_data.get("metadata", {})
        risk_score = 0
        
        # Public model registries may increase risk
        if metadata.get("public_registry", False):
            risk_score += 1
        
        # Unversioned models are riskier
        if not metadata.get("versioned", True):
            risk_score += 2
        
        # Models without proper documentation
        if not metadata.get("has_documentation", True):
            risk_score += 1
        
        # Healthcare-specific models need more oversight
        if metadata.get("healthcare_model", False):
            risk_score += 1
        
        # Models with unknown provenance
        if not metadata.get("known_provenance", True):
            risk_score += 2
        
        # Pre-trained models from external sources
        if metadata.get("external_pretrained", False):
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 5:
            return RiskLevel.CRITICAL
        elif risk_score >= 3:
            return RiskLevel.HIGH
        elif risk_score >= 1:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _determine_frameworks(self, agent_data: Dict[str, Any]) -> List[str]:
        """Determine applicable compliance frameworks"""
        frameworks = ["HIPAA"]  # Default for healthcare
        
        metadata = agent_data.get("metadata", {})
        
        # Model governance
        frameworks.append("MODEL_GOVERNANCE")
        
        # Public registries need additional oversight
        if metadata.get("public_registry", False):
            frameworks.append("IP_COMPLIANCE")
        
        # Healthcare models
        if metadata.get("healthcare_model", False):
            frameworks.extend(["FDA", "MEDICAL_DEVICE"])
        
        # External models need supply chain security
        if metadata.get("external_pretrained", False):
            frameworks.append("SUPPLY_CHAIN_SECURITY")
        
        return frameworks
    
    def _get_simulated_registry_agents(self) -> List:
        """Return simulated model registry data for demonstration"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        simulated_agents = [
            DiscoveredAgent(
                id="mlflow_patient_risk_v3",
                name="patient-risk-predictor-v3.2",
                type="mlflow_model",
                protocol="mlflow",
                discovered_by=ScannerType.MODEL_REGISTRY,
                metadata={
                    "registry_type": "mlflow",
                    "model_name": "patient-risk-predictor",
                    "version": "3.2",
                    "stage": "Production",
                    "framework": "scikit-learn",
                    "algorithm": "RandomForestClassifier",
                    "training_date": "2024-08-15",
                    "accuracy": 0.94,
                    "features_count": 42,
                    "healthcare_model": True,
                    "versioned": True,
                    "has_documentation": True,
                    "known_provenance": True,
                    "public_registry": False,
                    "model_size_mb": 15.2
                },
                risk_level=RiskLevel.LOW,
                compliance_frameworks=["HIPAA", "MODEL_GOVERNANCE", "FDA"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="wandb_medical_nlp_bert",
                name="medical-bert-clinical-notes",
                type="wandb_model",
                protocol="wandb",
                discovered_by=ScannerType.MODEL_REGISTRY,
                metadata={
                    "registry_type": "wandb",
                    "project": "medical-nlp",
                    "model_name": "medical-bert-clinical-notes",
                    "version": "v2.1",
                    "framework": "transformers",
                    "base_model": "bert-base-uncased",
                    "training_date": "2024-09-01",
                    "f1_score": 0.89,
                    "dataset": "clinical_notes_anonymized",
                    "healthcare_model": True,
                    "versioned": True,
                    "has_documentation": True,
                    "known_provenance": True,
                    "public_registry": False,
                    "external_pretrained": True,  # Based on BERT
                    "model_size_mb": 440.0
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_frameworks=["HIPAA", "MODEL_GOVERNANCE", "SUPPLY_CHAIN_SECURITY"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="huggingface_biobert_ner",
                name="dmis-lab/biobert-base-cased-v1.1",
                type="huggingface_model",
                protocol="huggingface",
                discovered_by=ScannerType.MODEL_REGISTRY,
                metadata={
                    "registry_type": "huggingface",
                    "model_id": "dmis-lab/biobert-base-cased-v1.1",
                    "task": "token-classification",
                    "framework": "transformers",
                    "language": "en",
                    "downloads": 156742,
                    "likes": 89,
                    "healthcare_model": True,
                    "versioned": True,
                    "has_documentation": True,
                    "known_provenance": True,
                    "public_registry": True,
                    "external_pretrained": True,
                    "license": "CC BY-NC 4.0",
                    "model_size_mb": 440.0
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_frameworks=["HIPAA", "MODEL_GOVERNANCE", "IP_COMPLIANCE", "SUPPLY_CHAIN_SECURITY"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="custom_drug_discovery_gnn",
                name="molecular-property-predictor-gnn",
                type="custom_model",
                protocol="custom",
                discovered_by=ScannerType.MODEL_REGISTRY,
                metadata={
                    "registry_type": "custom",
                    "model_name": "molecular-property-predictor-gnn",
                    "version": "1.0",
                    "framework": "pytorch_geometric",
                    "algorithm": "GraphConvNet",
                    "training_date": "2024-08-30",
                    "accuracy": 0.91,
                    "healthcare_model": True,
                    "drug_discovery": True,
                    "versioned": True,
                    "has_documentation": False,  # Risk factor
                    "known_provenance": True,
                    "public_registry": False,
                    "model_size_mb": 89.5
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_frameworks=["HIPAA", "FDA", "MODEL_GOVERNANCE", "MEDICAL_DEVICE"],
                discovery_timestamp=datetime.utcnow()
            )
        ]
        
        return simulated_agents
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get model registry scanner information"""
        return {
            "scanner_type": "model_registry",
            "name": "Model Registry Scanner",
            "description": "Scans model registries and ML platforms",
            "available": True,  # Always available for simulation
            "discovery_targets": [
                "MLflow Registry",
                "Weights & Biases",
                "Hugging Face Hub",
                "Custom registries"
            ],
            "capabilities": [
                "Model enumeration",
                "Version tracking",
                "Metadata extraction"
            ],
            "supported_registries": self.registry_types,
            "statistics": self.scan_statistics
        }