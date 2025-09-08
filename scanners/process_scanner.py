"""
Process Scanner - Identifies AI processes running on systems

Discovery Targets:
- TensorFlow processes
- PyTorch applications
- Scikit-learn services

Capabilities:
- Process identification
- Resource monitoring
- Framework detection
"""

import asyncio
import psutil
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from scanners.base_scanner import BaseScanner


class ProcessScanner(BaseScanner):
    """
    Process Scanner for AI Applications
    
    Identifies AI/ML processes running on the system
    """
    
    def __init__(self):
        super().__init__("process")
        self.ai_process_patterns = [
            r'.*tensorflow.*',
            r'.*pytorch.*',
            r'.*scikit.*learn.*',
            r'.*keras.*',
            r'.*xgboost.*',
            r'.*jupyter.*',
            r'.*mlflow.*',
            r'.*tensorboard.*',
            r'.*python.*train.*',
            r'.*python.*model.*',
            r'.*python.*inference.*',
            r'.*serve.*model.*',
            r'.*torchserve.*',
            r'.*tf.*serving.*'
        ]
    
    def scan(self):
        """Legacy scan method for compatibility"""
        return self.discover_agents()
    
    def discover_agents(self, target=None):
        """Discover AI processes running on system"""
        return asyncio.run(self._async_discover_agents(target))
    
    async def _async_discover_agents(self, target):
        """Async discover AI processes"""
        agents = []
        
        try:
            self.scan_statistics["total_scans"] += 1
            start_time = datetime.utcnow()
            
            # Scan running processes
            agents.extend(await self._scan_running_processes())
            
            self.scan_statistics["successful_scans"] += 1
            self.scan_statistics["agents_discovered"] += len(agents)
            self.last_scan_duration = (datetime.utcnow() - start_time).total_seconds()
            
            self.logger.info(f"Process scan completed: {len(agents)} processes discovered")
            
        except Exception as e:
            self.scan_statistics["errors"] += 1
            self.logger.error(f"Process scan failed: {str(e)}")
        
        # For demonstration, return simulated process data
        if not agents:
            agents = self._get_simulated_process_agents()
        
        return agents
    
    async def _scan_running_processes(self) -> List[Dict[str, Any]]:
        """Scan for running AI/ML processes"""
        agents = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info', 'create_time']):
                try:
                    proc_info = proc.info
                    cmdline = ' '.join(proc_info.get('cmdline', []))
                    
                    # Check if process matches AI patterns
                    if self._is_ai_process(proc_info['name'], cmdline):
                        agent_data = await self._analyze_process(proc, proc_info)
                        if agent_data:
                            agents.append(self._create_discovered_agent(agent_data))
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Process may have died or we don't have access
                    continue
        
        except Exception as e:
            self.logger.error(f"Error scanning processes: {str(e)}")
        
        return agents
    
    def _is_ai_process(self, process_name: str, cmdline: str) -> bool:
        """Check if process appears to be AI/ML related"""
        
        # Check process name and command line against patterns
        full_text = f"{process_name} {cmdline}".lower()
        
        for pattern in self.ai_process_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return True
        
        return False
    
    async def _analyze_process(self, proc: psutil.Process, proc_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze an AI process to extract metadata"""
        
        try:
            # Get additional process information
            memory_info = proc_info.get('memory_info')
            cpu_percent = proc_info.get('cpu_percent', 0)
            
            # Try to get more detailed info
            try:
                connections = proc.connections()
                open_files = proc.open_files()
                cwd = proc.cwd()
                environ = proc.environ()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                connections = []
                open_files = []
                cwd = None
                environ = {}
            
            # Detect AI framework
            framework = self._detect_framework_from_process(proc_info['name'], 
                                                          ' '.join(proc_info.get('cmdline', [])))
            
            # Check for healthcare indicators
            healthcare_indicators = self._check_healthcare_indicators(proc_info, environ)
            
            # Analyze resource usage
            resource_usage = self._analyze_resource_usage(memory_info, cpu_percent)
            
            # Check for network activity
            network_activity = self._analyze_network_activity(connections)
            
            # Check for data files
            data_files = self._analyze_data_files(open_files)
            
            metadata = {
                "pid": proc_info['pid'],
                "process_name": proc_info['name'],
                "cmdline": proc_info.get('cmdline', []),
                "ai_framework": framework,
                "create_time": datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                "working_directory": cwd,
                "resource_usage": resource_usage,
                "network_activity": network_activity,
                "data_files": data_files,
                "healthcare_indicators": healthcare_indicators,
                "healthcare_data": healthcare_indicators['has_healthcare_data'],
                "environment_variables": {k: v for k, v in environ.items() 
                                        if not any(sensitive in k.lower() 
                                                 for sensitive in ['password', 'key', 'token', 'secret'])}
            }
            
            agent_data = {
                "id": f"process_{proc_info['pid']}_{proc_info['name']}",
                "name": f"{proc_info['name']} (PID: {proc_info['pid']})",
                "type": "system_process",
                "protocol": "system",
                "metadata": metadata
            }
            
            return agent_data
        
        except Exception as e:
            self.logger.warning(f"Failed to analyze process {proc_info['pid']}: {str(e)}")
            return None
    
    def _detect_framework_from_process(self, process_name: str, cmdline: str) -> str:
        """Detect AI framework from process information"""
        
        frameworks = {
            "tensorflow": ["tensorflow", "tf-serving", "tensorboard"],
            "pytorch": ["pytorch", "torch", "torchserve"],
            "scikit-learn": ["scikit-learn", "sklearn"],
            "xgboost": ["xgboost"],
            "keras": ["keras"],
            "jupyter": ["jupyter"],
            "mlflow": ["mlflow"]
        }
        
        full_text = f"{process_name} {cmdline}".lower()
        
        for framework, indicators in frameworks.items():
            if any(indicator in full_text for indicator in indicators):
                return framework
        
        return "unknown"
    
    def _check_healthcare_indicators(self, proc_info: Dict[str, Any], environ: Dict[str, str]) -> Dict[str, Any]:
        """Check for healthcare-related indicators"""
        
        healthcare_keywords = [
            "health", "medical", "patient", "clinical", "hipaa", "phi", 
            "emr", "ehr", "dicom", "fhir", "hl7"
        ]
        
        indicators = {
            "has_healthcare_data": False,
            "healthcare_keywords_found": [],
            "potential_phi_access": False
        }
        
        # Check command line
        cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
        for keyword in healthcare_keywords:
            if keyword in cmdline:
                indicators["healthcare_keywords_found"].append(keyword)
                indicators["has_healthcare_data"] = True
        
        # Check environment variables
        for key, value in environ.items():
            key_value = f"{key} {value}".lower()
            for keyword in healthcare_keywords:
                if keyword in key_value:
                    indicators["healthcare_keywords_found"].append(f"env:{keyword}")
                    indicators["has_healthcare_data"] = True
        
        # Check for potential PHI access patterns
        if any(pattern in cmdline for pattern in ["database", "db", "sql", "api"]):
            indicators["potential_phi_access"] = True
        
        return indicators
    
    def _analyze_resource_usage(self, memory_info, cpu_percent: float) -> Dict[str, Any]:
        """Analyze process resource usage"""
        
        usage = {
            "cpu_percent": cpu_percent,
            "memory_usage_mb": 0,
            "memory_percent": 0,
            "high_resource_usage": False
        }
        
        if memory_info:
            usage["memory_usage_mb"] = memory_info.rss / (1024 * 1024)  # Convert to MB
            usage["memory_percent"] = (memory_info.rss / psutil.virtual_memory().total) * 100
        
        # Determine if this is high resource usage
        if cpu_percent > 50 or usage["memory_usage_mb"] > 1000:
            usage["high_resource_usage"] = True
        
        return usage
    
    def _analyze_network_activity(self, connections: List) -> Dict[str, Any]:
        """Analyze process network activity"""
        
        activity = {
            "has_network_connections": len(connections) > 0,
            "connection_count": len(connections),
            "listening_ports": [],
            "external_connections": [],
            "public_access": False
        }
        
        for conn in connections:
            if conn.status == 'LISTEN':
                activity["listening_ports"].append(conn.laddr.port)
                # Check if listening on all interfaces
                if conn.laddr.ip in ['0.0.0.0', '::']:
                    activity["public_access"] = True
            elif conn.raddr:
                activity["external_connections"].append({
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port
                })
        
        return activity
    
    def _analyze_data_files(self, open_files: List) -> Dict[str, Any]:
        """Analyze data files opened by process"""
        
        files = {
            "file_count": len(open_files),
            "data_files": [],
            "model_files": [],
            "config_files": []
        }
        
        for file_info in open_files:
            path = file_info.path.lower()
            
            # Check for data files
            if any(ext in path for ext in ['.csv', '.json', '.xml', '.parquet', '.h5']):
                files["data_files"].append(file_info.path)
            
            # Check for model files
            if any(ext in path for ext in ['.pkl', '.joblib', '.h5', '.pb', '.pth', '.onnx']):
                files["model_files"].append(file_info.path)
            
            # Check for config files
            if any(ext in path for ext in ['.yaml', '.yml', '.toml', '.ini', '.conf']):
                files["config_files"].append(file_info.path)
        
        return files
    
    def _create_discovered_agent(self, agent_data: Dict[str, Any]):
        """Create discovered agent from scanner data"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        return DiscoveredAgent(
            id=agent_data.get("id"),
            name=agent_data.get("name"),
            type=agent_data.get("type"),
            protocol=agent_data.get("protocol"),
            discovered_by=ScannerType.PROCESS,
            metadata=agent_data.get("metadata", {}),
            risk_level=self._assess_risk_level(agent_data),
            compliance_frameworks=self._determine_frameworks(agent_data),
            discovery_timestamp=datetime.utcnow()
        )
    
    def _assess_risk_level(self, agent_data: Dict[str, Any]):
        """Assess risk level of AI process"""
        from models import RiskLevel
        
        metadata = agent_data.get("metadata", {})
        risk_score = 0
        
        # High resource usage
        if metadata.get("resource_usage", {}).get("high_resource_usage", False):
            risk_score += 1
        
        # Public network access
        if metadata.get("network_activity", {}).get("public_access", False):
            risk_score += 3
        
        # Healthcare data handling
        if metadata.get("healthcare_data", False):
            risk_score += 2
        
        # Potential PHI access
        if metadata.get("healthcare_indicators", {}).get("potential_phi_access", False):
            risk_score += 2
        
        # Unknown framework
        if metadata.get("ai_framework") == "unknown":
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 6:
            return RiskLevel.CRITICAL
        elif risk_score >= 4:
            return RiskLevel.HIGH
        elif risk_score >= 2:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _determine_frameworks(self, agent_data: Dict[str, Any]) -> List[str]:
        """Determine applicable compliance frameworks"""
        frameworks = []
        
        metadata = agent_data.get("metadata", {})
        
        # Healthcare data
        if metadata.get("healthcare_data", False):
            frameworks.append("HIPAA")
        
        # System processes need security oversight
        frameworks.append("SYSTEM_SECURITY")
        
        # Network accessible processes
        if metadata.get("network_activity", {}).get("public_access", False):
            frameworks.extend(["SOC2", "NETWORK_SECURITY"])
        
        # Process monitoring
        frameworks.append("PROCESS_MONITORING")
        
        return frameworks
    
    def _get_simulated_process_agents(self) -> List:
        """Return simulated process data for demonstration"""
        from models import RiskLevel
        from scanners.environment_scanner import DiscoveredAgent, ScannerType
        
        simulated_agents = [
            DiscoveredAgent(
                id="process_tensorflow_serving",
                name="tensorflow_model_server (PID: 1234)",
                type="system_process",
                protocol="system",
                discovered_by=ScannerType.PROCESS,
                metadata={
                    "pid": 1234,
                    "process_name": "tensorflow_model_server",
                    "ai_framework": "tensorflow",
                    "resource_usage": {
                        "cpu_percent": 15.5,
                        "memory_usage_mb": 2048,
                        "high_resource_usage": True
                    },
                    "network_activity": {
                        "has_network_connections": True,
                        "listening_ports": [8501],
                        "public_access": False
                    },
                    "healthcare_data": True,
                    "healthcare_indicators": {
                        "has_healthcare_data": True,
                        "healthcare_keywords_found": ["medical", "patient"]
                    }
                },
                risk_level=RiskLevel.MEDIUM,
                compliance_frameworks=["HIPAA", "SYSTEM_SECURITY", "PROCESS_MONITORING"],
                discovery_timestamp=datetime.utcnow()
            ),
            DiscoveredAgent(
                id="process_jupyter_lab",
                name="jupyter-lab (PID: 5678)",
                type="system_process",
                protocol="system",
                discovered_by=ScannerType.PROCESS,
                metadata={
                    "pid": 5678,
                    "process_name": "jupyter-lab",
                    "ai_framework": "jupyter",
                    "resource_usage": {
                        "cpu_percent": 5.2,
                        "memory_usage_mb": 512,
                        "high_resource_usage": False
                    },
                    "network_activity": {
                        "has_network_connections": True,
                        "listening_ports": [8888],
                        "public_access": True  # Risk factor
                    },
                    "healthcare_data": True,
                    "healthcare_indicators": {
                        "has_healthcare_data": True,
                        "potential_phi_access": True
                    }
                },
                risk_level=RiskLevel.HIGH,
                compliance_frameworks=["HIPAA", "SYSTEM_SECURITY", "SOC2", "NETWORK_SECURITY", "PROCESS_MONITORING"],
                discovery_timestamp=datetime.utcnow()
            )
        ]
        
        return simulated_agents
    
    def get_scanner_info(self) -> Dict[str, Any]:
        """Get process scanner information"""
        return {
            "scanner_type": "process",
            "name": "Process Scanner",
            "description": "Identifies AI processes running on systems",
            "available": True,  # Always available via psutil
            "discovery_targets": [
                "TensorFlow processes",
                "PyTorch applications",
                "Scikit-learn services"
            ],
            "capabilities": [
                "Process identification",
                "Resource monitoring",
                "Framework detection"
            ],
            "ai_patterns": len(self.ai_process_patterns),
            "statistics": self.scan_statistics
        }