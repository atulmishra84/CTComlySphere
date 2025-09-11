"""
Shadow AI Scanner for detecting unauthorized AI systems
Critical for healthcare compliance - detects rogue AI that could expose PHI
"""

import os
import psutil
import json
import subprocess
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel, ScanStatus

class ShadowAIScanner(BaseScanner):
    """Comprehensive scanner for detecting unauthorized/shadow AI systems"""
    
    def __init__(self):
        super().__init__(scanner_type='shadow_ai')
        self.ai_libraries = {
            # Python AI/ML libraries
            'tensorflow', 'pytorch', 'torch', 'keras', 'scikit-learn', 'sklearn',
            'numpy', 'pandas', 'scipy', 'matplotlib', 'seaborn', 'plotly',
            'transformers', 'huggingface_hub', 'openai', 'anthropic', 'cohere',
            'langchain', 'llama_index', 'spacy', 'nltk', 'opencv-python', 'cv2',
            'xgboost', 'lightgbm', 'catboost', 'mlflow', 'wandb', 'optuna',
            'ray', 'dask', 'joblib', 'fastai', 'stable-baselines3', 'gym',
            # R packages
            'caret', 'randomForest', 'e1071', 'nnet', 'rpart', 'gbm',
            'glmnet', 'kernlab', 'MASS', 'lattice', 'ggplot2'
        }
        
        self.ai_model_extensions = {
            '.pkl', '.pickle', '.joblib', '.h5', '.hdf5', '.pb', '.pth', '.pt',
            '.onnx', '.tflite', '.bin', '.safetensors', '.model', '.weights',
            '.json', '.yaml', '.yml', '.cfg', '.xml', '.pmml'
        }
        
        self.ai_executable_patterns = [
            r'.*python.*', r'.*jupyter.*', r'.*anaconda.*', r'.*conda.*',
            r'.*Rscript.*', r'.*R\.exe.*', r'.*mlflow.*', r'.*tensorboard.*',
            r'.*streamlit.*', r'.*gradio.*', r'.*fastapi.*', r'.*uvicorn.*'
        ]
        
        self.external_ai_domains = {
            'openai.com', 'api.anthropic.com', 'cohere.ai', 'huggingface.co',
            'replicate.com', 'runpod.io', 'together.ai', 'fireworks.ai',
            'groq.com', 'perplexity.ai', 'claude.ai', 'gemini.google.com'
        }

    def scan(self, target=None):
        """Perform comprehensive shadow AI detection scan"""
        try:
            self.start_scan()
            
            # Comprehensive detection across multiple vectors
            detected_agents = []
            
            # 1. Process-based detection
            process_agents = self._scan_running_processes()
            detected_agents.extend(process_agents)
            
            # 2. Filesystem-based detection  
            filesystem_agents = self._scan_filesystem_models()
            detected_agents.extend(filesystem_agents)
            
            # 3. Network traffic analysis
            network_agents = self._scan_network_connections()
            detected_agents.extend(network_agents)
            
            # 4. Code repository scanning
            code_agents = self._scan_code_repositories()
            detected_agents.extend(code_agents)
            
            # 5. Container and virtualization detection
            container_agents = self._scan_containers_for_shadow_ai()
            detected_agents.extend(container_agents)
            
            # Deduplicate and assess risks
            unique_agents = self._deduplicate_shadow_agents(detected_agents)
            risk_assessed_agents = self._assess_shadow_ai_risks(unique_agents)
            
            # Store in database
            stored_agents = []
            for agent_data in risk_assessed_agents:
                agent = self.create_or_update_shadow_agent(agent_data)
                if agent:
                    stored_agents.append(agent)
            
            scan_duration = self.end_scan()
            
            self.logger.info(f"Shadow AI scan completed: {len(stored_agents)} unauthorized AI systems detected")
            
            return {
                'status': 'completed',
                'agents_detected': len(stored_agents),
                'high_risk_agents': len([a for a in stored_agents if hasattr(a, 'risk_level') and a.risk_level == 'HIGH']),
                'scan_duration': scan_duration,
                'detection_methods': ['process', 'filesystem', 'network', 'code', 'container'],
                'agents': stored_agents
            }
            
        except Exception as e:
            self.logger.error(f"Shadow AI scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }

    def discover_agents(self, target=None):
        """Discover shadow AI agents using multiple detection methods"""
        return self.scan(target)

    def _scan_running_processes(self) -> List[Dict]:
        """Scan running processes for AI/ML activity"""
        shadow_processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'environ', 'memory_info', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    cmdline = ' '.join(proc_info.get('cmdline', []))
                    
                    # Check for AI library usage
                    if self._is_ai_process(proc_info.get('name', ''), cmdline, proc_info.get('environ', {})):
                        agent_data = {
                            'name': f"Shadow AI Process: {proc_info['name']}",
                            'type': 'Unauthorized Process AI',
                            'protocol': 'process',
                            'endpoint': f"pid://{proc_info['pid']}",
                            'detection_method': 'process_scan',
                            'metadata': {
                                'pid': proc_info['pid'],
                                'command_line': self._sanitize_cmdline(cmdline),
                                'memory_usage_mb': round(proc_info.get('memory_info', {}).get('rss', 0) / 1024 / 1024, 2),
                                'cpu_percent': proc_info.get('cpu_percent', 0),
                                'ai_indicators': self._extract_ai_indicators_from_process(proc_info),
                                'discovery_timestamp': datetime.utcnow().isoformat(),
                                'shadow_risk_factors': ['unauthorized_process', 'direct_system_access'],
                                'compliance_concerns': ['unmonitored_ai', 'potential_phi_exposure']
                            }
                        }
                        shadow_processes.append(agent_data)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Process scanning failed: {e}")
            
        self.logger.info(f"Process scan found {len(shadow_processes)} potential shadow AI processes")
        return shadow_processes

    def _scan_filesystem_models(self) -> List[Dict]:
        """Scan filesystem for AI model files and datasets"""
        shadow_models = []
        
        # Define scan locations (common places for AI models)
        scan_locations = [
            '/home', '/opt', '/tmp', '/var/tmp', '/usr/local',
            '/models', '/data', '/datasets', '/notebooks', '/ml_models'
        ]
        
        try:
            for location in scan_locations:
                if os.path.exists(location) and os.access(location, os.R_OK):
                    models_found = self._scan_directory_for_ai_artifacts(location)
                    shadow_models.extend(models_found)
                    
        except Exception as e:
            self.logger.error(f"Filesystem scan failed: {e}")
            
        self.logger.info(f"Filesystem scan found {len(shadow_models)} potential AI model files")
        return shadow_models

    def _scan_network_connections(self) -> List[Dict]:
        """Scan network connections for external AI service usage"""
        shadow_network_agents = []
        
        try:
            # Get network connections
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.raddr and hasattr(conn.raddr, 'ip') and hasattr(conn.raddr, 'port') and conn.status == psutil.CONN_ESTABLISHED:
                    remote_host = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Check if connecting to known AI service domains
                    ai_service = self._identify_ai_service_by_connection(remote_host, remote_port)
                    if ai_service:
                        agent_data = {
                            'name': f"Shadow AI Network Connection: {ai_service}",
                            'type': 'Unauthorized External AI Service',
                            'protocol': 'https',
                            'endpoint': f"https://{remote_host}:{remote_port}",
                            'detection_method': 'network_scan',
                            'metadata': {
                                'remote_host': remote_host,
                                'remote_port': remote_port,
                                'ai_service': ai_service,
                                'local_port': conn.laddr.port,
                                'connection_status': conn.status,
                                'discovery_timestamp': datetime.utcnow().isoformat(),
                                'shadow_risk_factors': ['external_ai_service', 'uncontrolled_data_transmission'],
                                'compliance_concerns': ['data_exfiltration_risk', 'third_party_ai_usage']
                            }
                        }
                        shadow_network_agents.append(agent_data)
                        
        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
            
        self.logger.info(f"Network scan found {len(shadow_network_agents)} external AI connections")
        return shadow_network_agents

    def _scan_code_repositories(self) -> List[Dict]:
        """Scan code repositories for AI library usage"""
        shadow_code_agents = []
        
        # Common code locations
        code_locations = ['/home', '/opt', '/var/www', '/app', '/src', '/code']
        
        try:
            for location in code_locations:
                if os.path.exists(location):
                    code_agents = self._scan_directory_for_ai_code(location)
                    shadow_code_agents.extend(code_agents)
                    
        except Exception as e:
            self.logger.error(f"Code repository scan failed: {e}")
            
        self.logger.info(f"Code scan found {len(shadow_code_agents)} potential AI code implementations")
        return shadow_code_agents

    def _scan_containers_for_shadow_ai(self) -> List[Dict]:
        """Scan container environments for shadow AI"""
        shadow_container_agents = []
        
        try:
            # Check if running in container
            if os.path.exists('/.dockerenv') or os.path.exists('/proc/1/cgroup'):
                # Scan current container environment
                container_data = self._analyze_container_environment()
                if container_data:
                    shadow_container_agents.append(container_data)
                    
        except Exception as e:
            self.logger.error(f"Container scan failed: {e}")
            
        return shadow_container_agents

    def _is_ai_process(self, process_name: str, cmdline: str, environ: Dict) -> bool:
        """Determine if a process is AI-related"""
        # Check process name against AI patterns
        for pattern in self.ai_executable_patterns:
            if re.match(pattern, process_name, re.IGNORECASE):
                return True
                
        # Check command line for AI libraries
        cmdline_lower = cmdline.lower()
        for lib in self.ai_libraries:
            if lib.lower() in cmdline_lower:
                return True
                
        # Check environment variables for AI indicators
        for key, value in environ.items():
            key_lower = key.lower()
            if any(ai_term in key_lower for ai_term in ['model', 'ai', 'ml', 'tensorflow', 'pytorch', 'cuda']):
                return True
                
        return False

    def _extract_ai_indicators_from_process(self, proc_info: Dict) -> List[str]:
        """Extract AI indicators from process information"""
        indicators = []
        
        cmdline = ' '.join(proc_info.get('cmdline', []))
        environ = proc_info.get('environ', {})
        
        # Check for specific AI libraries in command line
        for lib in self.ai_libraries:
            if lib.lower() in cmdline.lower():
                indicators.append(f"AI Library: {lib}")
                
        # Check environment variables
        for key, value in environ.items():
            if any(term in key.lower() for term in ['model', 'ai', 'cuda', 'gpu']):
                indicators.append(f"AI Environment Variable: {key}")
                
        return indicators

    def _sanitize_cmdline(self, cmdline: str) -> str:
        """Sanitize command line to remove sensitive information"""
        if not cmdline:
            return ''
            
        # Remove potential API keys and secrets
        sensitive_patterns = [
            r'(--api[-_]?key[=\s]+)[^\s]+',
            r'(--secret[=\s]+)[^\s]+',
            r'(--token[=\s]+)[^\s]+',
            r'(--password[=\s]+)[^\s]+'
        ]
        
        sanitized = cmdline
        for pattern in sensitive_patterns:
            sanitized = re.sub(pattern, r'\1[REDACTED]', sanitized, flags=re.IGNORECASE)
            
        # Truncate very long command lines
        if len(sanitized) > 500:
            sanitized = sanitized[:500] + '...[truncated]'
            
        return sanitized

    def _scan_directory_for_ai_artifacts(self, directory: str) -> List[Dict]:
        """Scan directory for AI model files and artifacts"""
        artifacts = []
        
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system directories and hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['proc', 'sys', 'dev']]
                
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in self.ai_model_extensions:
                        agent_data = {
                            'name': f"Shadow AI Model: {file}",
                            'type': 'Unauthorized AI Model File',
                            'protocol': 'file',
                            'endpoint': f"file://{file_path}",
                            'detection_method': 'filesystem_scan',
                            'metadata': {
                                'file_path': str(file_path),
                                'file_size_mb': round(file_path.stat().st_size / 1024 / 1024, 2),
                                'file_extension': file_path.suffix,
                                'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                                'discovery_timestamp': datetime.utcnow().isoformat(),
                                'shadow_risk_factors': ['untracked_model_file', 'potential_model_deployment'],
                                'compliance_concerns': ['unvalidated_ai_model', 'data_governance_gap']
                            }
                        }
                        artifacts.append(agent_data)
                        
                        # Limit to prevent overwhelming results
                        if len(artifacts) >= 100:
                            break
                            
                if len(artifacts) >= 100:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
            
        return artifacts

    def _scan_directory_for_ai_code(self, directory: str) -> List[Dict]:
        """Scan directory for AI-related code"""
        code_artifacts = []
        
        try:
            for root, dirs, files in os.walk(directory):
                # Skip system and hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', '.git']]
                
                for file in files:
                    if file.endswith(('.py', '.r', '.R', '.ipynb', '.js', '.ts')):
                        file_path = Path(root) / file
                        
                        if self._analyze_file_for_ai_usage(file_path):
                            agent_data = {
                                'name': f"Shadow AI Code: {file}",
                                'type': 'Unauthorized AI Code Implementation',
                                'protocol': 'file',
                                'endpoint': f"file://{file_path}",
                                'detection_method': 'code_scan',
                                'metadata': {
                                    'file_path': str(file_path),
                                    'file_type': file_path.suffix,
                                    'ai_libraries_detected': self._get_ai_imports_from_file(file_path),
                                    'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                                    'discovery_timestamp': datetime.utcnow().isoformat(),
                                    'shadow_risk_factors': ['unauthorized_ai_development', 'unreviewed_ai_code'],
                                    'compliance_concerns': ['unvalidated_ai_implementation', 'code_governance_gap']
                                }
                            }
                            code_artifacts.append(agent_data)
                            
                        # Limit results
                        if len(code_artifacts) >= 50:
                            break
                            
                if len(code_artifacts) >= 50:
                    break
                    
        except Exception as e:
            self.logger.error(f"Error scanning code in {directory}: {e}")
            
        return code_artifacts

    def _analyze_file_for_ai_usage(self, file_path: Path) -> bool:
        """Analyze file for AI library usage"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)  # Read first 10KB
                
            content_lower = content.lower()
            
            # Check for AI library imports
            for lib in self.ai_libraries:
                if lib.lower() in content_lower:
                    return True
                    
            # Check for AI-specific patterns
            ai_patterns = [
                'import tensorflow', 'import torch', 'import sklearn',
                'from transformers', 'import openai', 'model.predict',
                'neural_network', 'machine_learning', 'deep_learning'
            ]
            
            for pattern in ai_patterns:
                if pattern.lower() in content_lower:
                    return True
                    
        except Exception:
            pass
            
        return False

    def _get_ai_imports_from_file(self, file_path: Path) -> List[str]:
        """Extract AI library imports from file"""
        imports = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip().lower()
                    if line.startswith(('import ', 'from ')):
                        for lib in self.ai_libraries:
                            if lib.lower() in line:
                                imports.append(lib)
                                break
                                
        except Exception:
            pass
            
        return list(set(imports))

    def _identify_ai_service_by_connection(self, host: str, port: int) -> Optional[str]:
        """Identify AI service by connection details"""
        # Common AI service ports and patterns
        ai_service_patterns = {
            'openai.com': 'OpenAI API',
            'api.anthropic.com': 'Anthropic Claude API',
            'cohere.ai': 'Cohere API',
            'huggingface.co': 'Hugging Face Hub',
            'replicate.com': 'Replicate AI',
            'together.ai': 'Together AI'
        }
        
        for domain, service in ai_service_patterns.items():
            if domain in host:
                return service
                
        return None

    def _analyze_container_environment(self) -> Optional[Dict]:
        """Analyze current container for shadow AI"""
        try:
            # Check for AI libraries in current Python environment
            ai_packages = self._get_installed_ai_packages()
            
            if ai_packages:
                return {
                    'name': 'Shadow AI Container Environment',
                    'type': 'Containerized Shadow AI',
                    'protocol': 'container',
                    'endpoint': 'container://current',
                    'detection_method': 'container_scan',
                    'metadata': {
                        'ai_packages_installed': ai_packages,
                        'container_detected': True,
                        'discovery_timestamp': datetime.utcnow().isoformat(),
                        'shadow_risk_factors': ['containerized_ai', 'package_installation'],
                        'compliance_concerns': ['untracked_ai_deployment', 'container_governance']
                    }
                }
        except Exception as e:
            self.logger.error(f"Container environment analysis failed: {e}")
            
        return None

    def _get_installed_ai_packages(self) -> List[str]:
        """Get list of installed AI packages"""
        installed_ai = []
        
        try:
            # Check pip packages
            result = subprocess.run(['pip', 'list'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                installed_packages = result.stdout.lower()
                for lib in self.ai_libraries:
                    if lib.lower() in installed_packages:
                        installed_ai.append(lib)
                        
        except Exception:
            pass
            
        return installed_ai

    def _deduplicate_shadow_agents(self, agents: List[Dict]) -> List[Dict]:
        """Remove duplicate shadow AI agents"""
        unique_agents = []
        seen_endpoints = set()
        
        for agent in agents:
            endpoint = agent.get('endpoint', '')
            if endpoint not in seen_endpoints:
                unique_agents.append(agent)
                seen_endpoints.add(endpoint)
                
        return unique_agents

    def _assess_shadow_ai_risks(self, agents: List[Dict]) -> List[Dict]:
        """Assess risk levels for shadow AI agents"""
        for agent in agents:
            # Calculate risk score based on shadow AI factors
            risk_factors = agent.get('metadata', {}).get('shadow_risk_factors', [])
            compliance_concerns = agent.get('metadata', {}).get('compliance_concerns', [])
            
            risk_score = self._calculate_shadow_ai_risk_score(risk_factors, compliance_concerns, agent)
            risk_level = self.determine_risk_level(risk_score, {'healthcare_critical': True})
            
            agent['risk_score'] = risk_score
            agent['risk_level'] = risk_level
            agent['shadow_ai_detection'] = True
            
        return agents

    def _calculate_shadow_ai_risk_score(self, risk_factors: List[str], compliance_concerns: List[str], agent_data: Dict) -> int:
        """Calculate risk score specific to shadow AI detection"""
        base_score = 50  # Shadow AI is inherently risky
        
        # Shadow-specific risk factors
        shadow_risk_weights = {
            'unauthorized_process': 20,
            'external_ai_service': 25,
            'untracked_model_file': 15,
            'unauthorized_ai_development': 20,
            'containerized_ai': 10,
            'direct_system_access': 15,
            'uncontrolled_data_transmission': 25,
            'potential_model_deployment': 15
        }
        
        # Compliance concern weights
        compliance_weights = {
            'unmonitored_ai': 15,
            'potential_phi_exposure': 25,
            'data_exfiltration_risk': 20,
            'third_party_ai_usage': 20,
            'unvalidated_ai_model': 15,
            'data_governance_gap': 10,
            'unvalidated_ai_implementation': 15,
            'code_governance_gap': 10,
            'untracked_ai_deployment': 15,
            'container_governance': 10
        }
        
        # Apply risk factor weights
        for factor in risk_factors:
            base_score += shadow_risk_weights.get(factor, 5)
            
        # Apply compliance concern weights  
        for concern in compliance_concerns:
            base_score += compliance_weights.get(concern, 5)
            
        # Additional risk factors for healthcare context
        metadata = agent_data.get('metadata', {})
        if 'memory_usage_mb' in metadata and metadata['memory_usage_mb'] > 1000:
            base_score += 10  # Large memory usage suggests significant AI processing
            
        if 'external' in agent_data.get('endpoint', '').lower():
            base_score += 15  # External connections are higher risk
            
        return min(base_score, 100)

    def create_or_update_shadow_agent(self, agent_data: Dict) -> Optional['AIAgent']:
        """Create or update shadow AI agent in database"""
        try:
            # Check if agent already exists
            existing_agent = AIAgent.query.filter_by(
                endpoint=agent_data['endpoint'],
                detection_method='shadow_ai'
            ).first()
            
            if existing_agent:
                # Update existing agent
                existing_agent.last_seen = datetime.utcnow()
                existing_agent.metadata.update(agent_data.get('metadata', {}))
                db.session.commit()
                return existing_agent
            else:
                # Create new shadow AI agent
                new_agent = AIAgent()
                new_agent.name = agent_data['name']
                new_agent.type = agent_data['type']
                new_agent.protocol = agent_data['protocol']
                new_agent.endpoint = agent_data['endpoint']
                new_agent.agent_metadata = agent_data.get('metadata', {})
                
                db.session.add(new_agent)
                db.session.commit()
                
                # Create security scan result
                self._create_shadow_ai_scan_result(new_agent, agent_data)
                
                return new_agent
                
        except Exception as e:
            self.logger.error(f"Failed to create/update shadow AI agent: {e}")
            db.session.rollback()
            return None

    def _create_shadow_ai_scan_result(self, agent: 'AIAgent', agent_data: Dict):
        """Create scan result for shadow AI agent"""
        try:
            # Enhanced security scan for shadow AI
            security_findings = self.enhanced_security_scan(agent_data)
            
            scan_result = ScanResult()
            scan_result.ai_agent_id = agent.id
            scan_result.scan_type = 'shadow_ai_detection'
            scan_result.status = ScanStatus.COMPLETED
            scan_result.vulnerabilities_found = len(agent_data.get('metadata', {}).get('shadow_risk_factors', []))
            scan_result.risk_score = agent_data.get('risk_score', 75)  # Default high risk for shadow AI
            scan_result.risk_level = getattr(RiskLevel, agent_data.get('risk_level', 'HIGH').upper())
            scan_result.phi_exposure_detected = True  # Shadow AI assumed to have PHI risk
            scan_result.scan_data = {
                'shadow_ai_detection': True,
                'detection_method': agent_data.get('detection_method'),
                'security_findings': security_findings,
                'risk_factors': agent_data.get('metadata', {}).get('shadow_risk_factors', []),
                'compliance_concerns': agent_data.get('metadata', {}).get('compliance_concerns', []),
                'compliance_violations': ['HIPAA: Unauthorized AI system']
            }
            
            db.session.add(scan_result)
            db.session.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to create shadow AI scan result: {e}")
            db.session.rollback()