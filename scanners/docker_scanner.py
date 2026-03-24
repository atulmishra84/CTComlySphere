from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
from datetime import datetime

try:
    import docker
    from docker.errors import DockerException, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None
    DockerException = Exception
    APIError = Exception

class DockerScanner(BaseScanner):
    """Scanner for Docker-deployed AI agents"""
    
    def __init__(self):
        super().__init__()
        self.docker_host = os.getenv('DOCKER_HOST', 'unix:///var/run/docker.sock')
        self.docker_client = None
        self._initialize_docker_client()
    
    def scan(self):
        """Scan Docker environment for AI agents"""
        self.start_scan()
        
        try:
            agents = self.discover_agents()
            results = []
            
            for agent_data in agents:
                agent = self.create_or_update_agent(agent_data)
                self.enrich_agent_metadata(agent, agent_data)
                scan_result = self.perform_security_scan(agent, agent_data)
                results.append(scan_result)
            
            duration = self.end_scan()
            return {
                'status': 'completed',
                'agents_found': len(agents),
                'scan_duration': duration,
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"Docker scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def _initialize_docker_client(self):
        """Initialize Docker client connection"""
        if not DOCKER_AVAILABLE:
            self.logger.warning("Docker library not available, using simulated data")
            self.docker_client = None
            return
            
        try:
            if os.path.exists('/var/run/docker.sock'):
                self.docker_client = docker.from_env()
                # Test connection with timeout
                self.docker_client.ping()
                self.logger.info("Connected to local Docker daemon")
            else:
                self.logger.warning("Docker socket not found, using simulated data")
                self.docker_client = None
        except Exception as e:
            self.logger.warning(f"Failed to connect to Docker daemon: {e}. Using simulated data.")
            self.docker_client = None
    
    def discover_agents(self, target=None):
        """Discover AI agents in Docker containers"""
        agents = []
        
        # Try to discover real containers first
        if self.docker_client:
            try:
                real_containers = self._discover_real_containers()
                if real_containers:
                    self.logger.info(f"Found {len(real_containers)} real Docker containers")
                    return real_containers
            except Exception as e:
                self.logger.error(f"Failed to discover real containers: {e}")
        
        # Fallback to mock data for demonstration
        self.logger.info("Using simulated Docker containers for demonstration")
        mock_containers = [
            {
                'id': 'container_1',
                'name': 'drug-discovery-ai',
                'image': 'rdkit/rdkit:latest',
                'status': 'running',
                'ports': {'8888/tcp': [{'HostPort': '8888'}]},
                'environment': {
                    'JUPYTER_ENABLE_LAB': 'yes',
                    'MODEL_TYPE': 'drug-discovery',
                    'DATA_SOURCE': 'clinical-trials'
                },
                'labels': {
                    'ai.type': 'drug-discovery',
                    'healthcare.compliance': 'fda-required'
                }
            },
            {
                'id': 'container_2',
                'name': 'ehr-assistant',
                'image': 'tensorflow/tensorflow:latest-jupyter',
                'status': 'running',
                'ports': {'8501/tcp': [{'HostPort': '8501'}]},
                'environment': {
                    'MODEL_NAME': 'ehr-assistant',
                    'PHI_ACCESS': 'true',
                    'ENCRYPTION': 'aes-256'
                },
                'labels': {
                    'ai.type': 'ehr-assistant',
                    'healthcare.phi': 'true'
                }
            }
        ]
        
        for container in mock_containers:
            agent_data = {
                'name': container['name'],
                'type': self.determine_ai_type(container),
                'protocol': 'docker',
                'endpoint': self.build_endpoint(container),
                'cloud_provider': 'docker',
                'region': 'local',
                'metadata': {
                    'container_id': container['id'],
                    'image': container['image'],
                    'status': container['status'],
                    'ports': container['ports'],
                    'environment': container['environment'],
                    'labels': container['labels'],
                    'discovery_method': 'simulated',
                    'discovery_timestamp': datetime.utcnow().isoformat()
                }
            }
            agents.append(agent_data)
        
        return agents
    
    def _discover_real_containers(self):
        """Discover actual running Docker containers with AI indicators"""
        ai_containers = []
        
        try:
            # Get all running containers
            containers = self.docker_client.containers.list(all=True)
            
            for container in containers:
                # Check if container has AI indicators
                if self._is_ai_container(container):
                    # Get container details
                    container_info = self._extract_container_info(container)
                    
                    agent_data = {
                        'name': container_info['name'],
                        'type': self.determine_ai_type(container_info),
                        'protocol': 'docker',
                        'endpoint': self.build_endpoint(container_info),
                        'cloud_provider': 'local-docker',
                        'region': 'local',
                        'metadata': {
                            'container_id': container_info['id'],
                            'image': container_info['image'],
                            'status': container_info['status'],
                            'ports': container_info['ports'],
                            'environment': container_info['environment'],
                            'labels': container_info['labels'],
                            'discovery_method': 'real-docker-scan',
                            'discovery_timestamp': datetime.utcnow().isoformat(),
                            'created': container_info.get('created', ''),
                            'command': container_info.get('command', ''),
                            'volumes': container_info.get('volumes', {})
                        }
                    }
                    ai_containers.append(agent_data)
                    
        except Exception as e:
            self.logger.error(f"Error discovering real containers: {e}")
            raise
        
        return ai_containers
    
    def _is_ai_container(self, container):
        """Check if container has AI/ML indicators"""
        # Check image name for AI indicators
        image_name = container.image.tags[0] if container.image.tags else str(container.image.id)
        ai_image_indicators = [
            'tensorflow', 'pytorch', 'jupyter', 'mlflow', 'sklearn', 'pandas',
            'nvidia/cuda', 'huggingface', 'transformers', 'opencv', 'keras',
            'xgboost', 'lightgbm', 'catboost', 'fastapi', 'flask', 'streamlit',
            'ai', 'ml', 'model', 'inference', 'train'
        ]
        
        # Check image name
        for indicator in ai_image_indicators:
            if indicator in image_name.lower():
                return True
        
        # Check labels
        labels = container.labels or {}
        for key, value in labels.items():
            for indicator in ai_image_indicators:
                if indicator in key.lower() or indicator in str(value).lower():
                    return True
        
        # Check environment variables
        try:
            env_vars = container.attrs.get('Config', {}).get('Env', [])
            for env_var in env_vars:
                if '=' in env_var:
                    key, value = env_var.split('=', 1)
                    for indicator in ai_image_indicators:
                        if indicator in key.lower() or indicator in value.lower():
                            return True
        except Exception:
            pass
        
        # Check running processes (for common AI tools)
        try:
            processes = container.top()
            if processes and 'Processes' in processes:
                for process in processes['Processes']:
                    command = ' '.join(process).lower()
                    ai_process_indicators = ['python', 'jupyter', 'tensorboard', 'mlflow', 'streamlit']
                    for indicator in ai_process_indicators:
                        if indicator in command:
                            return True
        except Exception:
            pass
        
        return False
    
    def _extract_container_info(self, container):
        """Extract relevant information from Docker container"""
        try:
            # Get detailed container attributes
            attrs = container.attrs
            config = attrs.get('Config', {})
            network_settings = attrs.get('NetworkSettings', {})
            
            # Extract ports
            ports = {}
            port_bindings = network_settings.get('Ports', {})
            for container_port, host_bindings in port_bindings.items():
                if host_bindings:
                    ports[container_port] = [{'HostPort': binding['HostPort']} for binding in host_bindings]
                else:
                    ports[container_port] = []
            
            # Extract and filter environment variables (security: avoid storing secrets)
            environment = {}
            env_list = config.get('Env', [])
            for env_var in env_list:
                if '=' in env_var:
                    key, value = env_var.split('=', 1)
                    # Only store non-sensitive environment variables
                    if self._is_safe_env_var(key):
                        environment[key] = value if len(value) < 100 else value[:50] + '...[truncated]'
                    elif self._is_ai_related_env_var(key):
                        # Store AI-related env vars but redact values for security
                        environment[key] = '[REDACTED]'
            
            # Extract volumes
            volumes = attrs.get('Mounts', [])
            volume_info = {}
            for volume in volumes:
                volume_info[volume.get('Destination', '')] = {
                    'source': volume.get('Source', ''),
                    'type': volume.get('Type', ''),
                    'mode': volume.get('Mode', '')
                }
            
            return {
                'id': container.id,
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else str(container.image.id),
                'status': container.status,
                'ports': ports,
                'environment': environment,
                'labels': container.labels or {},
                'created': attrs.get('Created', ''),
                'command': self._sanitize_command(' '.join(config.get('Cmd', [])) if config.get('Cmd') else ''),
                'volumes': volume_info
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting container info: {e}")
            return {
                'id': container.id,
                'name': container.name,
                'image': 'unknown',
                'status': container.status,
                'ports': {},
                'environment': {},
                'labels': {},
                'created': '',
                'command': '',
                'volumes': {}
            }
    
    def _is_safe_env_var(self, key):
        """Check if environment variable is safe to store (not a secret)"""
        key_lower = key.lower()
        
        # Unsafe patterns - likely to contain secrets
        unsafe_patterns = [
            'password', 'passwd', 'secret', 'key', 'token', 'auth', 'credential',
            'private', 'cert', 'ssl', 'tls', 'api_key', 'access_key', 'session',
            'jwt', 'oauth', 'bearer', 'signature', 'hash', 'salt', 'nonce'
        ]
        
        for pattern in unsafe_patterns:
            if pattern in key_lower:
                return False
        
        return True
    
    def _is_ai_related_env_var(self, key):
        """Check if environment variable is AI-related (worth noting but redacting value)"""
        key_lower = key.lower()
        
        ai_patterns = [
            'model', 'tensorflow', 'pytorch', 'ml', 'ai', 'cuda', 'gpu',
            'inference', 'training', 'dataset', 'algorithm', 'neural',
            'sklearn', 'keras', 'transformers', 'huggingface'
        ]
        
        for pattern in ai_patterns:
            if pattern in key_lower:
                return True
        
        return False
    
    def _sanitize_command(self, command):
        """Sanitize command string to avoid exposing sensitive information"""
        if not command:
            return ''
        
        # Truncate very long commands
        if len(command) > 200:
            command = command[:200] + '...[truncated]'
        
        # Basic sanitization - remove potential secrets from command line
        sensitive_flags = ['--password', '--secret', '--key', '--token', '--auth']
        words = command.split()
        sanitized_words = []
        skip_next = False
        
        for word in words:
            if skip_next:
                sanitized_words.append('[REDACTED]')
                skip_next = False
                continue
                
            # Check if this word is a sensitive flag
            if any(flag in word.lower() for flag in sensitive_flags):
                sanitized_words.append(word)
                if '=' not in word:  # If flag and value are separate words
                    skip_next = True
                else:  # If flag=value format
                    parts = word.split('=', 1)
                    sanitized_words[-1] = f"{parts[0]}=[REDACTED]"
            else:
                sanitized_words.append(word)
        
        return ' '.join(sanitized_words)
    
    def determine_ai_type(self, container):
        """Determine AI type from container metadata"""
        labels = container.get('labels', {})
        env = container.get('environment', {})
        
        ai_type = labels.get('ai.type', '')
        if ai_type == 'drug-discovery':
            return 'Drug Discovery AI'
        elif ai_type == 'ehr-assistant':
            return 'EHR AI Assistant'
        elif 'MODEL_TYPE' in env:
            return f"{env['MODEL_TYPE'].title()} AI"
        else:
            return 'Containerized AI Agent'
    
    def build_endpoint(self, container):
        """Build endpoint URL from container port configuration"""
        ports = container.get('ports', {})
        for container_port, host_bindings in ports.items():
            if host_bindings and len(host_bindings) > 0:
                host_port = host_bindings[0].get('HostPort')
                if host_port:
                    return f"http://localhost:{host_port}"
        
        return f"docker://{container['name']}"
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        agent = AIAgent.query.filter_by(
            name=agent_data['name'],
            endpoint=agent_data['endpoint']
        ).first()
        
        if not agent:
            agent = AIAgent(
                name=agent_data['name'],
                type=agent_data['type'],
                protocol=agent_data['protocol'],
                endpoint=agent_data['endpoint'],
                cloud_provider=agent_data['cloud_provider'],
                region=agent_data['region'],
                agent_metadata=agent_data.get('agent_metadata') or agent_data.get('metadata')
            )
            db.session.add(agent)
        else:
            agent.agent_metadata = agent_data.get('agent_metadata') or agent_data.get('metadata')
        
        db.session.commit()
        return agent
    
    def perform_security_scan(self, agent, agent_data):
        """Perform security scan on Docker container"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'none'
        
        container_meta = agent_data['agent_metadata']
        env = container_meta.get('environment', {})
        labels = container_meta.get('labels', {})
        
        # Check for PHI access
        if env.get('PHI_ACCESS') == 'true' or labels.get('healthcare.phi') == 'true':
            phi_exposure = True
            
        # Check encryption
        if env.get('ENCRYPTION'):
            encryption_status = 'strong' if 'aes-256' in env['ENCRYPTION'] else 'weak'
            
        # Security vulnerability checks
        image = container_meta.get('image', '')
        if 'latest' in image:
            vulnerabilities += 1  # Using latest tag is not recommended
            
        if container_meta.get('status') != 'running':
            vulnerabilities += 1
            
        # Check for privileged mode or other risky configurations
        if not env.get('SECURITY_CONTEXT'):
            vulnerabilities += 1
            
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='docker_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'image': image,
                'container_status': container_meta.get('status')
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure, encryption_status)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def generate_recommendations(self, vulnerabilities, phi_exposure, encryption_status):
        """Generate Docker-specific security recommendations"""
        recommendations = []
        
        if phi_exposure and encryption_status == 'none':
            recommendations.append({
                'priority': 'critical',
                'category': 'encryption',
                'description': 'PHI processing detected without encryption',
                'action': 'Implement encryption at rest and in transit for all PHI data'
            })
            
        if vulnerabilities > 2:
            recommendations.append({
                'priority': 'high',
                'category': 'container_security',
                'description': 'Multiple security issues detected',
                'action': 'Review Docker security best practices and implement security hardening'
            })
            
        recommendations.append({
            'priority': 'medium',
            'category': 'image_management',
            'description': 'Container image security review needed',
            'action': 'Use specific image tags and scan for vulnerabilities regularly'
        })
        
        return recommendations
