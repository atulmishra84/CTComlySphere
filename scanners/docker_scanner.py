from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
from datetime import datetime

class DockerScanner(BaseScanner):
    """Scanner for Docker-deployed AI agents"""
    
    def __init__(self):
        super().__init__()
        self.docker_host = os.getenv('DOCKER_HOST', 'unix://var/run/docker.sock')
    
    def scan(self):
        """Scan Docker environment for AI agents"""
        self.start_scan()
        
        try:
            agents = self.discover_agents()
            results = []
            
            for agent_data in agents:
                agent = self.create_or_update_agent(agent_data)
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
    
    def discover_agents(self, target=None):
        """Discover AI agents in Docker containers"""
        agents = []
        
        # Mock Docker container discovery
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
                    'discovery_method': 'legacy-scan',
                    'discovery_timestamp': datetime.utcnow().isoformat()
                }
            }
            agents.append(agent_data)
        
        return agents
    
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
                metadata=agent_data['metadata']
            )
            db.session.add(agent)
        else:
            agent.metadata = agent_data['metadata']
        
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
