from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
import socket

class GRPCScanner(BaseScanner):
    """Scanner for gRPC-based AI agents"""
    
    def __init__(self):
        super().__init__()
        self.timeout = int(os.getenv('GRPC_SCAN_TIMEOUT', '10'))
        self.grpc_ports = [9090, 9091, 8080, 50051, 50052]
    
    def scan(self):
        """Scan for gRPC-based AI agents"""
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
            self.logger.error(f"gRPC scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover gRPC AI agents through port scanning and service detection"""
        agents = []
        
        # Common hosts to scan
        hosts = ['localhost', '127.0.0.1']
        
        # Add any configured gRPC endpoints
        grpc_endpoints = os.getenv('GRPC_ENDPOINTS', '').split(',')
        for endpoint in grpc_endpoints:
            if endpoint.strip():
                host_port = endpoint.strip().split(':')
                if len(host_port) == 2:
                    hosts.append(host_port[0])
                    try:
                        port = int(host_port[1])
                        if port not in self.grpc_ports:
                            self.grpc_ports.append(port)
                    except ValueError:
                        pass
        
        for host in hosts:
            for port in self.grpc_ports:
                try:
                    if self.is_grpc_service(host, port):
                        agent_data = self.extract_grpc_service_info(host, port)
                        if agent_data:
                            agents.append(agent_data)
                except Exception as e:
                    self.logger.debug(f"Failed to check gRPC service at {host}:{port}: {str(e)}")
        
        return agents
    
    def is_grpc_service(self, host, port):
        """Check if a host:port combination is running a gRPC service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Port is open, try to detect gRPC
                return self.detect_grpc_protocol(host, port)
            
        except Exception:
            pass
        
        return False
    
    def detect_grpc_protocol(self, host, port):
        """Attempt to detect gRPC protocol on an open port"""
        try:
            # In a real implementation, you would use grpcio libraries
            # to probe the service and check for gRPC protocol
            # For now, we'll simulate detection based on common gRPC patterns
            
            # Mock gRPC service detection
            if port in [50051, 50052, 9090]:
                return True
            
            # Additional detection logic would go here
            # - Try to connect with gRPC client
            # - Check for HTTP/2 with specific headers
            # - Look for protocol buffer messages
            
        except Exception:
            pass
        
        return False
    
    def extract_grpc_service_info(self, host, port):
        """Extract service information from gRPC endpoint"""
        endpoint = f"{host}:{port}"
        
        # Mock service discovery - in real implementation would use reflection API
        mock_services = {
            50051: {
                'service_name': 'MedicalImagingService',
                'methods': ['AnalyzeXRay', 'ProcessMRI', 'ClassifyImage'],
                'package': 'healthcare.imaging.v1',
                'description': 'Medical imaging analysis service'
            },
            50052: {
                'service_name': 'ClinicalDecisionService',
                'methods': ['GetRecommendation', 'AnalyzeSymptoms', 'PredictOutcome'],
                'package': 'healthcare.clinical.v1',
                'description': 'Clinical decision support service'
            },
            9090: {
                'service_name': 'HealthcareNLPService',
                'methods': ['ExtractEntities', 'ClassifyDocument', 'SummarizeNote'],
                'package': 'healthcare.nlp.v1',
                'description': 'Healthcare NLP processing service'
            }
        }
        
        service_info = mock_services.get(port, {
            'service_name': f'GRPCService_{port}',
            'methods': ['UnknownMethod'],
            'package': 'unknown.package',
            'description': 'Unknown gRPC service'
        })
        
        return {
            'name': service_info['service_name'],
            'type': self.determine_ai_type(service_info),
            'protocol': 'grpc',
            'endpoint': endpoint,
            'cloud_provider': self.determine_cloud_provider(host),
            'region': 'local' if host in ['localhost', '127.0.0.1'] else 'unknown',
            'metadata': {
                'host': host,
                'port': port,
                'service_info': service_info,
                'tls_enabled': self.check_tls_support(host, port)
            }
        }
    
    def determine_ai_type(self, service_info):
        """Determine AI service type from gRPC service information"""
        service_name = service_info.get('service_name', '').lower()
        description = service_info.get('description', '').lower()
        package = service_info.get('package', '').lower()
        
        if 'imaging' in service_name or 'imaging' in package:
            return 'Medical Imaging AI'
        elif 'clinical' in service_name or 'decision' in service_name:
            return 'Clinical Decision Support'
        elif 'nlp' in service_name or 'nlp' in package:
            return 'Healthcare NLP AI'
        elif 'drug' in service_name or 'pharmaceutical' in description:
            return 'Drug Discovery AI'
        else:
            return 'Healthcare gRPC AI Service'
    
    def determine_cloud_provider(self, host):
        """Determine cloud provider from hostname"""
        if host in ['localhost', '127.0.0.1']:
            return 'Local'
        elif 'amazonaws.com' in host:
            return 'AWS'
        elif 'azure.com' in host:
            return 'Azure'
        elif 'googleapis.com' in host:
            return 'GCP'
        else:
            return 'Unknown'
    
    def check_tls_support(self, host, port):
        """Check if gRPC service supports TLS"""
        # In real implementation, would attempt TLS handshake
        # For now, assume TLS support based on port conventions
        return port in [443, 8443, 9443] or port > 50000
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        agent = AIAgent.query.filter_by(
            endpoint=agent_data['endpoint'],
            protocol='grpc'
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
        """Perform security scan on gRPC service"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'none'
        
        metadata = agent_data['metadata']
        service_info = metadata.get('service_info', {})
        
        # Check TLS support
        if metadata.get('tls_enabled'):
            encryption_status = 'tls'
        else:
            vulnerabilities += 1
            
        # Check for authentication
        # In real implementation, would check gRPC auth metadata
        if not self.check_authentication_required(agent_data):
            vulnerabilities += 1
            
        # Check for PHI handling
        methods = service_info.get('methods', [])
        if self.check_phi_handling(methods, service_info):
            phi_exposure = True
            
        # Check service configuration
        if not self.check_service_security_config(service_info):
            vulnerabilities += 1
            
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='grpc_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'tls_enabled': metadata.get('tls_enabled', False),
                'service_methods': methods,
                'package': service_info.get('package')
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure, encryption_status)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def check_authentication_required(self, agent_data):
        """Check if gRPC service requires authentication"""
        # In real implementation, would attempt unauthenticated calls
        # For now, simulate based on service type
        service_info = agent_data['metadata'].get('service_info', {})
        package = service_info.get('package', '')
        
        # Healthcare services should require authentication
        return 'healthcare' in package.lower()
    
    def check_phi_handling(self, methods, service_info):
        """Check if service handles PHI data"""
        phi_indicators = ['patient', 'medical', 'clinical', 'health', 'phi']
        
        # Check method names
        methods_str = ' '.join(methods).lower()
        description = service_info.get('description', '').lower()
        
        return any(indicator in methods_str + description for indicator in phi_indicators)
    
    def check_service_security_config(self, service_info):
        """Check gRPC service security configuration"""
        # In real implementation, would check:
        # - Rate limiting
        # - Input validation
        # - Security metadata
        # - Service mesh configuration
        
        # For now, simulate based on service maturity indicators
        package = service_info.get('package', '')
        return '.v1' in package or 'v2' in package  # Versioned APIs are more mature
    
    def generate_recommendations(self, vulnerabilities, phi_exposure, encryption_status):
        """Generate gRPC-specific security recommendations"""
        recommendations = []
        
        if encryption_status == 'none':
            recommendations.append({
                'priority': 'critical',
                'category': 'encryption',
                'description': 'gRPC service not using TLS encryption',
                'action': 'Enable TLS encryption for all gRPC communications'
            })
            
        if phi_exposure:
            recommendations.append({
                'priority': 'high',
                'category': 'data_protection',
                'description': 'Service processes PHI data without adequate protection',
                'action': 'Implement field-level encryption and access controls for PHI'
            })
            
        if vulnerabilities > 1:
            recommendations.append({
                'priority': 'medium',
                'category': 'service_security',
                'description': 'Multiple security issues in gRPC service',
                'action': 'Implement authentication, authorization, and rate limiting'
            })
            
        recommendations.append({
            'priority': 'low',
            'category': 'monitoring',
            'description': 'Enhance gRPC service monitoring',
            'action': 'Implement comprehensive logging and monitoring for gRPC calls'
        })
        
        return recommendations
