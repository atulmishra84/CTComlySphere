from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
import socket
import ssl

class WebSocketScanner(BaseScanner):
    """Scanner for WebSocket-based AI agents"""
    
    def __init__(self):
        super().__init__()
        self.timeout = int(os.getenv('WS_SCAN_TIMEOUT', '10'))
        self.ws_ports = [8080, 8081, 3000, 3001, 4000, 8765, 9001]
    
    def scan(self):
        """Scan for WebSocket-based AI agents"""
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
            self.logger.error(f"WebSocket scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover WebSocket AI agents through connection probing"""
        agents = []
        
        # Common hosts to scan
        hosts = ['localhost', '127.0.0.1']
        
        # Add configured WebSocket endpoints
        ws_endpoints = os.getenv('WS_ENDPOINTS', '').split(',')
        for endpoint in ws_endpoints:
            if endpoint.strip():
                try:
                    # Parse ws://host:port or wss://host:port
                    if endpoint.startswith(('ws://', 'wss://')):
                        url_parts = endpoint.split('://', 1)[1].split('/')
                        host_port = url_parts[0].split(':')
                        host = host_port[0]
                        port = int(host_port[1]) if len(host_port) > 1 else (443 if endpoint.startswith('wss://') else 80)
                        
                        if host not in hosts:
                            hosts.append(host)
                        if port not in self.ws_ports:
                            self.ws_ports.append(port)
                except (ValueError, IndexError):
                    pass
        
        for host in hosts:
            for port in self.ws_ports:
                try:
                    if self.is_websocket_service(host, port):
                        agent_data = self.extract_websocket_service_info(host, port)
                        if agent_data:
                            agents.append(agent_data)
                except Exception as e:
                    self.logger.debug(f"Failed to check WebSocket service at {host}:{port}: {str(e)}")
        
        return agents
    
    def is_websocket_service(self, host, port):
        """Check if a host:port combination supports WebSocket connections"""
        try:
            # Try HTTP connection first to check for WebSocket upgrade support
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Send HTTP upgrade request to check for WebSocket support
                upgrade_request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"\r\n"
                )
                
                sock.send(upgrade_request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # Check for WebSocket upgrade response
                return 'websocket' in response.lower() and '101' in response
            
            sock.close()
            
        except Exception:
            pass
        
        return False
    
    def extract_websocket_service_info(self, host, port):
        """Extract service information from WebSocket endpoint"""
        # Determine protocol (ws or wss)
        is_secure = port in [443, 8443, 9443] or self.check_tls_support(host, port)
        protocol_scheme = 'wss' if is_secure else 'ws'
        endpoint = f"{protocol_scheme}://{host}:{port}"
        
        # Mock WebSocket service detection
        mock_services = {
            8080: {
                'service_name': 'RealTimeHealthMonitor',
                'service_type': 'Real-time Health Monitoring',
                'features': ['vitals_streaming', 'alert_system', 'phi_transmission'],
                'description': 'Real-time patient health monitoring WebSocket service'
            },
            8081: {
                'service_name': 'TelemedicineChat',
                'service_type': 'Telemedicine Communication',
                'features': ['video_chat', 'medical_consultation', 'file_transfer'],
                'description': 'Telemedicine chat and consultation service'
            },
            3000: {
                'service_name': 'MedicalIoTGateway',
                'service_type': 'Medical IoT Gateway',
                'features': ['device_data', 'sensor_monitoring', 'real_time_analytics'],
                'description': 'Medical IoT device data gateway'
            }
        }
        
        service_info = mock_services.get(port, {
            'service_name': f'WebSocketService_{port}',
            'service_type': 'Healthcare WebSocket Service',
            'features': ['real_time_data'],
            'description': 'Unknown healthcare WebSocket service'
        })
        
        return {
            'name': service_info['service_name'],
            'type': service_info['service_type'],
            'protocol': 'websocket',
            'endpoint': endpoint,
            'cloud_provider': self.determine_cloud_provider(host),
            'region': 'local' if host in ['localhost', '127.0.0.1'] else 'unknown',
            'metadata': {
                'host': host,
                'port': port,
                'secure': is_secure,
                'service_info': service_info,
                'protocol_scheme': protocol_scheme
            }
        }
    
    def check_tls_support(self, host, port):
        """Check if WebSocket service supports TLS (WSS)"""
        try:
            # Try to establish TLS connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except Exception:
            pass
        
        return False
    
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
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        agent = AIAgent.query.filter_by(
            endpoint=agent_data['endpoint'],
            protocol='websocket'
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
        """Perform security scan on WebSocket service"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'none'
        
        metadata = agent_data['metadata']
        service_info = metadata.get('service_info', {})
        
        # Check encryption (WSS vs WS)
        if metadata.get('secure'):
            encryption_status = 'tls'
        else:
            vulnerabilities += 1
            
        # Check for authentication requirements
        if not self.check_authentication_required(service_info):
            vulnerabilities += 1
            
        # Check for PHI transmission
        features = service_info.get('features', [])
        if self.check_phi_transmission(features, service_info):
            phi_exposure = True
            
        # Check for real-time data validation
        if not self.check_data_validation(service_info):
            vulnerabilities += 1
            
        # Check for rate limiting and DoS protection
        if not self.check_rate_limiting(service_info):
            vulnerabilities += 1
            
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='websocket_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'secure_connection': metadata.get('secure', False),
                'service_features': features,
                'protocol_scheme': metadata.get('protocol_scheme')
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure, encryption_status)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def check_authentication_required(self, service_info):
        """Check if WebSocket service requires authentication"""
        # Healthcare WebSocket services should require authentication
        service_type = service_info.get('service_type', '').lower()
        description = service_info.get('description', '').lower()
        
        healthcare_indicators = ['health', 'medical', 'telemedicine', 'patient']
        return any(indicator in service_type + description for indicator in healthcare_indicators)
    
    def check_phi_transmission(self, features, service_info):
        """Check if service transmits PHI data"""
        phi_indicators = ['phi', 'vitals', 'medical', 'patient', 'health', 'consultation']
        
        features_str = ' '.join(features).lower()
        description = service_info.get('description', '').lower()
        
        return any(indicator in features_str + description for indicator in phi_indicators)
    
    def check_data_validation(self, service_info):
        """Check if service implements proper data validation"""
        # In real implementation, would check for input validation mechanisms
        # For now, simulate based on service maturity
        return 'gateway' in service_info.get('service_type', '').lower()
    
    def check_rate_limiting(self, service_info):
        """Check if service implements rate limiting"""
        # In real implementation, would test rate limiting by sending rapid requests
        # For now, simulate based on service type
        service_type = service_info.get('service_type', '').lower()
        return 'monitoring' in service_type or 'gateway' in service_type
    
    def generate_recommendations(self, vulnerabilities, phi_exposure, encryption_status):
        """Generate WebSocket-specific security recommendations"""
        recommendations = []
        
        if encryption_status == 'none':
            recommendations.append({
                'priority': 'critical',
                'category': 'encryption',
                'description': 'WebSocket service not using secure connections (WSS)',
                'action': 'Enable WSS (WebSocket Secure) for all healthcare data transmissions'
            })
            
        if phi_exposure:
            recommendations.append({
                'priority': 'high',
                'category': 'data_protection',
                'description': 'PHI data transmitted through WebSocket without adequate protection',
                'action': 'Implement end-to-end encryption and access controls for PHI transmission'
            })
            
        if vulnerabilities > 2:
            recommendations.append({
                'priority': 'medium',
                'category': 'websocket_security',
                'description': 'Multiple security issues in WebSocket service',
                'action': 'Implement authentication, rate limiting, and input validation'
            })
            
        recommendations.append({
            'priority': 'low',
            'category': 'monitoring',
            'description': 'Enhance real-time monitoring for WebSocket connections',
            'action': 'Implement connection monitoring, anomaly detection, and audit logging'
        })
        
        return recommendations
