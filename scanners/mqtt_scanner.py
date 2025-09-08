from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import json
import os
import socket

class MQTTScanner(BaseScanner):
    """Scanner for MQTT-based AI agents and IoT healthcare devices"""
    
    def __init__(self):
        super().__init__()
        self.timeout = int(os.getenv('MQTT_SCAN_TIMEOUT', '10'))
        self.mqtt_ports = [1883, 8883, 8884, 18830]  # Standard and secure MQTT ports
    
    def scan(self):
        """Scan for MQTT-based AI agents and IoT devices"""
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
            self.logger.error(f"MQTT scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover MQTT brokers and connected AI/IoT healthcare devices"""
        agents = []
        
        # Common hosts to scan
        hosts = ['localhost', '127.0.0.1']
        
        # Add configured MQTT brokers
        mqtt_brokers = os.getenv('MQTT_BROKERS', '').split(',')
        for broker in mqtt_brokers:
            if broker.strip():
                host_port = broker.strip().split(':')
                if len(host_port) >= 1:
                    hosts.append(host_port[0])
                    if len(host_port) == 2:
                        try:
                            port = int(host_port[1])
                            if port not in self.mqtt_ports:
                                self.mqtt_ports.append(port)
                        except ValueError:
                            pass
        
        for host in hosts:
            for port in self.mqtt_ports:
                try:
                    if self.is_mqtt_broker(host, port):
                        broker_info = self.extract_broker_info(host, port)
                        if broker_info:
                            # Get connected devices/agents from broker
                            connected_agents = self.get_connected_agents(host, port, broker_info)
                            agents.extend(connected_agents)
                except Exception as e:
                    self.logger.debug(f"Failed to check MQTT broker at {host}:{port}: {str(e)}")
        
        return agents
    
    def is_mqtt_broker(self, host, port):
        """Check if a host:port combination is running an MQTT broker"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Try to send MQTT CONNECT packet
                mqtt_connect = self.create_mqtt_connect_packet()
                sock.send(mqtt_connect)
                
                # Read response
                response = sock.recv(1024)
                sock.close()
                
                # Check for MQTT CONNACK response
                return len(response) >= 4 and response[0] == 0x20  # CONNACK packet type
            
            sock.close()
            
        except Exception:
            pass
        
        return False
    
    def create_mqtt_connect_packet(self):
        """Create a basic MQTT CONNECT packet for broker detection"""
        # Simplified MQTT CONNECT packet
        # In real implementation, would use proper MQTT client library
        client_id = "healthcare_scanner"
        
        # MQTT CONNECT packet structure (simplified)
        packet = bytearray()
        packet.extend(b'\x10')  # CONNECT packet type
        packet.extend(b'\x0c')  # Remaining length (simplified)
        packet.extend(b'\x00\x04MQTT')  # Protocol name
        packet.extend(b'\x04')  # Protocol level (MQTT 3.1.1)
        packet.extend(b'\x00')  # Connect flags
        packet.extend(b'\x00\x3c')  # Keep alive (60 seconds)
        packet.extend(len(client_id).to_bytes(2, 'big'))
        packet.extend(client_id.encode())
        
        return bytes(packet)
    
    def extract_broker_info(self, host, port):
        """Extract MQTT broker information"""
        is_secure = port in [8883, 8884]  # Standard secure MQTT ports
        
        return {
            'host': host,
            'port': port,
            'secure': is_secure,
            'protocol': 'mqtts' if is_secure else 'mqtt',
            'broker_type': self.determine_broker_type(host, port)
        }
    
    def determine_broker_type(self, host, port):
        """Determine MQTT broker type/vendor"""
        # In real implementation, would analyze broker responses for vendor info
        if port == 1883:
            return 'mosquitto'
        elif port == 8883:
            return 'secure_broker'
        else:
            return 'unknown'
    
    def get_connected_agents(self, host, port, broker_info):
        """Get AI agents and IoT devices connected to MQTT broker"""
        agents = []
        
        # Mock connected healthcare devices/agents
        mock_devices = [
            {
                'client_id': 'patient_monitor_001',
                'topics': ['vitals/heart_rate', 'vitals/blood_pressure', 'alerts/critical'],
                'device_type': 'Patient Monitoring AI',
                'description': 'AI-powered patient vital signs monitoring device',
                'phi_data': True,
                'last_seen': '2025-09-08T10:30:00Z'
            },
            {
                'client_id': 'insulin_pump_ai_007',
                'topics': ['devices/insulin_pump/data', 'devices/insulin_pump/control'],
                'device_type': 'Insulin Pump AI',
                'description': 'AI-controlled insulin delivery system',
                'phi_data': True,
                'last_seen': '2025-09-08T10:25:00Z'
            },
            {
                'client_id': 'medical_imaging_processor',
                'topics': ['imaging/xray/processed', 'imaging/mri/analysis', 'ai/diagnostics'],
                'device_type': 'Medical Imaging AI',
                'description': 'AI system for medical image analysis and diagnosis',
                'phi_data': True,
                'last_seen': '2025-09-08T10:20:00Z'
            }
        ]
        
        for device in mock_devices:
            endpoint = f"{broker_info['protocol']}://{host}:{port}"
            
            agent_data = {
                'name': device['client_id'],
                'type': device['device_type'],
                'protocol': 'mqtt',
                'endpoint': endpoint,
                'cloud_provider': self.determine_cloud_provider(host),
                'region': 'local' if host in ['localhost', '127.0.0.1'] else 'unknown',
                'metadata': {
                    'broker_host': host,
                    'broker_port': port,
                    'broker_secure': broker_info['secure'],
                    'client_id': device['client_id'],
                    'topics': device['topics'],
                    'device_info': device,
                    'phi_data_handling': device.get('phi_data', False)
                }
            }
            
            agents.append(agent_data)
        
        return agents
    
    def determine_cloud_provider(self, host):
        """Determine cloud provider from hostname"""
        if host in ['localhost', '127.0.0.1']:
            return 'Local'
        elif 'amazonaws.com' in host or 'iot.amazonaws.com' in host:
            return 'AWS IoT'
        elif 'azure.com' in host or 'azure-devices.net' in host:
            return 'Azure IoT'
        elif 'googleapis.com' in host or 'googlecloud.com' in host:
            return 'GCP IoT'
        else:
            return 'Unknown'
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        # Use client_id as unique identifier for MQTT devices
        client_id = agent_data['metadata']['client_id']
        
        agent = AIAgent.query.filter_by(
            name=client_id,
            protocol='mqtt'
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
        """Perform security scan on MQTT device/agent"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'none'
        
        metadata = agent_data['metadata']
        device_info = metadata.get('device_info', {})
        
        # Check broker security
        if metadata.get('broker_secure'):
            encryption_status = 'tls'
        else:
            vulnerabilities += 1
            
        # Check PHI data handling
        if metadata.get('phi_data_handling'):
            phi_exposure = True
            
        # Check topic security
        topics = metadata.get('topics', [])
        if self.check_insecure_topics(topics):
            vulnerabilities += 1
            
        # Check authentication
        if not self.check_device_authentication(device_info):
            vulnerabilities += 1
            
        # Check for device certificate validation
        if not self.check_certificate_validation(device_info):
            vulnerabilities += 1
            
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='mqtt_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'broker_secure': metadata.get('broker_secure', False),
                'topics': topics,
                'device_type': device_info.get('device_type')
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure, encryption_status)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def check_insecure_topics(self, topics):
        """Check for insecure MQTT topic configurations"""
        insecure_patterns = [
            '+/+/+',  # Too broad wildcards
            '#',      # Root wildcard
            'test/',  # Test topics in production
            'debug/'  # Debug topics
        ]
        
        for topic in topics:
            for pattern in insecure_patterns:
                if pattern in topic.lower():
                    return True
        
        return False
    
    def check_device_authentication(self, device_info):
        """Check if device uses proper authentication"""
        # In real implementation, would check for:
        # - Client certificates
        # - Username/password authentication
        # - Token-based authentication
        
        # For now, simulate based on device type
        device_type = device_info.get('device_type', '').lower()
        return 'ai' in device_type or 'monitor' in device_type
    
    def check_certificate_validation(self, device_info):
        """Check if device implements proper certificate validation"""
        # Healthcare IoT devices should use certificate-based authentication
        device_type = device_info.get('device_type', '').lower()
        critical_devices = ['insulin', 'monitor', 'pump', 'imaging']
        
        return any(device in device_type for device in critical_devices)
    
    def generate_recommendations(self, vulnerabilities, phi_exposure, encryption_status):
        """Generate MQTT-specific security recommendations"""
        recommendations = []
        
        if encryption_status == 'none':
            recommendations.append({
                'priority': 'critical',
                'category': 'encryption',
                'description': 'MQTT broker not using TLS encryption',
                'action': 'Enable MQTTS (MQTT over TLS) for all healthcare IoT communications'
            })
            
        if phi_exposure:
            recommendations.append({
                'priority': 'high',
                'category': 'data_protection',
                'description': 'PHI data transmitted through MQTT without adequate protection',
                'action': 'Implement message-level encryption and access controls for PHI data'
            })
            
        if vulnerabilities > 2:
            recommendations.append({
                'priority': 'medium',
                'category': 'iot_security',
                'description': 'Multiple security issues in MQTT IoT devices',
                'action': 'Implement device authentication, certificate management, and secure topics'
            })
            
        recommendations.append({
            'priority': 'low',
            'category': 'monitoring',
            'description': 'Enhance IoT device monitoring and alerting',
            'action': 'Implement device health monitoring, anomaly detection, and audit logging'
        })
        
        return recommendations
