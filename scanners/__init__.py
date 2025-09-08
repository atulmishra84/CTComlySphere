from .base_scanner import BaseScanner
from .kubernetes_scanner import KubernetesScanner
from .docker_scanner import DockerScanner
from .api_scanner import APIScanner
from .grpc_scanner import GRPCScanner
from .websocket_scanner import WebSocketScanner
from .mqtt_scanner import MQTTScanner
from .graphql_scanner import GraphQLScanner
from .cloud_scanner import CloudServiceScanner
from .a2a_scanner import A2ACommunicationScanner
from .mcp_scanner import MCPScanner
from .fhir_scanner import FHIRScanner
from .hl7_scanner import HL7Scanner
from .dicom_scanner import DICOMScanner
from .webrtc_scanner import WebRTCScanner
from .amqp_scanner import AMQPScanner

class ProtocolScanner:
    """Main scanner orchestrator that manages all protocol-specific scanners"""
    
    def __init__(self):
        self.scanners = {
            'kubernetes': KubernetesScanner(),
            'docker': DockerScanner(),
            'rest_api': APIScanner(),
            'grpc': GRPCScanner(),
            'websocket': WebSocketScanner(),
            'mqtt': MQTTScanner(),
            'graphql': GraphQLScanner(),
            'cloud_services': CloudServiceScanner(),
            'a2a_communication': A2ACommunicationScanner(),
            'mcp_protocol': MCPScanner(),
            'fhir': FHIRScanner(),
            'hl7': HL7Scanner(),
            'dicom': DICOMScanner(),
            'webrtc': WebRTCScanner(),
            'amqp': AMQPScanner()
        }
    
    def start_comprehensive_scan(self, protocols, cloud_providers=None):
        """Start a comprehensive scan across specified protocols"""
        import uuid
        scan_id = str(uuid.uuid4())
        
        results = {}
        for protocol in protocols:
            if protocol in self.scanners:
                try:
                    scanner_results = self.scanners[protocol].scan()
                    results[protocol] = scanner_results
                except Exception as e:
                    results[protocol] = {'error': str(e)}
        
        return scan_id
    
    def get_supported_protocols(self):
        """Get list of all supported scanning protocols"""
        return list(self.scanners.keys())

# Initialize global scanner instance
protocol_scanner = ProtocolScanner()
