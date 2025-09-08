"""
Scanner Manager for Healthcare Compliance AI Agent
Manages and coordinates all protocol scanners
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from scanners.api_scanner import APIScanner
from scanners.kubernetes_scanner import KubernetesScanner
from scanners.docker_scanner import DockerScanner
from scanners.graphql_scanner import GraphQLScanner
from scanners.mqtt_scanner import MQTTScanner
from scanners.webrtc_scanner import WebRTCScanner
from scanners.fhir_scanner import FHIRScanner
from scanners.dicom_scanner import DICOMScanner
from scanners.amqp_scanner import AMQPScanner
from scanners.a2a_scanner import A2ACommunicationScanner


class ScannerManager:
    """
    Manages and coordinates all healthcare AI protocol scanners
    Used by the Healthcare Compliance AI Agent for autonomous discovery
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scanners = self._initialize_scanners()
        self.scan_history: List[Dict[str, Any]] = []
    
    def _initialize_scanners(self) -> Dict[str, Any]:
        """Initialize all available scanners"""
        scanners = {}
        
        try:
            scanners['rest_api'] = APIScanner()
            self.logger.info("REST API scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize REST API scanner: {e}")
        
        try:
            scanners['kubernetes'] = KubernetesScanner()
            self.logger.info("Kubernetes scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize Kubernetes scanner: {e}")
        
        try:
            scanners['docker'] = DockerScanner()
            self.logger.info("Docker scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize Docker scanner: {e}")
        
        try:
            scanners['graphql'] = GraphQLScanner()
            self.logger.info("GraphQL scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize GraphQL scanner: {e}")
        
        try:
            scanners['mqtt'] = MQTTScanner()
            self.logger.info("MQTT scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize MQTT scanner: {e}")
        
        try:
            scanners['webrtc'] = WebRTCScanner()
            self.logger.info("WebRTC scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize WebRTC scanner: {e}")
        
        try:
            scanners['fhir'] = FHIRScanner()
            self.logger.info("FHIR scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize FHIR scanner: {e}")
        
        try:
            scanners['dicom'] = DICOMScanner()
            self.logger.info("DICOM scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize DICOM scanner: {e}")
        
        try:
            scanners['amqp'] = AMQPScanner()
            self.logger.info("AMQP scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize AMQP scanner: {e}")
        
        try:
            scanners['a2a'] = A2ACommunicationScanner()
            self.logger.info("A2A Communication scanner initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize A2A Communication scanner: {e}")
        
        self.logger.info(f"Scanner Manager initialized with {len(scanners)} scanners")
        return scanners
    
    async def run_protocol_scan(self, protocol: str) -> Dict[str, Any]:
        """Run scan for a specific protocol"""
        if protocol not in self.scanners:
            raise ValueError(f"Unknown protocol: {protocol}")
        
        scanner = self.scanners[protocol]
        start_time = datetime.utcnow()
        
        try:
            self.logger.info(f"Starting {protocol} scan")
            
            # For now, call the synchronous scan method
            # In a real implementation, you'd make these truly async
            result = scanner.scan()
            
            scan_record = {
                'protocol': protocol,
                'start_time': start_time.isoformat(),
                'end_time': datetime.utcnow().isoformat(),
                'status': 'completed',
                'result': result
            }
            
            self.scan_history.append(scan_record)
            self.logger.info(f"Completed {protocol} scan")
            
            return result
            
        except Exception as e:
            scan_record = {
                'protocol': protocol,
                'start_time': start_time.isoformat(),
                'end_time': datetime.utcnow().isoformat(),
                'status': 'failed',
                'error': str(e)
            }
            
            self.scan_history.append(scan_record)
            self.logger.error(f"Failed {protocol} scan: {e}")
            
            return {
                'status': 'failed',
                'error': str(e),
                'agents': []
            }
    
    async def run_comprehensive_scan(self, protocols: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run comprehensive scan across multiple protocols"""
        if protocols is None:
            protocols = list(self.scanners.keys())
        
        self.logger.info(f"Starting comprehensive scan for protocols: {protocols}")
        
        results = {}
        total_agents = 0
        
        # Run scans in parallel for better performance
        tasks = []
        for protocol in protocols:
            if protocol in self.scanners:
                task = asyncio.create_task(self.run_protocol_scan(protocol))
                tasks.append((protocol, task))
        
        # Wait for all scans to complete
        for protocol, task in tasks:
            try:
                result = await task
                results[protocol] = result
                if 'agents_found' in result:
                    total_agents += result['agents_found']
            except Exception as e:
                self.logger.error(f"Comprehensive scan failed for {protocol}: {e}")
                results[protocol] = {'status': 'failed', 'error': str(e)}
        
        return {
            'status': 'completed',
            'protocols_scanned': len(results),
            'total_agents_found': total_agents,
            'results': results,
            'scan_timestamp': datetime.utcnow().isoformat()
        }
    
    def get_available_protocols(self) -> List[str]:
        """Get list of available scanning protocols"""
        return list(self.scanners.keys())
    
    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent scan history"""
        return self.scan_history[-limit:]
    
    def get_scanner_status(self) -> Dict[str, Any]:
        """Get status of all scanners"""
        status = {
            'total_scanners': len(self.scanners),
            'available_protocols': list(self.scanners.keys()),
            'scan_history_count': len(self.scan_history),
            'last_scan': self.scan_history[-1] if self.scan_history else None
        }
        
        return status


# Global scanner manager instance
scanner_manager = ScannerManager()