"""
Continuous Environment Scanner Service

Automatically discovers AI agents across infrastructure and adds them to the system.
Runs background scans at configurable intervals to ensure comprehensive coverage.
"""

import asyncio
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

from app import db
from models import AIAgent, ScanResult, RiskLevel, AIAgentType, ScanStatus
from scanners.environment_scanner import environment_scanner, ScanTarget, ScannerType
from agents.classification_engine import AgentClassificationEngine


class ScanMode(Enum):
    DISCOVERY = "discovery"  # Find new agents only
    FULL = "full"  # Complete environment scan
    TARGETED = "targeted"  # Scan specific protocols/environments


@dataclass
class ScanConfiguration:
    """Configuration for continuous scanning"""
    enabled: bool = False
    scan_interval_minutes: int = 30
    scan_mode: ScanMode = ScanMode.DISCOVERY
    target_protocols: List[str] = None
    target_environments: List[str] = None
    auto_register: bool = True
    notification_enabled: bool = True
    
    def __post_init__(self):
        if self.target_protocols is None:
            self.target_protocols = ['kubernetes', 'docker', 'rest_api', 'grpc']
        if self.target_environments is None:
            self.target_environments = ['development', 'staging', 'production']


class ContinuousScanner:
    """Service for continuous environment scanning and AI agent discovery"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.scan_thread: Optional[threading.Thread] = None
        self.configuration = ScanConfiguration()
        self.classification_engine = AgentClassificationEngine()
        
        # Statistics tracking
        self.stats = {
            'total_scans': 0,
            'agents_discovered': 0,
            'agents_added': 0,
            'last_scan_time': None,
            'next_scan_time': None,
            'scan_errors': 0,
            'scan_history': []
        }
        
        self.logger.info("Continuous Scanner service initialized")
    
    def start_scanning(self, config: Optional[ScanConfiguration] = None) -> bool:
        """Start continuous scanning with specified configuration"""
        if self.is_running:
            self.logger.warning("Continuous scanning is already running")
            return False
        
        if config:
            self.configuration = config
        
        if not self.configuration.enabled:
            self.logger.info("Continuous scanning is disabled in configuration")
            return False
        
        self.is_running = True
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        self.logger.info(f"Started continuous scanning with {self.configuration.scan_interval_minutes} minute intervals")
        return True
    
    def stop_scanning(self) -> bool:
        """Stop continuous scanning"""
        if not self.is_running:
            self.logger.warning("Continuous scanning is not running")
            return False
        
        self.is_running = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=5)
        
        self.logger.info("Stopped continuous scanning")
        return True
    
    def update_configuration(self, config: ScanConfiguration) -> None:
        """Update scanning configuration"""
        self.configuration = config
        self.logger.info(f"Updated scanning configuration: {config.scan_mode.value} mode, "
                        f"{config.scan_interval_minutes} minute intervals")
    
    def trigger_immediate_scan(self) -> str:
        """Trigger an immediate scan and return scan ID"""
        try:
            scan_id = asyncio.run(self._execute_scan())
            self.logger.info(f"Triggered immediate scan: {scan_id}")
            return scan_id
        except Exception as e:
            self.logger.error(f"Failed to trigger immediate scan: {str(e)}")
            raise
    
    def _scan_loop(self):
        """Main scanning loop running in background thread"""
        self.logger.info("Continuous scanning loop started")
        
        while self.is_running:
            try:
                # Calculate next scan time
                self.stats['next_scan_time'] = datetime.utcnow() + timedelta(
                    minutes=self.configuration.scan_interval_minutes
                )
                
                # Execute scan
                scan_id = asyncio.run(self._execute_scan())
                self.stats['last_scan_time'] = datetime.utcnow()
                self.stats['total_scans'] += 1
                
                # Add to scan history
                self.stats['scan_history'].append({
                    'scan_id': scan_id,
                    'timestamp': self.stats['last_scan_time'].isoformat(),
                    'mode': self.configuration.scan_mode.value
                })
                
                # Keep only last 50 scans in history
                if len(self.stats['scan_history']) > 50:
                    self.stats['scan_history'] = self.stats['scan_history'][-50:]
                
                self.logger.info(f"Completed continuous scan {scan_id}")
                
            except Exception as e:
                self.stats['scan_errors'] += 1
                self.logger.error(f"Error in continuous scan: {str(e)}")
            
            # Wait for next scan interval
            sleep_time = self.configuration.scan_interval_minutes * 60
            for _ in range(sleep_time):
                if not self.is_running:
                    break
                time.sleep(1)
        
        self.logger.info("Continuous scanning loop stopped")
    
    async def _execute_scan(self) -> str:
        """Execute a single scan cycle"""
        try:
            # Create scan target based on configuration
            scan_target = self._create_scan_target()
            
            # Run environment scan
            scan_id = await environment_scanner.run_scan(scan_target)
            
            # Wait for scan completion
            await self._wait_for_scan_completion(scan_id)
            
            # Process discovered agents
            await self._process_discovered_agents(scan_id)
            
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Scan execution failed: {str(e)}")
            raise
    
    def _create_scan_target(self) -> ScanTarget:
        """Create scan target based on current configuration"""
        scanner_types = []
        
        # Map protocol names to scanner types
        protocol_mapping = {
            'kubernetes': ScannerType.KUBERNETES,
            'docker': ScannerType.DOCKER,
            'cloud_service': ScannerType.CLOUD_SERVICE,
            'a2a_communication': ScannerType.A2A_COMMUNICATION,
            'mcp_protocol': ScannerType.MCP_PROTOCOL,
            'api_endpoint': ScannerType.API_ENDPOINT,
            'model_registry': ScannerType.MODEL_REGISTRY,
            'process': ScannerType.PROCESS
        }
        
        for protocol in self.configuration.target_protocols:
            if protocol in protocol_mapping:
                scanner_types.append(protocol_mapping[protocol])
        
        # Default to all scanners if none specified
        if not scanner_types:
            scanner_types = list(protocol_mapping.values())
        
        return ScanTarget(
            environment=self.configuration.target_environments[0] if self.configuration.target_environments else 'development',
            scan_types=scanner_types,
            include_compliance_check=True,
            include_risk_assessment=True
        )
    
    async def _wait_for_scan_completion(self, scan_id: str, timeout_minutes: int = 10):
        """Wait for scan to complete with timeout"""
        timeout_time = datetime.utcnow() + timedelta(minutes=timeout_minutes)
        
        while datetime.utcnow() < timeout_time:
            scan_result = environment_scanner.get_scan_result(scan_id)
            if scan_result and scan_result.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                if scan_result.status == ScanStatus.FAILED:
                    raise Exception(f"Scan {scan_id} failed: {scan_result.errors}")
                return
            
            await asyncio.sleep(2)
        
        raise Exception(f"Scan {scan_id} timed out after {timeout_minutes} minutes")
    
    async def _process_discovered_agents(self, scan_id: str):
        """Process discovered agents and add new ones to database"""
        scan_result = environment_scanner.get_scan_result(scan_id)
        if not scan_result or not scan_result.discovered_agents:
            return
        
        new_agents_count = 0
        
        for agent_data in scan_result.discovered_agents:
            try:
                # Check if agent already exists
                existing_agent = AIAgent.query.filter_by(
                    name=agent_data.get('name'),
                    endpoint=agent_data.get('endpoint')
                ).first()
                
                if existing_agent:
                    # Update last scanned time
                    existing_agent.last_scanned = datetime.utcnow()
                    db.session.commit()
                    continue
                
                # Create new agent if auto-registration is enabled
                if self.configuration.auto_register:
                    new_agent = await self._create_agent_from_discovery(agent_data)
                    if new_agent:
                        new_agents_count += 1
                        self.logger.info(f"Auto-registered new AI agent: {new_agent.name}")
                
            except Exception as e:
                self.logger.error(f"Failed to process discovered agent {agent_data.get('name', 'unknown')}: {str(e)}")
        
        self.stats['agents_discovered'] += len(scan_result.discovered_agents)
        self.stats['agents_added'] += new_agents_count
        
        if new_agents_count > 0:
            self.logger.info(f"Added {new_agents_count} new AI agents to the system")
    
    async def _create_agent_from_discovery(self, agent_data: Dict[str, Any]) -> Optional[AIAgent]:
        """Create AIAgent instance from discovered agent data"""
        try:
            # Use classification engine to determine AI type
            ai_type = await self._classify_agent_type(agent_data)
            
            # Create new AI agent
            new_agent = AIAgent(
                name=agent_data.get('name'),
                type=agent_data.get('type', 'Unknown AI Agent'),
                protocol=agent_data.get('protocol'),
                endpoint=agent_data.get('endpoint'),
                ai_type=ai_type,
                agent_metadata=agent_data.get('metadata', {}),
                discovered_at=datetime.utcnow(),
                last_scanned=datetime.utcnow(),
                risk_level=agent_data.get('risk_level', RiskLevel.MEDIUM)
            )
            
            db.session.add(new_agent)
            db.session.commit()
            
            return new_agent
            
        except Exception as e:
            self.logger.error(f"Failed to create agent from discovery: {str(e)}")
            db.session.rollback()
            return None
    
    async def _classify_agent_type(self, agent_data: Dict[str, Any]) -> AIAgentType:
        """Classify discovered agent to determine AI type"""
        try:
            # Use the classification engine for sophisticated classification
            classification_result = await self.classification_engine.classify_agent(agent_data)
            
            # Map classification result to AIAgentType
            ai_type_mapping = {
                'GenAI': AIAgentType.GENAI,
                'Agentic AI': AIAgentType.AGENTIC_AI,
                'Multimodal AI': AIAgentType.MULTIMODAL_AI,
                'Computer Vision': AIAgentType.COMPUTER_VISION,
                'NLP': AIAgentType.NLP,
                'Traditional ML': AIAgentType.TRADITIONAL_ML
            }
            
            classified_type = classification_result.get('ai_type', 'Traditional ML')
            return ai_type_mapping.get(classified_type, AIAgentType.TRADITIONAL_ML)
            
        except Exception as e:
            self.logger.error(f"Classification failed, using default: {str(e)}")
            return AIAgentType.TRADITIONAL_ML
    
    def get_status(self) -> Dict[str, Any]:
        """Get current scanning status and statistics"""
        return {
            'is_running': self.is_running,
            'configuration': asdict(self.configuration),
            'statistics': self.stats.copy(),
            'scan_thread_alive': self.scan_thread.is_alive() if self.scan_thread else False
        }
    
    def get_scan_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent scan history"""
        return self.stats['scan_history'][-limit:] if self.stats['scan_history'] else []


# Global instance
continuous_scanner = ContinuousScanner()