from abc import ABC, abstractmethod
from datetime import datetime
import logging

class BaseScanner(ABC):
    """Abstract base class for all protocol scanners"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.scan_start_time = None
        self.scan_end_time = None
    
    @abstractmethod
    def scan(self):
        """Perform the actual scanning operation"""
        pass
    
    @abstractmethod
    def discover_agents(self):
        """Discover AI agents using this protocol"""
        pass
    
    def start_scan(self):
        """Initialize scan timing"""
        self.scan_start_time = datetime.utcnow()
        self.logger.info(f"Starting {self.__class__.__name__} scan")
    
    def end_scan(self):
        """Finalize scan timing"""
        self.scan_end_time = datetime.utcnow()
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        self.logger.info(f"Completed {self.__class__.__name__} scan in {duration:.2f} seconds")
        return duration
    
    def calculate_risk_score(self, vulnerabilities, phi_exposure, encryption_status):
        """Calculate risk score based on findings"""
        base_score = 0
        
        # Vulnerability scoring
        base_score += min(vulnerabilities * 10, 50)
        
        # PHI exposure is critical in healthcare
        if phi_exposure:
            base_score += 40
        
        # Encryption status
        if encryption_status == 'none':
            base_score += 20
        elif encryption_status == 'weak':
            base_score += 10
        
        # Cap at 100
        return min(base_score, 100)
    
    def determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
