"""
Scheduler Integration for Continuous Scanning

Integrates the continuous scanner with the Flask application lifecycle
to provide truly automated background scanning.
"""

import logging
import atexit
import threading
from typing import Optional

from services.continuous_scanner import continuous_scanner, ScanConfiguration, ScanMode


class SchedulerIntegration:
    """Handles integration between Flask app and continuous scanning scheduler"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.is_initialized = False
        self._shutdown_handler_registered = False
    
    def initialize_with_app(self, app):
        """Initialize scheduler integration with Flask app"""
        if self.is_initialized:
            return
        
        self.logger.info("Initializing scheduler integration for continuous scanning")
        
        # Register shutdown handler
        if not self._shutdown_handler_registered:
            atexit.register(self._cleanup_on_shutdown)
            self._shutdown_handler_registered = True
        
        # Start with default configuration if enabled
        self._start_default_scanning()
        
        self.is_initialized = True
        self.logger.info("Scheduler integration initialized successfully")
    
    def _start_default_scanning(self):
        """Start continuous scanning with default configuration"""
        try:
            # Enable automatic scanning by default for healthcare compliance monitoring
            default_config = ScanConfiguration(
                enabled=True,  # Auto-enabled for continuous compliance monitoring
                scan_interval_minutes=15,  # More frequent scanning for better coverage
                scan_mode=ScanMode.DISCOVERY,
                target_protocols=['kubernetes', 'docker', 'a2a_communication', 'api_endpoint', 'mcp_protocol'],
                target_environments=['development', 'staging', 'production'],
                auto_register=True,
                notification_enabled=True
            )
            
            # Start automatic scanning immediately
            success = continuous_scanner.start_scanning(default_config)
            
            if success:
                self.logger.info("✅ Automatic continuous scanning started successfully")
                self.logger.info(f"📊 Scanning every {default_config.scan_interval_minutes} minutes for AI agent discovery")
                self.logger.info(f"🎯 Monitoring protocols: {', '.join(default_config.target_protocols)}")
                self.logger.info(f"🏥 Healthcare compliance monitoring is now ACTIVE")
            else:
                self.logger.warning("⚠️  Failed to start automatic scanning - will retry")
                # Retry after a short delay
                import threading
                import time
                def retry_start():
                    time.sleep(5)
                    retry_success = continuous_scanner.start_scanning(default_config)
                    if retry_success:
                        self.logger.info("✅ Automatic scanning started on retry")
                    else:
                        self.logger.error("❌ Failed to start automatic scanning after retry")
                
                retry_thread = threading.Thread(target=retry_start, daemon=True)
                retry_thread.start()
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start automatic scanning: {str(e)}")
            # Log the error but don't crash the application
    
    def start_automatic_scanning(self, config: Optional[ScanConfiguration] = None):
        """Start automatic scanning (can be called from routes)"""
        try:
            if config is None:
                config = ScanConfiguration(
                    enabled=True,
                    scan_interval_minutes=30,
                    scan_mode=ScanMode.DISCOVERY,
                    target_protocols=['kubernetes', 'docker', 'a2a_communication'],
                    auto_register=True
                )
            
            success = continuous_scanner.start_scanning(config)
            if success:
                self.logger.info("Automatic scanning started successfully")
            else:
                self.logger.warning("Failed to start automatic scanning")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error starting automatic scanning: {str(e)}")
            return False
    
    def stop_automatic_scanning(self):
        """Stop automatic scanning"""
        try:
            success = continuous_scanner.stop_scanning()
            if success:
                self.logger.info("Automatic scanning stopped successfully")
            else:
                self.logger.warning("Failed to stop automatic scanning")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error stopping automatic scanning: {str(e)}")
            return False
    
    def get_scanner_status(self):
        """Get current scanner status"""
        try:
            return continuous_scanner.get_status()
        except Exception as e:
            self.logger.error(f"Error getting scanner status: {str(e)}")
            return {
                'is_running': False,
                'error': str(e)
            }
    
    def _cleanup_on_shutdown(self):
        """Cleanup when application shuts down"""
        try:
            self.logger.info("Application shutdown detected, stopping continuous scanning")
            continuous_scanner.stop_scanning()
            self.logger.info("Continuous scanning stopped cleanly")
        except Exception as e:
            self.logger.error(f"Error during scanner cleanup: {str(e)}")


# Global instance
scheduler_integration = SchedulerIntegration()


def init_scheduler_with_app(app):
    """Initialize scheduler integration with Flask app"""
    scheduler_integration.initialize_with_app(app)