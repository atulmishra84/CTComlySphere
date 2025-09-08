"""
Continuous Scanner for Healthcare AI Compliance Platform
Manages webhook-based continuous scanning of AI environments
"""

import logging
import requests
import json
from datetime import datetime, timedelta
from threading import Thread
import time
from app import db
from models import WebhookConfig, AIAgent, ScanResult
from scanners import ProtocolScanner
import schedule
import os

class ContinuousScanner:
    """Manages continuous scanning through webhooks and scheduled tasks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scanner = ProtocolScanner()
        self.running = False
        self.scan_threads = {}
    
    def start_continuous_scanning(self):
        """Start the continuous scanning service"""
        self.logger.info("Starting continuous scanning service")
        self.running = True
        
        # Start webhook scheduler
        scheduler_thread = Thread(target=self._run_scheduler, daemon=True)
        scheduler_thread.start()
        
        # Schedule initial webhook checks
        self._schedule_webhooks()
        
        return True
    
    def stop_continuous_scanning(self):
        """Stop the continuous scanning service"""
        self.logger.info("Stopping continuous scanning service")
        self.running = False
        
        # Clear scheduled jobs
        schedule.clear()
        
        return True
    
    def trigger_scan(self, webhook_config):
        """Manually trigger a scan for a specific webhook"""
        try:
            self.logger.info(f"Triggering scan for webhook: {webhook_config.name}")
            
            # Prepare scan parameters
            protocols = webhook_config.protocols or ['kubernetes', 'docker', 'rest_api']
            
            # Start scan in background thread
            scan_thread = Thread(
                target=self._execute_webhook_scan,
                args=(webhook_config, protocols),
                daemon=True
            )
            scan_thread.start()
            
            # Track active scan
            self.scan_threads[webhook_config.id] = scan_thread
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to trigger scan for webhook {webhook_config.id}: {str(e)}")
            raise
    
    def _run_scheduler(self):
        """Run the webhook scheduler"""
        self.logger.info("Webhook scheduler started")
        
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Scheduler error: {str(e)}")
                time.sleep(60)
    
    def _schedule_webhooks(self):
        """Schedule all active webhooks"""
        active_webhooks = WebhookConfig.query.filter_by(is_active=True).all()
        
        for webhook in active_webhooks:
            self._schedule_webhook(webhook)
    
    def _schedule_webhook(self, webhook_config):
        """Schedule a specific webhook"""
        try:
            # Convert frequency from seconds to minutes
            frequency_minutes = max(1, webhook_config.scan_frequency // 60)
            
            # Schedule the webhook
            schedule.every(frequency_minutes).minutes.do(
                self._scheduled_webhook_scan,
                webhook_config.id
            ).tag(f"webhook_{webhook_config.id}")
            
            self.logger.info(f"Scheduled webhook {webhook_config.name} every {frequency_minutes} minutes")
            
        except Exception as e:
            self.logger.error(f"Failed to schedule webhook {webhook_config.id}: {str(e)}")
    
    def _scheduled_webhook_scan(self, webhook_id):
        """Execute a scheduled webhook scan"""
        try:
            webhook_config = WebhookConfig.query.get(webhook_id)
            if not webhook_config or not webhook_config.is_active:
                # Remove schedule if webhook is inactive
                schedule.clear(f"webhook_{webhook_id}")
                return
            
            # Check if enough time has passed since last scan
            if webhook_config.last_triggered:
                time_since_last = datetime.utcnow() - webhook_config.last_triggered
                if time_since_last.total_seconds() < webhook_config.scan_frequency:
                    return  # Too soon for next scan
            
            self.trigger_scan(webhook_config)
            
        except Exception as e:
            self.logger.error(f"Scheduled scan failed for webhook {webhook_id}: {str(e)}")
    
    def _execute_webhook_scan(self, webhook_config, protocols):
        """Execute the actual webhook scan"""
        scan_start_time = datetime.utcnow()
        
        try:
            self.logger.info(f"Executing scan for webhook: {webhook_config.name}")
            
            # Perform discovery scan
            discovered_agents = self._perform_discovery_scan(protocols)
            
            # Send webhook notification (pre-scan)
            self._send_webhook_notification(webhook_config, 'scan_started', {
                'scan_id': f"webhook_{webhook_config.id}_{int(scan_start_time.timestamp())}",
                'protocols': protocols,
                'agents_discovered': len(discovered_agents)
            })
            
            # Perform security scans on discovered agents
            scan_results = self._perform_security_scans(discovered_agents)
            
            # Update webhook last triggered time
            webhook_config.last_triggered = datetime.utcnow()
            db.session.commit()
            
            # Send completion notification
            self._send_webhook_notification(webhook_config, 'scan_completed', {
                'scan_id': f"webhook_{webhook_config.id}_{int(scan_start_time.timestamp())}",
                'agents_scanned': len(scan_results),
                'high_risk_findings': sum(1 for r in scan_results if r.get('risk_level') in ['HIGH', 'CRITICAL']),
                'scan_duration': (datetime.utcnow() - scan_start_time).total_seconds()
            })
            
            self.logger.info(f"Completed scan for webhook: {webhook_config.name}")
            
        except Exception as e:
            self.logger.error(f"Webhook scan failed for {webhook_config.name}: {str(e)}")
            
            # Send error notification
            self._send_webhook_notification(webhook_config, 'scan_failed', {
                'error': str(e),
                'scan_duration': (datetime.utcnow() - scan_start_time).total_seconds()
            })
        
        finally:
            # Clean up thread tracking
            if webhook_config.id in self.scan_threads:
                del self.scan_threads[webhook_config.id]
    
    def _perform_discovery_scan(self, protocols):
        """Perform agent discovery across specified protocols"""
        discovered_agents = []
        
        for protocol in protocols:
            try:
                if protocol in self.scanner.scanners:
                    agents = self.scanner.scanners[protocol].discover_agents()
                    discovered_agents.extend(agents)
                    self.logger.debug(f"Discovered {len(agents)} agents via {protocol}")
            except Exception as e:
                self.logger.error(f"Discovery failed for protocol {protocol}: {str(e)}")
        
        return discovered_agents
    
    def _perform_security_scans(self, discovered_agents):
        """Perform security scans on discovered agents"""
        scan_results = []
        
        for agent_data in discovered_agents:
            try:
                # Create or update agent in database
                agent = self._create_or_update_agent(agent_data)
                
                # Perform security scan using appropriate scanner
                protocol = agent_data['protocol']
                if protocol in self.scanner.scanners:
                    scanner = self.scanner.scanners[protocol]
                    scan_result = scanner.perform_security_scan(agent, agent_data)
                    scan_results.append({
                        'agent_id': agent.id,
                        'protocol': protocol,
                        'risk_level': scan_result.risk_level.value,
                        'risk_score': scan_result.risk_score,
                        'vulnerabilities': scan_result.vulnerabilities_found,
                        'phi_exposure': scan_result.phi_exposure_detected
                    })
                    
            except Exception as e:
                self.logger.error(f"Security scan failed for agent {agent_data.get('name', 'unknown')}: {str(e)}")
        
        return scan_results
    
    def _create_or_update_agent(self, agent_data):
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
                agent_metadata=agent_data['metadata']
            )
            db.session.add(agent)
        else:
            agent.agent_metadata = agent_data['metadata']
            agent.last_scanned = datetime.utcnow()
        
        db.session.commit()
        return agent
    
    def _send_webhook_notification(self, webhook_config, event_type, data):
        """Send webhook notification"""
        try:
            payload = {
                'event_type': event_type,
                'webhook_id': webhook_config.id,
                'webhook_name': webhook_config.name,
                'timestamp': datetime.utcnow().isoformat(),
                'data': data
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'HealthcareAI-Compliance-Scanner/1.0',
                'X-Webhook-Event': event_type
            }
            
            response = requests.post(
                webhook_config.url,
                json=payload,
                headers=headers,
                timeout=30,
                verify=True
            )
            
            if response.status_code == 200:
                self.logger.info(f"Webhook notification sent successfully to {webhook_config.url}")
            else:
                self.logger.warning(f"Webhook notification failed: {response.status_code} {response.text}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to send webhook notification to {webhook_config.url}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error sending webhook notification: {str(e)}")
    
    def get_scan_status(self, webhook_id):
        """Get current scan status for a webhook"""
        webhook_config = WebhookConfig.query.get(webhook_id)
        if not webhook_config:
            return None
        
        is_scanning = webhook_id in self.scan_threads and self.scan_threads[webhook_id].is_alive()
        
        # Get recent scan results
        recent_scans = ScanResult.query.join(AIAgent).filter(
            ScanResult.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        return {
            'webhook_id': webhook_id,
            'webhook_name': webhook_config.name,
            'is_active': webhook_config.is_active,
            'is_scanning': is_scanning,
            'last_triggered': webhook_config.last_triggered.isoformat() if webhook_config.last_triggered else None,
            'scan_frequency': webhook_config.scan_frequency,
            'recent_scans_24h': recent_scans,
            'protocols': webhook_config.protocols
        }
    
    def update_webhook_config(self, webhook_id, config_updates):
        """Update webhook configuration"""
        try:
            webhook_config = WebhookConfig.query.get(webhook_id)
            if not webhook_config:
                raise ValueError(f"Webhook {webhook_id} not found")
            
            # Update configuration
            for key, value in config_updates.items():
                if hasattr(webhook_config, key):
                    setattr(webhook_config, key, value)
            
            db.session.commit()
            
            # Reschedule if frequency changed
            if 'scan_frequency' in config_updates or 'is_active' in config_updates:
                schedule.clear(f"webhook_{webhook_id}")
                if webhook_config.is_active:
                    self._schedule_webhook(webhook_config)
            
            self.logger.info(f"Updated webhook configuration for {webhook_config.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update webhook {webhook_id}: {str(e)}")
            db.session.rollback()
            raise
    
    def create_webhook_from_scan_results(self, scan_results, webhook_name):
        """Create a webhook configuration based on scan results"""
        try:
            # Analyze scan results to determine optimal protocols
            protocols_found = set()
            for result in scan_results:
                if 'protocol' in result:
                    protocols_found.add(result['protocol'])
            
            # Create webhook configuration
            webhook_config = WebhookConfig(
                name=webhook_name,
                url=os.getenv('DEFAULT_WEBHOOK_URL', 'https://example.com/webhook'),
                is_active=False,  # Start inactive for manual review
                scan_frequency=3600,  # 1 hour default
                protocols=list(protocols_found)
            )
            
            db.session.add(webhook_config)
            db.session.commit()
            
            self.logger.info(f"Created webhook configuration: {webhook_name}")
            return webhook_config.id
            
        except Exception as e:
            self.logger.error(f"Failed to create webhook from scan results: {str(e)}")
            db.session.rollback()
            raise
    
    def get_webhook_statistics(self):
        """Get statistics about webhook scanning activity"""
        try:
            total_webhooks = WebhookConfig.query.count()
            active_webhooks = WebhookConfig.query.filter_by(is_active=True).count()
            
            # Get recent scan activity
            last_24h = datetime.utcnow() - timedelta(hours=24)
            recent_scans = ScanResult.query.filter(ScanResult.created_at >= last_24h).count()
            
            # Get webhook with most recent activity
            most_recent_webhook = WebhookConfig.query.filter(
                WebhookConfig.last_triggered.isnot(None)
            ).order_by(WebhookConfig.last_triggered.desc()).first()
            
            return {
                'total_webhooks': total_webhooks,
                'active_webhooks': active_webhooks,
                'inactive_webhooks': total_webhooks - active_webhooks,
                'scans_last_24h': recent_scans,
                'most_recent_scan': {
                    'webhook_name': most_recent_webhook.name if most_recent_webhook else None,
                    'timestamp': most_recent_webhook.last_triggered.isoformat() if most_recent_webhook and most_recent_webhook.last_triggered else None
                },
                'currently_scanning': len(self.scan_threads)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get webhook statistics: {str(e)}")
            return {}

# Global continuous scanner instance
continuous_scanner = ContinuousScanner()
