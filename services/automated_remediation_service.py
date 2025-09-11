"""
Automated Remediation Service
Orchestrates automated remediation workflows based on compliance violations and security alerts
"""

import logging
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from app import db
from models import (
    RemediationWorkflow, RemediationExecution, RemediationActionExecution,
    RemediationWorkflowStatus, RemediationTriggerType, RemediationActionType,
    AIAgent, ScanResult, ComplianceEvaluation, RiskLevel, ComplianceFramework
)
from remediation.workflow_engine import RemediationWorkflowEngine

logger = logging.getLogger(__name__)


@dataclass
class RemediationTrigger:
    """Represents a trigger for automated remediation"""
    trigger_type: RemediationTriggerType
    agent_id: int
    severity: RiskLevel
    details: Dict[str, Any]
    framework: Optional[ComplianceFramework] = None
    scan_result_id: Optional[int] = None
    compliance_evaluation_id: Optional[int] = None


class AutomatedRemediationService:
    """
    Main service for automated remediation workflows
    Monitors for compliance violations and security alerts, then triggers appropriate remediation workflows
    """
    
    def __init__(self):
        self.logger = logger
        self.workflow_engine = RemediationWorkflowEngine()
        self.active_monitors = {}
        self.remediation_queue = asyncio.Queue()
        
    async def initialize(self):
        """Initialize the automated remediation service"""
        try:
            self.logger.info("🔧 Initializing Automated Remediation Service")
            
            # Load active workflows
            active_workflows = RemediationWorkflow.query.filter_by(is_active=True).all()
            self.logger.info(f"📋 Found {len(active_workflows)} active remediation workflows")
            
            # Start monitoring for triggers
            await self.start_monitoring()
            
            # Start remediation processing loop
            asyncio.create_task(self._process_remediation_queue())
            
            self.logger.info("✅ Automated Remediation Service initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Automated Remediation Service: {str(e)}")
            raise
    
    async def start_monitoring(self):
        """Start monitoring for remediation triggers"""
        self.logger.info("🔍 Starting automated remediation monitoring")
        
        # Monitor compliance violations
        asyncio.create_task(self._monitor_compliance_violations())
        
        # Monitor security alerts
        asyncio.create_task(self._monitor_security_alerts())
        
        # Monitor risk threshold exceedances
        asyncio.create_task(self._monitor_risk_thresholds())
        
        # Monitor shadow AI detections
        asyncio.create_task(self._monitor_shadow_ai_detections())
    
    async def _monitor_compliance_violations(self):
        """Monitor for new compliance violations"""
        while True:
            try:
                # Check for recent compliance evaluations that failed
                recent_time = datetime.utcnow() - timedelta(minutes=5)
                
                violations = ComplianceEvaluation.query.filter(
                    ComplianceEvaluation.evaluated_at >= recent_time,
                    ComplianceEvaluation.is_compliant == False,
                    ComplianceEvaluation.compliance_score < 70  # Critical threshold
                ).all()
                
                for violation in violations:
                    # Check if we've already triggered remediation for this
                    existing_execution = RemediationExecution.query.filter(
                        RemediationExecution.agent_id == violation.ai_agent_id,
                        RemediationExecution.trigger_data.contains({"compliance_evaluation_id": violation.id})
                    ).first()
                    
                    if not existing_execution:
                        trigger = RemediationTrigger(
                            trigger_type=RemediationTriggerType.COMPLIANCE_VIOLATION,
                            agent_id=violation.ai_agent_id,
                            severity=RiskLevel.HIGH if violation.compliance_score < 50 else RiskLevel.MEDIUM,
                            details={
                                "compliance_score": violation.compliance_score,
                                "findings": violation.findings,
                                "framework": violation.framework.value
                            },
                            framework=violation.framework,
                            compliance_evaluation_id=violation.id
                        )
                        
                        await self.remediation_queue.put(trigger)
                        self.logger.info(f"🚨 Queued remediation for compliance violation: Agent {violation.ai_agent_id}, Framework {violation.framework.value}")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring compliance violations: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    async def _monitor_security_alerts(self):
        """Monitor for new security alerts"""
        while True:
            try:
                # Check for recent scan results with high/critical risk
                recent_time = datetime.utcnow() - timedelta(minutes=5)
                
                alerts = ScanResult.query.filter(
                    ScanResult.created_at >= recent_time,
                    ScanResult.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL]),
                    ScanResult.phi_exposure_detected == True
                ).all()
                
                for alert in alerts:
                    # Check if we've already triggered remediation
                    existing_execution = RemediationExecution.query.filter(
                        RemediationExecution.agent_id == alert.ai_agent_id,
                        RemediationExecution.trigger_data.contains({"scan_result_id": alert.id})
                    ).first()
                    
                    if not existing_execution:
                        trigger = RemediationTrigger(
                            trigger_type=RemediationTriggerType.SECURITY_ALERT,
                            agent_id=alert.ai_agent_id,
                            severity=alert.risk_level,
                            details={
                                "risk_score": alert.risk_score,
                                "vulnerabilities": alert.vulnerabilities_found,
                                "phi_exposure": alert.phi_exposure_detected,
                                "scan_type": alert.scan_type
                            },
                            scan_result_id=alert.id
                        )
                        
                        await self.remediation_queue.put(trigger)
                        self.logger.info(f"🔒 Queued remediation for security alert: Agent {alert.ai_agent_id}, Risk {alert.risk_level.value}")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring security alerts: {str(e)}")
                await asyncio.sleep(300)
    
    async def _monitor_risk_thresholds(self):
        """Monitor for agents exceeding risk thresholds"""
        while True:
            try:
                # Find agents with consistently high risk scores
                high_risk_agents = db.session.query(AIAgent).join(ScanResult).filter(
                    ScanResult.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL]),
                    ScanResult.created_at >= datetime.utcnow() - timedelta(hours=1)
                ).group_by(AIAgent.id).having(db.func.count(ScanResult.id) >= 3).all()
                
                for agent in high_risk_agents:
                    # Check recent remediations to avoid spam
                    recent_remediation = RemediationExecution.query.filter(
                        RemediationExecution.agent_id == agent.id,
                        RemediationExecution.trigger_data.contains({"trigger_type": "risk_threshold"})
                    ).filter(
                        RemediationExecution.started_at >= datetime.utcnow() - timedelta(hours=6)
                    ).first()
                    
                    if not recent_remediation:
                        trigger = RemediationTrigger(
                            trigger_type=RemediationTriggerType.RISK_THRESHOLD_EXCEEDED,
                            agent_id=agent.id,
                            severity=RiskLevel.HIGH,
                            details={
                                "reason": "Consistently high risk scores",
                                "trigger_type": "risk_threshold"
                            }
                        )
                        
                        await self.remediation_queue.put(trigger)
                        self.logger.info(f"⚠️ Queued remediation for risk threshold exceeded: Agent {agent.id}")
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring risk thresholds: {str(e)}")
                await asyncio.sleep(600)
    
    async def _monitor_shadow_ai_detections(self):
        """Monitor for new Shadow AI detections"""
        while True:
            try:
                # Look for agents detected through shadow AI scanning
                recent_time = datetime.utcnow() - timedelta(minutes=10)
                
                shadow_agents = AIAgent.query.filter(
                    AIAgent.discovered_at >= recent_time,
                    AIAgent.agent_metadata.op('?')('discovery_method')
                ).filter(
                    AIAgent.agent_metadata['discovery_method'].astext == 'shadow_ai'
                ).all()
                
                for agent in shadow_agents:
                    # Shadow AI detections always need immediate attention
                    trigger = RemediationTrigger(
                        trigger_type=RemediationTriggerType.SECURITY_ALERT,
                        agent_id=agent.id,
                        severity=RiskLevel.CRITICAL,  # Shadow AI is always critical
                        details={
                            "reason": "Unauthorized AI system detected (Shadow AI)",
                            "discovery_method": "shadow_ai",
                            "requires_immediate_attention": True
                        }
                    )
                    
                    await self.remediation_queue.put(trigger)
                    self.logger.warning(f"🕵️ Queued remediation for Shadow AI detection: Agent {agent.id} ({agent.name})")
                
                await asyncio.sleep(300)  # Check every 5 minutes for shadow AI
                
            except Exception as e:
                self.logger.error(f"Error monitoring shadow AI detections: {str(e)}")
                await asyncio.sleep(600)
    
    async def _process_remediation_queue(self):
        """Process queued remediation triggers"""
        while True:
            try:
                # Get next trigger from queue
                trigger = await self.remediation_queue.get()
                
                # Find matching workflows
                matching_workflows = await self._find_matching_workflows(trigger)
                
                if not matching_workflows:
                    self.logger.warning(f"No matching workflows found for trigger: Agent {trigger.agent_id}, Type {trigger.trigger_type.value}")
                    continue
                
                # Execute workflows (highest priority first)
                for workflow in matching_workflows:
                    try:
                        self.logger.info(f"🔄 Executing workflow '{workflow.name}' for agent {trigger.agent_id}")
                        
                        trigger_data = {
                            "trigger_type": trigger.trigger_type.value,
                            "severity": trigger.severity.value,
                            "details": trigger.details,
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        if trigger.scan_result_id:
                            trigger_data["scan_result_id"] = trigger.scan_result_id
                        if trigger.compliance_evaluation_id:
                            trigger_data["compliance_evaluation_id"] = trigger.compliance_evaluation_id
                        
                        # Execute workflow asynchronously
                        execution = await self.workflow_engine.execute_workflow(
                            workflow.id, 
                            trigger.agent_id, 
                            trigger_data
                        )
                        
                        if execution.status == RemediationWorkflowStatus.COMPLETED:
                            self.logger.info(f"✅ Workflow '{workflow.name}' completed successfully for agent {trigger.agent_id}")
                        else:
                            self.logger.warning(f"⚠️ Workflow '{workflow.name}' execution status: {execution.status.value}")
                        
                    except Exception as e:
                        self.logger.error(f"❌ Failed to execute workflow '{workflow.name}': {str(e)}")
                
                # Mark trigger as processed
                self.remediation_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error processing remediation queue: {str(e)}")
                await asyncio.sleep(30)
    
    async def _find_matching_workflows(self, trigger: RemediationTrigger) -> List[RemediationWorkflow]:
        """Find workflows that match the trigger conditions"""
        # Get all active workflows
        workflows = RemediationWorkflow.query.filter_by(
            is_active=True,
            trigger_type=trigger.trigger_type
        ).all()
        
        matching_workflows = []
        
        for workflow in workflows:
            # Check if workflow matches the trigger conditions
            if self._workflow_matches_trigger(workflow, trigger):
                matching_workflows.append(workflow)
        
        # Sort by priority (critical issues first, then by execution count to balance load)
        matching_workflows.sort(key=lambda w: (
            0 if trigger.severity == RiskLevel.CRITICAL else 1,
            w.execution_count
        ))
        
        return matching_workflows
    
    def _workflow_matches_trigger(self, workflow: RemediationWorkflow, trigger: RemediationTrigger) -> bool:
        """Check if a workflow matches the trigger conditions"""
        # Check risk level targeting
        if workflow.target_risk_levels:
            if trigger.severity.value not in workflow.target_risk_levels:
                return False
        
        # Check framework targeting
        if workflow.target_frameworks and trigger.framework:
            if trigger.framework.value not in workflow.target_frameworks:
                return False
        
        # Check trigger conditions
        if workflow.trigger_conditions:
            conditions = workflow.trigger_conditions
            
            # Check minimum severity
            if "min_severity" in conditions:
                required_severity = RiskLevel(conditions["min_severity"])
                if trigger.severity.value < required_severity.value:
                    return False
            
            # Check specific conditions based on trigger type
            if trigger.trigger_type == RemediationTriggerType.COMPLIANCE_VIOLATION:
                if "min_compliance_score" in conditions:
                    if trigger.details.get("compliance_score", 100) >= conditions["min_compliance_score"]:
                        return False
            
            elif trigger.trigger_type == RemediationTriggerType.SECURITY_ALERT:
                if "require_phi_exposure" in conditions:
                    if conditions["require_phi_exposure"] and not trigger.details.get("phi_exposure", False):
                        return False
        
        return True
    
    async def trigger_manual_remediation(self, agent_id: int, workflow_id: int, user: str, reason: str) -> RemediationExecution:
        """Manually trigger a remediation workflow"""
        try:
            trigger_data = {
                "trigger_type": RemediationTriggerType.MANUAL_REQUEST.value,
                "requested_by": user,
                "reason": reason,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            execution = await self.workflow_engine.execute_workflow(
                workflow_id, 
                agent_id, 
                trigger_data
            )
            
            self.logger.info(f"🔧 Manual remediation triggered by {user}: Workflow {workflow_id}, Agent {agent_id}")
            return execution
            
        except Exception as e:
            self.logger.error(f"Failed to trigger manual remediation: {str(e)}")
            raise
    
    async def get_remediation_status(self) -> Dict[str, Any]:
        """Get current status of automated remediation service"""
        try:
            # Count active workflows
            active_workflows = RemediationWorkflow.query.filter_by(is_active=True).count()
            
            # Count recent executions
            recent_time = datetime.utcnow() - timedelta(hours=24)
            recent_executions = RemediationExecution.query.filter(
                RemediationExecution.started_at >= recent_time
            ).count()
            
            # Count executions by status
            status_counts = {}
            for status in RemediationWorkflowStatus:
                count = RemediationExecution.query.filter(
                    RemediationExecution.status == status,
                    RemediationExecution.started_at >= recent_time
                ).count()
                status_counts[status.value] = count
            
            # Queue size
            queue_size = self.remediation_queue.qsize()
            
            return {
                "active_workflows": active_workflows,
                "recent_executions": recent_executions,
                "execution_status_counts": status_counts,
                "queue_size": queue_size,
                "monitors_active": len(self.active_monitors),
                "service_status": "running"
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get remediation status: {str(e)}")
            return {"service_status": "error", "error": str(e)}


# Global instance
automated_remediation_service = AutomatedRemediationService()