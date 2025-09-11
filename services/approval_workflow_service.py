"""
Approval Workflow Service
Handles approval workflows for critical remediation actions that require human oversight
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum

from app import db
from models import (
    RemediationExecution, RemediationWorkflow, RemediationWorkflowStatus,
    RemediationTriggerType, AIAgent
)

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalWorkflowService:
    """
    Manages approval workflows for critical remediation actions
    """
    
    def __init__(self):
        self.logger = logger
        self.approval_timeout_hours = 24  # Default timeout for approvals
        
    def request_approval(self, execution: RemediationExecution, requester: str, reason: str) -> Dict[str, Any]:
        """Request approval for a critical remediation execution"""
        try:
            # Mark execution as requiring approval
            execution.approval_requested = True
            execution.status = RemediationWorkflowStatus.PENDING
            
            # Create approval request
            approval_request = {
                'execution_id': execution.id,
                'workflow_name': execution.workflow.name,
                'agent_name': execution.agent.name,
                'requester': requester,
                'reason': reason,
                'requested_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(hours=self.approval_timeout_hours)).isoformat(),
                'status': ApprovalStatus.PENDING.value,
                'risk_level': execution.workflow.target_risk_levels[0] if execution.workflow.target_risk_levels else 'HIGH',
                'trigger_type': execution.workflow.trigger_type.value,
                'actions_to_execute': execution.workflow.actions
            }
            
            db.session.commit()
            
            # Log approval request
            self.logger.warning(f"🔐 Approval requested for execution {execution.id}: {execution.workflow.name}")
            
            # Send notifications (placeholder - would integrate with notification system)
            self._send_approval_notifications(approval_request)
            
            return {
                'success': True,
                'approval_id': execution.id,
                'message': f'Approval requested for {execution.workflow.name}',
                'expires_at': approval_request['expires_at']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to request approval for execution {execution.id}: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
    
    def approve_execution(self, execution_id: int, approver: str, comments: str = "") -> Dict[str, Any]:
        """Approve a pending remediation execution"""
        try:
            execution = RemediationExecution.query.get_or_404(execution_id)
            
            if not execution.approval_requested:
                return {
                    'success': False,
                    'error': 'This execution does not require approval'
                }
            
            if execution.status != RemediationWorkflowStatus.PENDING:
                return {
                    'success': False,
                    'error': f'Execution is in {execution.status.value} state, cannot approve'
                }
            
            # Approve the execution
            execution.approval_granted_by = approver
            execution.approval_granted_at = datetime.utcnow()
            execution.status = RemediationWorkflowStatus.RUNNING
            
            # Add approval log
            approval_log = f"APPROVED by {approver} at {datetime.utcnow().isoformat()}"
            if comments:
                approval_log += f" - Comments: {comments}"
            
            if execution.execution_log:
                execution.execution_log += f"\n{approval_log}"
            else:
                execution.execution_log = approval_log
            
            db.session.commit()
            
            self.logger.info(f"✅ Execution {execution_id} approved by {approver}")
            
            # Trigger actual execution (would integrate with workflow engine)
            self._trigger_approved_execution(execution)
            
            return {
                'success': True,
                'message': f'Execution approved by {approver}',
                'execution_id': execution_id
            }
            
        except Exception as e:
            self.logger.error(f"Failed to approve execution {execution_id}: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
    
    def reject_execution(self, execution_id: int, rejector: str, reason: str) -> Dict[str, Any]:
        """Reject a pending remediation execution"""
        try:
            execution = RemediationExecution.query.get_or_404(execution_id)
            
            if not execution.approval_requested:
                return {
                    'success': False,
                    'error': 'This execution does not require approval'
                }
            
            if execution.status != RemediationWorkflowStatus.PENDING:
                return {
                    'success': False,
                    'error': f'Execution is in {execution.status.value} state, cannot reject'
                }
            
            # Reject the execution
            execution.status = RemediationWorkflowStatus.CANCELLED
            execution.completed_at = datetime.utcnow()
            execution.error_message = f"REJECTED by {rejector}: {reason}"
            
            # Add rejection log
            rejection_log = f"REJECTED by {rejector} at {datetime.utcnow().isoformat()} - Reason: {reason}"
            
            if execution.execution_log:
                execution.execution_log += f"\n{rejection_log}"
            else:
                execution.execution_log = rejection_log
            
            db.session.commit()
            
            self.logger.warning(f"❌ Execution {execution_id} rejected by {rejector}: {reason}")
            
            return {
                'success': True,
                'message': f'Execution rejected by {rejector}',
                'execution_id': execution_id
            }
            
        except Exception as e:
            self.logger.error(f"Failed to reject execution {execution_id}: {str(e)}")
            db.session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of pending approval requests"""
        try:
            pending_executions = RemediationExecution.query.filter_by(
                approval_requested=True,
                status=RemediationWorkflowStatus.PENDING
            ).filter(
                RemediationExecution.started_at >= datetime.utcnow() - timedelta(days=7)  # Last 7 days
            ).all()
            
            approvals = []
            for execution in pending_executions:
                # Check if approval has expired
                if self._is_approval_expired(execution):
                    self._expire_approval(execution)
                    continue
                
                approval = {
                    'execution_id': execution.id,
                    'workflow_name': execution.workflow.name,
                    'agent_name': execution.agent.name,
                    'trigger_type': execution.workflow.trigger_type.value,
                    'requested_at': execution.started_at.isoformat() if execution.started_at else None,
                    'expires_at': (execution.started_at + timedelta(hours=self.approval_timeout_hours)).isoformat() if execution.started_at else None,
                    'risk_level': execution.workflow.target_risk_levels[0] if execution.workflow.target_risk_levels else 'HIGH',
                    'description': execution.workflow.description,
                    'trigger_data': execution.trigger_data,
                    'actions_count': len(execution.workflow.actions) if execution.workflow.actions else 0
                }
                approvals.append(approval)
            
            return approvals
            
        except Exception as e:
            self.logger.error(f"Failed to get pending approvals: {str(e)}")
            return []
    
    def _send_approval_notifications(self, approval_request: Dict[str, Any]):
        """Send approval notifications (placeholder for integration with notification system)"""
        try:
            # This would integrate with email, Slack, or other notification systems
            self.logger.info(f"📧 Approval notification sent for execution {approval_request['execution_id']}")
            
            # Log notification details for audit
            notification_details = {
                'type': 'approval_request',
                'execution_id': approval_request['execution_id'],
                'workflow': approval_request['workflow_name'],
                'agent': approval_request['agent_name'],
                'risk_level': approval_request['risk_level'],
                'sent_at': datetime.utcnow().isoformat()
            }
            
            # In production, this would send actual notifications
            self.logger.debug(f"Notification details: {notification_details}")
            
        except Exception as e:
            self.logger.error(f"Failed to send approval notification: {str(e)}")
    
    def _trigger_approved_execution(self, execution: RemediationExecution):
        """Trigger the actual execution of an approved workflow"""
        try:
            # This would integrate with the workflow engine to actually execute the workflow
            self.logger.info(f"🚀 Triggering approved execution {execution.id}: {execution.workflow.name}")
            
            # Update execution status
            execution.started_at = datetime.utcnow()
            
            # In production, this would call the workflow engine
            # For now, we'll just log that it would be executed
            execution_log = f"Approved execution started at {datetime.utcnow().isoformat()}"
            if execution.execution_log:
                execution.execution_log += f"\n{execution_log}"
            else:
                execution.execution_log = execution_log
            
            db.session.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to trigger approved execution {execution.id}: {str(e)}")
            # Mark execution as failed
            execution.status = RemediationWorkflowStatus.FAILED
            execution.error_message = f"Failed to trigger approved execution: {str(e)}"
            execution.completed_at = datetime.utcnow()
            db.session.commit()
    
    def _is_approval_expired(self, execution: RemediationExecution) -> bool:
        """Check if an approval request has expired"""
        if not execution.started_at:
            return False
        
        expiry_time = execution.started_at + timedelta(hours=self.approval_timeout_hours)
        return datetime.utcnow() > expiry_time
    
    def _expire_approval(self, execution: RemediationExecution):
        """Mark an approval request as expired"""
        try:
            execution.status = RemediationWorkflowStatus.CANCELLED
            execution.completed_at = datetime.utcnow()
            execution.error_message = "Approval request expired"
            
            expiry_log = f"Approval request expired at {datetime.utcnow().isoformat()}"
            if execution.execution_log:
                execution.execution_log += f"\n{expiry_log}"
            else:
                execution.execution_log = expiry_log
            
            db.session.commit()
            
            self.logger.warning(f"⏰ Approval for execution {execution.id} expired")
            
        except Exception as e:
            self.logger.error(f"Failed to expire approval for execution {execution.id}: {str(e)}")
            db.session.rollback()
    
    def cleanup_expired_approvals(self):
        """Cleanup expired approval requests (should be run periodically)"""
        try:
            expired_executions = RemediationExecution.query.filter_by(
                approval_requested=True,
                status=RemediationWorkflowStatus.PENDING
            ).filter(
                RemediationExecution.started_at < datetime.utcnow() - timedelta(hours=self.approval_timeout_hours)
            ).all()
            
            for execution in expired_executions:
                self._expire_approval(execution)
            
            if expired_executions:
                self.logger.info(f"🧹 Cleaned up {len(expired_executions)} expired approval requests")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired approvals: {str(e)}")


# Global instance
approval_workflow_service = ApprovalWorkflowService()