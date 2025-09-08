"""
Automated Remediation Workflow Engine

This module provides the core engine for executing automated remediation workflows
in response to compliance violations, security alerts, and other triggers.
"""

import logging
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from threading import Thread
from app import db
from models import (
    RemediationWorkflow, RemediationExecution, RemediationActionExecution,
    RemediationWorkflowStatus, RemediationActionType, RemediationTriggerType,
    AIAgent, ScanResult, ComplianceEvaluation
)

logger = logging.getLogger(__name__)


class WorkflowExecutionError(Exception):
    """Custom exception for workflow execution errors"""
    pass


class RemediationWorkflowEngine:
    """Core engine for executing automated remediation workflows"""
    
    def __init__(self):
        self.logger = logger
        self.action_handlers = self._register_action_handlers()
        self.running_executions = {}  # Track running workflow executions
        
    def _register_action_handlers(self) -> Dict[RemediationActionType, callable]:
        """Register action handlers for different remediation actions"""
        return {
            RemediationActionType.UPDATE_CONFIGURATION: self._handle_update_configuration,
            RemediationActionType.APPLY_SECURITY_PATCH: self._handle_apply_security_patch,
            RemediationActionType.ROTATE_CREDENTIALS: self._handle_rotate_credentials,
            RemediationActionType.ENABLE_ENCRYPTION: self._handle_enable_encryption,
            RemediationActionType.UPDATE_ACCESS_CONTROLS: self._handle_update_access_controls,
            RemediationActionType.BACKUP_DATA: self._handle_backup_data,
            RemediationActionType.NOTIFY_STAKEHOLDERS: self._handle_notify_stakeholders,
            RemediationActionType.RESTART_SERVICE: self._handle_restart_service,
            RemediationActionType.SCALE_RESOURCES: self._handle_scale_resources,
            RemediationActionType.RUN_COMPLIANCE_SCAN: self._handle_run_compliance_scan,
            RemediationActionType.UPDATE_MONITORING: self._handle_update_monitoring,
            RemediationActionType.QUARANTINE_SYSTEM: self._handle_quarantine_system,
        }
    
    async def execute_workflow(self, workflow_id: int, agent_id: int, 
                             trigger_data: Dict[str, Any]) -> RemediationExecution:
        """Execute a remediation workflow for a specific agent"""
        try:
            # Get workflow and agent
            workflow = RemediationWorkflow.query.get(workflow_id)
            agent = AIAgent.query.get(agent_id)
            
            if not workflow:
                raise WorkflowExecutionError(f"Workflow {workflow_id} not found")
            if not agent:
                raise WorkflowExecutionError(f"Agent {agent_id} not found")
            
            # Create execution record
            execution = RemediationExecution(
                workflow_id=workflow_id,
                agent_id=agent_id,
                status=RemediationWorkflowStatus.PENDING,
                trigger_data=trigger_data,
                execution_context=self._build_execution_context(workflow, agent, trigger_data)
            )
            db.session.add(execution)
            db.session.commit()
            
            self.logger.info(f"Starting workflow '{workflow.name}' execution {execution.id} for agent '{agent.name}'")
            
            # Check if approval is required
            if workflow.requires_approval and not trigger_data.get('approved', False):
                execution.approval_requested = True
                execution.status = RemediationWorkflowStatus.PENDING
                db.session.commit()
                self.logger.info(f"Workflow execution {execution.id} requires approval")
                return execution
            
            # Start execution
            execution.status = RemediationWorkflowStatus.RUNNING
            execution.started_at = datetime.utcnow()
            db.session.commit()
            
            # Track running execution
            self.running_executions[execution.id] = execution
            
            # Execute workflow actions
            await self._execute_workflow_actions(execution, workflow, agent)
            
            return execution
            
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {str(e)}")
            if 'execution' in locals():
                execution.status = RemediationWorkflowStatus.FAILED
                execution.error_message = str(e)
                execution.completed_at = datetime.utcnow()
                if execution.started_at:
                    execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
                db.session.commit()
            raise
    
    async def _execute_workflow_actions(self, execution: RemediationExecution, 
                                      workflow: RemediationWorkflow, agent: AIAgent):
        """Execute all actions in a workflow"""
        try:
            # Run safety checks first
            safety_check_result = await self._run_safety_checks(workflow, agent, execution)
            if not safety_check_result['passed']:
                raise WorkflowExecutionError(f"Safety checks failed: {safety_check_result['message']}")
            
            # Get actions to execute
            actions = workflow.actions or []
            execution_order = workflow.execution_order or list(range(len(actions)))
            
            # Execute actions based on execution mode
            if workflow.parallel_execution:
                await self._execute_actions_parallel(execution, actions, execution_order, agent)
            else:
                await self._execute_actions_sequential(execution, actions, execution_order, agent)
            
            # Check final status
            failed_actions = execution.actions_failed or []
            completed_actions = execution.actions_completed or []
            
            if failed_actions and not completed_actions:
                execution.status = RemediationWorkflowStatus.FAILED
            elif failed_actions:
                execution.status = RemediationWorkflowStatus.PARTIALLY_COMPLETED
            else:
                execution.status = RemediationWorkflowStatus.COMPLETED
            
            # Update workflow statistics
            workflow.last_executed = datetime.utcnow()
            workflow.execution_count += 1
            
            execution.completed_at = datetime.utcnow()
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
            
            db.session.commit()
            
            # Remove from running executions
            self.running_executions.pop(execution.id, None)
            
            self.logger.info(f"Workflow execution {execution.id} completed with status: {execution.status.value}")
            
        except Exception as e:
            self.logger.error(f"Action execution failed: {str(e)}")
            execution.status = RemediationWorkflowStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow()
            if execution.started_at:
                execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
            
            # Attempt rollback if enabled
            if workflow.auto_rollback:
                await self._perform_rollback(execution)
            
            db.session.commit()
            self.running_executions.pop(execution.id, None)
            raise
    
    async def _execute_actions_sequential(self, execution: RemediationExecution, 
                                        actions: List[Dict], execution_order: List[int], agent: AIAgent):
        """Execute actions sequentially"""
        completed_actions = []
        failed_actions = []
        
        for order_index in execution_order:
            if order_index >= len(actions):
                continue
                
            action_config = actions[order_index]
            action_execution = await self._execute_single_action(
                execution, action_config, order_index, agent
            )
            
            if action_execution.success:
                completed_actions.append({
                    'action_name': action_execution.action_name,
                    'action_type': action_execution.action_type.value,
                    'duration': action_execution.duration_seconds,
                    'result': action_execution.result_data
                })
            else:
                failed_actions.append({
                    'action_name': action_execution.action_name,
                    'action_type': action_execution.action_type.value,
                    'error': action_execution.error_message,
                    'retry_count': action_execution.retry_count
                })
                
                # Stop execution on failure if not configured to continue
                if not action_config.get('continue_on_failure', False):
                    break
        
        execution.actions_completed = completed_actions
        execution.actions_failed = failed_actions
    
    async def _execute_actions_parallel(self, execution: RemediationExecution, 
                                       actions: List[Dict], execution_order: List[int], agent: AIAgent):
        """Execute actions in parallel"""
        tasks = []
        for order_index in execution_order:
            if order_index >= len(actions):
                continue
            action_config = actions[order_index]
            task = asyncio.create_task(
                self._execute_single_action(execution, action_config, order_index, agent)
            )
            tasks.append(task)
        
        # Wait for all actions to complete
        action_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        completed_actions = []
        failed_actions = []
        
        for result in action_results:
            if isinstance(result, Exception):
                failed_actions.append({
                    'error': str(result),
                    'action_type': 'unknown'
                })
            elif result.success:
                completed_actions.append({
                    'action_name': result.action_name,
                    'action_type': result.action_type.value,
                    'duration': result.duration_seconds,
                    'result': result.result_data
                })
            else:
                failed_actions.append({
                    'action_name': result.action_name,
                    'action_type': result.action_type.value,
                    'error': result.error_message,
                    'retry_count': result.retry_count
                })
        
        execution.actions_completed = completed_actions
        execution.actions_failed = failed_actions
    
    async def _execute_single_action(self, execution: RemediationExecution, 
                                   action_config: Dict, order_index: int, agent: AIAgent) -> RemediationActionExecution:
        """Execute a single remediation action"""
        action_type = RemediationActionType(action_config['type'])
        action_name = action_config.get('name', f"{action_type.value}_{order_index}")
        
        # Create action execution record
        action_execution = RemediationActionExecution(
            execution_id=execution.id,
            action_type=action_type,
            action_name=action_name,
            action_config=action_config,
            execution_order=order_index,
            status=RemediationWorkflowStatus.RUNNING,
            started_at=datetime.utcnow()
        )
        db.session.add(action_execution)
        db.session.commit()
        
        # Capture pre-execution state
        action_execution.pre_execution_state = await self._capture_system_state(agent, action_type)
        
        try:
            # Get action handler
            handler = self.action_handlers.get(action_type)
            if not handler:
                raise WorkflowExecutionError(f"No handler found for action type: {action_type.value}")
            
            # Execute action with retry logic
            max_retries = action_config.get('max_retries', 3)
            retry_count = 0
            
            while retry_count <= max_retries:
                try:
                    result = await handler(agent, action_config, execution.execution_context)
                    action_execution.success = True
                    action_execution.result_data = result
                    break
                except Exception as e:
                    retry_count += 1
                    action_execution.retry_count = retry_count
                    if retry_count > max_retries:
                        raise e
                    else:
                        await asyncio.sleep(2 ** retry_count)  # Exponential backoff
            
            action_execution.status = RemediationWorkflowStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Action {action_name} failed: {str(e)}")
            action_execution.success = False
            action_execution.error_message = str(e)
            action_execution.status = RemediationWorkflowStatus.FAILED
        
        # Capture post-execution state
        action_execution.post_execution_state = await self._capture_system_state(agent, action_type)
        
        # Complete action execution
        action_execution.completed_at = datetime.utcnow()
        action_execution.duration_seconds = (
            action_execution.completed_at - action_execution.started_at
        ).total_seconds()
        
        db.session.commit()
        return action_execution
    
    async def _run_safety_checks(self, workflow: RemediationWorkflow, 
                               agent: AIAgent, execution: RemediationExecution) -> Dict[str, Any]:
        """Run safety checks before executing workflow"""
        safety_checks = workflow.safety_checks or {}
        
        # Default safety checks
        checks = {
            'agent_accessible': await self._check_agent_accessibility(agent),
            'no_concurrent_execution': self._check_no_concurrent_execution(agent.id),
            'execution_window': self._check_execution_window(safety_checks.get('execution_window')),
            'resource_availability': await self._check_resource_availability(agent, safety_checks.get('required_resources', {}))
        }
        
        # Custom safety checks
        for check_name, check_config in safety_checks.items():
            if check_name.startswith('custom_'):
                checks[check_name] = await self._run_custom_safety_check(check_config, agent, execution)
        
        failed_checks = [name for name, passed in checks.items() if not passed]
        
        return {
            'passed': len(failed_checks) == 0,
            'checks': checks,
            'failed_checks': failed_checks,
            'message': f"Failed safety checks: {', '.join(failed_checks)}" if failed_checks else "All safety checks passed"
        }
    
    def _build_execution_context(self, workflow: RemediationWorkflow, 
                               agent: AIAgent, trigger_data: Dict[str, Any]) -> Dict[str, Any]:
        """Build execution context with workflow, agent, and trigger information"""
        return {
            'workflow_id': workflow.id,
            'workflow_name': workflow.name,
            'agent_id': agent.id,
            'agent_name': agent.name,
            'agent_protocol': agent.protocol,
            'agent_endpoint': agent.endpoint,
            'trigger_data': trigger_data,
            'execution_time': datetime.utcnow().isoformat(),
            'timeout_minutes': workflow.timeout_minutes,
            'auto_rollback': workflow.auto_rollback
        }
    
    # Action handlers - these would be implemented based on specific requirements
    async def _handle_update_configuration(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle configuration updates"""
        self.logger.info(f"Updating configuration for agent {agent.name}")
        # Simulate configuration update
        return {
            'action': 'update_configuration',
            'agent_id': agent.id,
            'config_updated': action_config.get('config_params', {}),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_apply_security_patch(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle security patch application"""
        self.logger.info(f"Applying security patch to agent {agent.name}")
        return {
            'action': 'apply_security_patch',
            'agent_id': agent.id,
            'patch_id': action_config.get('patch_id'),
            'patch_applied': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_rotate_credentials(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle credential rotation"""
        self.logger.info(f"Rotating credentials for agent {agent.name}")
        return {
            'action': 'rotate_credentials',
            'agent_id': agent.id,
            'credentials_rotated': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_enable_encryption(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle encryption enablement"""
        self.logger.info(f"Enabling encryption for agent {agent.name}")
        return {
            'action': 'enable_encryption',
            'agent_id': agent.id,
            'encryption_enabled': True,
            'encryption_type': action_config.get('encryption_type', 'AES-256'),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_update_access_controls(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle access control updates"""
        self.logger.info(f"Updating access controls for agent {agent.name}")
        return {
            'action': 'update_access_controls',
            'agent_id': agent.id,
            'access_controls_updated': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_backup_data(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle data backup"""
        self.logger.info(f"Backing up data for agent {agent.name}")
        return {
            'action': 'backup_data',
            'agent_id': agent.id,
            'backup_created': True,
            'backup_location': action_config.get('backup_location', '/tmp/backup'),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_notify_stakeholders(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle stakeholder notifications"""
        self.logger.info(f"Notifying stakeholders about agent {agent.name}")
        return {
            'action': 'notify_stakeholders',
            'agent_id': agent.id,
            'notifications_sent': True,
            'recipients': action_config.get('recipients', []),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_restart_service(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle service restart"""
        self.logger.info(f"Restarting service for agent {agent.name}")
        return {
            'action': 'restart_service',
            'agent_id': agent.id,
            'service_restarted': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_scale_resources(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle resource scaling"""
        self.logger.info(f"Scaling resources for agent {agent.name}")
        return {
            'action': 'scale_resources',
            'agent_id': agent.id,
            'resources_scaled': True,
            'scale_factor': action_config.get('scale_factor', 1.5),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_run_compliance_scan(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle compliance scan execution"""
        self.logger.info(f"Running compliance scan for agent {agent.name}")
        return {
            'action': 'run_compliance_scan',
            'agent_id': agent.id,
            'scan_completed': True,
            'frameworks': action_config.get('frameworks', ['HIPAA', 'GDPR']),
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_update_monitoring(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle monitoring configuration updates"""
        self.logger.info(f"Updating monitoring for agent {agent.name}")
        return {
            'action': 'update_monitoring',
            'agent_id': agent.id,
            'monitoring_updated': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def _handle_quarantine_system(self, agent: AIAgent, action_config: Dict, context: Dict) -> Dict:
        """Handle system quarantine"""
        self.logger.info(f"Quarantining agent {agent.name}")
        return {
            'action': 'quarantine_system',
            'agent_id': agent.id,
            'system_quarantined': True,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    # Helper methods
    async def _check_agent_accessibility(self, agent: AIAgent) -> bool:
        """Check if agent is accessible"""
        return True  # Simplified - would implement actual connectivity check
    
    def _check_no_concurrent_execution(self, agent_id: int) -> bool:
        """Check if there are no concurrent executions for this agent"""
        concurrent_executions = [
            ex for ex in self.running_executions.values() 
            if ex.agent_id == agent_id and ex.status == RemediationWorkflowStatus.RUNNING
        ]
        return len(concurrent_executions) == 0
    
    def _check_execution_window(self, execution_window: Optional[Dict]) -> bool:
        """Check if current time is within allowed execution window"""
        if not execution_window:
            return True
        # Simplified - would implement actual time window checking
        return True
    
    async def _check_resource_availability(self, agent: AIAgent, required_resources: Dict) -> bool:
        """Check if required resources are available"""
        return True  # Simplified - would implement actual resource checking
    
    async def _run_custom_safety_check(self, check_config: Dict, agent: AIAgent, execution: RemediationExecution) -> bool:
        """Run custom safety check"""
        return True  # Simplified - would implement based on check_config
    
    async def _capture_system_state(self, agent: AIAgent, action_type: RemediationActionType) -> Dict:
        """Capture system state before/after action execution"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'agent_status': 'active',
            'action_type': action_type.value
        }
    
    async def _perform_rollback(self, execution: RemediationExecution):
        """Perform rollback of completed actions"""
        self.logger.info(f"Performing rollback for execution {execution.id}")
        rollback_actions = []
        
        # Get completed actions in reverse order
        completed_actions = execution.actions_completed or []
        for action in reversed(completed_actions):
            try:
                # Attempt to rollback each action
                rollback_result = await self._rollback_action(action, execution)
                rollback_actions.append(rollback_result)
            except Exception as e:
                self.logger.error(f"Rollback failed for action {action['action_name']}: {str(e)}")
                rollback_actions.append({
                    'action_name': action['action_name'],
                    'rollback_status': 'failed',
                    'error': str(e)
                })
        
        execution.rollback_actions = rollback_actions
    
    async def _rollback_action(self, action: Dict, execution: RemediationExecution) -> Dict:
        """Rollback a specific action"""
        # Simplified rollback - would implement specific rollback logic per action type
        return {
            'action_name': action['action_name'],
            'action_type': action['action_type'],
            'rollback_status': 'completed',
            'timestamp': datetime.utcnow().isoformat()
        }


# Global workflow engine instance
workflow_engine = RemediationWorkflowEngine()