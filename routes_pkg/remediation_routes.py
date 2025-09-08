"""
Remediation Workflow Routes

This module provides web routes for managing automated remediation workflows.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app import db
from models import (
    RemediationWorkflow, RemediationExecution, RemediationActionExecution,
    RemediationTemplate, RemediationWorkflowStatus, RemediationActionType,
    RemediationTriggerType, AIAgent, ScanResult, ComplianceEvaluation
)
from datetime import datetime, timedelta
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

# Create blueprint
remediation_bp = Blueprint('remediation', __name__, url_prefix='/remediation')

# Import workflow engine
try:
    from remediation.workflow_engine import workflow_engine
    WORKFLOW_ENGINE_AVAILABLE = True
except ImportError as e:
    WORKFLOW_ENGINE_AVAILABLE = False
    workflow_engine = None
    logger.warning(f"Workflow engine not available: {e}")


@remediation_bp.route('/')
def index():
    """Remediation workflows dashboard"""
    try:
        # Get workflow statistics
        total_workflows = RemediationWorkflow.query.count()
        active_workflows = RemediationWorkflow.query.filter_by(is_active=True).count()
        
        # Get recent executions
        recent_executions = RemediationExecution.query.order_by(
            RemediationExecution.started_at.desc()
        ).limit(10).all()
        
        # Get execution statistics
        executions_today = RemediationExecution.query.filter(
            RemediationExecution.started_at >= datetime.utcnow().date()
        ).count()
        
        successful_executions = RemediationExecution.query.filter_by(
            status=RemediationWorkflowStatus.COMPLETED
        ).count()
        
        failed_executions = RemediationExecution.query.filter_by(
            status=RemediationWorkflowStatus.FAILED
        ).count()
        
        # Get all workflows for display
        workflows = RemediationWorkflow.query.order_by(
            RemediationWorkflow.created_at.desc()
        ).all()
        
        return render_template('remediation/index.html',
                             workflows=workflows,
                             recent_executions=recent_executions,
                             total_workflows=total_workflows,
                             active_workflows=active_workflows,
                             executions_today=executions_today,
                             successful_executions=successful_executions,
                             failed_executions=failed_executions,
                             workflow_engine_available=WORKFLOW_ENGINE_AVAILABLE)
    
    except Exception as e:
        logger.error(f"Error in remediation dashboard: {str(e)}")
        flash(f'Error loading remediation dashboard: {str(e)}', 'error')
        return render_template('remediation/index.html',
                             workflows=[],
                             recent_executions=[],
                             total_workflows=0,
                             active_workflows=0,
                             executions_today=0,
                             successful_executions=0,
                             failed_executions=0,
                             workflow_engine_available=False)


@remediation_bp.route('/workflows')
def workflows():
    """List all remediation workflows"""
    try:
        workflows = RemediationWorkflow.query.order_by(
            RemediationWorkflow.created_at.desc()
        ).all()
        
        # Get execution counts for each workflow
        workflow_stats = {}
        for workflow in workflows:
            executions = RemediationExecution.query.filter_by(workflow_id=workflow.id).all()
            successful = len([e for e in executions if e.status == RemediationWorkflowStatus.COMPLETED])
            failed = len([e for e in executions if e.status == RemediationWorkflowStatus.FAILED])
            
            workflow_stats[workflow.id] = {
                'total_executions': len(executions),
                'successful': successful,
                'failed': failed,
                'success_rate': (successful / len(executions) * 100) if executions else 0
            }
        
        return render_template('remediation/workflows.html',
                             workflows=workflows,
                             workflow_stats=workflow_stats)
    
    except Exception as e:
        logger.error(f"Error listing workflows: {str(e)}")
        flash(f'Error loading workflows: {str(e)}', 'error')
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/workflows/create', methods=['GET', 'POST'])
def create_workflow():
    """Create a new remediation workflow"""
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name')
            description = request.form.get('description')
            workflow_type = request.form.get('workflow_type')
            trigger_type = request.form.get('trigger_type')
            
            # Parse JSON fields
            trigger_conditions = json.loads(request.form.get('trigger_conditions', '{}'))
            actions = json.loads(request.form.get('actions', '[]'))
            target_frameworks = request.form.getlist('target_frameworks')
            target_protocols = request.form.getlist('target_protocols')
            target_risk_levels = request.form.getlist('target_risk_levels')
            
            # Workflow configuration
            parallel_execution = request.form.get('parallel_execution') == 'on'
            requires_approval = request.form.get('requires_approval') == 'on'
            auto_rollback = request.form.get('auto_rollback') == 'on'
            timeout_minutes = int(request.form.get('timeout_minutes', 60))
            retry_attempts = int(request.form.get('retry_attempts', 3))
            
            # Validate required fields
            if not all([name, workflow_type, trigger_type]):
                flash('Name, workflow type, and trigger type are required', 'error')
                return render_template('remediation/create_workflow.html',
                                     action_types=RemediationActionType,
                                     trigger_types=RemediationTriggerType)
            
            # Create workflow
            workflow = RemediationWorkflow(
                name=name,
                description=description,
                workflow_type=workflow_type,
                trigger_type=RemediationTriggerType(trigger_type),
                trigger_conditions=trigger_conditions,
                actions=actions,
                parallel_execution=parallel_execution,
                requires_approval=requires_approval,
                auto_rollback=auto_rollback,
                timeout_minutes=timeout_minutes,
                retry_attempts=retry_attempts,
                target_frameworks=target_frameworks,
                target_protocols=target_protocols,
                target_risk_levels=target_risk_levels,
                created_by='web_user'
            )
            
            db.session.add(workflow)
            db.session.commit()
            
            flash(f'Workflow "{name}" created successfully!', 'success')
            return redirect(url_for('remediation.view_workflow', id=workflow.id))
        
        except Exception as e:
            logger.error(f"Error creating workflow: {str(e)}")
            flash(f'Error creating workflow: {str(e)}', 'error')
            db.session.rollback()
    
    return render_template('remediation/create_workflow.html',
                         action_types=RemediationActionType,
                         trigger_types=RemediationTriggerType)


@remediation_bp.route('/workflows/<int:id>')
def view_workflow(id):
    """View a specific remediation workflow"""
    try:
        workflow = RemediationWorkflow.query.get_or_404(id)
        
        # Get recent executions for this workflow
        executions = RemediationExecution.query.filter_by(
            workflow_id=id
        ).order_by(RemediationExecution.started_at.desc()).limit(20).all()
        
        # Get execution statistics
        total_executions = RemediationExecution.query.filter_by(workflow_id=id).count()
        successful = RemediationExecution.query.filter_by(
            workflow_id=id, status=RemediationWorkflowStatus.COMPLETED
        ).count()
        failed = RemediationExecution.query.filter_by(
            workflow_id=id, status=RemediationWorkflowStatus.FAILED
        ).count()
        
        success_rate = (successful / total_executions * 100) if total_executions > 0 else 0
        
        # Get available agents for manual execution
        agents = AIAgent.query.limit(50).all()
        
        return render_template('remediation/view_workflow.html',
                             workflow=workflow,
                             executions=executions,
                             total_executions=total_executions,
                             successful=successful,
                             failed=failed,
                             success_rate=success_rate,
                             agents=agents,
                             workflow_engine_available=WORKFLOW_ENGINE_AVAILABLE)
    
    except Exception as e:
        logger.error(f"Error viewing workflow {id}: {str(e)}")
        flash(f'Error loading workflow: {str(e)}', 'error')
        return redirect(url_for('remediation.workflows'))


@remediation_bp.route('/workflows/<int:id>/execute', methods=['POST'])
def execute_workflow():
    """Manually execute a workflow"""
    try:
        workflow_id = request.form.get('workflow_id')
        agent_id = request.form.get('agent_id')
        
        if not all([workflow_id, agent_id]):
            flash('Workflow and agent must be selected', 'error')
            return redirect(url_for('remediation.view_workflow', id=workflow_id))
        
        if not WORKFLOW_ENGINE_AVAILABLE:
            flash('Workflow engine is not available', 'error')
            return redirect(url_for('remediation.view_workflow', id=workflow_id))
        
        # Prepare trigger data for manual execution
        trigger_data = {
            'trigger_type': 'manual_request',
            'triggered_by': 'web_user',
            'trigger_time': datetime.utcnow().isoformat(),
            'manual_execution': True,
            'approved': True  # Manual executions are pre-approved
        }
        
        # Execute workflow asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        execution = loop.run_until_complete(
            workflow_engine.execute_workflow(
                int(workflow_id), int(agent_id), trigger_data
            )
        )
        loop.close()
        
        flash(f'Workflow execution started! Execution ID: {execution.id}', 'success')
        return redirect(url_for('remediation.view_execution', id=execution.id))
    
    except Exception as e:
        logger.error(f"Error executing workflow: {str(e)}")
        flash(f'Error executing workflow: {str(e)}', 'error')
        return redirect(url_for('remediation.view_workflow', id=workflow_id))


@remediation_bp.route('/executions')
def executions():
    """List all workflow executions"""
    try:
        # Get filter parameters
        status_filter = request.args.get('status')
        workflow_filter = request.args.get('workflow')
        
        # Build query
        query = RemediationExecution.query
        
        if status_filter:
            query = query.filter_by(status=RemediationWorkflowStatus(status_filter))
        
        if workflow_filter:
            query = query.filter_by(workflow_id=int(workflow_filter))
        
        # Get executions with pagination
        page = request.args.get('page', 1, type=int)
        executions = query.order_by(
            RemediationExecution.started_at.desc()
        ).paginate(
            page=page, per_page=20, error_out=False
        )
        
        # Get workflows for filter dropdown
        workflows = RemediationWorkflow.query.all()
        
        return render_template('remediation/executions.html',
                             executions=executions,
                             workflows=workflows,
                             status_filter=status_filter,
                             workflow_filter=workflow_filter,
                             workflow_statuses=RemediationWorkflowStatus)
    
    except Exception as e:
        logger.error(f"Error listing executions: {str(e)}")
        flash(f'Error loading executions: {str(e)}', 'error')
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/executions/<int:id>')
def view_execution(id):
    """View a specific workflow execution"""
    try:
        execution = RemediationExecution.query.get_or_404(id)
        
        # Get action executions
        action_executions = RemediationActionExecution.query.filter_by(
            execution_id=id
        ).order_by(RemediationActionExecution.execution_order).all()
        
        return render_template('remediation/view_execution.html',
                             execution=execution,
                             action_executions=action_executions)
    
    except Exception as e:
        logger.error(f"Error viewing execution {id}: {str(e)}")
        flash(f'Error loading execution: {str(e)}', 'error')
        return redirect(url_for('remediation.executions'))


@remediation_bp.route('/templates')
def templates():
    """List remediation workflow templates"""
    try:
        templates = RemediationTemplate.query.order_by(
            RemediationTemplate.created_at.desc()
        ).all()
        
        return render_template('remediation/templates.html', templates=templates)
    
    except Exception as e:
        logger.error(f"Error listing templates: {str(e)}")
        flash(f'Error loading templates: {str(e)}', 'error')
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/templates/<int:id>/create-workflow', methods=['POST'])
def create_workflow_from_template():
    """Create a workflow from a template"""
    try:
        template_id = request.form.get('template_id')
        workflow_name = request.form.get('workflow_name')
        
        template = RemediationTemplate.query.get_or_404(template_id)
        
        if not workflow_name:
            workflow_name = f"{template.name} - {datetime.utcnow().strftime('%Y%m%d_%H%M')}"
        
        # Create workflow from template
        template_config = template.template_config or {}
        
        workflow = RemediationWorkflow(
            name=workflow_name,
            description=f"Created from template: {template.name}",
            workflow_type=template_config.get('workflow_type', 'compliance'),
            trigger_type=RemediationTriggerType(template_config.get('trigger_type', 'manual_request')),
            trigger_conditions=template_config.get('trigger_conditions', {}),
            actions=template_config.get('actions', []),
            parallel_execution=template_config.get('parallel_execution', False),
            requires_approval=template_config.get('requires_approval', False),
            auto_rollback=template_config.get('auto_rollback', True),
            timeout_minutes=template_config.get('timeout_minutes', 60),
            retry_attempts=template_config.get('retry_attempts', 3),
            target_frameworks=template_config.get('target_frameworks', []),
            target_protocols=template_config.get('target_protocols', []),
            target_risk_levels=template_config.get('target_risk_levels', []),
            created_by='web_user'
        )
        
        db.session.add(workflow)
        
        # Update template usage count
        template.usage_count += 1
        
        db.session.commit()
        
        flash(f'Workflow "{workflow_name}" created from template!', 'success')
        return redirect(url_for('remediation.view_workflow', id=workflow.id))
    
    except Exception as e:
        logger.error(f"Error creating workflow from template: {str(e)}")
        flash(f'Error creating workflow from template: {str(e)}', 'error')
        db.session.rollback()
        return redirect(url_for('remediation.templates'))


@remediation_bp.route('/api/workflows/<int:id>/toggle', methods=['POST'])
def toggle_workflow_status():
    """Toggle workflow active status"""
    try:
        workflow = RemediationWorkflow.query.get_or_404(request.json.get('workflow_id'))
        workflow.is_active = not workflow.is_active
        db.session.commit()
        
        return jsonify({
            'success': True,
            'is_active': workflow.is_active,
            'message': f'Workflow {"activated" if workflow.is_active else "deactivated"}'
        })
    
    except Exception as e:
        logger.error(f"Error toggling workflow status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@remediation_bp.route('/api/executions/<int:id>/cancel', methods=['POST'])
def cancel_execution():
    """Cancel a running workflow execution"""
    try:
        execution = RemediationExecution.query.get_or_404(request.json.get('execution_id'))
        
        if execution.status != RemediationWorkflowStatus.RUNNING:
            return jsonify({
                'success': False,
                'error': 'Execution is not currently running'
            }), 400
        
        execution.status = RemediationWorkflowStatus.CANCELLED
        execution.completed_at = datetime.utcnow()
        if execution.started_at:
            execution.duration_seconds = (execution.completed_at - execution.started_at).total_seconds()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Execution cancelled successfully'
        })
    
    except Exception as e:
        logger.error(f"Error cancelling execution: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@remediation_bp.route('/api/dashboard-stats')
def dashboard_stats():
    """Get dashboard statistics via API"""
    try:
        # Get workflow execution statistics for the last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        daily_stats = []
        for i in range(30):
            day = thirty_days_ago + timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            
            executions = RemediationExecution.query.filter(
                RemediationExecution.started_at >= day_start,
                RemediationExecution.started_at < day_end
            ).all()
            
            successful = len([e for e in executions if e.status == RemediationWorkflowStatus.COMPLETED])
            failed = len([e for e in executions if e.status == RemediationWorkflowStatus.FAILED])
            
            daily_stats.append({
                'date': day.strftime('%Y-%m-%d'),
                'total': len(executions),
                'successful': successful,
                'failed': failed
            })
        
        # Get action type statistics
        action_stats = {}
        recent_executions = RemediationExecution.query.filter(
            RemediationExecution.started_at >= thirty_days_ago
        ).all()
        
        for execution in recent_executions:
            actions_completed = execution.actions_completed or []
            for action in actions_completed:
                action_type = action.get('action_type', 'unknown')
                if action_type not in action_stats:
                    action_stats[action_type] = 0
                action_stats[action_type] += 1
        
        return jsonify({
            'daily_stats': daily_stats,
            'action_stats': action_stats
        })
    
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        return jsonify({
            'error': str(e)
        }), 500