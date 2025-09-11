"""
Remediation Workflow Routes

This module provides web routes for managing automated remediation workflows.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app import db
from models import (
    RemediationWorkflow, RemediationExecution, RemediationActionExecution,
    RemediationTemplate, RemediationWorkflowStatus, RemediationActionType,
    RemediationTriggerType, AIAgent, ScanResult, ComplianceEvaluation, RiskLevel
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
    """Automated Remediation Dashboard"""
    try:
        # Get service status from automated remediation service
        try:
            from services.automated_remediation_service import automated_remediation_service
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            status = loop.run_until_complete(automated_remediation_service.get_remediation_status())
            loop.close()
        except Exception as e:
            logger.warning(f"Could not get automated remediation status: {e}")
            status = {
                "active_workflows": RemediationWorkflow.query.filter_by(is_active=True).count(),
                "recent_executions": RemediationExecution.query.filter(
                    RemediationExecution.started_at >= datetime.utcnow() - timedelta(hours=24)
                ).count(),
                "queue_size": 0,
                "execution_status_counts": {},
                "service_status": "unknown"
            }
        
        # Get recent executions for detailed display
        recent_executions = RemediationExecution.query.order_by(
            RemediationExecution.started_at.desc()
        ).limit(10).all()
        
        # Get active workflows for display
        active_workflows = RemediationWorkflow.query.filter_by(is_active=True).order_by(
            RemediationWorkflow.created_at.desc()
        ).all()
        
        # Calculate execution status counts if not provided
        if not status.get("execution_status_counts"):
            recent_time = datetime.utcnow() - timedelta(hours=24)
            status["execution_status_counts"] = {}
            for status_enum in RemediationWorkflowStatus:
                count = RemediationExecution.query.filter(
                    RemediationExecution.status == status_enum,
                    RemediationExecution.started_at >= recent_time
                ).count()
                status["execution_status_counts"][status_enum.value] = count
        
        return render_template('remediation/dashboard.html',
                             status=status,
                             recent_executions=recent_executions,
                             active_workflows=active_workflows,
                             workflow_engine_available=WORKFLOW_ENGINE_AVAILABLE)
    
    except Exception as e:
        logger.error(f"Error in remediation dashboard: {str(e)}")
        flash(f'Error loading remediation dashboard: {str(e)}', 'error')
        return render_template('remediation/dashboard.html',
                             status={"service_status": "error"},
                             recent_executions=[],
                             active_workflows=[],
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


@remediation_bp.route('/workflows/<int:id>/edit', methods=['GET', 'POST'])
def edit_workflow(id):
    """Edit a remediation workflow"""
    try:
        workflow = RemediationWorkflow.query.get_or_404(id)
        
        if request.method == 'POST':
            # Update workflow with form data
            workflow.name = request.form.get('name', workflow.name)
            workflow.description = request.form.get('description', workflow.description)
            workflow.trigger_type = RemediationTriggerType(request.form.get('trigger_type', workflow.trigger_type.value))
            workflow.action_type = RemediationActionType(request.form.get('action_type', workflow.action_type.value))
            workflow.priority = RiskLevel(request.form.get('priority', workflow.priority.value))
            workflow.is_enabled = request.form.get('is_enabled') == 'on'
            workflow.auto_execute = request.form.get('auto_execute') == 'on'
            workflow.auto_rollback = request.form.get('auto_rollback') == 'on'
            
            # Parse integer fields
            try:
                if request.form.get('timeout_minutes'):
                    workflow.timeout_minutes = int(request.form.get('timeout_minutes'))
                if request.form.get('retry_attempts'):
                    workflow.retry_attempts = int(request.form.get('retry_attempts'))
            except ValueError:
                flash('Invalid timeout or retry attempts value', 'error')
                return render_template('remediation/edit_workflow.html', 
                                     workflow=workflow,
                                     action_types=RemediationActionType,
                                     trigger_types=RemediationTriggerType,
                                     priorities=RiskLevel)
            
            # Parse target arrays
            target_frameworks = request.form.getlist('target_frameworks')
            target_protocols = request.form.getlist('target_protocols')
            target_risk_levels = request.form.getlist('target_risk_levels')
            
            workflow.target_frameworks = target_frameworks
            workflow.target_protocols = target_protocols
            workflow.target_risk_levels = target_risk_levels
            
            db.session.commit()
            flash(f'Workflow "{workflow.name}" updated successfully!', 'success')
            return redirect(url_for('remediation.view_workflow', id=workflow.id))
        
        # GET request - show edit form
        return render_template('remediation/edit_workflow.html',
                             workflow=workflow,
                             action_types=RemediationActionType,
                             trigger_types=RemediationTriggerType,
                             priorities=RiskLevel)
    
    except Exception as e:
        logger.error(f"Error editing workflow {id}: {str(e)}")
        flash(f'Error editing workflow: {str(e)}', 'error')
        return redirect(url_for('remediation.view_workflow', id=id))


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


# Additional API endpoints for the new dashboard

@remediation_bp.route('/status')
def get_status():
    """Get remediation service status (API endpoint)"""
    try:
        from services.automated_remediation_service import automated_remediation_service
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        status = loop.run_until_complete(automated_remediation_service.get_remediation_status())
        loop.close()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {str(e)}")
        return jsonify({"service_status": "error", "error": str(e)})


@remediation_bp.route('/executions/<int:execution_id>')
def execution_details(execution_id):
    """View detailed execution information"""
    try:
        execution = RemediationExecution.query.get_or_404(execution_id)
        
        # Get action executions
        action_executions = RemediationActionExecution.query.filter_by(
            execution_id=execution_id
        ).order_by(RemediationActionExecution.execution_order).all()
        
        return render_template('remediation/execution_details.html',
                             execution=execution,
                             action_executions=action_executions)
    
    except Exception as e:
        logger.error(f"Error viewing execution {execution_id}: {str(e)}")
        flash(f'Error loading execution: {str(e)}', 'error')
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/workflows/<int:workflow_id>')
def workflow_details(workflow_id):
    """View detailed workflow information"""
    try:
        workflow = RemediationWorkflow.query.get_or_404(workflow_id)
        
        # Get recent executions for this workflow
        executions = RemediationExecution.query.filter_by(
            workflow_id=workflow_id
        ).order_by(RemediationExecution.started_at.desc()).limit(20).all()
        
        # Get execution statistics
        total_executions = RemediationExecution.query.filter_by(workflow_id=workflow_id).count()
        successful = RemediationExecution.query.filter_by(
            workflow_id=workflow_id, status=RemediationWorkflowStatus.COMPLETED
        ).count()
        failed = RemediationExecution.query.filter_by(
            workflow_id=workflow_id, status=RemediationWorkflowStatus.FAILED
        ).count()
        
        success_rate = (successful / total_executions * 100) if total_executions > 0 else 0
        
        # Get available agents for manual execution
        agents = AIAgent.query.limit(50).all()
        
        return render_template('remediation/workflow_details.html',
                             workflow=workflow,
                             executions=executions,
                             total_executions=total_executions,
                             successful=successful,
                             failed=failed,
                             success_rate=success_rate,
                             agents=agents,
                             workflow_engine_available=WORKFLOW_ENGINE_AVAILABLE)
    
    except Exception as e:
        logger.error(f"Error viewing workflow {workflow_id}: {str(e)}")
        flash(f'Error loading workflow: {str(e)}', 'error')
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/workflow_templates')
def workflow_templates():
    """View workflow templates"""
    try:
        from services.remediation_templates import remediation_template_manager
        
        # Get available templates
        templates = remediation_template_manager.get_available_templates()
        
        # Get existing workflows created from templates
        existing_workflows = RemediationWorkflow.query.filter_by(created_by="system").all()
        
        return render_template('remediation/templates.html',
                             templates=templates,
                             existing_workflows=existing_workflows)
    
    except Exception as e:
        logger.error(f"Error loading templates: {str(e)}")
        flash(f'Error loading templates: {str(e)}', 'error')
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/create_workflow', methods=['POST'])
def create_workflow_new():
    """Create a new workflow from dashboard"""
    try:
        # Get form data
        name = request.form.get('name')
        description = request.form.get('description', '')
        workflow_type = request.form.get('workflow_type')
        trigger_type = request.form.get('trigger_type')
        target_frameworks = request.form.getlist('target_frameworks')
        requires_approval = 'requires_approval' in request.form
        auto_rollback = 'auto_rollback' in request.form
        
        # Validate required fields
        if not all([name, workflow_type, trigger_type]):
            flash('Name, workflow type, and trigger type are required', 'error')
            return redirect(url_for('remediation.index'))
        
        # Create basic workflow (user will need to add actions separately)
        workflow = RemediationWorkflow(
            name=name,
            description=description,
            workflow_type=workflow_type,
            trigger_type=RemediationTriggerType(trigger_type),
            target_frameworks=target_frameworks,
            requires_approval=requires_approval,
            auto_rollback=auto_rollback,
            actions=[],  # Empty initially
            created_by='web_user',
            is_active=False  # Start inactive until actions are configured
        )
        
        db.session.add(workflow)
        db.session.commit()
        
        flash(f'Workflow "{name}" created successfully! Configure actions to activate.', 'success')
        return redirect(url_for('remediation.workflow_details', workflow_id=workflow.id))
    
    except Exception as e:
        logger.error(f"Error creating workflow: {str(e)}")
        flash(f'Error creating workflow: {str(e)}', 'error')
        db.session.rollback()
        return redirect(url_for('remediation.index'))


@remediation_bp.route('/workflows/<int:workflow_id>/enable', methods=['POST'])
def enable_workflow(workflow_id):
    """Enable a workflow"""
    try:
        workflow = RemediationWorkflow.query.get_or_404(workflow_id)
        workflow.is_active = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Workflow enabled'})
    
    except Exception as e:
        logger.error(f"Error enabling workflow: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@remediation_bp.route('/workflows/<int:workflow_id>/disable', methods=['POST'])
def disable_workflow(workflow_id):
    """Disable a workflow"""
    try:
        workflow = RemediationWorkflow.query.get_or_404(workflow_id)
        workflow.is_active = False
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Workflow disabled'})
    
    except Exception as e:
        logger.error(f"Error disabling workflow: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@remediation_bp.route('/executions/<int:execution_id>/cancel', methods=['POST'])
def cancel_execution_new(execution_id):
    """Cancel a workflow execution"""
    try:
        execution = RemediationExecution.query.get_or_404(execution_id)
        
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


@remediation_bp.route('/executions/<int:execution_id>/retry', methods=['POST'])
def retry_execution(execution_id):
    """Retry a failed workflow execution"""
    try:
        original_execution = RemediationExecution.query.get_or_404(execution_id)
        
        if original_execution.status not in [RemediationWorkflowStatus.FAILED, RemediationWorkflowStatus.CANCELLED]:
            return jsonify({
                'success': False,
                'error': 'Can only retry failed or cancelled executions'
            }), 400
        
        if not WORKFLOW_ENGINE_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'Workflow engine is not available'
            }), 500
        
        # Create new execution with same parameters
        trigger_data = original_execution.trigger_data.copy() if original_execution.trigger_data else {}
        trigger_data['retry_of_execution_id'] = original_execution.id
        trigger_data['retry_timestamp'] = datetime.utcnow().isoformat()
        
        # Execute workflow asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        new_execution = loop.run_until_complete(
            workflow_engine.execute_workflow(
                original_execution.workflow_id,
                original_execution.agent_id,
                trigger_data
            )
        )
        loop.close()
        
        return jsonify({
            'success': True,
            'message': f'Execution retried successfully. New execution ID: {new_execution.id}',
            'new_execution_id': new_execution.id
        })
    
    except Exception as e:
        logger.error(f"Error retrying execution: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500