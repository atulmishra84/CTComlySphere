"""
Routes for Agent Registration Playbooks
Provides web interface for plain English playbook configuration
"""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app import db
from models import (
    RegistrationPlaybook, AgentRegistration, AIAgentInventory, PlaybookExecution,
    AIAgent, RegistrationStatus, InventoryStatus
)
from playbooks.playbook_manager import PlaybookManager
import json
from datetime import datetime

playbook_bp = Blueprint('playbooks', __name__, url_prefix='/playbooks')
playbook_manager = PlaybookManager()


@playbook_bp.route('/')
def index():
    """Playbook management dashboard"""
    playbooks = RegistrationPlaybook.query.order_by(RegistrationPlaybook.created_at.desc()).all()
    total_registrations = AgentRegistration.query.count()
    active_playbooks = RegistrationPlaybook.query.filter_by(is_active=True).count()
    auto_onboarding_count = RegistrationPlaybook.query.filter_by(auto_onboarding_enabled=True).count()
    
    return render_template('playbooks/index.html', 
                         playbooks=playbooks,
                         total_registrations=total_registrations,
                         active_playbooks=active_playbooks,
                         auto_onboarding_count=auto_onboarding_count)


@playbook_bp.route('/create', methods=['GET', 'POST'])
def create_playbook():
    """Create new registration playbook"""
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            plain_english_config = request.form.get('plain_english_config')
            
            if not all([name, description, plain_english_config]):
                flash('All fields are required', 'error')
                return render_template('playbooks/create.html')
            
            # Create playbook with auto-generated backend code
            playbook = playbook_manager.create_playbook_from_english(
                name=name,
                description=description,
                plain_english_config=plain_english_config,
                created_by='web_user'
            )
            
            flash(f'Playbook "{name}" created successfully with auto-generated backend code!', 'success')
            return redirect(url_for('playbooks.view_playbook', id=playbook.id))
            
        except Exception as e:
            flash(f'Error creating playbook: {str(e)}', 'error')
            db.session.rollback()
    
    # Provide examples for user guidance
    examples = {
        'healthcare_ai': '''Automatically register all AI agents discovered in healthcare environments.
When discovered through Kubernetes or Docker protocols, validate that they have proper encryption.
Check HIPAA and FDA compliance for all medical AI systems.
Add to inventory with high criticality level.
Notify security team via email when PHI exposure is detected.
Require authentication for all healthcare AI endpoints.''',
        
        'cloud_ai': '''Auto onboard AI agents from AWS, Azure, and GCP cloud providers.
When discovered through REST API or gRPC protocols, perform security scan.
Validate that cloud AI services have proper IAM roles.
Add to inventory with medium criticality level.
Check SOX compliance for financial AI models.
Notify admin team when high risk agents are discovered.''',
        
        'research_ai': '''Register research and development AI agents automatically.
When discovered, validate metadata and check for proper documentation.
Add to inventory with low criticality level for development environment.
Notify research team when new AI models are deployed.
Require version control integration for all research AI systems.'''
    }
    
    return render_template('playbooks/create.html', examples=examples)


@playbook_bp.route('/<int:id>')
def view_playbook(id):
    """View playbook details and generated code"""
    playbook = RegistrationPlaybook.query.get_or_404(id)
    registrations = AgentRegistration.query.filter_by(playbook_id=id).order_by(
        AgentRegistration.started_at.desc()
    ).limit(10).all()
    executions = PlaybookExecution.query.filter_by(playbook_id=id).order_by(
        PlaybookExecution.started_at.desc()
    ).limit(10).all()
    
    return render_template('playbooks/view.html', 
                         playbook=playbook,
                         registrations=registrations,
                         executions=executions)


@playbook_bp.route('/<int:id>/edit', methods=['GET', 'POST'])
def edit_playbook(id):
    """Edit playbook configuration"""
    playbook = RegistrationPlaybook.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            plain_english_config = request.form.get('plain_english_config')
            
            if not plain_english_config:
                flash('Configuration is required', 'error')
                return render_template('playbooks/edit.html', playbook=playbook)
            
            # Update playbook and regenerate backend code
            updated_playbook = playbook_manager.update_playbook(
                playbook_id=id,
                plain_english_config=plain_english_config
            )
            
            flash('Playbook updated successfully! Backend code has been regenerated.', 'success')
            return redirect(url_for('playbooks.view_playbook', id=id))
            
        except Exception as e:
            flash(f'Error updating playbook: {str(e)}', 'error')
            db.session.rollback()
    
    return render_template('playbooks/edit.html', playbook=playbook)


@playbook_bp.route('/<int:id>/toggle', methods=['POST'])
def toggle_playbook(id):
    """Toggle playbook active status"""
    playbook = RegistrationPlaybook.query.get_or_404(id)
    playbook.is_active = not playbook.is_active
    db.session.commit()
    
    status = 'activated' if playbook.is_active else 'deactivated'
    return jsonify({
        'success': True,
        'message': f'Playbook {status} successfully',
        'is_active': playbook.is_active
    })


@playbook_bp.route('/<int:id>/auto-onboarding', methods=['POST'])
def toggle_auto_onboarding(id):
    """Toggle auto-onboarding for playbook"""
    playbook = RegistrationPlaybook.query.get_or_404(id)
    playbook.auto_onboarding_enabled = not playbook.auto_onboarding_enabled
    db.session.commit()
    
    status = 'enabled' if playbook.auto_onboarding_enabled else 'disabled'
    return jsonify({
        'success': True,
        'message': f'Auto-onboarding {status} successfully',
        'auto_onboarding_enabled': playbook.auto_onboarding_enabled
    })


@playbook_bp.route('/execute', methods=['POST'])
def execute_playbook():
    """Manually execute playbook for an agent"""
    try:
        agent_id = request.json.get('agent_id')
        playbook_id = request.json.get('playbook_id')
        
        if not agent_id or not playbook_id:
            return jsonify({'success': False, 'message': 'Agent ID and Playbook ID required'}), 400
        
        execution = playbook_manager.execute_playbook(agent_id, playbook_id)
        
        return jsonify({
            'success': True,
            'message': 'Playbook execution started',
            'execution_id': execution.id,
            'status': execution.execution_status.value
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@playbook_bp.route('/inventory')
def inventory():
    """AI Agent Inventory dashboard"""
    # Get inventory summary
    summary = playbook_manager.get_inventory_summary()
    
    # Get recent registrations
    recent_registrations = db.session.query(
        AIAgentInventory, AIAgent
    ).join(AIAgent).order_by(
        AIAgentInventory.added_to_inventory.desc()
    ).limit(20).all()
    
    # Get agents by status
    status_counts = {}
    for status in InventoryStatus:
        count = AIAgentInventory.query.filter_by(inventory_status=status).count()
        status_counts[status.value] = count
    
    return render_template('playbooks/inventory.html',
                         summary=summary,
                         recent_registrations=recent_registrations,
                         status_counts=status_counts)


@playbook_bp.route('/inventory/<int:agent_id>')
def inventory_details(agent_id):
    """View detailed inventory information for an agent"""
    agent = AIAgent.query.get_or_404(agent_id)
    inventory = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
    registrations = AgentRegistration.query.filter_by(agent_id=agent_id).all()
    
    return render_template('playbooks/inventory_details.html',
                         agent=agent,
                         inventory=inventory,
                         registrations=registrations)


@playbook_bp.route('/inventory/<int:agent_id>/update', methods=['POST'])
def update_inventory(agent_id):
    """Update agent inventory information"""
    try:
        inventory = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
        if not inventory:
            # Create new inventory record
            inventory = AIAgentInventory(agent_id=agent_id)
            db.session.add(inventory)
        
        # Update fields
        inventory.business_owner = request.form.get('business_owner')
        inventory.technical_owner = request.form.get('technical_owner')
        inventory.department = request.form.get('department')
        inventory.use_case = request.form.get('use_case')
        inventory.data_classification = request.form.get('data_classification')
        inventory.criticality_level = request.form.get('criticality_level')
        inventory.deployment_environment = request.form.get('deployment_environment')
        inventory.cost_center = request.form.get('cost_center')
        
        # Handle JSON fields
        regulatory_scope = request.form.getlist('regulatory_scope')
        inventory.regulatory_scope = regulatory_scope
        
        db.session.commit()
        flash('Inventory updated successfully', 'success')
        
    except Exception as e:
        flash(f'Error updating inventory: {str(e)}', 'error')
        db.session.rollback()
    
    return redirect(url_for('playbooks.inventory_details', agent_id=agent_id))


@playbook_bp.route('/api/agents/unregistered')
def unregistered_agents():
    """API endpoint to get agents not yet in inventory"""
    # Find agents without inventory records
    unregistered = db.session.query(AIAgent).outerjoin(
        AIAgentInventory, AIAgent.id == AIAgentInventory.agent_id
    ).filter(AIAgentInventory.id.is_(None)).all()
    
    agents_data = []
    for agent in unregistered:
        agents_data.append({
            'id': agent.id,
            'name': agent.name,
            'type': agent.type,
            'protocol': agent.protocol,
            'endpoint': agent.endpoint,
            'cloud_provider': agent.cloud_provider,
            'discovered_at': agent.discovered_at.isoformat() if agent.discovered_at else None
        })
    
    return jsonify(agents_data)


@playbook_bp.route('/api/playbooks/active')
def active_playbooks():
    """API endpoint to get active playbooks"""
    playbooks = RegistrationPlaybook.query.filter_by(is_active=True).all()
    
    playbooks_data = []
    for playbook in playbooks:
        playbooks_data.append({
            'id': playbook.id,
            'name': playbook.name,
            'description': playbook.description,
            'auto_onboarding_enabled': playbook.auto_onboarding_enabled,
            'trigger_conditions': playbook.trigger_conditions
        })
    
    return jsonify(playbooks_data)


@playbook_bp.route('/auto-onboard/trigger', methods=['POST'])
def trigger_auto_onboarding():
    """Manually trigger auto-onboarding for all unregistered agents"""
    try:
        # Get all unregistered agents
        unregistered = db.session.query(AIAgent).outerjoin(
            AIAgentInventory, AIAgent.id == AIAgentInventory.agent_id
        ).filter(AIAgentInventory.id.is_(None)).all()
        
        triggered_count = 0
        for agent in unregistered:
            playbook_manager.trigger_auto_onboarding(agent)
            triggered_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Auto-onboarding triggered for {triggered_count} agents'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@playbook_bp.route('/execution/<int:execution_id>')
def execution_details(execution_id):
    """View execution details"""
    execution = PlaybookExecution.query.get_or_404(execution_id)
    return render_template('playbooks/execution_details.html', execution=execution)


@playbook_bp.route('/api/stats')
def stats():
    """API endpoint for playbook statistics"""
    total_playbooks = RegistrationPlaybook.query.count()
    active_playbooks = RegistrationPlaybook.query.filter_by(is_active=True).count()
    total_registrations = AgentRegistration.query.count()
    successful_registrations = AgentRegistration.query.filter_by(
        registration_status=RegistrationStatus.COMPLETED
    ).count()
    
    # Recent activity
    recent_executions = PlaybookExecution.query.order_by(
        PlaybookExecution.started_at.desc()
    ).limit(5).all()
    
    recent_activity = []
    for execution in recent_executions:
        recent_activity.append({
            'id': execution.id,
            'playbook_name': execution.playbook.name,
            'agent_name': execution.agent.name,
            'status': execution.execution_status.value,
            'started_at': execution.started_at.isoformat()
        })
    
    return jsonify({
        'total_playbooks': total_playbooks,
        'active_playbooks': active_playbooks,
        'total_registrations': total_registrations,
        'successful_registrations': successful_registrations,
        'success_rate': (successful_registrations / total_registrations * 100) if total_registrations > 0 else 0,
        'recent_activity': recent_activity
    })