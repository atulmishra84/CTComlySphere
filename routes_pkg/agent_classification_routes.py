"""
Routes for AI Agent Classification and Controls Management
"""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app import db
from models import AIAgent, AIAgentInventory, ComplianceFramework
from agents.classification_engine import AgentClassificationEngine
from agents.controls_manager import AgentControlsManager
from agents.registration_workflow import EnhancedRegistrationWorkflow
import json
import logging

logger = logging.getLogger(__name__)

agent_classification_bp = Blueprint('agent_classification', __name__, url_prefix='/agents')

# Initialize managers
classification_engine = AgentClassificationEngine()
controls_manager = AgentControlsManager()
registration_workflow = EnhancedRegistrationWorkflow()


@agent_classification_bp.route('/classification')
def classification_dashboard():
    """Agent classification dashboard"""
    try:
        # Get all agents with their classification status
        agents_query = db.session.query(AIAgent, AIAgentInventory).outerjoin(
            AIAgentInventory, AIAgent.id == AIAgentInventory.agent_id
        ).all()
        
        agents_data = []
        classification_stats = {
            'total_agents': 0,
            'classified_agents': 0,
            'unclassified_agents': 0,
            'healthcare_ai': 0,
            'financial_ai': 0,
            'operational_ai': 0,
            'research_ai': 0,
            'personal_data_ai': 0
        }
        
        for agent, inventory in agents_query:
            classification_stats['total_agents'] += 1
            
            if inventory and inventory.primary_classification:
                classification_stats['classified_agents'] += 1
                if inventory.primary_classification in classification_stats:
                    classification_stats[inventory.primary_classification] += 1
            else:
                classification_stats['unclassified_agents'] += 1
            
            agents_data.append({
                'agent': agent,
                'inventory': inventory,
                'classification_status': 'classified' if inventory and inventory.primary_classification else 'unclassified',
                'frameworks': inventory.applicable_frameworks if inventory else [],
                'controls_status': len(inventory.applied_controls or []) if inventory else 0
            })
        
        return render_template('agents/classification_dashboard.html',
                             agents=agents_data,
                             stats=classification_stats)
    
    except Exception as e:
        logger.error(f"Error in classification dashboard: {str(e)}")
        flash(f"Error loading classification dashboard: {str(e)}", 'error')
        return render_template('agents/classification_dashboard.html', agents=[], stats={})


@agent_classification_bp.route('/<int:agent_id>/classify', methods=['POST'])
def classify_agent(agent_id):
    """Classify a specific agent"""
    try:
        agent = AIAgent.query.get_or_404(agent_id)
        
        # Prepare agent data
        agent_data = {
            'id': agent.id,
            'name': agent.name,
            'type': agent.type,
            'protocol': agent.protocol,
            'endpoint': agent.endpoint,
            'version': agent.version,
            'cloud_provider': agent.cloud_provider,
            'region': agent.region,
            'agent_metadata': agent.agent_metadata or {}
        }
        
        # Perform classification
        classification_result = classification_engine.classify_agent(agent_data)
        
        # Update or create inventory record
        inventory_record = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
        if not inventory_record:
            inventory_record = AIAgentInventory(agent_id=agent_id)
            db.session.add(inventory_record)
        
        # Update classification fields
        inventory_record.primary_classification = classification_result.get('primary_classification')
        inventory_record.secondary_classifications = classification_result.get('secondary_classifications', [])
        inventory_record.classification_confidence = classification_result.get('confidence_score', 0.0)
        inventory_record.classification_reasons = classification_result.get('classification_reasons', [])
        inventory_record.applicable_frameworks = classification_result.get('applicable_frameworks', [])
        inventory_record.required_controls = classification_result.get('required_controls', [])
        inventory_record.criticality_level = classification_result.get('criticality_level', 'low')
        inventory_record.last_classification_update = db.func.now()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Agent {agent.name} classified successfully',
            'classification_result': classification_result
        })
    
    except Exception as e:
        logger.error(f"Error classifying agent {agent_id}: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_classification_bp.route('/<int:agent_id>/apply-controls', methods=['POST'])
def apply_controls(agent_id):
    """Apply security controls to an agent"""
    try:
        agent = AIAgent.query.get_or_404(agent_id)
        inventory_record = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
        
        if not inventory_record or not inventory_record.required_controls:
            return jsonify({
                'success': False,
                'error': 'Agent must be classified first to determine required controls'
            }), 400
        
        # Apply controls
        controls_result = controls_manager.apply_controls_to_agent(
            agent_id, inventory_record.required_controls
        )
        
        # Update inventory record with control results
        inventory_record.applied_controls = controls_result.get('controls_applied', [])
        inventory_record.failed_controls = controls_result.get('controls_failed', [])
        inventory_record.control_status = {
            control: result.get('status', 'unknown')
            for control, result in controls_result.get('validation_results', {}).items()
        }
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Controls applied to agent {agent.name}',
            'controls_result': controls_result
        })
    
    except Exception as e:
        logger.error(f"Error applying controls to agent {agent_id}: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_classification_bp.route('/<int:agent_id>/register', methods=['POST'])
def register_agent(agent_id):
    """Register agent with full classification and controls workflow"""
    try:
        # Execute complete registration workflow
        workflow_result = registration_workflow.register_agent_with_classification(
            agent_id, auto_apply_controls=True
        )
        
        if workflow_result['workflow_status'] == 'completed':
            return jsonify({
                'success': True,
                'message': f'Agent registration completed successfully',
                'workflow_result': workflow_result
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Agent registration failed: {workflow_result.get("error", "Unknown error")}',
                'workflow_result': workflow_result
            }), 500
    
    except Exception as e:
        logger.error(f"Error in agent registration workflow: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_classification_bp.route('/<int:agent_id>/status')
def get_agent_status(agent_id):
    """Get comprehensive agent status"""
    try:
        agent = AIAgent.query.get_or_404(agent_id)
        inventory_record = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
        
        # Get registration status
        registration_status = registration_workflow.get_registration_status(agent_id)
        
        # Get control status
        control_status = controls_manager.get_agent_control_status(agent_id)
        
        agent_status = {
            'agent_info': {
                'id': agent.id,
                'name': agent.name,
                'type': agent.type,
                'protocol': agent.protocol,
                'endpoint': agent.endpoint,
                'discovered_at': agent.discovered_at.isoformat() if agent.discovered_at else None
            },
            'classification': {
                'primary_classification': inventory_record.primary_classification if inventory_record else None,
                'secondary_classifications': inventory_record.secondary_classifications if inventory_record else [],
                'confidence_score': inventory_record.classification_confidence if inventory_record else 0.0,
                'applicable_frameworks': inventory_record.applicable_frameworks if inventory_record else [],
                'criticality_level': inventory_record.criticality_level if inventory_record else 'unknown'
            },
            'registration_status': registration_status,
            'control_status': control_status,
            'inventory_status': inventory_record.inventory_status.value if inventory_record else 'not_in_inventory'
        }
        
        return jsonify(agent_status)
    
    except Exception as e:
        logger.error(f"Error getting agent status: {str(e)}")
        return jsonify({'error': str(e)}), 500


@agent_classification_bp.route('/bulk-classify', methods=['POST'])
def bulk_classify_agents():
    """Classify multiple agents at once"""
    try:
        agent_ids = request.json.get('agent_ids', [])
        
        if not agent_ids:
            return jsonify({
                'success': False,
                'error': 'No agent IDs provided'
            }), 400
        
        results = []
        
        for agent_id in agent_ids:
            try:
                # Classify agent
                response = classify_agent(agent_id)
                if response.status_code == 200:
                    results.append({
                        'agent_id': agent_id,
                        'status': 'success',
                        'result': response.get_json()
                    })
                else:
                    results.append({
                        'agent_id': agent_id,
                        'status': 'failed',
                        'error': response.get_json().get('error', 'Unknown error')
                    })
            except Exception as e:
                results.append({
                    'agent_id': agent_id,
                    'status': 'failed',
                    'error': str(e)
                })
        
        successful_count = len([r for r in results if r['status'] == 'success'])
        
        return jsonify({
            'success': True,
            'message': f'Bulk classification completed. {successful_count}/{len(agent_ids)} agents classified successfully',
            'results': results
        })
    
    except Exception as e:
        logger.error(f"Error in bulk classification: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_classification_bp.route('/auto-register-discovered', methods=['POST'])
def auto_register_discovered_agents():
    """Automatically register all discovered but unregistered agents"""
    try:
        # Find agents that don't have inventory records or are not registered
        unregistered_agents = db.session.query(AIAgent).outerjoin(
            AIAgentInventory, AIAgent.id == AIAgentInventory.agent_id
        ).filter(
            db.or_(
                AIAgentInventory.id.is_(None),
                AIAgentInventory.inventory_status != 'registered'
            )
        ).all()
        
        if not unregistered_agents:
            return jsonify({
                'success': True,
                'message': 'No unregistered agents found',
                'agents_processed': 0
            })
        
        results = []
        
        for agent in unregistered_agents:
            try:
                # Execute full registration workflow
                workflow_result = registration_workflow.register_agent_with_classification(
                    agent.id, auto_apply_controls=True
                )
                
                results.append({
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'status': workflow_result['workflow_status'],
                    'classification': workflow_result.get('classification_result', {}).get('primary_classification'),
                    'frameworks': workflow_result.get('classification_result', {}).get('applicable_frameworks', [])
                })
                
            except Exception as e:
                logger.error(f"Failed to register agent {agent.id}: {str(e)}")
                results.append({
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'status': 'failed',
                    'error': str(e)
                })
        
        successful_registrations = len([r for r in results if r['status'] == 'completed'])
        
        return jsonify({
            'success': True,
            'message': f'Auto-registration completed. {successful_registrations}/{len(results)} agents registered successfully',
            'agents_processed': len(results),
            'results': results
        })
    
    except Exception as e:
        logger.error(f"Error in auto-registration: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@agent_classification_bp.route('/controls-dashboard')
def controls_dashboard():
    """Dashboard for agent-level controls management"""
    try:
        # Get all agents with their control status
        inventory_records = AIAgentInventory.query.join(AIAgent).all()
        
        controls_stats = {
            'total_agents': len(inventory_records),
            'agents_with_controls': 0,
            'fully_compliant': 0,
            'partially_compliant': 0,
            'non_compliant': 0,
            'control_types': {}
        }
        
        agents_data = []
        
        for inventory in inventory_records:
            agent = inventory.agent
            applied_controls = inventory.applied_controls or []
            required_controls = inventory.required_controls or []
            control_status = inventory.control_status or {}
            
            if applied_controls:
                controls_stats['agents_with_controls'] += 1
            
            # Calculate compliance status
            if required_controls:
                compliance_ratio = len(applied_controls) / len(required_controls)
                if compliance_ratio >= 0.9:
                    controls_stats['fully_compliant'] += 1
                    compliance_status = 'compliant'
                elif compliance_ratio >= 0.7:
                    controls_stats['partially_compliant'] += 1
                    compliance_status = 'partially_compliant'
                else:
                    controls_stats['non_compliant'] += 1
                    compliance_status = 'non_compliant'
            else:
                compliance_status = 'no_requirements'
            
            # Count control types
            for control in applied_controls:
                if control in controls_stats['control_types']:
                    controls_stats['control_types'][control] += 1
                else:
                    controls_stats['control_types'][control] = 1
            
            agents_data.append({
                'agent': agent,
                'inventory': inventory,
                'applied_controls': applied_controls,
                'required_controls': required_controls,
                'control_status': control_status,
                'compliance_status': compliance_status,
                'compliance_percentage': (len(applied_controls) / len(required_controls) * 100) if required_controls else 0
            })
        
        return render_template('agents/controls_dashboard.html',
                             agents=agents_data,
                             stats=controls_stats)
    
    except Exception as e:
        logger.error(f"Error in controls dashboard: {str(e)}")
        flash(f"Error loading controls dashboard: {str(e)}", 'error')
        return render_template('agents/controls_dashboard.html', agents=[], stats={})