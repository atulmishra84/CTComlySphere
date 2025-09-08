"""
Routes for Healthcare Compliance AI Agent Interface
Provides web endpoints for interacting with the autonomous compliance agent
"""

from flask import Blueprint, request, jsonify, render_template, session
from datetime import datetime
import asyncio
import json

from agents.healthcare_compliance_agent import healthcare_compliance_agent
from agents.agent_interface import agent_interface
from models import AIAgent, ComplianceEvaluation, ScanResult

agent_bp = Blueprint('agent', __name__, url_prefix='/agent')


@agent_bp.route('/')
def agent_dashboard():
    """Main agent dashboard showing agent status and interaction interface"""
    # Get agent status
    agent_status = healthcare_compliance_agent.get_agent_status()
    
    # Get recent agent activity
    recent_tasks = healthcare_compliance_agent.task_queue[-10:]  # Last 10 tasks
    
    # Get compliance summary for context
    total_agents = AIAgent.query.count()
    recent_evaluations = ComplianceEvaluation.query.all()
    
    context_data = {
        "total_agents": total_agents,
        "recent_evaluations": len(recent_evaluations),
        "agent_running": agent_status["running"]
    }
    
    # Generate contextual suggestions
    suggestions = agent_interface.generate_suggestions(context_data)
    
    return render_template('agent/dashboard.html',
                         agent_status=agent_status,
                         recent_tasks=recent_tasks,
                         suggestions=suggestions,
                         context_data=context_data)


@agent_bp.route('/chat', methods=['POST'])
def chat_with_agent():
    """Handle natural language queries to the compliance agent"""
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({
                "success": False,
                "message": "Please provide a query"
            }), 400
        
        # Get user context from session
        user_context = {
            "session_id": session.get('session_id'),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Process the query asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            response = loop.run_until_complete(
                agent_interface.process_query(query, user_context)
            )
        finally:
            loop.close()
        
        # Add suggestions for follow-up
        if response.get("success"):
            response["suggestions"] = agent_interface.generate_suggestions()
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "An error occurred while processing your request"
        }), 500


@agent_bp.route('/status')
def get_agent_status():
    """Get current agent status via API"""
    status = healthcare_compliance_agent.get_agent_status()
    
    # Add additional status information
    status.update({
        "system_health": "healthy" if status["running"] else "stopped",
        "uptime": "active" if status["running"] else "inactive",
        "last_check": datetime.utcnow().isoformat()
    })
    
    return jsonify(status)


@agent_bp.route('/start', methods=['POST'])
def start_agent():
    """Start the autonomous compliance agent"""
    try:
        if healthcare_compliance_agent.running:
            return jsonify({
                "success": False,
                "message": "Agent is already running"
            })
        
        # Start the agent in background
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Note: In production, this should be handled by a proper task queue
        # For demo purposes, we'll simulate starting
        healthcare_compliance_agent.running = True
        
        return jsonify({
            "success": True,
            "message": "Healthcare Compliance AI Agent started successfully",
            "status": healthcare_compliance_agent.get_agent_status()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "Failed to start the agent"
        }), 500


@agent_bp.route('/stop', methods=['POST'])
def stop_agent():
    """Stop the autonomous compliance agent"""
    try:
        healthcare_compliance_agent.stop_agent()
        
        return jsonify({
            "success": True,
            "message": "Healthcare Compliance AI Agent stopped successfully",
            "status": healthcare_compliance_agent.get_agent_status()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "Failed to stop the agent"
        }), 500


@agent_bp.route('/tasks')
def get_agent_tasks():
    """Get current agent task queue"""
    tasks = healthcare_compliance_agent.task_queue
    
    # Convert tasks to JSON-serializable format
    task_data = []
    for task in tasks[-20:]:  # Last 20 tasks
        task_info = {
            "id": task.id,
            "action": task.action.value,
            "priority": task.priority.value,
            "created_at": task.created_at.isoformat(),
            "completed": task.completed,
            "scheduled_for": task.scheduled_for.isoformat() if task.scheduled_for else None
        }
        task_data.append(task_info)
    
    return jsonify({
        "tasks": task_data,
        "total_tasks": len(tasks),
        "pending_tasks": len([t for t in tasks if not t.completed])
    })


@agent_bp.route('/insights')
def get_agent_insights():
    """Get AI agent insights and analytics"""
    # Get compliance insights
    evaluations = ComplianceEvaluation.query.all()
    
    insights = {
        "compliance_trends": {},
        "risk_patterns": {},
        "agent_performance": {},
        "recommendations": []
    }
    
    if evaluations:
        # Calculate compliance trends
        framework_scores = {}
        for eval in evaluations:
            framework = eval.framework.value
            if framework not in framework_scores:
                framework_scores[framework] = []
            framework_scores[framework].append(eval.compliance_score)
        
        for framework, scores in framework_scores.items():
            insights["compliance_trends"][framework] = {
                "average": sum(scores) / len(scores),
                "trend": "improving" if scores[-1] > scores[0] else "declining" if len(scores) > 1 else "stable"
            }
    
    # Get agent performance metrics
    status = healthcare_compliance_agent.get_agent_status()
    insights["agent_performance"] = {
        "tasks_completed": status["completed_tasks"],
        "decisions_made": status["decisions_made"],
        "efficiency": "high" if status["completed_tasks"] > 10 else "moderate"
    }
    
    # Generate recommendations
    insights["recommendations"] = [
        "Consider implementing automated remediation for HIPAA violations",
        "Review GenAI systems for bias testing compliance",
        "Schedule quarterly compliance audits for critical systems"
    ]
    
    return jsonify(insights)


@agent_bp.route('/history')
def get_decision_history():
    """Get agent decision history"""
    decisions = healthcare_compliance_agent.decision_history[-50:]  # Last 50 decisions
    
    # Format decisions for display
    formatted_decisions = []
    for decision in decisions:
        formatted_decisions.append({
            "task_id": decision.get("task_id"),
            "action": decision.get("action"),
            "timestamp": decision.get("timestamp"),
            "success": decision.get("result", {}).get("success", True),
            "summary": f"Executed {decision.get('action', 'unknown')} action"
        })
    
    return jsonify({
        "decisions": formatted_decisions,
        "total_decisions": len(healthcare_compliance_agent.decision_history)
    })


@agent_bp.route('/quick-actions')
def get_quick_actions():
    """Get available quick actions for the agent"""
    actions = [
        {
            "id": "discover_systems",
            "name": "Discover AI Systems",
            "description": "Scan for new AI systems in the environment",
            "icon": "fas fa-search",
            "priority": "high"
        },
        {
            "id": "check_compliance",
            "name": "Check Compliance",
            "description": "Assess current compliance status",
            "icon": "fas fa-shield-alt",
            "priority": "high"
        },
        {
            "id": "generate_report",
            "name": "Generate Report",
            "description": "Create comprehensive compliance report",
            "icon": "fas fa-file-alt",
            "priority": "medium"
        },
        {
            "id": "fix_issues",
            "name": "Fix Issues",
            "description": "Automatically remediate compliance issues",
            "icon": "fas fa-wrench",
            "priority": "critical"
        },
        {
            "id": "monitor_systems",
            "name": "Monitor Systems",
            "description": "Enable continuous compliance monitoring",
            "icon": "fas fa-chart-line",
            "priority": "medium"
        }
    ]
    
    return jsonify({"actions": actions})


@agent_bp.route('/execute-action', methods=['POST'])
def execute_quick_action():
    """Execute a quick action via the agent"""
    try:
        data = request.get_json()
        action_id = data.get('action_id')
        
        if not action_id:
            return jsonify({
                "success": False,
                "message": "Action ID is required"
            }), 400
        
        # Map action IDs to natural language queries
        action_queries = {
            "discover_systems": "Discover all AI systems in the environment",
            "check_compliance": "Check compliance status for all systems",
            "generate_report": "Generate a comprehensive compliance report",
            "fix_issues": "Fix all critical compliance issues",
            "monitor_systems": "Enable continuous monitoring for all systems"
        }
        
        query = action_queries.get(action_id)
        if not query:
            return jsonify({
                "success": False,
                "message": "Unknown action"
            }), 400
        
        # Process the action via the agent interface
        user_context = {
            "quick_action": True,
            "action_id": action_id
        }
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            response = loop.run_until_complete(
                agent_interface.process_query(query, user_context)
            )
        finally:
            loop.close()
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "Failed to execute action"
        }), 500


# Error handlers
@agent_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "message": "Agent endpoint not found"
    }), 404


@agent_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "message": "Internal agent error"
    }), 500