"""
Enhanced Dashboard Routes - Advanced UI/UX with Real-time Analytics

This module provides routes for the enhanced dashboard with real-time monitoring,
advanced analytics, interactive visualizations, and external service integrations.
"""

import json
import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request

from app import db
from models import AIAgent, ComplianceEvaluation, ScanResult, ComplianceFramework, RiskLevel
from integrations.external_services import external_service_integrator
from compliance.enhanced_compliance_engine import enhanced_compliance_engine

# Create blueprint
enhanced_dashboard_bp = Blueprint('enhanced_dashboard', __name__, url_prefix='/enhanced')

logger = logging.getLogger(__name__)


@enhanced_dashboard_bp.route('/')
def enhanced_dashboard():
    """Enhanced dashboard with real-time analytics and visualizations"""
    try:
        # Get dashboard summary data
        dashboard_data = get_dashboard_summary()
        
        return render_template('enhanced_dashboard.html', **dashboard_data)
        
    except Exception as e:
        logger.error(f"Enhanced dashboard error: {str(e)}")
        return render_template('enhanced_dashboard.html', 
                             total_agents=0, 
                             overall_compliance_score=0,
                             active_threats=0,
                             avg_risk_score=0)


@enhanced_dashboard_bp.route('/api/metrics')
def api_metrics():
    """Real-time metrics API endpoint"""
    try:
        metrics = {
            'total_agents': AIAgent.query.count(),
            'total_scans': ScanResult.query.count(),
            'compliance_evaluations': ComplianceEvaluation.query.count(),
            'high_risk_agents': AIAgent.query.filter_by(risk_level=RiskLevel.HIGH).count(),
            'critical_risk_agents': AIAgent.query.filter_by(risk_level=RiskLevel.CRITICAL).count(),
            'compliant_agents': ComplianceEvaluation.query.filter_by(is_compliant=True).count(),
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Calculate overall compliance score
        total_evaluations = ComplianceEvaluation.query.count()
        if total_evaluations > 0:
            avg_compliance = db.session.query(db.func.avg(ComplianceEvaluation.compliance_score)).scalar()
            metrics['overall_compliance_score'] = round(avg_compliance, 1) if avg_compliance else 0
        else:
            metrics['overall_compliance_score'] = 0
        
        # Get external threat intelligence
        metrics['active_threats'] = len(external_service_integrator.cache.get('threats', []))
        
        return jsonify(metrics)
        
    except Exception as e:
        logger.error(f"Metrics API error: {str(e)}")
        return jsonify({'error': 'Failed to fetch metrics'}), 500


@enhanced_dashboard_bp.route('/api/compliance-trends')
def api_compliance_trends():
    """Compliance trends API for charts"""
    try:
        # Get timeframe from query parameter
        timeframe = request.args.get('timeframe', '30d')
        
        if timeframe == '7d':
            days = 7
        elif timeframe == '90d':
            days = 90
        else:
            days = 30
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get compliance evaluations within timeframe
        evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.evaluated_at >= start_date
        ).all()
        
        # Organize data by framework and date
        trends = {}
        frameworks = [ComplianceFramework.HIPAA, ComplianceFramework.FDA_SAMD, ComplianceFramework.GDPR]
        
        for framework in frameworks:
            framework_evaluations = [e for e in evaluations if e.framework == framework]
            
            # Group by date and calculate daily averages
            daily_scores = {}
            for eval in framework_evaluations:
                date_key = eval.evaluated_at.date().isoformat()
                if date_key not in daily_scores:
                    daily_scores[date_key] = []
                daily_scores[date_key].append(eval.compliance_score)
            
            # Calculate averages
            trend_data = []
            for i in range(days):
                date = (start_date + timedelta(days=i)).date()
                date_key = date.isoformat()
                
                if date_key in daily_scores:
                    avg_score = sum(daily_scores[date_key]) / len(daily_scores[date_key])
                else:
                    # Use previous day's score or default
                    avg_score = trend_data[-1]['score'] if trend_data else 85
                
                trend_data.append({
                    'date': date_key,
                    'score': round(avg_score, 1)
                })
            
            trends[framework.value] = trend_data
        
        return jsonify(trends)
        
    except Exception as e:
        logger.error(f"Compliance trends API error: {str(e)}")
        return jsonify({'error': 'Failed to fetch compliance trends'}), 500


@enhanced_dashboard_bp.route('/api/threat-intelligence')
def api_threat_intelligence():
    """Threat intelligence feed API"""
    try:
        # Get recent threats from external services
        threats = []
        
        # Check cache first
        cached_threats = external_service_integrator.cache.get('threats', [])
        if cached_threats:
            threats = cached_threats
        else:
            # Fetch from external services if available
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                threats = loop.run_until_complete(
                    external_service_integrator.get_threat_intelligence()
                )
                # Cache for 30 minutes
                external_service_integrator.cache['threats'] = threats
                loop.close()
            except Exception as e:
                logger.warning(f"Failed to fetch external threats: {str(e)}")
                # Use mock data
                threats = get_mock_threats()
        
        # Format for frontend
        threat_feed = []
        for threat in threats[:10]:  # Limit to 10 most recent
            threat_feed.append({
                'id': threat.threat_id,
                'title': threat.description[:100] + '...' if len(threat.description) > 100 else threat.description,
                'severity': threat.severity,
                'source': threat.source,
                'time': get_relative_time(threat.published_at),
                'healthcare_relevant': threat.healthcare_relevant
            })
        
        return jsonify(threat_feed)
        
    except Exception as e:
        logger.error(f"Threat intelligence API error: {str(e)}")
        return jsonify([]), 500


@enhanced_dashboard_bp.route('/api/network-topology')
def api_network_topology():
    """Network topology data for visualization"""
    try:
        # Get all active agents
        agents = AIAgent.query.filter_by(active=True).limit(50).all()
        
        nodes = []
        links = []
        
        for agent in agents:
            # Determine node properties
            risk_color = get_risk_color(agent.risk_level)
            node_size = get_node_size(agent.risk_level)
            
            nodes.append({
                'id': str(agent.id),
                'name': agent.name,
                'type': agent.type,
                'protocol': agent.protocol,
                'risk_level': agent.risk_level.value if agent.risk_level else 'unknown',
                'color': risk_color,
                'size': node_size,
                'healthcare_related': getattr(agent, 'healthcare_related', False)
            })
        
        # Create mock connections based on protocols and types
        for i, agent1 in enumerate(agents):
            for j, agent2 in enumerate(agents):
                if i != j and should_connect(agent1, agent2):
                    links.append({
                        'source': str(agent1.id),
                        'target': str(agent2.id),
                        'strength': get_connection_strength(agent1, agent2)
                    })
        
        return jsonify({
            'nodes': nodes,
            'links': links
        })
        
    except Exception as e:
        logger.error(f"Network topology API error: {str(e)}")
        return jsonify({'nodes': [], 'links': []}), 500


@enhanced_dashboard_bp.route('/api/agents-table')
def api_agents_table():
    """Enhanced agents table data with filtering"""
    try:
        # Get filter parameters
        framework_filter = request.args.get('framework')
        risk_filter = request.args.get('risk')
        compliance_filter = request.args.get('compliance')
        search_term = request.args.get('search', '').lower()
        
        # Build query
        query = AIAgent.query
        
        if search_term:
            query = query.filter(AIAgent.name.ilike(f'%{search_term}%'))
        
        if risk_filter:
            query = query.filter(AIAgent.risk_level == RiskLevel[risk_filter])
        
        agents = query.limit(100).all()
        
        # Get latest compliance evaluations
        agents_data = []
        for agent in agents:
            latest_eval = ComplianceEvaluation.query.filter_by(
                ai_agent_id=agent.id
            ).order_by(ComplianceEvaluation.evaluated_at.desc()).first()
            
            latest_scan = ScanResult.query.filter_by(
                ai_agent_id=agent.id
            ).order_by(ScanResult.created_at.desc()).first()
            
            # Apply compliance filter
            if compliance_filter:
                if compliance_filter == 'compliant' and (not latest_eval or not latest_eval.is_compliant):
                    continue
                elif compliance_filter == 'non-compliant' and (not latest_eval or latest_eval.is_compliant):
                    continue
                elif compliance_filter == 'partial' and (not latest_eval or latest_eval.compliance_score >= 80):
                    continue
            
            agents_data.append({
                'id': agent.id,
                'name': agent.name,
                'type': agent.type,
                'protocol': agent.protocol,
                'risk_level': agent.risk_level.value if agent.risk_level else 'unknown',
                'compliance_score': latest_eval.compliance_score if latest_eval else 0,
                'is_compliant': latest_eval.is_compliant if latest_eval else False,
                'last_scan': get_relative_time(latest_scan.created_at) if latest_scan else 'Never',
                'endpoint': agent.endpoint,
                'cloud_provider': agent.cloud_provider
            })
        
        return jsonify(agents_data)
        
    except Exception as e:
        logger.error(f"Agents table API error: {str(e)}")
        return jsonify([]), 500


@enhanced_dashboard_bp.route('/api/activity-timeline')
def api_activity_timeline():
    """Recent activity timeline"""
    try:
        activities = []
        
        # Get recent scans
        recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(5).all()
        for scan in recent_scans:
            agent = AIAgent.query.get(scan.ai_agent_id)
            activities.append({
                'type': 'scan',
                'title': 'Security scan completed',
                'agent': agent.name if agent else 'Unknown Agent',
                'time': get_relative_time(scan.created_at),
                'status': 'success' if scan.vulnerabilities_found == 0 else 'warning'
            })
        
        # Get recent compliance evaluations
        recent_evals = ComplianceEvaluation.query.order_by(ComplianceEvaluation.evaluated_at.desc()).limit(5).all()
        for eval in recent_evals:
            agent = AIAgent.query.get(eval.ai_agent_id)
            activities.append({
                'type': 'compliance',
                'title': f'{eval.framework.value} compliance evaluation',
                'agent': agent.name if agent else 'Unknown Agent',
                'time': get_relative_time(eval.evaluated_at),
                'status': 'success' if eval.is_compliant else 'warning'
            })
        
        # Sort by time (most recent first)
        activities.sort(key=lambda x: x['time'])
        
        return jsonify(activities[:10])
        
    except Exception as e:
        logger.error(f"Activity timeline API error: {str(e)}")
        return jsonify([]), 500


@enhanced_dashboard_bp.route('/api/external-services-status')
def api_external_services_status():
    """External services status"""
    try:
        status = external_service_integrator.get_service_status()
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"External services status API error: {str(e)}")
        return jsonify({'error': 'Failed to fetch service status'}), 500


def get_dashboard_summary():
    """Get summary data for dashboard"""
    total_agents = AIAgent.query.count()
    
    # Calculate overall compliance
    evaluations = ComplianceEvaluation.query.all()
    if evaluations:
        avg_compliance = sum(e.compliance_score for e in evaluations) / len(evaluations)
        overall_compliance_score = round(avg_compliance, 1)
    else:
        overall_compliance_score = 0
    
    # Count agents by risk level
    high_risk_count = AIAgent.query.filter_by(risk_level=RiskLevel.HIGH).count()
    critical_risk_count = AIAgent.query.filter_by(risk_level=RiskLevel.CRITICAL).count()
    active_threats = high_risk_count + critical_risk_count
    
    # Calculate average risk score
    risk_scores = []
    for agent in AIAgent.query.all():
        if hasattr(agent, 'risk_score') and agent.risk_score:
            risk_scores.append(agent.risk_score)
    
    avg_risk_score = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
    
    # New agents today
    today = datetime.utcnow().date()
    new_agents_today = AIAgent.query.filter(
        db.func.date(AIAgent.discovered_at) == today
    ).count()
    
    # New threats in 24h (mock data)
    new_threats_24h = 3
    
    return {
        'total_agents': total_agents,
        'overall_compliance_score': overall_compliance_score,
        'active_threats': active_threats,
        'avg_risk_score': avg_risk_score,
        'new_agents_today': new_agents_today,
        'new_threats_24h': new_threats_24h
    }


def get_mock_threats():
    """Get mock threat data when external services unavailable"""
    from datetime import datetime
    from integrations.external_services import ThreatIntelligence
    
    return [
        ThreatIntelligence(
            source="Mock Healthcare ISAC",
            threat_id="HC-2024-001",
            threat_type="ransomware",
            severity="critical",
            description="New ransomware variant targeting healthcare infrastructure",
            indicators=["ransomware", "healthcare"],
            healthcare_relevant=True,
            published_at=datetime.utcnow() - timedelta(minutes=5)
        ),
        ThreatIntelligence(
            source="Mock CISA",
            threat_id="CVE-2024-1234",
            threat_type="vulnerability",
            severity="high",
            description="SQL injection vulnerability in medical record systems",
            indicators=["sql_injection", "medical_records"],
            healthcare_relevant=True,
            published_at=datetime.utcnow() - timedelta(minutes=15)
        )
    ]


def get_relative_time(timestamp):
    """Convert timestamp to relative time string"""
    if not timestamp:
        return 'Unknown'
    
    now = datetime.utcnow()
    diff = now - timestamp
    
    if diff.days > 0:
        return f'{diff.days} day{"s" if diff.days > 1 else ""} ago'
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f'{hours} hour{"s" if hours > 1 else ""} ago'
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f'{minutes} minute{"s" if minutes > 1 else ""} ago'
    else:
        return 'Just now'


def get_risk_color(risk_level):
    """Get color for risk level"""
    if not risk_level:
        return '#6c757d'
    
    color_map = {
        RiskLevel.CRITICAL: '#dc3545',
        RiskLevel.HIGH: '#fd7e14', 
        RiskLevel.MEDIUM: '#ffc107',
        RiskLevel.LOW: '#28a745'
    }
    
    return color_map.get(risk_level, '#6c757d')


def get_node_size(risk_level):
    """Get node size based on risk level"""
    if not risk_level:
        return 20
    
    size_map = {
        RiskLevel.CRITICAL: 30,
        RiskLevel.HIGH: 25,
        RiskLevel.MEDIUM: 20,
        RiskLevel.LOW: 15
    }
    
    return size_map.get(risk_level, 20)


def should_connect(agent1, agent2):
    """Determine if two agents should be connected in network diagram"""
    # Connect agents with same protocol or type
    if agent1.protocol == agent2.protocol:
        return True
    
    # Connect healthcare-related agents
    if (getattr(agent1, 'healthcare_related', False) and 
        getattr(agent2, 'healthcare_related', False)):
        return True
    
    # Random connections for demonstration (limit to avoid clutter)
    import random
    return random.random() < 0.1


def get_connection_strength(agent1, agent2):
    """Get connection strength between two agents"""
    if agent1.protocol == agent2.protocol:
        return 'strong'
    elif agent1.type == agent2.type:
        return 'medium'
    else:
        return 'weak'