from flask import render_template, request, jsonify, redirect, url_for, flash
from app import app, db
from models import *
from scanners import protocol_scanner
from compliance.evaluator import ComplianceEvaluator
from analytics.risk_scoring import RiskScorer
from analytics.predictive import PredictiveAnalytics
from webhooks.continuous_scanner import ContinuousScanner
from cloud.multi_cloud import MultiCloudManager
import json
from datetime import datetime, timedelta

@app.route('/')
def dashboard():
    """Main dashboard with overview of AI agents and compliance status"""
    total_agents = AIAgent.query.count()
    recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    
    # Compliance summary
    compliance_summary = {}
    for framework in ComplianceFramework:
        evaluations = ComplianceEvaluation.query.filter_by(framework=framework).all()
        if evaluations:
            avg_score = sum(e.compliance_score for e in evaluations) / len(evaluations)
            compliant_count = sum(1 for e in evaluations if e.is_compliant)
            compliance_summary[framework.value] = {
                'average_score': round(avg_score, 2),
                'compliant_percentage': round((compliant_count / len(evaluations)) * 100, 2)
            }
        else:
            compliance_summary[framework.value] = {'average_score': 0, 'compliant_percentage': 0}
    
    # Risk distribution
    risk_distribution = {}
    for risk_level in RiskLevel:
        count = ScanResult.query.filter_by(risk_level=risk_level).count()
        risk_distribution[risk_level.value] = count
    
    return render_template('dashboard.html', 
                         total_agents=total_agents,
                         recent_scans=recent_scans,
                         compliance_summary=compliance_summary,
                         risk_distribution=risk_distribution)

@app.route('/scan/start', methods=['POST'])
def start_scan():
    """Start a new comprehensive scan"""
    scanner = protocol_scanner
    
    # Get scan parameters
    protocols = request.form.getlist('protocols')
    cloud_providers = request.form.getlist('cloud_providers')
    
    if not protocols:
        protocols = ['kubernetes', 'docker', 'rest_api', 'grpc', 'websocket', 'mqtt', 'graphql']
    
    try:
        # Start scan
        scan_id = scanner.start_comprehensive_scan(protocols, cloud_providers)
        flash(f'Scan started successfully with ID: {scan_id}', 'success')
    except Exception as e:
        flash(f'Failed to start scan: {str(e)}', 'error')
    
    return redirect(url_for('scan_results'))

@app.route('/scan/results')
def scan_results():
    """Display scan results and discovered AI agents"""
    page = request.args.get('page', 1, type=int)
    agents = AIAgent.query.paginate(page=page, per_page=20, error_out=False)
    
    # Get latest scan results for each agent
    agent_data = []
    for agent in agents.items:
        latest_scan = ScanResult.query.filter_by(ai_agent_id=agent.id)\
                                    .order_by(ScanResult.created_at.desc()).first()
        latest_compliance = ComplianceEvaluation.query.filter_by(ai_agent_id=agent.id)\
                                                     .order_by(ComplianceEvaluation.evaluated_at.desc()).first()
        
        agent_data.append({
            'agent': agent,
            'latest_scan': latest_scan,
            'latest_compliance': latest_compliance
        })
    
    return render_template('scan_results.html', 
                         agents=agents,
                         agent_data=agent_data)

@app.route('/compliance/evaluate/<int:agent_id>')
def evaluate_compliance(agent_id):
    """Evaluate compliance for a specific AI agent"""
    agent = AIAgent.query.get_or_404(agent_id)
    evaluator = ComplianceEvaluator()
    
    try:
        # Evaluate against all frameworks
        results = {}
        for framework in ComplianceFramework:
            evaluation = evaluator.evaluate_agent(agent, framework)
            results[framework.value] = evaluation
        
        flash('Compliance evaluation completed successfully', 'success')
    except Exception as e:
        flash(f'Compliance evaluation failed: {str(e)}', 'error')
        results = {}
    
    return render_template('compliance_report.html', agent=agent, results=results)

@app.route('/compliance/report')
def compliance_report():
    """Generate comprehensive compliance report"""
    framework = request.args.get('framework', 'all')
    
    if framework == 'all':
        evaluations = ComplianceEvaluation.query.all()
    else:
        try:
            framework_enum = ComplianceFramework(framework.upper())
            evaluations = ComplianceEvaluation.query.filter_by(framework=framework_enum).all()
        except ValueError:
            flash('Invalid compliance framework specified', 'error')
            return redirect(url_for('dashboard'))
    
    # Generate executive summary
    if evaluations:
        avg_score = sum(e.compliance_score for e in evaluations) / len(evaluations)
        compliant_count = sum(1 for e in evaluations if e.is_compliant)
        compliance_rate = (compliant_count / len(evaluations)) * 100
        
        # High-risk findings
        high_risk_findings = []
        for eval in evaluations:
            if eval.compliance_score < 60:  # Below 60% compliance
                high_risk_findings.append(eval)
    else:
        avg_score = 0
        compliance_rate = 0
        high_risk_findings = []
    
    executive_summary = {
        'total_evaluations': len(evaluations),
        'average_score': round(avg_score, 2),
        'compliance_rate': round(compliance_rate, 2),
        'high_risk_count': len(high_risk_findings)
    }
    
    return render_template('compliance_report.html', 
                         evaluations=evaluations,
                         executive_summary=executive_summary,
                         high_risk_findings=high_risk_findings,
                         selected_framework=framework)

@app.route('/analytics')
def analytics():
    """Advanced analytics dashboard with predictive insights"""
    # Risk scoring trends
    risk_scorer = RiskScorer()
    trend_data = risk_scorer.get_risk_trends(days=30)
    
    # Predictive analytics
    predictor = PredictiveAnalytics()
    predictions = predictor.generate_security_predictions()
    
    # Protocol distribution
    protocol_stats = db.session.query(AIAgent.protocol, db.func.count(AIAgent.id))\
                              .group_by(AIAgent.protocol).all()
    
    # Cloud provider distribution
    cloud_stats = db.session.query(AIAgent.cloud_provider, db.func.count(AIAgent.id))\
                           .group_by(AIAgent.cloud_provider).all()
    
    return render_template('analytics.html',
                         trend_data=trend_data,
                         predictions=predictions,
                         protocol_stats=protocol_stats,
                         cloud_stats=cloud_stats)

@app.route('/webhooks')
def webhooks():
    """Webhook management for continuous scanning"""
    webhooks = WebhookConfig.query.all()
    return render_template('webhooks.html', webhooks=webhooks)

@app.route('/webhooks/add', methods=['POST'])
def add_webhook():
    """Add new webhook configuration"""
    webhook = WebhookConfig(
        name=request.form['name'],
        url=request.form['url'],
        scan_frequency=int(request.form.get('frequency', 3600)),
        protocols=request.form.getlist('protocols')
    )
    
    db.session.add(webhook)
    db.session.commit()
    
    flash('Webhook added successfully', 'success')
    return redirect(url_for('webhooks'))

@app.route('/webhooks/trigger/<int:webhook_id>')
def trigger_webhook(webhook_id):
    """Manually trigger a webhook scan"""
    webhook = WebhookConfig.query.get_or_404(webhook_id)
    scanner = ContinuousScanner()
    
    try:
        scanner.trigger_scan(webhook)
        webhook.last_triggered = datetime.utcnow()
        db.session.commit()
        flash('Webhook triggered successfully', 'success')
    except Exception as e:
        flash(f'Failed to trigger webhook: {str(e)}', 'error')
    
    return redirect(url_for('webhooks'))

@app.route('/multi-cloud')
def multi_cloud():
    """Multi-cloud deployment management"""
    deployments = CloudDeployment.query.all()
    manager = MultiCloudManager()
    
    # Get health status for each deployment
    deployment_status = []
    for deployment in deployments:
        status = manager.check_health(deployment)
        deployment_status.append({
            'deployment': deployment,
            'status': status
        })
    
    return render_template('multi_cloud.html', deployment_status=deployment_status)

@app.route('/api/data-flow')
def api_data_flow():
    """API endpoint for data flow mapping visualization"""
    flows = DataFlowMap.query.all()
    
    # Format data for D3.js visualization
    nodes = []
    links = []
    node_ids = set()
    
    for flow in flows:
        source_agent = AIAgent.query.get(flow.source_agent_id)
        dest_agent = AIAgent.query.get(flow.destination_agent_id)
        
        if source_agent and dest_agent:
            if source_agent.id not in node_ids:
                nodes.append({
                    'id': source_agent.id,
                    'name': source_agent.name,
                    'type': source_agent.type,
                    'protocol': source_agent.protocol,
                    'risk_level': 'medium'  # This would come from latest scan
                })
                node_ids.add(source_agent.id)
            
            if dest_agent.id not in node_ids:
                nodes.append({
                    'id': dest_agent.id,
                    'name': dest_agent.name,
                    'type': dest_agent.type,
                    'protocol': dest_agent.protocol,
                    'risk_level': 'low'
                })
                node_ids.add(dest_agent.id)
            
            links.append({
                'source': flow.source_agent_id,
                'target': flow.destination_agent_id,
                'data_type': flow.data_type,
                'volume': flow.flow_volume,
                'encryption': flow.encryption_status,
                'compliance': flow.compliance_status
            })
    
    return jsonify({'nodes': nodes, 'links': links})

@app.route('/api/risk-trends')
def api_risk_trends():
    """API endpoint for risk trending data"""
    days = request.args.get('days', 30, type=int)
    
    # Get risk scores over time
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    scans = ScanResult.query.filter(
        ScanResult.created_at >= start_date,
        ScanResult.created_at <= end_date
    ).order_by(ScanResult.created_at).all()
    
    # Group by date
    daily_scores = {}
    for scan in scans:
        date_key = scan.created_at.strftime('%Y-%m-%d')
        if date_key not in daily_scores:
            daily_scores[date_key] = []
        daily_scores[date_key].append(scan.risk_score)
    
    # Calculate daily averages
    trend_data = []
    for date_key, scores in daily_scores.items():
        avg_score = sum(scores) / len(scores)
        trend_data.append({
            'date': date_key,
            'average_risk_score': round(avg_score, 2),
            'scan_count': len(scores)
        })
    
    return jsonify(trend_data)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
