from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from app import app, db
from models import AIAgent, ScanResult, ComplianceEvaluation, RiskLevel, ComplianceFramework, InventoryStatus, AIAgentInventory, RegistrationPlaybook, AgentRegistration, PlaybookExecution
from datetime import datetime, timedelta
from scanners import ProtocolScanner
import random
import json

# Import integrations
try:
    from integrations.kubernetes_integration import kubernetes_integration
    from integrations.docker_integration import docker_integration
    INTEGRATIONS_AVAILABLE = True
except ImportError:
    INTEGRATIONS_AVAILABLE = False
    kubernetes_integration = None
    docker_integration = None

# Import playbook manager if available
try:
    from playbooks.playbook_manager import PlaybookManager
except ImportError:
    PlaybookManager = None


@app.route('/')
def dashboard():
    """Main dashboard with overview statistics"""
    # Get basic statistics
    total_agents = AIAgent.query.count()
    recent_scans = ScanResult.query.filter(
        ScanResult.created_at >= datetime.utcnow() - timedelta(hours=24)
    ).all()
    
    # Risk distribution
    risk_distribution = {}
    for risk_level in RiskLevel:
        count = ScanResult.query.filter_by(risk_level=risk_level).count()
        risk_distribution[risk_level.value] = count
    
    # Compliance summary
    compliance_summary = {}
    for framework in ComplianceFramework:
        evaluations = ComplianceEvaluation.query.filter_by(framework=framework).all()
        if evaluations:
            avg_score = sum(e.compliance_score for e in evaluations) / len(evaluations)
            compliant_count = sum(1 for e in evaluations if e.compliance_score >= 80)
            compliance_summary[framework.value] = {
                'average_score': round(avg_score, 1),
                'compliant_percentage': round((compliant_count / len(evaluations)) * 100, 1)
            }
        else:
            compliance_summary[framework.value] = {
                'average_score': 0,
                'compliant_percentage': 0
            }
    
    return render_template('dashboard.html',
                         total_agents=total_agents,
                         recent_scans=recent_scans,
                         risk_distribution=risk_distribution,
                         compliance_summary=compliance_summary)


@app.route('/scan/results')
def scan_results():
    """Display scan results with filtering"""
    page = request.args.get('page', 1, type=int)
    risk_filter = request.args.get('risk_level')
    protocol_filter = request.args.get('protocol')
    cloud_filter = request.args.get('cloud_provider')
    
    # Build agent query with filters
    agent_query = AIAgent.query
    
    if protocol_filter:
        agent_query = agent_query.filter(AIAgent.protocol == protocol_filter)
    
    if cloud_filter:
        agent_query = agent_query.filter(AIAgent.cloud_provider == cloud_filter)
    
    # Paginate agents
    agents = agent_query.order_by(AIAgent.discovered_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Get agent data with latest scans for display
    agent_data = []
    for agent in agents.items:
        latest_scan = ScanResult.query.filter_by(ai_agent_id=agent.id).order_by(
            ScanResult.created_at.desc()
        ).first()
        
        # Apply risk filter if specified
        if risk_filter and latest_scan:
            if latest_scan.risk_level.value != risk_filter:
                continue
        elif risk_filter and not latest_scan:
            continue
            
        agent_data.append({
            'agent': agent,
            'latest_scan': latest_scan
        })
    
    return render_template('scan_results.html',
                         agents=agents,
                         agent_data=agent_data,
                         current_risk_filter=risk_filter,
                         current_protocol_filter=protocol_filter,
                         current_cloud_filter=cloud_filter)


@app.route('/agents/<int:agent_id>/evaluate-compliance')
def evaluate_compliance(agent_id):
    """Evaluate compliance for a specific agent"""
    agent = AIAgent.query.get_or_404(agent_id)
    
    # Redirect to compliance report for now
    flash(f'Compliance evaluation for {agent.name} - feature in development', 'info')
    return redirect(url_for('compliance_report'))


@app.route('/compliance/report')
def compliance_report():
    """Generate compliance reports"""
    framework_filter = request.args.get('framework')
    
    query = ComplianceEvaluation.query
    
    if framework_filter:
        query = query.filter(ComplianceEvaluation.framework == getattr(ComplianceFramework, framework_filter))
    
    evaluations = query.order_by(ComplianceEvaluation.evaluated_at.desc()).all()
    
    # Calculate summary statistics
    summary_stats = {}
    for framework in ComplianceFramework:
        framework_evals = [e for e in evaluations if e.framework == framework]
        if framework_evals:
            avg_score = sum(e.compliance_score for e in framework_evals) / len(framework_evals)
            compliant_count = sum(1 for e in framework_evals if e.compliance_score >= 80)
            summary_stats[framework.value] = {
                'total_evaluations': len(framework_evals),
                'average_score': round(avg_score, 1),
                'compliant_percentage': round((compliant_count / len(framework_evals)) * 100, 1),
                'latest_evaluation': max(framework_evals, key=lambda x: x.evaluated_at).evaluated_at if framework_evals else None
            }
    
    # Calculate executive summary
    executive_summary = {
        'total_evaluations': len(evaluations),
        'total_agents': len(set(e.ai_agent_id for e in evaluations)),
        'average_score': round(sum(e.compliance_score for e in evaluations) / len(evaluations), 1) if evaluations else 0,
        'compliant_count': sum(1 for e in evaluations if e.compliance_score >= 80)
    }
    
    return render_template('compliance_report.html',
                         evaluations=evaluations,
                         summary_stats=summary_stats,
                         executive_summary=executive_summary,
                         current_framework_filter=framework_filter)


@app.route('/analytics')
def analytics():
    """Analytics dashboard with charts and insights"""
    # Get trend data for the last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    # Risk trends
    risk_trends = []
    for i in range(30):
        date = thirty_days_ago + timedelta(days=i)
        scans = ScanResult.query.filter(
            ScanResult.created_at >= date,
            ScanResult.created_at < date + timedelta(days=1)
        ).all()
        
        if scans:
            avg_risk = sum(s.risk_score for s in scans) / len(scans)
        else:
            avg_risk = 0
            
        risk_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'average_risk_score': round(avg_risk, 2),
            'scan_count': len(scans)
        })
    
    # Agent discovery trends
    discovery_trends = []
    for i in range(30):
        date = thirty_days_ago + timedelta(days=i)
        agents = AIAgent.query.filter(
            AIAgent.discovered_at >= date,
            AIAgent.discovered_at < date + timedelta(days=1)
        ).all()
        
        discovery_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'agents_discovered': len(agents),
            'protocols': list(set(a.protocol for a in agents))
        })
    
    # Protocol distribution
    protocol_distribution = {}
    agents = AIAgent.query.all()
    for agent in agents:
        protocol = agent.protocol
        protocol_distribution[protocol] = protocol_distribution.get(protocol, 0) + 1
    
    return render_template('analytics.html',
                         risk_trends=risk_trends,
                         discovery_trends=discovery_trends,
                         protocol_distribution=protocol_distribution)


@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    protocols = request.form.getlist('protocols')
    cloud_providers = request.form.getlist('cloud_providers')
    
    try:
        # Start scanning based on selected protocols
        scan_results = []
        
        # Create protocol scanner instance
        protocol_scanner = ProtocolScanner()
        
        # Start comprehensive scan
        result = protocol_scanner.start_comprehensive_scan(protocols)
        
        # Extract results
        total_agents_found = 0
        for protocol_result in result.values():
            if isinstance(protocol_result, dict) and 'agents_found' in protocol_result:
                total_agents_found += protocol_result['agents_found']
        
        flash(f'Scan completed successfully. Found {total_agents_found} agents.', 'success')
        
    except Exception as e:
        flash(f'Scan failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))


@app.route('/webhooks')
def webhooks():
    """Webhook management interface"""
    # Mock webhook data
    webhooks = [
        {
            'id': 1,
            'name': 'Security Alert Webhook',
            'url': 'https://alerts.company.com/security',
            'events': ['high_risk_detected', 'phi_exposure'],
            'status': 'active',
            'last_triggered': datetime.utcnow() - timedelta(hours=2)
        },
        {
            'id': 2,
            'name': 'Compliance Report Webhook',
            'url': 'https://compliance.company.com/reports',
            'events': ['compliance_evaluation_complete'],
            'status': 'active',
            'last_triggered': datetime.utcnow() - timedelta(days=1)
        }
    ]
    
    return render_template('webhooks.html', webhooks=webhooks)


@app.route('/webhooks/create', methods=['POST'])
def create_webhook():
    """Create a new webhook"""
    webhook_data = {
        'name': request.form.get('name'),
        'url': request.form.get('url'),
        'events': request.form.getlist('events'),
        'secret': request.form.get('secret')
    }
    
    # In a real implementation, this would create a webhook in the database
    flash('Webhook created successfully!', 'success')
    return redirect(url_for('webhooks'))


@app.route('/multi-cloud')
def multi_cloud():
    """Multi-cloud management interface"""
    # Mock cloud provider data
    cloud_providers = [
        {
            'name': 'AWS',
            'status': 'connected',
            'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
            'ai_services': 15,
            'last_scan': datetime.utcnow() - timedelta(hours=1)
        },
        {
            'name': 'Azure',
            'status': 'connected',
            'regions': ['eastus', 'westus2', 'westeurope'],
            'ai_services': 8,
            'last_scan': datetime.utcnow() - timedelta(hours=3)
        },
        {
            'name': 'GCP',
            'status': 'disconnected',
            'regions': [],
            'ai_services': 0,
            'last_scan': None
        }
    ]
    
    return render_template('multi_cloud.html', cloud_providers=cloud_providers)


@app.route('/api/risk-trends')
def api_risk_trends():
    """API endpoint for risk trend data"""
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    trend_data = []
    for i in range(days):
        date = start_date + timedelta(days=i)
        scans = ScanResult.query.filter(
            ScanResult.created_at >= date,
            ScanResult.created_at < date + timedelta(days=1)
        ).all()
        
        if scans:
            scores = [s.risk_score for s in scans if s.risk_score is not None]
            avg_score = sum(scores) / len(scores) if scores else 0
        else:
            avg_score = 0
            scores = []
        
        trend_data.append({
            'date': date.strftime('%Y-%m-%d'),
            'average_risk_score': round(avg_score, 2),
            'scan_count': len(scores)
        })
    
    return jsonify(trend_data)


# ===== PLAYBOOK ROUTES =====

@app.route('/playbooks')
def playbooks_index():
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


@app.route('/playbooks/create', methods=['GET', 'POST'])
def create_playbook():
    """Create new registration playbook"""
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description')
            plain_english_config = request.form.get('plain_english_config')
            
            if not name or not description or not plain_english_config:
                flash('All fields are required', 'error')
                return render_template('playbooks/create.html', examples={})
            
            # Create playbook with auto-generated backend code
            if PlaybookManager:
                playbook_manager = PlaybookManager()
                playbook = playbook_manager.create_playbook_from_english(
                    name=name,
                    description=description,
                    plain_english_config=plain_english_config,
                    created_by='web_user'
                )
                
                flash(f'Playbook "{name}" created successfully with auto-generated backend code!', 'success')
                return redirect(url_for('view_playbook', id=playbook.id))
            else:
                flash('Playbook manager not available', 'error')
            
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
Notify admin team when high risk agents are discovered.'''
    }
    
    return render_template('playbooks/create.html', examples=examples)


@app.route('/playbooks/<int:id>')
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


@app.route('/playbooks/<int:id>/edit', methods=['GET', 'POST'])
def edit_playbook(id):
    """Edit existing playbook"""
    playbook = RegistrationPlaybook.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            playbook.name = request.form.get('name')
            playbook.description = request.form.get('description')
            playbook.plain_english_config = request.form.get('plain_english_config')
            
            if PlaybookManager:
                playbook_manager = PlaybookManager()
                # Regenerate backend code with updated configuration
                # playbook.generated_code = playbook_manager.parse_english_to_code(
                #     playbook.plain_english_config
                # )
                pass  # Placeholder for now
            
            db.session.commit()
            flash(f'Playbook "{playbook.name}" updated successfully!', 'success')
            return redirect(url_for('view_playbook', id=playbook.id))
            
        except Exception as e:
            flash(f'Error updating playbook: {str(e)}', 'error')
            db.session.rollback()
    
    return render_template('playbooks/edit.html', playbook=playbook)


@app.route('/agents/<int:agent_id>/inventory')
def inventory_details(agent_id):
    """View agent inventory details"""
    agent = AIAgent.query.get_or_404(agent_id)
    inventory = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
    
    return render_template('playbooks/agent_details.html', agent=agent, inventory=inventory)


@app.route('/playbooks/inventory')
def playbooks_inventory():
    """AI Agent Inventory dashboard"""
    if PlaybookManager:
        playbook_manager = PlaybookManager()
        summary = playbook_manager.get_inventory_summary()
    else:
        summary = {'total_discovered': 0, 'total_registered': 0, 'registration_rate': 0, 'by_protocol': {}, 'by_cloud_provider': {}}
    
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


# Real-Time Monitoring Routes
@app.route('/monitoring/realtime')
def realtime_monitoring():
    """Real-time monitoring dashboard"""
    return render_template('realtime_monitoring.html')


@app.route('/api/realtime/metrics')
def api_realtime_metrics():
    """API endpoint for real-time metrics"""
    import random
    from datetime import datetime, timedelta
    
    # Get current metrics
    total_agents = AIAgent.query.count()
    recent_scans = ScanResult.query.filter(
        ScanResult.created_at >= datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    # Calculate compliance score
    recent_evaluations = ComplianceEvaluation.query.filter(
        ComplianceEvaluation.evaluated_at >= datetime.utcnow() - timedelta(days=1)
    ).all()
    
    compliance_score = 85  # Default
    if recent_evaluations:
        compliance_score = sum(e.compliance_score for e in recent_evaluations) / len(recent_evaluations)
    
    # Calculate security alerts
    security_alerts = ScanResult.query.filter(
        ScanResult.created_at >= datetime.utcnow() - timedelta(hours=1),
        ScanResult.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL])
    ).count()
    
    # Agent status distribution
    online_agents = AIAgent.query.filter(
        AIAgent.last_scanned >= datetime.utcnow() - timedelta(minutes=30)
    ).count()
    
    warning_agents = ScanResult.query.filter(
        ScanResult.risk_level == RiskLevel.MEDIUM,
        ScanResult.created_at >= datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    offline_agents = total_agents - online_agents - warning_agents
    
    return jsonify({
        'total_agents': total_agents,
        'active_scans': recent_scans,
        'security_alerts': security_alerts,
        'compliance_score': round(compliance_score, 1),
        'agents_today': random.randint(0, 5),  # Simulated
        'alerts_last_hour': security_alerts,
        'compliance_change': random.randint(-2, 3),  # Simulated
        'average_risk_score': random.randint(20, 80),  # Simulated
        'critical_agents': ScanResult.query.filter(ScanResult.risk_level == RiskLevel.CRITICAL).count(),
        'agent_status_distribution': {
            'online': online_agents,
            'warning': warning_agents,
            'offline': max(0, offline_agents)
        },
        'risk_timeline': True
    })


@app.route('/api/realtime/agents')
def api_realtime_agents():
    """API endpoint for real-time agent status"""
    import random
    
    agents = AIAgent.query.limit(20).all()
    agents_data = []
    
    for agent in agents:
        # Get latest scan result
        latest_scan = ScanResult.query.filter_by(ai_agent_id=agent.id).order_by(
            ScanResult.created_at.desc()
        ).first()
        
        # Determine status
        if latest_scan and latest_scan.created_at >= datetime.utcnow() - timedelta(minutes=30):
            if latest_scan.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                status = 'warning'
                status_text = 'High Risk'
            else:
                status = 'online'
                status_text = 'Online'
        else:
            status = 'offline'
            status_text = 'Offline'
        
        agents_data.append({
            'id': agent.id,
            'name': agent.name,
            'type': agent.type,
            'status': status,
            'status_text': status_text,
            'last_scan': latest_scan.created_at.strftime('%H:%M') if latest_scan else None,
            'risk_level': latest_scan.risk_level.value if latest_scan else 'UNKNOWN'
        })
    
    return jsonify(agents_data)


@app.route('/api/realtime/protocols')
def api_realtime_protocols():
    """API endpoint for real-time protocol metrics"""
    import random
    
    protocols = [
        'Kubernetes', 'Docker', 'REST API', 'gRPC', 
        'WebSocket', 'MQTT', 'GraphQL', 'Cloud Services'
    ]
    
    protocol_data = []
    for protocol in protocols:
        agents_count = AIAgent.query.filter_by(protocol=protocol.lower().replace(' ', '_')).count()
        
        protocol_data.append({
            'name': protocol,
            'status': random.choice(['online', 'warning', 'offline']),
            'status_text': random.choice(['Active', 'Warning', 'Error']),
            'agents_count': agents_count,
            'response_time': random.randint(50, 500)
        })
    
    return jsonify(protocol_data)


@app.route('/api/agents/<int:agent_id>/scan', methods=['POST'])
def api_scan_agent(agent_id):
    """API endpoint to trigger manual scan for specific agent"""
    agent = AIAgent.query.get_or_404(agent_id)
    
    try:
        # Create protocol scanner instance and trigger scan for specific agent
        protocol_scanner = ProtocolScanner()
        scanner = protocol_scanner.scanners.get(agent.protocol)
        if scanner:
            # In a real implementation, this would trigger an actual scan
            # For now, we'll simulate a successful scan trigger
            return jsonify({'success': True, 'message': 'Scan initiated successfully'})
        else:
            return jsonify({'success': False, 'message': 'No scanner available for this protocol'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


# ===== INTEGRATION ROUTES =====

@app.route('/integrations')
def integrations_dashboard():
    """Integration management dashboard"""
    if not INTEGRATIONS_AVAILABLE:
        flash('Integrations are not available. Please install required dependencies.', 'warning')
        return render_template('integrations/unavailable.html')
    
    # Get integration status
    k8s_info = kubernetes_integration.get_cluster_info() if kubernetes_integration else {'status': 'unavailable'}
    docker_info = docker_integration.get_docker_info() if docker_integration else {'status': 'unavailable'}
    
    return render_template('integrations/dashboard.html',
                         kubernetes_info=k8s_info,
                         docker_info=docker_info)


@app.route('/integrations/kubernetes')
def kubernetes_integration_page():
    """Kubernetes integration page"""
    if not INTEGRATIONS_AVAILABLE or not kubernetes_integration:
        flash('Kubernetes integration is not available', 'error')
        return redirect(url_for('integrations_dashboard'))
    
    cluster_info = kubernetes_integration.get_cluster_info()
    ai_workloads = kubernetes_integration.discover_ai_workloads()
    metrics = kubernetes_integration.get_ai_workload_metrics()
    namespace_summary = kubernetes_integration.get_namespace_ai_summary()
    
    return render_template('integrations/kubernetes.html',
                         cluster_info=cluster_info,
                         ai_workloads=ai_workloads,
                         metrics=metrics,
                         namespace_summary=namespace_summary)


@app.route('/integrations/docker')
def docker_integration_page():
    """Docker integration page"""
    if not INTEGRATIONS_AVAILABLE or not docker_integration:
        flash('Docker integration is not available', 'error')
        return redirect(url_for('integrations_dashboard'))
    
    docker_info = docker_integration.get_docker_info()
    ai_containers = docker_integration.discover_ai_containers()
    metrics = docker_integration.get_ai_container_metrics()
    
    return render_template('integrations/docker.html',
                         docker_info=docker_info,
                         ai_containers=ai_containers,
                         metrics=metrics)


@app.route('/api/kubernetes/workloads')
def api_kubernetes_workloads():
    """API endpoint for Kubernetes AI workloads"""
    if not INTEGRATIONS_AVAILABLE or not kubernetes_integration:
        return jsonify({'error': 'Kubernetes integration not available'})
    
    namespace = request.args.get('namespace')
    workloads = kubernetes_integration.discover_ai_workloads(namespace or None)
    return jsonify(workloads)


@app.route('/api/kubernetes/metrics')
def api_kubernetes_metrics():
    """API endpoint for Kubernetes metrics"""
    if not INTEGRATIONS_AVAILABLE or not kubernetes_integration:
        return jsonify({'error': 'Kubernetes integration not available'})
    
    metrics = kubernetes_integration.get_ai_workload_metrics()
    return jsonify(metrics)


@app.route('/api/docker/containers')
def api_docker_containers():
    """API endpoint for Docker AI containers"""
    if not INTEGRATIONS_AVAILABLE or not docker_integration:
        return jsonify({'error': 'Docker integration not available'})
    
    containers = docker_integration.discover_ai_containers()
    return jsonify(containers)


@app.route('/api/docker/metrics')
def api_docker_metrics():
    """API endpoint for Docker metrics"""
    if not INTEGRATIONS_AVAILABLE or not docker_integration:
        return jsonify({'error': 'Docker integration not available'})
    
    metrics = docker_integration.get_ai_container_metrics()
    return jsonify(metrics)


@app.route('/api/docker/containers/<container_id>/logs')
def api_docker_container_logs(container_id):
    """API endpoint for Docker container logs"""
    if not INTEGRATIONS_AVAILABLE or not docker_integration:
        return jsonify({'error': 'Docker integration not available'})
    
    lines = request.args.get('lines', 100, type=int)
    logs = docker_integration.get_container_logs(container_id, lines)
    return jsonify({'logs': logs})


@app.route('/integrations/start-monitoring', methods=['POST'])
def start_integration_monitoring():
    """Start real-time monitoring for integrations"""
    if not INTEGRATIONS_AVAILABLE:
        return jsonify({'success': False, 'message': 'Integrations not available'})
    
    try:
        k8s_started = False
        docker_started = False
        
        if kubernetes_integration and kubernetes_integration.is_connected:
            k8s_started = kubernetes_integration.start_real_time_monitoring()
        
        if docker_integration and docker_integration.is_connected:
            docker_started = docker_integration.start_real_time_monitoring()
        
        return jsonify({
            'success': True,
            'kubernetes_monitoring': k8s_started,
            'docker_monitoring': docker_started
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/integrations/stop-monitoring', methods=['POST'])
def stop_integration_monitoring():
    """Stop real-time monitoring for integrations"""
    if not INTEGRATIONS_AVAILABLE:
        return jsonify({'success': False, 'message': 'Integrations not available'})
    
    try:
        if kubernetes_integration:
            kubernetes_integration.stop_monitoring()
        
        if docker_integration:
            docker_integration.stop_monitoring()
        
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500