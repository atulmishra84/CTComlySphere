from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from app import app, db
from models import AIAgent, ScanResult, ComplianceEvaluation, RiskLevel, ComplianceFramework, InventoryStatus, AIAgentInventory, RegistrationPlaybook, AgentRegistration, PlaybookExecution, RemediationWorkflow, RemediationExecution, RemediationActionExecution
from datetime import datetime, timedelta
# ProtocolScanner imported later to avoid import-time failures
import random
import json

# Import agent classification and controls managers
try:
    from agents.classification_engine import AgentClassificationEngine
    from agents.controls_manager import AgentControlsManager
    from agents.registration_workflow import EnhancedRegistrationWorkflow
    AGENT_MANAGEMENT_AVAILABLE = True
    classification_engine = AgentClassificationEngine()
    controls_manager = AgentControlsManager()
    registration_workflow = EnhancedRegistrationWorkflow()
except ImportError as e:
    AGENT_MANAGEMENT_AVAILABLE = False
    classification_engine = None
    controls_manager = None
    registration_workflow = None
    print(f"Warning: Agent management features not available: {e}")

# Import integrations
try:
    from integrations.kubernetes_integration import kubernetes_integration
    from integrations.docker_integration import docker_integration
    from integrations.mcp_integration import mcp_integration
    INTEGRATIONS_AVAILABLE = True
except ImportError:
    INTEGRATIONS_AVAILABLE = False
    kubernetes_integration = None
    docker_integration = None
    mcp_integration = None

# Import playbook manager if available
try:
    from playbooks.playbook_manager import PlaybookManager
except ImportError:
    PlaybookManager = None

# Import model registry routes
try:
    from routes_pkg.model_registry_routes import model_registry_bp
    app.register_blueprint(model_registry_bp)
    MODEL_REGISTRY_AVAILABLE = True
except ImportError as e:
    MODEL_REGISTRY_AVAILABLE = False
    print(f"Warning: Model registry features not available: {e}")

# Import audit and onboarding routes
try:
    from routes_pkg.audit_routes import audit_bp
    from routes_pkg.onboarding_routes import onboarding_bp
    app.register_blueprint(audit_bp)
    app.register_blueprint(onboarding_bp)
    AUDIT_ONBOARDING_AVAILABLE = True
except ImportError as e:
    AUDIT_ONBOARDING_AVAILABLE = False
    print(f"Warning: Audit and onboarding features not available: {e}")

# Import agent routes
try:
    from routes_pkg.agent_routes import agent_bp
    app.register_blueprint(agent_bp)
    AGENT_AVAILABLE = True
except ImportError as e:
    AGENT_AVAILABLE = False
    print(f"Warning: Healthcare Compliance Agent features not available: {e}")

# Import remediation routes
try:
    from routes_pkg.remediation_routes import remediation_bp
    app.register_blueprint(remediation_bp)
    REMEDIATION_ROUTES_AVAILABLE = True
except ImportError as e:
    REMEDIATION_ROUTES_AVAILABLE = False
    print(f"Warning: Remediation workflow features not available: {e}")


@app.route('/')
def dashboard():
    """Main dashboard with overview statistics including GenAI and Agentic AI insights"""
    # Get basic statistics
    total_agents = AIAgent.query.count()
    recent_scans = ScanResult.query.filter(
        ScanResult.created_at >= datetime.utcnow() - timedelta(hours=24)
    ).all()
    
    # AI Type distribution with GenAI and Agentic AI metrics
    from models import AIAgentType
    ai_type_distribution = {}
    genai_count = AIAgent.query.filter_by(ai_type=AIAgentType.GENAI).count()
    agentic_count = AIAgent.query.filter_by(ai_type=AIAgentType.AGENTIC_AI).count()
    multimodal_count = AIAgent.query.filter_by(ai_type=AIAgentType.MULTIMODAL_AI).count()
    traditional_count = AIAgent.query.filter_by(ai_type=AIAgentType.TRADITIONAL_ML).count()
    
    ai_type_distribution = {
        'GenAI': genai_count,
        'Agentic AI': agentic_count,
        'Multimodal AI': multimodal_count,
        'Traditional ML': traditional_count,
        'Computer Vision': AIAgent.query.filter_by(ai_type=AIAgentType.COMPUTER_VISION).count(),
        'NLP': AIAgent.query.filter_by(ai_type=AIAgentType.NLP).count(),
        'Conversational AI': AIAgent.query.filter_by(ai_type=AIAgentType.CONVERSATIONAL_AI).count()
    }
    
    # GenAI specific metrics
    genai_agents = AIAgent.query.filter_by(ai_type=AIAgentType.GENAI).all()
    genai_metrics = {
        'total_genai': genai_count,
        'fine_tuned_count': sum(1 for agent in genai_agents if agent.fine_tuned),
        'multimodal_genai': sum(1 for agent in genai_agents if agent.multimodal),
        'model_families': list(set(agent.model_family for agent in genai_agents if agent.model_family)),
        'capabilities_summary': {}
    }
    
    # Agentic AI specific metrics
    agentic_agents = AIAgent.query.filter_by(ai_type=AIAgentType.AGENTIC_AI).all()
    agentic_metrics = {
        'total_agentic': agentic_count,
        'autonomous_count': sum(1 for agent in agentic_agents if agent.autonomy_level in ['high', 'full']),
        'planning_enabled': sum(1 for agent in agentic_agents if agent.planning_capability),
        'memory_enabled': sum(1 for agent in agentic_agents if agent.memory_enabled),
        'frameworks': list(set(agent.agent_framework for agent in agentic_agents if agent.agent_framework))
    }
    
    # Risk distribution
    risk_distribution = {}
    for risk_level in RiskLevel:
        count = ScanResult.query.filter_by(risk_level=risk_level).count()
        risk_distribution[risk_level.value] = count
    
    # GenAI/Agentic AI specific risk analysis
    genai_risk_analysis = {
        'high_risk_genai': 0,
        'critical_risk_agentic': 0,
        'total_specialized_risks': 0
    }
    
    for agent in genai_agents:
        latest_scan = ScanResult.query.filter_by(ai_agent_id=agent.id).order_by(ScanResult.created_at.desc()).first()
        if latest_scan and latest_scan.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            genai_risk_analysis['high_risk_genai'] += 1
    
    for agent in agentic_agents:
        latest_scan = ScanResult.query.filter_by(ai_agent_id=agent.id).order_by(ScanResult.created_at.desc()).first()
        if latest_scan and latest_scan.risk_level == RiskLevel.CRITICAL:
            genai_risk_analysis['critical_risk_agentic'] += 1
    
    # Compliance summary with GenAI/Agentic frameworks
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
    
    # Recent specialized AI discoveries
    recent_genai = AIAgent.query.filter_by(ai_type=AIAgentType.GENAI).filter(
        AIAgent.discovered_at >= datetime.utcnow() - timedelta(days=7)
    ).count()
    
    recent_agentic = AIAgent.query.filter_by(ai_type=AIAgentType.AGENTIC_AI).filter(
        AIAgent.discovered_at >= datetime.utcnow() - timedelta(days=7)
    ).count()
    
    return render_template('dashboard.html',
                         total_agents=total_agents,
                         recent_scans=recent_scans,
                         risk_distribution=risk_distribution,
                         compliance_summary=compliance_summary,
                         ai_type_distribution=ai_type_distribution,
                         genai_metrics=genai_metrics,
                         agentic_metrics=agentic_metrics,
                         genai_risk_analysis=genai_risk_analysis,
                         recent_genai=recent_genai,
                         recent_agentic=recent_agentic)


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
        
        # Import and create protocol scanner instance safely
        try:
            from scanners import ProtocolScanner
            protocol_scanner = ProtocolScanner()
        except ImportError as e:
            flash(f'Scan unavailable: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
        
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


# Continuous Scanning Routes
@app.route('/continuous_scanning')
def continuous_scanning():
    """Continuous scanning management dashboard"""
    try:
        from services.continuous_scanner import continuous_scanner
        status = continuous_scanner.get_status()
        scan_history = continuous_scanner.get_scan_history()
        
        return render_template('continuous_scanning.html',
                             status=status,
                             scan_history=scan_history)
    except ImportError:
        flash('Continuous scanning service not available', 'error')
        return redirect(url_for('dashboard'))


@app.route('/api/continuous_scanning/start', methods=['POST'])
def api_start_continuous_scanning():
    """Start continuous scanning with configuration"""
    try:
        from services.continuous_scanner import continuous_scanner, ScanConfiguration, ScanMode
        
        data = request.get_json() or {}
        
        # Create configuration from request data
        config = ScanConfiguration(
            enabled=True,
            scan_interval_minutes=data.get('interval_minutes', 30),
            scan_mode=ScanMode(data.get('scan_mode', 'discovery')),
            target_protocols=data.get('target_protocols', ['kubernetes', 'docker', 'rest_api']),
            target_environments=data.get('target_environments', ['development']),
            auto_register=data.get('auto_register', True),
            notification_enabled=data.get('notifications', True)
        )
        
        success = continuous_scanner.start_scanning(config)
        
        return jsonify({
            'success': success,
            'message': 'Continuous scanning started' if success else 'Failed to start scanning',
            'status': continuous_scanner.get_status()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/continuous_scanning/stop', methods=['POST'])
def api_stop_continuous_scanning():
    """Stop continuous scanning"""
    try:
        from services.continuous_scanner import continuous_scanner
        
        success = continuous_scanner.stop_scanning()
        
        return jsonify({
            'success': success,
            'message': 'Continuous scanning stopped' if success else 'Failed to stop scanning',
            'status': continuous_scanner.get_status()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/continuous_scanning/trigger', methods=['POST'])
def api_trigger_immediate_scan():
    """Trigger an immediate scan"""
    try:
        from services.continuous_scanner import continuous_scanner
        
        scan_id = continuous_scanner.trigger_immediate_scan()
        
        return jsonify({
            'success': True,
            'message': f'Immediate scan triggered: {scan_id}',
            'scan_id': scan_id
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/continuous_scanning/status')
def api_continuous_scanning_status():
    """Get continuous scanning status"""
    try:
        from services.continuous_scanner import continuous_scanner
        
        status = continuous_scanner.get_status()
        scan_history = continuous_scanner.get_scan_history()
        
        return jsonify({
            'success': True,
            'status': status,
            'scan_history': scan_history
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/continuous_scanning/configure', methods=['POST'])
def api_configure_continuous_scanning():
    """Update continuous scanning configuration"""
    try:
        from services.continuous_scanner import continuous_scanner, ScanConfiguration, ScanMode
        
        data = request.get_json() or {}
        
        # Create new configuration
        config = ScanConfiguration(
            enabled=data.get('enabled', False),
            scan_interval_minutes=data.get('interval_minutes', 30),
            scan_mode=ScanMode(data.get('scan_mode', 'discovery')),
            target_protocols=data.get('target_protocols', []),
            target_environments=data.get('target_environments', []),
            auto_register=data.get('auto_register', True),
            notification_enabled=data.get('notifications', True)
        )
        
        continuous_scanner.update_configuration(config)
        
        return jsonify({
            'success': True,
            'message': 'Configuration updated',
            'status': continuous_scanner.get_status()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
def api_realtime_protocols():
    """API endpoint for real-time protocol metrics"""
    import random
    
    protocols = [
        'Kubernetes', 'Docker', 'REST API', 'gRPC', 
        'WebSocket', 'MQTT', 'GraphQL', 'Cloud Services',
        'MCP Protocol', 'A2A Communication', 'FHIR',
        'HL7', 'DICOM', 'WebRTC', 'AMQP'
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
    mcp_info = mcp_integration.get_mcp_ecosystem_info() if mcp_integration else {'status': 'unavailable'}
    
    return render_template('integrations/dashboard.html',
                         kubernetes_info=k8s_info,
                         docker_info=docker_info,
                         mcp_info=mcp_info)


@app.route('/integrations/kubernetes')
def kubernetes_integration_page():
    """Kubernetes integration page"""
    if not INTEGRATIONS_AVAILABLE or not kubernetes_integration:
        flash('Kubernetes integration is not available', 'error')
        return redirect(url_for('integrations_dashboard'))
    
    cluster_info = kubernetes_integration.get_cluster_info()
    ai_workloads = kubernetes_integration.discover_ai_workloads()
    metrics = {}  # Real-time metrics removed
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
    metrics = {}  # Real-time metrics removed
    
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
    
    return jsonify({'error': 'Real-time metrics feature removed'})


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
    
    return jsonify({'error': 'Real-time metrics feature removed'})


@app.route('/api/docker/containers/<container_id>/logs')
def api_docker_container_logs(container_id):
    """API endpoint for Docker container logs"""
    if not INTEGRATIONS_AVAILABLE or not docker_integration:
        return jsonify({'error': 'Docker integration not available'})
    
    lines = request.args.get('lines', 100, type=int)
    logs = docker_integration.get_container_logs(container_id, lines)
    return jsonify({'logs': logs})


@app.route('/integrations/mcp')
def mcp_integration_page():
    """MCP integration page"""
    if not INTEGRATIONS_AVAILABLE or not mcp_integration:
        flash('MCP integration is not available', 'error')
        return redirect(url_for('integrations_dashboard'))
    
    ecosystem_info = mcp_integration.get_mcp_ecosystem_info()
    mcp_agents = mcp_integration.discover_mcp_agents()
    context_flows = mcp_integration.get_context_flow_metrics()
    server_details = mcp_integration.get_server_details()
    performance_metrics = mcp_integration.get_performance_metrics()
    
    return render_template('integrations/mcp.html',
                         ecosystem_info=ecosystem_info,
                         mcp_agents=mcp_agents,
                         context_flows=context_flows,
                         server_details=server_details,
                         performance_metrics=performance_metrics)


@app.route('/api/mcp/agents')
def api_mcp_agents():
    """API endpoint for MCP agents"""
    if not INTEGRATIONS_AVAILABLE or not mcp_integration:
        return jsonify({'error': 'MCP integration not available'})
    
    agents = mcp_integration.discover_mcp_agents()
    return jsonify(agents)


@app.route('/api/mcp/ecosystem')
def api_mcp_ecosystem():
    """API endpoint for MCP ecosystem status"""
    if not INTEGRATIONS_AVAILABLE or not mcp_integration:
        return jsonify({'error': 'MCP integration not available'})
    
    ecosystem_info = mcp_integration.get_mcp_ecosystem_info()
    return jsonify(ecosystem_info)


@app.route('/api/mcp/context-flows')
def api_mcp_context_flows():
    """API endpoint for MCP context flows"""
    if not INTEGRATIONS_AVAILABLE or not mcp_integration:
        return jsonify({'error': 'MCP integration not available'})
    
    context_flows = mcp_integration.get_context_flow_metrics()
    return jsonify(context_flows)


@app.route('/api/mcp/servers')
def api_mcp_servers():
    """API endpoint for MCP server details"""
    if not INTEGRATIONS_AVAILABLE or not mcp_integration:
        return jsonify({'error': 'MCP integration not available'})
    
    servers = mcp_integration.get_server_details()
    return jsonify(servers)


@app.route('/integrations/configuration')
def integration_configuration_page():
    """Integration configuration page"""
    try:
        from integrations.config_manager import config_manager
        config = config_manager.get_configuration()
        return render_template('integrations/configuration.html', config=config)
    except ImportError:
        flash('Configuration management is not available', 'error')
        return redirect(url_for('integrations_dashboard'))


@app.route('/integrations/configuration/save', methods=['POST'])
def save_integration_config():
    """Save integration configuration"""
    try:
        from integrations.config_manager import config_manager, IntegrationConfiguration, KubernetesConfig, DockerConfig, MCPConfig, GeneralConfig
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No configuration data provided'})
        
        # Create configuration objects
        config = IntegrationConfiguration(
            kubernetes=KubernetesConfig(**data.get('kubernetes', {})),
            docker=DockerConfig(**data.get('docker', {})),
            mcp=MCPConfig(**data.get('mcp', {})),
            general=GeneralConfig(**data.get('general', {}))
        )
        
        # Validate configuration
        errors = config_manager.validate_configuration(config)
        if errors:
            return jsonify({'success': False, 'message': 'Configuration validation failed', 'errors': errors})
        
        # Save configuration
        success = config_manager.save_configuration(config)
        if success:
            flash('Configuration saved successfully', 'success')
            return jsonify({'success': True, 'message': 'Configuration saved successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to save configuration'})
            
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/integrations/export-config')
def api_export_integration_config():
    """Export integration configuration"""
    try:
        from integrations.config_manager import config_manager
        config_dict = config_manager.export_configuration()
        return jsonify(config_dict)
    except Exception as e:
        logger.error(f"Failed to export configuration: {e}")
        return jsonify({'error': str(e)})


@app.route('/api/integrations/import-config', methods=['POST'])
def api_import_integration_config():
    """Import integration configuration"""
    try:
        from integrations.config_manager import config_manager
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No configuration data provided'})
        
        success = config_manager.import_configuration(data)
        if success:
            return jsonify({'success': True, 'message': 'Configuration imported successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to import configuration'})
            
    except Exception as e:
        logger.error(f"Failed to import configuration: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/integrations/reset-config', methods=['POST'])
def api_reset_integration_config():
    """Reset integration configuration to defaults"""
    try:
        from integrations.config_manager import config_manager
        
        integration_type = request.get_json().get('integration_type') if request.get_json() else None
        success = config_manager.reset_to_defaults(integration_type)
        
        if success:
            return jsonify({'success': True, 'message': 'Configuration reset to defaults'})
        else:
            return jsonify({'success': False, 'message': 'Failed to reset configuration'})
            
    except Exception as e:
        logger.error(f"Failed to reset configuration: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/integrations/validate-config', methods=['POST'])
def api_validate_integration_config():
    """Validate integration configuration"""
    try:
        from integrations.config_manager import config_manager, IntegrationConfiguration, KubernetesConfig, DockerConfig, MCPConfig, GeneralConfig
        
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'errors': {'general': ['No configuration data provided']}})
        
        # Create configuration objects
        config = IntegrationConfiguration(
            kubernetes=KubernetesConfig(**data.get('kubernetes', {})),
            docker=DockerConfig(**data.get('docker', {})),
            mcp=MCPConfig(**data.get('mcp', {})),
            general=GeneralConfig(**data.get('general', {}))
        )
        
        # Validate configuration
        errors = config_manager.validate_configuration(config)
        return jsonify({'valid': not bool(errors), 'errors': errors})
        
    except Exception as e:
        logger.error(f"Failed to validate configuration: {e}")
        return jsonify({'valid': False, 'errors': {'general': [str(e)]}})


@app.route('/integrations/start-monitoring', methods=['POST'])
def start_integration_monitoring():
    """Start real-time monitoring for integrations"""
    if not INTEGRATIONS_AVAILABLE:
        return jsonify({'success': False, 'message': 'Integrations not available'})
    
    try:
        k8s_started = False
        docker_started = False
        
        # Real-time monitoring feature removed
        k8s_started = False
        docker_started = False
        
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


@app.route('/agents/classification')
def agent_classification_dashboard():
    """Agent classification dashboard"""
    if not AGENT_MANAGEMENT_AVAILABLE:
        flash('Agent management features are not available', 'error')
        return redirect(url_for('dashboard'))
    
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
        flash(f"Error loading classification dashboard: {str(e)}", 'error')
        return render_template('agents/classification_dashboard.html', agents=[], stats={})


@app.route('/agents/<int:agent_id>/classify', methods=['POST'])
def classify_agent(agent_id):
    """Classify a specific agent"""
    if not AGENT_MANAGEMENT_AVAILABLE:
        return jsonify({'success': False, 'error': 'Agent management not available'}), 500
    
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
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/agents/<int:agent_id>/register', methods=['POST'])
def register_agent_with_classification(agent_id):
    """Register agent with full classification and controls workflow"""
    if not AGENT_MANAGEMENT_AVAILABLE:
        return jsonify({'success': False, 'error': 'Agent management not available'}), 500
    
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
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/agents/auto-register', methods=['POST'])
def auto_register_discovered_agents():
    """Automatically register all discovered but unregistered agents"""
    if not AGENT_MANAGEMENT_AVAILABLE:
        return jsonify({'success': False, 'error': 'Agent management not available'}), 500
    
    try:
        # Find agents that don't have inventory records or are not registered
        unregistered_agents = db.session.query(AIAgent).outerjoin(
            AIAgentInventory, AIAgent.id == AIAgentInventory.agent_id
        ).filter(
            db.or_(
                AIAgentInventory.id.is_(None),
                AIAgentInventory.inventory_status != InventoryStatus.REGISTERED
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
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/upload_logo', methods=['POST'])
def upload_logo():
    """Handle logo upload for header customization"""
    try:
        if 'logo' not in request.files:
            return jsonify({'success': False, 'message': 'No file selected'})
        
        file = request.files['logo']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        if file and file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            import os
            import uuid
            filename = f"logo_{uuid.uuid4().hex[:8]}.{file.filename.split('.')[-1]}"
            filepath = os.path.join('static', 'img', filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            
            return jsonify({
                'success': True, 
                'message': 'Logo uploaded successfully',
                'logo_url': f'/static/img/{filename}'
            })
        
        return jsonify({'success': False, 'message': 'Invalid file type. Please upload an image file.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Upload failed: {str(e)}'})

@app.route('/playbooks/<int:id>/duplicate', methods=['POST'])
def duplicate_playbook(id):
    """Duplicate an existing playbook"""
    try:
        original = RegistrationPlaybook.query.get_or_404(id)
        
        # Create duplicate with modified name
        duplicate = RegistrationPlaybook(
            name=f"{original.name} (Copy)",
            description=f"Copy of {original.description}",
            conditions=original.conditions,
            actions=original.actions,
            priority=original.priority,
            enabled=False  # Duplicates start disabled
        )
        
        db.session.add(duplicate)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Playbook duplicated successfully',
            'new_id': duplicate.id
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Duplication failed: {str(e)}'})

@app.route('/playbooks/<int:id>/delete', methods=['POST'])
def delete_playbook(id):
    """Delete a playbook"""
    try:
        playbook = RegistrationPlaybook.query.get_or_404(id)
        db.session.delete(playbook)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Playbook deleted successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Deletion failed: {str(e)}'})

@app.route('/api/auto-registration/toggle', methods=['POST'])
def toggle_auto_registration():
    """Toggle auto-registration on/off"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        # In a real implementation, this would update a system setting
        # For now, we'll just return success
        return jsonify({
            'success': True,
            'message': f'Auto-registration {"enabled" if enabled else "disabled"}',
            'enabled': enabled
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Toggle failed: {str(e)}'})

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500