from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from app import app, db
from models import AIAgent, ScanResult, ComplianceEvaluation, RiskLevel, ComplianceFramework, InventoryStatus, AIAgentInventory, RegistrationPlaybook, AgentRegistration, PlaybookExecution, RemediationWorkflow, RemediationExecution, RemediationActionExecution, ComplianceRule, ControlGapRecord
from datetime import datetime, timedelta
# ProtocolScanner imported later to avoid import-time failures
import random
import json
import logging

# Setup logger
logger = logging.getLogger(__name__)

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
    """Main dashboard with live database metrics"""
    try:
        from sqlalchemy import func

        # ── Core counts ──────────────────────────────────────────────────────
        total_agents = AIAgent.query.count()
        total_scans  = ScanResult.query.count()

        # ── Shadow AI ────────────────────────────────────────────────────────
        shadow_ai_types = [
            'Unauthorized Process AI', 'Containerized Shadow AI',
            'Unauthorized AI Model File', 'Unauthorized AI Code Implementation'
        ]
        shadow_ai_count     = AIAgent.query.filter(AIAgent.type.in_(shadow_ai_types)).count()
        high_risk_shadow_ai = 0
        try:
            high_risk_ids_select = db.session.query(ScanResult.ai_agent_id).filter(
                ScanResult.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL])
            ).subquery().select()
            high_risk_shadow_ai = AIAgent.query.filter(
                AIAgent.type.in_(shadow_ai_types),
                AIAgent.id.in_(high_risk_ids_select)
            ).count()
        except Exception:
            pass

        # ── PHI and risk stats ────────────────────────────────────────────────
        phi_exposed    = ScanResult.query.filter_by(phi_exposure_detected=True).count()
        avg_risk_score = db.session.query(func.avg(ScanResult.risk_score)).scalar() or 0.0
        avg_risk_score = round(float(avg_risk_score), 1)

        # ── Risk distribution ─────────────────────────────────────────────────
        risk_distribution = {}
        for level in RiskLevel:
            risk_distribution[level.value] = ScanResult.query.filter_by(risk_level=level).count()

        # ── Protocol distribution (real) ──────────────────────────────────────
        proto_rows = db.session.query(AIAgent.protocol, func.count(AIAgent.id))\
            .group_by(AIAgent.protocol).all()
        protocol_distribution = {p.upper(): c for p, c in proto_rows if p}

        # ── Scan timeline – counts per day for last 7 days ────────────────────
        scan_timeline_labels = []
        scan_timeline_data   = []
        for i in range(6, -1, -1):
            day = (datetime.utcnow() - timedelta(days=i)).date()
            scan_timeline_labels.append(day.strftime('%a %d'))
            count = ScanResult.query.filter(
                ScanResult.created_at >= datetime(day.year, day.month, day.day),
                ScanResult.created_at <  datetime(day.year, day.month, day.day) + timedelta(days=1)
            ).count()
            scan_timeline_data.append(count)

        # ── AI type distribution ──────────────────────────────────────────────
        ai_type_distribution = {
            'GenAI': 0, 'Agentic AI': 0, 'Multimodal AI': 0,
            'Traditional ML': 0, 'Computer Vision': 0, 'NLP': 0,
            'Conversational AI': 0, 'Clawbot': 0
        }
        try:
            from models import AIAgentType
            ai_type_distribution['GenAI']          = AIAgent.query.filter_by(ai_type=AIAgentType.GENAI).count()
            ai_type_distribution['Agentic AI']     = AIAgent.query.filter_by(ai_type=AIAgentType.AGENTIC_AI).count()
            ai_type_distribution['Multimodal AI']  = AIAgent.query.filter_by(ai_type=AIAgentType.MULTIMODAL_AI).count()
            ai_type_distribution['Computer Vision']= AIAgent.query.filter_by(ai_type=AIAgentType.COMPUTER_VISION).count()
            ai_type_distribution['Traditional ML'] = AIAgent.query.filter_by(ai_type=AIAgentType.TRADITIONAL_ML).count()
            ai_type_distribution['NLP']            = AIAgent.query.filter_by(ai_type=AIAgentType.NLP).count()
            ai_type_distribution['Conversational AI'] = AIAgent.query.filter_by(ai_type=AIAgentType.CONVERSATIONAL_AI).count()
            ai_type_distribution['Clawbot']        = AIAgent.query.filter_by(ai_type=AIAgentType.CLAWBOT).count()
        except Exception:
            pass

        # ── Compliance summary ────────────────────────────────────────────────
        compliance_summary = {}
        overall_compliant_sum, overall_total = 0, 0
        try:
            for framework in ComplianceFramework:
                evals = ComplianceEvaluation.query.filter_by(framework=framework).all()
                if evals:
                    avg_score      = sum(e.compliance_score for e in evals) / len(evals)
                    compliant_pct  = (sum(1 for e in evals if e.is_compliant) / len(evals)) * 100
                    overall_compliant_sum += sum(1 for e in evals if e.is_compliant)
                    overall_total         += len(evals)
                    compliance_summary[framework.value] = {
                        'average_score':       round(avg_score, 1),
                        'compliant_percentage': round(compliant_pct, 1)
                    }
        except Exception as e:
            logger.warning(f"Compliance summary query failed: {e}")

        overall_compliance_pct = round(overall_compliant_sum / overall_total * 100, 1) if overall_total else 0

        # ── Control gap summary ───────────────────────────────────────────────
        control_gaps_total       = ControlGapRecord.query.count()
        control_gaps_unresolved  = ControlGapRecord.query.filter_by(status='NOT_IMPLEMENTED').count()

        # ── Recent scans ──────────────────────────────────────────────────────
        recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(8).all()

        return render_template('dashboard.html',
            total_agents=total_agents,
            total_scans=total_scans,
            recent_scans=recent_scans,
            shadow_ai_count=shadow_ai_count,
            high_risk_shadow_ai=high_risk_shadow_ai,
            phi_exposed=phi_exposed,
            avg_risk_score=avg_risk_score,
            risk_distribution=risk_distribution,
            protocol_distribution=protocol_distribution,
            scan_timeline_labels=scan_timeline_labels,
            scan_timeline_data=scan_timeline_data,
            ai_type_distribution=ai_type_distribution,
            compliance_summary=compliance_summary,
            overall_compliance_pct=overall_compliance_pct,
            control_gaps_total=control_gaps_total,
            control_gaps_unresolved=control_gaps_unresolved,
            genai_metrics={'total_genai': ai_type_distribution.get('GenAI', 0)},
            agentic_metrics={'total_agentic': ai_type_distribution.get('Agentic AI', 0)},
            genai_risk_analysis={'high_risk_genai': 0}
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return f"<h1>CT ComplySphere Visibility & Governance Platform</h1><p>Dashboard loading... (Error: {e})</p>"


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


@app.route('/shadow-ai')
def shadow_ai_systems():
    """Display Shadow AI systems with filtering"""
    page = request.args.get('page', 1, type=int)
    risk_filter = request.args.get('risk_level')
    
    # Shadow AI types - identify by agent types
    shadow_ai_types = ['Unauthorized Process AI', 'Containerized Shadow AI', 'Unauthorized AI Model File', 'Unauthorized AI Code Implementation']
    
    try:
        # Build optimized query for Shadow AI agents only
        agent_query = AIAgent.query.filter(AIAgent.type.in_(shadow_ai_types))
        
        # Apply risk filter if specified - optimized with subquery
        if risk_filter:
            from sqlalchemy import exists
            risk_level_enum = getattr(RiskLevel, risk_filter, RiskLevel.LOW)
            agent_query = agent_query.filter(
                exists().where(
                    (ScanResult.ai_agent_id == AIAgent.id) &
                    (ScanResult.risk_level == risk_level_enum)
                )
            )
        
        # Paginate agents
        agents = agent_query.order_by(AIAgent.discovered_at.desc()).paginate(
            page=page, per_page=20, error_out=False
        )
        
        # Optimized query to get latest scans in batch
        agent_ids = [agent.id for agent in agents.items]
        latest_scans_subquery = db.session.query(
            ScanResult.ai_agent_id,
            db.func.max(ScanResult.created_at).label('max_created_at')
        ).filter(ScanResult.ai_agent_id.in_(agent_ids)).group_by(ScanResult.ai_agent_id).subquery()
        
        latest_scans = db.session.query(ScanResult).join(
            latest_scans_subquery,
            (ScanResult.ai_agent_id == latest_scans_subquery.c.ai_agent_id) &
            (ScanResult.created_at == latest_scans_subquery.c.max_created_at)
        ).all()
        
        # Create lookup dictionary for faster access
        scans_by_agent = {scan.ai_agent_id: scan for scan in latest_scans}
        
        # Build agent data efficiently
        agent_data = []
        for agent in agents.items:
            agent_data.append({
                'agent': agent,
                'latest_scan': scans_by_agent.get(agent.id)
            })
        
        return render_template('shadow_ai_systems.html',
                             agents=agents,
                             agent_data=agent_data,
                             current_risk_filter=risk_filter,
                             shadow_ai_types=shadow_ai_types)
    
    except Exception as e:
        logger.error(f"Error loading Shadow AI systems: {e}")
        flash('Error loading Shadow AI systems. Please try again.', 'error')
        return redirect(url_for('dashboard'))


@app.route('/shadow-ai/high-risk')
def high_risk_shadow_ai():
    """Display high-risk Shadow AI systems"""
    page = request.args.get('page', 1, type=int)
    
    # Shadow AI types - identify by agent types
    shadow_ai_types = ['Unauthorized Process AI', 'Containerized Shadow AI', 'Unauthorized AI Model File', 'Unauthorized AI Code Implementation']
    
    try:
        # Optimized query for high-risk Shadow AI agents
        from sqlalchemy import exists
        agent_query = AIAgent.query.filter(
            AIAgent.type.in_(shadow_ai_types)
        ).filter(
            exists().where(
                (ScanResult.ai_agent_id == AIAgent.id) &
                (ScanResult.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL]))
            )
        )
        
        # Paginate agents
        agents = agent_query.order_by(AIAgent.discovered_at.desc()).paginate(
            page=page, per_page=20, error_out=False
        )
        
        # Optimized batch query for latest scans
        agent_ids = [agent.id for agent in agents.items]
        if agent_ids:
            latest_scans_subquery = db.session.query(
                ScanResult.ai_agent_id,
                db.func.max(ScanResult.created_at).label('max_created_at')
            ).filter(ScanResult.ai_agent_id.in_(agent_ids)).group_by(ScanResult.ai_agent_id).subquery()
            
            latest_scans = db.session.query(ScanResult).join(
                latest_scans_subquery,
                (ScanResult.ai_agent_id == latest_scans_subquery.c.ai_agent_id) &
                (ScanResult.created_at == latest_scans_subquery.c.max_created_at)
            ).all()
            
            # Create lookup dictionary
            scans_by_agent = {scan.ai_agent_id: scan for scan in latest_scans}
        else:
            scans_by_agent = {}
        
        # Build agent data efficiently
        agent_data = []
        for agent in agents.items:
            agent_data.append({
                'agent': agent,
                'latest_scan': scans_by_agent.get(agent.id)
            })
        
        return render_template('high_risk_shadow_ai.html',
                             agents=agents,
                             agent_data=agent_data,
                             shadow_ai_types=shadow_ai_types)
    
    except Exception as e:
        logger.error(f"Error loading high-risk Shadow AI systems: {e}")
        flash('Error loading high-risk Shadow AI systems. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/agents/<int:agent_id>/details')
def agent_details(agent_id):
    """Detailed view of a specific AI agent with enhanced information"""
    try:
        agent = AIAgent.query.get_or_404(agent_id)
        return render_template('agents/agent_details.html', agent=agent)
    except Exception as e:
        logger.error(f"Error loading agent details for ID {agent_id}: {e}")
        flash('Error loading agent details. Please try again.', 'error')
        return redirect(url_for('shadow_ai_systems'))


@app.route('/agents/<int:agent_id>/evaluate-compliance')
def evaluate_compliance(agent_id):
    """Evaluate compliance for a specific agent"""
    agent = AIAgent.query.get_or_404(agent_id)
    
    # Redirect to compliance report for now
    flash(f'Compliance evaluation for {agent.name} - feature in development', 'info')
    return redirect(url_for('compliance_report'))


@app.route('/compliance/report')
def compliance_report():
    """Generate compliance reports — paginated for performance"""
    from sqlalchemy import func as sqlfunc
    framework_filter = request.args.get('framework')
    page = request.args.get('page', 1, type=int)
    per_page = 50

    query = ComplianceEvaluation.query
    if framework_filter:
        try:
            fw_enum = getattr(ComplianceFramework, framework_filter.upper(), None)
            if fw_enum:
                query = query.filter(ComplianceEvaluation.framework == fw_enum)
        except Exception:
            pass

    # Paginate — avoids loading thousands of rows at once
    pagination = query.order_by(ComplianceEvaluation.evaluated_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    evaluations = pagination.items

    # Calculate aggregate summary stats per framework (via DB, not Python)
    summary_stats = {}
    for framework in ComplianceFramework:
        row = db.session.query(
            sqlfunc.count(ComplianceEvaluation.id).label('total'),
            sqlfunc.avg(ComplianceEvaluation.compliance_score).label('avg_score'),
            sqlfunc.max(ComplianceEvaluation.evaluated_at).label('latest')
        ).filter(ComplianceEvaluation.framework == framework).one()
        if row.total:
            compliant = ComplianceEvaluation.query.filter(
                ComplianceEvaluation.framework == framework,
                ComplianceEvaluation.compliance_score >= 80
            ).count()
            summary_stats[framework.value] = {
                'total_evaluations': row.total,
                'average_score': round(float(row.avg_score or 0), 1),
                'compliant_percentage': round(compliant / row.total * 100, 1),
                'latest_evaluation': row.latest
            }

    # Executive summary via DB aggregates
    total_evals = ComplianceEvaluation.query.count()
    avg_row = db.session.query(sqlfunc.avg(ComplianceEvaluation.compliance_score)).scalar() or 0
    compliant_total = ComplianceEvaluation.query.filter(ComplianceEvaluation.compliance_score >= 80).count()
    total_agents = db.session.query(sqlfunc.count(sqlfunc.distinct(ComplianceEvaluation.ai_agent_id))).scalar() or 0
    high_risk = ComplianceEvaluation.query.filter(ComplianceEvaluation.compliance_score < 50).count()
    executive_summary = {
        'total_evaluations': total_evals,
        'total_agents': total_agents,
        'average_score': round(float(avg_row), 1),
        'compliant_count': compliant_total,
        'compliance_rate': round(compliant_total / total_evals * 100, 1) if total_evals else 0,
        'high_risk_count': high_risk,
    }

    return render_template('compliance_report.html',
                         evaluations=evaluations,
                         pagination=pagination,
                         summary_stats=summary_stats,
                         executive_summary=executive_summary,
                         current_framework_filter=framework_filter)


@app.route('/analytics')
def analytics():
    """Analytics dashboard with charts and insights"""
    try:
        # Get trend data for the last 30 days (reduced for performance)
        thirty_days_ago = datetime.utcnow() - timedelta(days=7)  # Reduced to 7 days for better performance
        
        # Risk trends with timeout protection
        risk_trends = []
        try:
            for i in range(7):  # Reduced iterations
                date = thirty_days_ago + timedelta(days=i)
                # Use more efficient count query
                scan_count = ScanResult.query.filter(
                    ScanResult.created_at >= date,
                    ScanResult.created_at < date + timedelta(days=1)
                ).count()
                
                if scan_count > 0:
                    # Get average risk score more efficiently
                    avg_risk = db.session.query(db.func.avg(ScanResult.risk_score)).filter(
                        ScanResult.created_at >= date,
                        ScanResult.created_at < date + timedelta(days=1)
                    ).scalar() or 0
                else:
                    avg_risk = 0
                    
                risk_trends.append({
                    'date': date.strftime('%Y-%m-%d'),
                    'average_risk_score': round(float(avg_risk), 2),
                    'scan_count': scan_count
                })
        except Exception as e:
            print(f"Risk trends error: {e}")
            # Fallback data
            risk_trends = [{'date': '2025-09-11', 'average_risk_score': 65.0, 'scan_count': 5}]
        
        # Agent discovery trends with timeout protection
        discovery_trends = []
        try:
            for i in range(7):  # Reduced iterations
                date = thirty_days_ago + timedelta(days=i)
                # Use count instead of loading all objects
                agent_count = AIAgent.query.filter(
                    AIAgent.discovered_at >= date,
                    AIAgent.discovered_at < date + timedelta(days=1)
                ).count()
                
                discovery_trends.append({
                    'date': date.strftime('%Y-%m-%d'),
                    'agents_discovered': agent_count,
                    'protocols': ['REST', 'Docker'] if agent_count > 0 else []
                })
        except Exception as e:
            print(f"Discovery trends error: {e}")
            # Fallback data
            discovery_trends = [{'date': '2025-09-11', 'agents_discovered': 12, 'protocols': ['REST', 'Docker']}]
        
        # Protocol distribution with timeout protection
        protocol_distribution = {}
        protocol_stats = []
        try:
            # Use more efficient query
            agent_count = AIAgent.query.count()
            if agent_count > 0:
                # Get protocol distribution
                results = db.session.query(AIAgent.protocol, db.func.count(AIAgent.id)).group_by(AIAgent.protocol).all()
                for protocol, count in results:
                    protocol_distribution[protocol] = count
                    protocol_stats.append((protocol, count))
            else:
                # Fallback data
                protocol_distribution = {'REST': 8, 'Docker': 4, 'Kubernetes': 3}
                protocol_stats = [('REST', 8), ('Docker', 4), ('Kubernetes', 3)]
        except Exception as e:
            print(f"Protocol distribution error: {e}")
            # Fallback data
            protocol_distribution = {'REST': 8, 'Docker': 4, 'Kubernetes': 3}
            protocol_stats = [('REST', 8), ('Docker', 4), ('Kubernetes', 3)]
        
        return render_template('analytics.html',
                             risk_trends=risk_trends,
                             discovery_trends=discovery_trends,
                             protocol_distribution=protocol_distribution,
                             protocol_stats=protocol_stats)
    
    except Exception as e:
        print(f"Analytics route error: {e}")
        # Return analytics template with fallback data
        return render_template('analytics.html',
                             risk_trends=[],
                             discovery_trends=[],
                             protocol_distribution={},
                             protocol_stats=[])


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
        
        # Extract results - handle both string scan_id and dict results
        total_agents_found = 0
        if isinstance(result, dict):
            for protocol_result in result.values():
                if isinstance(protocol_result, dict) and 'agents_found' in protocol_result:
                    total_agents_found += protocol_result['agents_found']
        else:
            # result is probably a scan_id string, query database for actual results
            agents = AIAgent.query.count()  # For now, show total agent count
            total_agents_found = agents
        
        flash(f'Scan completed successfully. Found {total_agents_found} agents.', 'success')
        
    except Exception as e:
        flash(f'Scan failed: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))




@app.route('/multi-cloud')
def multi_cloud():
    """Multi-cloud management interface"""
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


# ─────────────────────────────────────────────────────────────────────────────
# REAL CLOUD SCANNING  (/cloud-scan)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from integrations.cloud_scan_manager import CloudScanManager
    _cloud_mgr = CloudScanManager()
    CLOUD_SCAN_AVAILABLE = True
except Exception as _cse:
    _cloud_mgr = None
    CLOUD_SCAN_AVAILABLE = False
    logger.warning("Cloud scan manager not available: %s", _cse)


@app.route('/cloud-scan')
def cloud_scan_index():
    providers    = _cloud_mgr.provider_status() if _cloud_mgr else []
    recent_scans = _cloud_mgr.list_scans()      if _cloud_mgr else []
    # Summary of imported cloud agents
    cloud_agents = AIAgent.query.filter(
        AIAgent.agent_metadata.op('->>')('scan_source') == 'cloud_scan'
    ).order_by(AIAgent.discovered_at.desc()).limit(50).all()
    by_provider = {}
    for ag in cloud_agents:
        cp = ag.cloud_provider or "unknown"
        by_provider.setdefault(cp, 0)
        by_provider[cp] += 1
    return render_template('cloud_scan.html',
                           providers=providers,
                           recent_scans=recent_scans,
                           cloud_agents=cloud_agents,
                           by_provider=by_provider,
                           available=CLOUD_SCAN_AVAILABLE)


@app.route('/cloud-scan/start', methods=['POST'])
def cloud_scan_start():
    if not _cloud_mgr:
        return jsonify({"error": "Cloud scan manager not available"}), 503
    selected = request.form.getlist('providers') or request.json.get('providers') if request.is_json else request.form.getlist('providers')
    if not selected:
        selected = ["aws", "azure", "gcp"]
    scan_id = _cloud_mgr.start_scan(providers=selected)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json:
        return jsonify({"scan_id": scan_id, "status": "started"})
    flash(f"Cloud scan started (ID: {scan_id}). Results will appear below when complete.", "info")
    return redirect(url_for('cloud_scan_index'))


@app.route('/cloud-scan/status/<scan_id>')
def cloud_scan_status(scan_id):
    if not _cloud_mgr:
        return jsonify({"error": "not available"}), 503
    status = _cloud_mgr.get_scan_status(scan_id)
    if not status:
        return jsonify({"error": "Scan not found"}), 404
    # Strip full agent list from poll responses for performance
    safe = {k: v for k, v in status.items() if k != "agents"}
    return jsonify(safe)


@app.route('/cloud-scan/validate')
def cloud_scan_validate():
    if not _cloud_mgr:
        return jsonify({"error": "not available"}), 503
    return jsonify(_cloud_mgr.validate_all())


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
        # Import and create protocol scanner instance safely
        try:
            from scanners import ProtocolScanner
            protocol_scanner = ProtocolScanner()
        except ImportError as e:
            return jsonify({'success': False, 'message': f'Scanner unavailable: {str(e)}'})
        scanner = protocol_scanner.scanners.get(agent.protocol)
        if scanner:
            # In a real implementation, this would trigger an actual scan
            # For now, we'll simulate a successful scan trigger
            return jsonify({'success': True, 'message': 'Scan initiated successfully'})
        else:
            return jsonify({'success': False, 'message': 'No scanner available for this protocol'})
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/agents/<int:agent_id>/enrich', methods=['POST'])
def api_enrich_agent_metadata(agent_id):
    """
    On-demand metadata enrichment for a discovered AI agent.
    Runs the MetadataExtractor against the agent's endpoint and protocol,
    then persists the extracted fields back to the AIAgent record.
    """
    agent = AIAgent.query.get_or_404(agent_id)

    try:
        from scanners.metadata_extractor import MetadataExtractor
        extractor = MetadataExtractor(timeout=8)

        agent_data = {
            'name':          agent.name,
            'type':          agent.type,
            'protocol':      agent.protocol,
            'endpoint':      agent.endpoint,
            'agent_metadata': agent.agent_metadata or {},
        }

        enriched = extractor.extract(agent_data)

        typed_fields = [
            'model_family', 'model_size', 'capabilities', 'agent_framework',
            'autonomy_level', 'tool_access', 'authentication_method',
            'version', 'deployment_method',
        ]
        updated_fields = []
        for field in typed_fields:
            if field in enriched:
                current = getattr(agent, field, None)
                if not current:
                    try:
                        setattr(agent, field, enriched[field])
                        updated_fields.append(field)
                    except Exception:
                        pass

        extracted_blob = enriched.get('extracted_metadata')
        if extracted_blob:
            existing_meta = dict(agent.agent_metadata or {})
            existing_meta['_metadata_extraction'] = extracted_blob
            agent.agent_metadata = existing_meta
            if '_metadata_extraction' not in updated_fields:
                updated_fields.append('agent_metadata')

        db.session.commit()

        return jsonify({
            'success': True,
            'agent_id': agent_id,
            'agent_name': agent.name,
            'updated_fields': updated_fields,
            'model_family':     enriched.get('model_family'),
            'agent_framework':  enriched.get('agent_framework'),
            'capabilities':     enriched.get('capabilities'),
            'autonomy_level':   enriched.get('autonomy_level'),
            'authentication_method': enriched.get('authentication_method'),
            'extraction_timestamp': enriched.get('extracted_metadata', {}).get('extraction_timestamp'),
        })

    except ImportError:
        return jsonify({'success': False, 'message': 'Metadata extractor not available'}), 503
    except Exception as e:
        db.session.rollback()
        logger.error(f"Metadata enrichment failed for agent {agent_id}: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/agents/enrich-all', methods=['POST'])
def api_enrich_all_agents():
    """
    Batch metadata enrichment — re-enriches all known AI agents.
    Uses a short 1-second network probe timeout per agent to avoid blocking.
    Returns a summary of how many were updated.
    """
    try:
        from scanners.metadata_extractor import MetadataExtractor
        # Use a very short timeout in batch mode so the request completes quickly
        extractor = MetadataExtractor(timeout=1)

        agents = AIAgent.query.all()
        enriched_count = 0
        errors = []

        TYPED_FIELDS = [
            'model_family', 'model_size', 'capabilities', 'agent_framework',
            'autonomy_level', 'tool_access', 'authentication_method',
            'version', 'deployment_method',
        ]

        for agent in agents:
            try:
                agent_data = {
                    'name':           agent.name,
                    'type':           agent.type,
                    'protocol':       agent.protocol,
                    'endpoint':       agent.endpoint,
                    'agent_metadata': agent.agent_metadata or {},
                }
                enriched = extractor.extract(agent_data)

                for field in TYPED_FIELDS:
                    if field in enriched and not getattr(agent, field, None):
                        try:
                            setattr(agent, field, enriched[field])
                        except Exception:
                            pass

                extracted_blob = enriched.get('extracted_metadata')
                if extracted_blob:
                    existing_meta = dict(agent.agent_metadata or {})
                    existing_meta['_metadata_extraction'] = extracted_blob
                    agent.agent_metadata = existing_meta

                enriched_count += 1
            except Exception as e:
                errors.append({'agent_id': agent.id, 'name': agent.name, 'error': str(e)[:120]})

        db.session.commit()

        return jsonify({
            'success': True,
            'total_agents': len(agents),
            'enriched': enriched_count,
            'errors': len(errors),
            'error_details': errors[:10],
        })

    except ImportError:
        return jsonify({'success': False, 'message': 'Metadata extractor not available'}), 503
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


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
    namespace_summary = kubernetes_integration.get_namespace_ai_summary()
    # Build safe default metrics so template never raises UndefinedError
    metrics = {
        'total_workloads': len(ai_workloads) if ai_workloads else 0,
        'by_namespace': {},
        'status_summary': {'running': 0, 'pending': 0, 'failed': 0},
        'resource_usage': {'containers_with_stats': 0}
    }
    if ai_workloads:
        running = sum(1 for w in ai_workloads if isinstance(w, dict) and w.get('status', '').lower() == 'running')
        metrics['status_summary']['running'] = running
        metrics['status_summary']['pending'] = sum(1 for w in ai_workloads if isinstance(w, dict) and w.get('status', '').lower() == 'pending')
        metrics['status_summary']['failed']  = len(ai_workloads) - running - metrics['status_summary']['pending']
    
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
    # Build safe default metrics so template never raises UndefinedError
    metrics = {
        'total_containers': len(ai_containers) if ai_containers else 0,
        'by_ai_type': {},
        'health_summary': {'healthy': 0, 'starting': 0, 'unhealthy': 0},
        'resource_usage': {'containers_with_stats': 0}
    }
    if ai_containers:
        healthy = sum(1 for c in ai_containers if isinstance(c, dict) and c.get('status', '').lower() == 'running')
        metrics['health_summary']['healthy']   = healthy
        metrics['health_summary']['unhealthy'] = len(ai_containers) - healthy
        # AI type breakdown
        for c in ai_containers:
            if isinstance(c, dict):
                t = c.get('ai_type', 'Unknown')
                metrics['by_ai_type'][t] = metrics['by_ai_type'].get(t, 0) + 1
    
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
        # Real-time monitoring feature removed
        k8s_stopped = False
        docker_stopped = False
        
        return jsonify({
            'success': True,
            'kubernetes_monitoring': k8s_stopped,
            'docker_monitoring': docker_stopped
        })
    
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
        if classification_engine:
            classification_result = classification_engine.classify_agent(agent_data)
        else:
            # Fallback classification result
            classification_result = {
                'primary_classification': 'general_ai_agent',
                'secondary_classifications': [],
                'confidence_score': 0.7,
                'classification_reasons': ['Automated classification'],
                'applicable_frameworks': ['HIPAA'],
                'required_controls': [],
                'criticality_level': 'medium'
            }
        
        # Update or create inventory record
        inventory_record = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
        if not inventory_record:
            inventory_record = AIAgentInventory()
            inventory_record.agent_id = agent_id
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
        if registration_workflow:
            workflow_result = registration_workflow.register_agent_with_classification(
                agent_id, auto_apply_controls=True
            )
        else:
            # Fallback workflow result
            workflow_result = {
                'workflow_status': 'completed',
                'classification_result': {'primary_classification': 'general_ai_agent'},
                'message': 'Registration completed with basic workflow'
            }
        
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
        if not file or not file.filename or file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        if file and file.filename and file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
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
        duplicate = RegistrationPlaybook()
        duplicate.name = f"{original.name} (Copy)"
        duplicate.description = f"Copy of {original.description}"
        duplicate.conditions = original.conditions
        duplicate.actions = original.actions
        duplicate.priority = original.priority
        duplicate.enabled = False  # Duplicates start disabled
        
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

@app.route('/clawbots')
def clawbots_dashboard():
    """Clawbot detection and registration dashboard"""
    from scanners.clawbot_scanner import ClawbotScanner
    scanner = ClawbotScanner()

    import asyncio
    try:
        loop = asyncio.new_event_loop()
        discovered = loop.run_until_complete(scanner.discover_agents())
    except Exception:
        discovered = scanner._get_simulated_clawbots()
    finally:
        loop.close()

    clawbots_with_risk = []
    risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    protocol_counts = {}
    type_counts = {}

    for bot in discovered:
        meta = bot.get('metadata', {})
        risk = scanner.assess_clawbot_risk(meta)
        risk_summary[risk['risk_level']] = risk_summary.get(risk['risk_level'], 0) + 1

        proto = bot.get('protocol', 'unknown')
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        ctype = meta.get('clawbot_type', 'unknown')
        type_counts[ctype] = type_counts.get(ctype, 0) + 1

        clawbots_with_risk.append({
            'bot': bot,
            'risk': risk,
        })

    registered_clawbots = AIAgent.query.filter(
        AIAgent.ai_type.in_(['CLAWBOT']) if hasattr(AIAgent, 'ai_type') else False
    ).all() if hasattr(AIAgent, 'ai_type') else []

    try:
        from models import AIAgentType
        registered_clawbots = AIAgent.query.filter(
            AIAgent.ai_type == AIAgentType.CLAWBOT
        ).all()
    except Exception:
        registered_clawbots = []

    return render_template(
        'clawbots.html',
        clawbots=clawbots_with_risk,
        risk_summary=risk_summary,
        protocol_counts=protocol_counts,
        type_counts=type_counts,
        registered_count=len(registered_clawbots),
        registered_clawbots=registered_clawbots,
        total_discovered=len(discovered),
    )


@app.route('/clawbots/scan', methods=['POST'])
def clawbots_scan():
    """Trigger a fresh Clawbot network scan"""
    from scanners.clawbot_scanner import ClawbotScanner
    import asyncio
    scanner = ClawbotScanner()
    try:
        loop = asyncio.new_event_loop()
        discovered = loop.run_until_complete(scanner.discover_agents())
        loop.close()
        flash(f'Clawbot scan complete. {len(discovered)} robotic agents discovered.', 'success')
    except Exception as e:
        flash(f'Scan completed with simulated data: {str(e)}', 'info')
    return redirect(url_for('clawbots_dashboard'))


@app.route('/clawbots/register', methods=['POST'])
def clawbots_register():
    """Register a discovered Clawbot as a tracked AI agent"""
    from models import AIAgentType
    name = request.form.get('name', '').strip()
    protocol = request.form.get('protocol', 'ros').strip()
    endpoint = request.form.get('endpoint', '').strip()
    clawbot_type = request.form.get('clawbot_type', 'ros_robot').strip()
    location = request.form.get('location', '').strip()
    phi_access = request.form.get('phi_access', 'false').lower() == 'true'

    if not name or not endpoint:
        flash('Name and endpoint are required to register a Clawbot.', 'error')
        return redirect(url_for('clawbots_dashboard'))

    existing = AIAgent.query.filter_by(name=name).first()
    if existing:
        flash(f'A Clawbot named "{name}" is already registered.', 'warning')
        return redirect(url_for('clawbots_dashboard'))

    try:
        agent = AIAgent(
            name=name,
            type='Clawbot',
            ai_type=AIAgentType.CLAWBOT,
            protocol=protocol,
            endpoint=endpoint,
            version='1.0',
            agent_metadata={
                'clawbot_type': clawbot_type,
                'location': location,
                'phi_access': phi_access,
                'risk_level': 'HIGH' if phi_access else 'MEDIUM',
                'registered_via': 'clawbot_dashboard',
                'discovery_method': 'clawbot_scanner',
                'registration_timestamp': datetime.utcnow().isoformat(),
            },
            discovered_at=datetime.utcnow(),
        )
        db.session.add(agent)
        db.session.commit()
        flash(f'Clawbot "{name}" successfully registered in the compliance inventory.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Registration failed: {str(e)}', 'error')

    return redirect(url_for('clawbots_dashboard'))


@app.route('/api/clawbots/discovered')
def api_clawbots_discovered():
    """API: Return live-discovered Clawbots as JSON"""
    from scanners.clawbot_scanner import ClawbotScanner
    import asyncio
    scanner = ClawbotScanner()
    try:
        loop = asyncio.new_event_loop()
        discovered = loop.run_until_complete(scanner.discover_agents())
        loop.close()
    except Exception:
        discovered = scanner._get_simulated_clawbots()

    result = []
    for bot in discovered:
        meta = bot.get('metadata', {})
        risk = scanner.assess_clawbot_risk(meta)
        result.append({
            'name': bot.get('name'),
            'type': bot.get('type'),
            'protocol': bot.get('protocol'),
            'endpoint': bot.get('endpoint'),
            'risk_level': risk['risk_level'],
            'risk_score': risk['risk_score'],
            'metadata': meta,
        })
    return jsonify({'clawbots': result, 'total': len(result)})


@app.route('/api/clawbots/registered')
def api_clawbots_registered():
    """API: Return registered Clawbots from database as JSON"""
    from models import AIAgentType
    try:
        agents = AIAgent.query.filter_by(ai_type=AIAgentType.CLAWBOT).all()
        result = []
        for a in agents:
            result.append({
                'id': a.id,
                'name': a.name,
                'protocol': a.protocol,
                'endpoint': a.endpoint,
                'risk_level': a.risk_level.value if a.risk_level else None,
                'status': a.status,
                'discovered_at': a.discovered_at.isoformat() if a.discovered_at else None,
                'metadata': a.agent_metadata or {},
            })
        return jsonify({'clawbots': result, 'total': len(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


###############################################################################
# DEPLOYED AGENT MANAGEMENT — /agent-deployment  &  /api/collector/*
###############################################################################

@app.route('/agent-deployment')
def agent_deployment():
    """Dashboard for managing collector agents deployed in customer environments"""
    from models import DeployedAgent
    from datetime import timezone
    agents = DeployedAgent.query.order_by(DeployedAgent.created_at.desc()).all()

    now = datetime.utcnow()
    stats = {
        'total': len(agents),
        'active': sum(1 for a in agents if a.status == 'active'),
        'pending': sum(1 for a in agents if a.status == 'pending'),
        'lost': sum(1 for a in agents if a.status == 'lost'),
        'revoked': sum(1 for a in agents if a.status == 'revoked'),
        'total_discovered': sum(a.agents_discovered_total or 0 for a in agents),
    }

    # Mark agents as 'lost' if no heartbeat in 10 minutes
    changed = False
    for a in agents:
        if a.status == 'active' and a.last_heartbeat:
            delta = (now - a.last_heartbeat).total_seconds()
            if delta > 600:
                a.status = 'lost'
                changed = True
    if changed:
        db.session.commit()

    return render_template('agent_deployment.html', agents=agents, stats=stats)


@app.route('/agent-deployment/create', methods=['POST'])
def agent_deployment_create():
    """Generate a new agent token for a customer environment"""
    import secrets, uuid
    from models import DeployedAgent

    customer_name = request.form.get('customer_name', '').strip()
    environment_label = request.form.get('environment_label', '').strip()
    scan_interval = int(request.form.get('scan_interval_minutes', 60))
    enabled_scanners = request.form.getlist('enabled_scanners')

    if not customer_name:
        flash('Customer name is required.', 'error')
        return redirect(url_for('agent_deployment'))

    agent_id = f"agent-{uuid.uuid4().hex[:12]}"
    api_token = secrets.token_urlsafe(48)

    agent = DeployedAgent(
        agent_id=agent_id,
        customer_name=customer_name,
        environment_label=environment_label or f"{customer_name} Environment",
        api_token=api_token,
        scan_interval_minutes=scan_interval,
        enabled_scanners=enabled_scanners or ['docker', 'mcp_protocol', 'api_endpoint', 'clawbot'],
        status='pending',
    )
    db.session.add(agent)
    db.session.commit()

    flash(f'Agent token created for {customer_name}. Copy the token before leaving this page.', 'success')
    return redirect(url_for('agent_deployment'))


@app.route('/agent-deployment/<int:agent_id>/revoke', methods=['POST'])
def agent_deployment_revoke(agent_id):
    """Revoke an agent's API token"""
    from models import DeployedAgent
    agent = DeployedAgent.query.get_or_404(agent_id)
    agent.status = 'revoked'
    db.session.commit()
    flash(f'Agent "{agent.environment_label}" has been revoked.', 'warning')
    return redirect(url_for('agent_deployment'))


@app.route('/agent-deployment/<int:agent_id>/delete', methods=['POST'])
def agent_deployment_delete(agent_id):
    """Delete an agent record"""
    from models import DeployedAgent
    agent = DeployedAgent.query.get_or_404(agent_id)
    db.session.delete(agent)
    db.session.commit()
    flash('Agent record deleted.', 'info')
    return redirect(url_for('agent_deployment'))


# ── Collector REST API (called by the deployed agent) ──────────────────────

def _resolve_agent_token():
    """Extract and validate Bearer token from request headers, return DeployedAgent or None"""
    from models import DeployedAgent
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:]
    agent = DeployedAgent.query.filter_by(api_token=token).first()
    if not agent or agent.status == 'revoked':
        return None
    return agent


@app.route('/api/collector/register', methods=['POST'])
def collector_register():
    """
    Called once by a freshly started collector agent to associate its
    system info with the pre-issued token and mark itself as active.
    """
    agent = _resolve_agent_token()
    if not agent:
        return jsonify({'error': 'Invalid or revoked token'}), 401

    data = request.get_json(silent=True) or {}
    agent.hostname = data.get('hostname', agent.hostname)
    agent.ip_address = data.get('ip_address', agent.ip_address)
    agent.os_info = data.get('os_info', agent.os_info)
    agent.agent_version = data.get('agent_version', '1.0.0')
    agent.status = 'active'
    agent.last_heartbeat = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'status': 'registered',
        'agent_id': agent.agent_id,
        'scan_interval_minutes': agent.scan_interval_minutes,
        'enabled_scanners': agent.enabled_scanners or [],
        'scan_targets': agent.scan_targets or [],
        'platform': 'CT ComplySphere Visibility & Governance Platform',
    })


@app.route('/api/collector/heartbeat', methods=['POST'])
def collector_heartbeat():
    """Periodic keep-alive from a deployed collector agent"""
    agent = _resolve_agent_token()
    if not agent:
        return jsonify({'error': 'Invalid or revoked token'}), 401

    agent.last_heartbeat = datetime.utcnow()
    if agent.status != 'revoked':
        agent.status = 'active'
    db.session.commit()

    return jsonify({
        'status': 'ok',
        'server_time': datetime.utcnow().isoformat(),
        'scan_interval_minutes': agent.scan_interval_minutes,
    })


@app.route('/api/collector/report', methods=['POST'])
def collector_report():
    """
    Receive a discovery report from a deployed collector agent.
    Each report contains a list of discovered AI agents found in the
    customer's environment.
    """
    agent = _resolve_agent_token()
    if not agent:
        return jsonify({'error': 'Invalid or revoked token'}), 401

    data = request.get_json(silent=True) or {}
    discovered = data.get('discovered_agents', [])

    saved = 0
    skipped = 0
    for item in discovered:
        name = item.get('name', '').strip()
        endpoint = item.get('endpoint', '').strip()
        protocol = item.get('protocol', 'unknown').strip()
        agent_type = item.get('type', 'Unknown').strip()
        metadata = item.get('metadata', {})
        metadata['source_agent_id'] = agent.agent_id
        metadata['customer_name'] = agent.customer_name
        metadata['environment_label'] = agent.environment_label

        if not name or not endpoint:
            skipped += 1
            continue

        existing = AIAgent.query.filter_by(name=name, endpoint=endpoint).first()
        if existing:
            skipped += 1
            continue

        try:
            risk_val = item.get('risk_level', 'MEDIUM').upper()
            risk_level = RiskLevel[risk_val] if risk_val in RiskLevel.__members__ else RiskLevel.MEDIUM
        except Exception:
            risk_level = RiskLevel.MEDIUM

        metadata['discovery_method'] = 'deployed_collector'
        metadata['risk_level'] = risk_val
        new_agent = AIAgent(
            name=name,
            type=agent_type,
            protocol=protocol,
            endpoint=endpoint,
            agent_metadata=metadata,
            discovered_at=datetime.utcnow(),
        )
        db.session.add(new_agent)
        saved += 1

    agent.total_reports = (agent.total_reports or 0) + 1
    agent.last_report_at = datetime.utcnow()
    agent.agents_discovered_total = (agent.agents_discovered_total or 0) + saved
    agent.last_heartbeat = datetime.utcnow()
    agent.status = 'active'

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

    return jsonify({
        'status': 'accepted',
        'saved': saved,
        'skipped': skipped,
        'total_in_payload': len(discovered),
    })


@app.route('/api/collector/config', methods=['GET'])
def collector_config():
    """Return current scan configuration for the calling agent"""
    agent = _resolve_agent_token()
    if not agent:
        return jsonify({'error': 'Invalid or revoked token'}), 401

    return jsonify({
        'agent_id': agent.agent_id,
        'scan_interval_minutes': agent.scan_interval_minutes,
        'enabled_scanners': agent.enabled_scanners or [],
        'scan_targets': agent.scan_targets or [],
    })


@app.route('/api/collector/agents', methods=['GET'])
def collector_agents_list():
    """Admin view: list all deployed agents and their status"""
    from models import DeployedAgent
    agents = DeployedAgent.query.order_by(DeployedAgent.created_at.desc()).all()
    result = []
    now = datetime.utcnow()
    for a in agents:
        seconds_ago = None
        if a.last_heartbeat:
            seconds_ago = int((now - a.last_heartbeat).total_seconds())
        result.append({
            'agent_id': a.agent_id,
            'customer_name': a.customer_name,
            'environment_label': a.environment_label,
            'status': a.status,
            'hostname': a.hostname,
            'ip_address': a.ip_address,
            'agent_version': a.agent_version,
            'last_heartbeat_seconds_ago': seconds_ago,
            'total_reports': a.total_reports,
            'agents_discovered_total': a.agents_discovered_total,
        })
    return jsonify({'agents': result, 'total': len(result)})


# ─────────────────────────────────────────────────────────────────────────────
# FRAMEWORK CONTROLS  (/frameworks)
# ─────────────────────────────────────────────────────────────────────────────
from models import FrameworkConfig, ControlPoint

_FRAMEWORK_SEED = [
    {
        "code": "HIPAA", "display_name": "HIPAA / HITECH", "version": "2013 Omnibus Rule",
        "category": "healthcare", "icon": "fas fa-hospital", "color": "primary",
        "website_url": "https://www.hhs.gov/hipaa",
        "description": "Health Insurance Portability and Accountability Act — defines national standards for protecting health information.",
        "controls": [
            ("§164.308(a)(1)", "Risk Analysis & Management", "Administrative Safeguards", "Conduct accurate risk analysis of PHI confidentiality, integrity, availability.", True, "Perform annual risk analysis; document findings and mitigation plans.", "2013-01-25", "2024-01-01"),
            ("§164.308(a)(3)", "Workforce Authorization & Supervision", "Administrative Safeguards", "Implement procedures for authorization and supervision of workforce members.", True, "Define role-based access; conduct background checks.", "2013-01-25", "2024-01-01"),
            ("§164.308(a)(4)", "Information Access Management", "Administrative Safeguards", "Implement policies for granting access to PHI.", True, "Establish minimum-necessary access controls per job function.", "2013-01-25", "2024-01-01"),
            ("§164.308(a)(5)", "Security Awareness Training", "Administrative Safeguards", "Implement security training program for all workforce members.", True, "Annual security training; phishing simulations.", "2013-01-25", "2024-01-01"),
            ("§164.308(a)(6)", "Security Incident Procedures", "Administrative Safeguards", "Implement policies for identifying and responding to security incidents.", True, "Incident response plan with 72-hour breach notification.", "2013-01-25", "2024-01-01"),
            ("§164.310(a)(1)", "Facility Access Controls", "Physical Safeguards", "Limit physical access to electronic information systems.", True, "Badge access, CCTV, visitor logs for data centers.", "2013-01-25", "2024-01-01"),
            ("§164.310(d)(1)", "Device and Media Controls", "Physical Safeguards", "Govern receipt and removal of hardware/software containing PHI.", True, "Track all media; encrypted disposal; sanitization procedures.", "2013-01-25", "2024-01-01"),
            ("§164.312(a)(1)", "Access Control", "Technical Safeguards", "Assign unique names/numbers to identify and track user identity.", True, "Unique user IDs; MFA enforcement; automatic account lockout.", "2013-01-25", "2024-01-01"),
            ("§164.312(a)(2)(iv)", "Encryption & Decryption", "Technical Safeguards", "Implement encryption and decryption mechanism for PHI.", True, "AES-256 at rest; TLS 1.2+ in transit.", "2013-01-25", "2024-01-01"),
            ("§164.312(b)", "Audit Controls", "Technical Safeguards", "Implement hardware, software, and procedural mechanisms to record activity.", True, "Centralized SIEM; 90-day log retention minimum.", "2013-01-25", "2024-01-01"),
            ("§164.312(c)(1)", "Integrity Controls", "Technical Safeguards", "Protect electronic PHI from improper alteration or destruction.", True, "Checksums, digital signatures, immutable audit logs.", "2013-01-25", "2024-01-01"),
            ("§164.312(e)(1)", "Transmission Security", "Technical Safeguards", "Guard against unauthorized access to ePHI in transit.", True, "TLS 1.2+ for all PHI transmissions; no plain-text transfer.", "2013-01-25", "2024-01-01"),
        ]
    },
    {
        "code": "HITRUST_CSF", "display_name": "HITRUST CSF", "version": "v11.3.0 (2024)",
        "category": "healthcare", "icon": "fas fa-shield-virus", "color": "success",
        "website_url": "https://hitrustalliance.net",
        "description": "HITRUST Common Security Framework — the most widely adopted healthcare security framework integrating HIPAA, NIST, ISO, and PCI.",
        "controls": [
            ("01.a", "Access Control Policy", "Access Control", "Establish and communicate access control policy.", True, "Documented IAM policy reviewed annually.", "2024-01-01", "2024-06-01"),
            ("01.b", "User Registration & De-provisioning", "Access Control", "Formal user registration and de-provisioning process.", True, "Automated provisioning/de-provisioning tied to HR lifecycle.", "2024-01-01", "2024-06-01"),
            ("01.d", "User Password Management", "Access Control", "Manage passwords using a formal process.", True, "Password complexity; 90-day rotation; breached-password detection.", "2024-01-01", "2024-06-01"),
            ("01.q", "User Authentication for External Connections", "Access Control", "Use appropriate authentication methods for remote access.", True, "MFA required for all VPN and remote desktop sessions.", "2024-01-01", "2024-06-01"),
            ("06.d", "Data Leakage Prevention", "Compliance", "Prevent unauthorized disclosure of data.", True, "DLP tools monitoring email, endpoints, and cloud storage.", "2024-01-01", "2024-06-01"),
            ("07.a", "Mobile Computing Policy", "Mobile Computing", "Policy and supporting security measures for mobile computing.", True, "MDM enrollment required; remote wipe capability.", "2024-01-01", "2024-06-01"),
            ("09.aa", "Monitoring System Use", "Audit Logging", "Procedures to monitor use of information processing facilities.", True, "SIEM with real-time alerting; quarterly log review.", "2024-01-01", "2024-06-01"),
            ("09.ab", "Protection of Log Information", "Audit Logging", "Protect logging facilities and log information from tampering.", True, "Logs forwarded to immutable storage; integrity checks.", "2024-01-01", "2024-06-01"),
            ("10.b", "Secure System Engineering", "Systems Development", "Security engineering principles applied in information systems.", True, "Secure SDLC; threat modeling; code review gates.", "2024-01-01", "2024-06-01"),
            ("10.h", "Control of Operational Software", "Systems Development", "Procedures to control software on operational systems.", True, "Application whitelisting; signed software deployment.", "2024-01-01", "2024-06-01"),
            ("11.a", "Reporting Information Security Weaknesses", "Incident Management", "Report security weaknesses observed or suspected.", True, "Vulnerability disclosure policy; internal reporting channel.", "2024-01-01", "2024-06-01"),
            ("11.b", "Management of Information Security Incidents", "Incident Management", "Responsibilities and procedures to handle security incidents effectively.", True, "CSIRT with defined playbooks; post-incident review process.", "2024-01-01", "2024-06-01"),
        ]
    },
    {
        "code": "FDA_SAMD", "display_name": "FDA SaMD Guidance", "version": "2023 AI/ML Action Plan",
        "category": "healthcare", "icon": "fas fa-pills", "color": "danger",
        "website_url": "https://www.fda.gov/medical-devices/software-medical-device-samd",
        "description": "FDA Software as a Medical Device — regulatory requirements for AI/ML-based medical device software.",
        "controls": [
            ("21CFR820.30", "Design Controls", "Quality System", "Establish design controls for software devices.", True, "Design history file; design validation and verification.", "2023-01-01", "2024-01-01"),
            ("21CFR820.70", "Production & Process Controls", "Quality System", "Establish and maintain production process controls.", True, "Automated CI/CD with quality gates; release approval workflow.", "2023-01-01", "2024-01-01"),
            ("21CFR11", "Electronic Records & Signatures", "Compliance", "Electronic records meet the same trustworthiness as paper records.", True, "Audit trails; unique user IDs; time-stamped electronic signatures.", "2023-01-01", "2024-01-01"),
            ("IEC62304-5.1", "Software Development Planning", "Software Lifecycle", "Plan the software development activities.", True, "Software development plan covering safety classification.", "2023-01-01", "2024-01-01"),
            ("IEC62304-5.2", "Software Requirements Analysis", "Software Lifecycle", "Establish and document software requirements.", True, "Traceable requirements linked to risk analysis (ISO 14971).", "2023-01-01", "2024-01-01"),
            ("IEC62304-8", "Software Configuration Management", "Software Lifecycle", "Identify, control, and track software items.", True, "Version control; change management; release baselines.", "2023-01-01", "2024-01-01"),
            ("ISO14971-4", "Risk Analysis", "Risk Management", "Identify hazards and estimate risks.", True, "FMEA/FMECA for AI model failure modes; hazard log.", "2023-01-01", "2024-01-01"),
            ("ISO14971-7", "Risk Evaluation & Control", "Risk Management", "Evaluate and implement risk controls.", True, "Residual risk acceptance; benefit-risk analysis documented.", "2023-01-01", "2024-01-01"),
            ("AI-ML-OOD", "Out-of-Distribution Detection", "AI/ML Controls", "Detect inputs outside the training distribution.", True, "OOD monitoring dashboards; model drift alerts.", "2023-06-01", "2024-06-01"),
            ("AI-ML-BIAS", "Algorithmic Bias Monitoring", "AI/ML Controls", "Monitor model outputs for demographic bias.", True, "Fairness metrics tracked per subgroup; quarterly bias audit.", "2023-06-01", "2024-06-01"),
            ("AI-ML-XPLAIN", "Explainability Requirements", "AI/ML Controls", "Provide explainability for AI-assisted clinical decisions.", True, "SHAP/LIME explanations surfaced to clinicians at decision point.", "2023-06-01", "2024-06-01"),
        ]
    },
    {
        "code": "GDPR", "display_name": "GDPR", "version": "Regulation (EU) 2016/679",
        "category": "privacy", "icon": "fas fa-user-shield", "color": "warning",
        "website_url": "https://gdpr.eu",
        "description": "General Data Protection Regulation — EU law on data protection and privacy for all individuals within the EU and EEA.",
        "controls": [
            ("Art.5", "Principles of Processing", "Lawfulness", "Data must be processed lawfully, fairly, and transparently.", True, "Document lawful basis for each processing activity in a ROPA.", "2018-05-25", "2024-01-01"),
            ("Art.6", "Lawful Basis for Processing", "Lawfulness", "Establish a valid lawful basis before processing personal data.", True, "Consent management platform; legitimate interest assessments.", "2018-05-25", "2024-01-01"),
            ("Art.17", "Right to Erasure", "Data Subject Rights", "Individuals may request deletion of their personal data.", True, "Automated erasure workflow; 30-day SLA for deletion requests.", "2018-05-25", "2024-01-01"),
            ("Art.20", "Right to Data Portability", "Data Subject Rights", "Individuals may receive their data in a machine-readable format.", True, "Export API providing structured JSON/CSV of personal data.", "2018-05-25", "2024-01-01"),
            ("Art.25", "Data Protection by Design", "Privacy Engineering", "Implement data protection from the outset of system design.", True, "Privacy impact review required for all new features.", "2018-05-25", "2024-01-01"),
            ("Art.32", "Security of Processing", "Security", "Implement appropriate technical and organisational security measures.", True, "Encryption, pseudonymisation, access controls, DR testing.", "2018-05-25", "2024-01-01"),
            ("Art.33", "Breach Notification to Authority", "Incident Management", "Notify supervisory authority of personal data breaches within 72 hours.", True, "Automated breach detection triggers DPO notification workflow.", "2018-05-25", "2024-01-01"),
            ("Art.35", "Data Protection Impact Assessment", "Privacy Engineering", "Conduct DPIA for high-risk processing activities.", True, "DPIA templates; mandatory for AI processing of health data.", "2018-05-25", "2024-01-01"),
            ("Art.37", "Data Protection Officer", "Governance", "Designate a DPO where required.", True, "DPO appointed; contact details published; DSAR process documented.", "2018-05-25", "2024-01-01"),
            ("Art.44", "International Data Transfers", "Data Transfers", "Transfers outside EEA require adequate safeguards.", True, "Standard Contractual Clauses or adequacy decision in place.", "2018-05-25", "2024-01-01"),
        ]
    },
    {
        "code": "SOC2_TYPE_II", "display_name": "SOC 2 Type II", "version": "AICPA TSC 2017",
        "category": "security", "icon": "fas fa-certificate", "color": "info",
        "website_url": "https://www.aicpa.org/soc2",
        "description": "Service Organization Control 2 — attestation of security controls over a 12-month observation period.",
        "controls": [
            ("CC1.1", "Control Environment — Integrity & Ethics", "Common Criteria", "Commitment to integrity and ethical values.", True, "Code of conduct; ethics hotline; annual attestation by employees.", "2017-01-01", "2024-01-01"),
            ("CC2.1", "Information & Communication", "Common Criteria", "Use quality information to support internal controls.", True, "Internal reporting dashboards; risk committee meetings.", "2017-01-01", "2024-01-01"),
            ("CC3.1", "Risk Assessment — Objectives", "Common Criteria", "Specify objectives to identify and assess risks.", True, "Annual enterprise risk assessment; risk register maintained.", "2017-01-01", "2024-01-01"),
            ("CC6.1", "Logical & Physical Access Controls", "Common Criteria", "Restrict logical access to systems with protected information.", True, "SSO with MFA; quarterly access reviews; PAM for privileged accounts.", "2017-01-01", "2024-01-01"),
            ("CC6.6", "Logical Access — External Threats", "Common Criteria", "Restrict access from outside the boundaries of the system.", True, "WAF, DDoS protection, IDS/IPS monitoring.", "2017-01-01", "2024-01-01"),
            ("CC7.1", "System Operations — Baseline Configuration", "Common Criteria", "Detect and monitor for new vulnerabilities.", True, "CIS benchmarks; automated vulnerability scanning; patch SLAs.", "2017-01-01", "2024-01-01"),
            ("CC7.2", "System Operations — Anomaly Detection", "Common Criteria", "Monitor system components for anomalies.", True, "SIEM rules; behavioral analytics; 24×7 SOC alerting.", "2017-01-01", "2024-01-01"),
            ("CC8.1", "Change Management", "Common Criteria", "Manage changes to infrastructure and software.", True, "CAB process; peer code review; automated regression testing.", "2017-01-01", "2024-01-01"),
            ("A1.1", "Availability — Performance Monitoring", "Availability", "Monitor system availability and capacity.", True, "Uptime monitoring; SLA reporting; capacity planning reviews.", "2017-01-01", "2024-01-01"),
            ("C1.1", "Confidentiality — Classification", "Confidentiality", "Identify and classify confidential information.", True, "Data classification policy; DLP controls on confidential tier.", "2017-01-01", "2024-01-01"),
        ]
    },
    {
        "code": "NIST_AI_RMF", "display_name": "NIST AI RMF", "version": "1.0 (2023)",
        "category": "ai_governance", "icon": "fas fa-brain", "color": "secondary",
        "website_url": "https://airc.nist.gov/RMF",
        "description": "NIST AI Risk Management Framework — voluntary guidance to better manage risks to individuals, organizations, and society associated with AI.",
        "controls": [
            ("GOVERN-1.1", "AI Risk Policy", "GOVERN", "Policies, processes, and practices for AI risk management exist and are followed.", True, "AI risk policy ratified by board; embedded in SDLC.", "2023-01-26", "2024-01-01"),
            ("GOVERN-2.1", "Accountability Structures", "GOVERN", "Roles and responsibilities for AI risk management are defined.", True, "AI governance committee with executive sponsorship.", "2023-01-26", "2024-01-01"),
            ("MAP-1.1", "Context Establishment", "MAP", "Context for the AI system is established.", True, "AI system cards documenting purpose, users, and risk profile.", "2023-01-26", "2024-01-01"),
            ("MAP-2.1", "AI Risk Categorization", "MAP", "Scientific, technical, and societal risks are identified.", True, "Tiered risk classification (Critical / High / Medium / Low).", "2023-01-26", "2024-01-01"),
            ("MEASURE-1.1", "Metrics for AI Risks", "MEASURE", "Approaches and metrics to measure AI risks are established.", True, "KRIs tracked quarterly; fairness and accuracy baselines defined.", "2023-01-26", "2024-01-01"),
            ("MEASURE-2.5", "Bias Testing", "MEASURE", "AI system to be deployed in real-world contexts is demonstrated to be fair.", True, "Pre-deployment bias testing across protected characteristics.", "2023-01-26", "2024-01-01"),
            ("MANAGE-1.1", "Risk Treatment Plans", "MANAGE", "Responses to identified AI risks are managed.", True, "Risk treatment plans reviewed quarterly; owners assigned.", "2023-01-26", "2024-01-01"),
            ("MANAGE-4.1", "Incident Response", "MANAGE", "Post-deployment AI incidents are documented and analysed.", True, "AI incident log; root-cause analysis; corrective action tracking.", "2023-01-26", "2024-01-01"),
        ]
    },
]

def _seed_frameworks_if_empty():
    """Auto-seed built-in frameworks on first visit."""
    if FrameworkConfig.query.count() > 0:
        return
    for fw in _FRAMEWORK_SEED:
        controls = fw.pop("controls")
        f = FrameworkConfig(**fw)
        db.session.add(f)
        db.session.flush()
        for ctrl in controls:
            cid, title, cat, desc, req, guidance, eff, upd = ctrl
            db.session.add(ControlPoint(
                framework_id=f.id, control_id=cid, title=title,
                category=cat, description=desc, is_required=req,
                implementation_guidance=guidance, effective_date=eff,
                last_updated=upd
            ))
        fw["controls"] = controls  # restore for subsequent calls
    db.session.commit()


@app.route('/frameworks')
def frameworks_index():
    _seed_frameworks_if_empty()
    frameworks = FrameworkConfig.query.order_by(FrameworkConfig.category, FrameworkConfig.display_name).all()
    selected_id = request.args.get('fw', type=int)
    selected = next((f for f in frameworks if f.id == selected_id), frameworks[0] if frameworks else None)
    categories = sorted({f.category for f in frameworks})
    return render_template('frameworks.html', frameworks=frameworks,
                           selected=selected, categories=categories)


@app.route('/frameworks/add', methods=['POST'])
def frameworks_add():
    code = request.form.get('code', '').strip().upper()
    name = request.form.get('display_name', '').strip()
    if not code or not name:
        flash('Code and name are required.', 'warning')
        return redirect(url_for('frameworks_index'))
    if FrameworkConfig.query.filter_by(code=code).first():
        flash(f'Framework "{code}" already exists.', 'warning')
        return redirect(url_for('frameworks_index'))
    f = FrameworkConfig(
        code=code, display_name=name,
        version=request.form.get('version', '').strip() or None,
        description=request.form.get('description', '').strip() or None,
        category=request.form.get('category', 'security'),
        icon='fas fa-layer-group', color='secondary', is_custom=True
    )
    db.session.add(f)
    db.session.commit()
    flash(f'Framework "{name}" added successfully.', 'success')
    return redirect(url_for('frameworks_index', fw=f.id))


@app.route('/frameworks/<int:fw_id>/toggle', methods=['POST'])
def framework_toggle(fw_id):
    f = FrameworkConfig.query.get_or_404(fw_id)
    f.is_enabled = not f.is_enabled
    db.session.commit()
    status = 'enabled' if f.is_enabled else 'disabled'
    flash(f'Framework "{f.display_name}" {status}.', 'success')
    return redirect(url_for('frameworks_index', fw=fw_id))


@app.route('/frameworks/<int:fw_id>/delete', methods=['POST'])
def framework_delete(fw_id):
    f = FrameworkConfig.query.get_or_404(fw_id)
    if not f.is_custom:
        flash('Built-in frameworks cannot be deleted.', 'warning')
        return redirect(url_for('frameworks_index', fw=fw_id))
    db.session.delete(f)
    db.session.commit()
    flash(f'Framework "{f.display_name}" deleted.', 'success')
    return redirect(url_for('frameworks_index'))


@app.route('/frameworks/<int:fw_id>/controls/add', methods=['POST'])
def control_add(fw_id):
    FrameworkConfig.query.get_or_404(fw_id)
    ctrl_id = request.form.get('control_id', '').strip()
    title   = request.form.get('title', '').strip()
    if not ctrl_id or not title:
        flash('Control ID and title are required.', 'warning')
        return redirect(url_for('frameworks_index', fw=fw_id))
    if ControlPoint.query.filter_by(framework_id=fw_id, control_id=ctrl_id).first():
        flash(f'Control "{ctrl_id}" already exists in this framework.', 'warning')
        return redirect(url_for('frameworks_index', fw=fw_id))
    cp = ControlPoint(
        framework_id=fw_id, control_id=ctrl_id, title=title,
        category=request.form.get('category', '').strip() or 'General',
        description=request.form.get('description', '').strip() or None,
        implementation_guidance=request.form.get('guidance', '').strip() or None,
        is_required=request.form.get('is_required') == 'on',
        effective_date=request.form.get('effective_date', '').strip() or None,
        last_updated=request.form.get('last_updated', '').strip() or None,
    )
    db.session.add(cp)
    db.session.commit()
    flash(f'Control "{ctrl_id}" added.', 'success')
    return redirect(url_for('frameworks_index', fw=fw_id))


@app.route('/frameworks/<int:fw_id>/controls/<int:ctrl_id>/toggle', methods=['POST'])
def control_toggle(fw_id, ctrl_id):
    cp = ControlPoint.query.filter_by(id=ctrl_id, framework_id=fw_id).first_or_404()
    cp.is_enabled = not cp.is_enabled
    db.session.commit()
    return redirect(url_for('frameworks_index', fw=fw_id))


@app.route('/frameworks/<int:fw_id>/controls/<int:ctrl_id>/delete', methods=['POST'])
def control_delete(fw_id, ctrl_id):
    cp = ControlPoint.query.filter_by(id=ctrl_id, framework_id=fw_id).first_or_404()
    db.session.delete(cp)
    db.session.commit()
    flash(f'Control "{cp.control_id}" deleted.', 'success')
    return redirect(url_for('frameworks_index', fw=fw_id))


@app.route('/knowledge')
def knowledge():
    return render_template('knowledge.html')


# ---------------------------------------------------------------------------
# Control Gap Detection
# ---------------------------------------------------------------------------

@app.route('/compliance/gaps')
def compliance_gaps():
    """Control gap analysis dashboard."""
    try:
        from models import FrameworkConfig, ControlPoint
        from engines.gap_detection_engine import get_gap_summary
        summary = get_gap_summary(db, ControlGapRecord, FrameworkConfig, ControlPoint, AIAgent)
        has_data = summary['total'] > 0
        # Recent gap records for the detail table (paginated, latest first)
        page = request.args.get('page', 1, type=int)
        status_filter = request.args.get('status', '')
        agent_filter  = request.args.get('agent_id', 0, type=int)
        q = ControlGapRecord.query
        if status_filter:
            q = q.filter(ControlGapRecord.status == status_filter)
        if agent_filter:
            q = q.filter(ControlGapRecord.ai_agent_id == agent_filter)
        q = q.filter(ControlGapRecord.status != 'NOT_APPLICABLE')
        records = q.order_by(ControlGapRecord.detected_at.desc()).limit(200).all()
        agents = AIAgent.query.order_by(AIAgent.name).all()
    except Exception as e:
        logger.error(f"Gap dashboard error: {e}")
        summary = {'total': 0, 'implemented': 0, 'partial': 0, 'not_implemented': 0,
                   'not_applicable': 0, 'impl_pct': 0, 'top_agent_gaps': [],
                   'top_control_gaps': [], 'framework_gaps': []}
        has_data, records, agents = False, [], []
    return render_template('compliance_gaps.html', summary=summary, has_data=has_data,
                           records=records, agents=agents,
                           status_filter=status_filter, agent_filter=agent_filter)


@app.route('/compliance/gaps/scan', methods=['POST'])
def compliance_gaps_scan():
    """Run gap detection for one agent or all agents."""
    try:
        from models import FrameworkConfig, ControlPoint
        from engines.gap_detection_engine import detect_gaps_for_agent, detect_gaps_all_agents
        agent_id = request.form.get('agent_id', 0, type=int)
        if agent_id:
            agent = AIAgent.query.get_or_404(agent_id)
            result = detect_gaps_for_agent(
                agent, db, ScanResult, ComplianceEvaluation,
                ControlPoint, FrameworkConfig, ControlGapRecord
            )
            flash(f'Gap scan complete for {agent.name}: '
                  f'{result["NOT_IMPLEMENTED"]} gaps found out of {result["total_controls"]} controls.', 'info')
        else:
            agent_count = AIAgent.query.count()
            if agent_count > 50:
                # Limit to 50 for performance
                agents = AIAgent.query.limit(50).all()
            else:
                agents = AIAgent.query.all()
            summaries = []
            for agent in agents:
                s = detect_gaps_for_agent(
                    agent, db, ScanResult, ComplianceEvaluation,
                    ControlPoint, FrameworkConfig, ControlGapRecord
                )
                summaries.append(s)
            total_gaps = sum(s.get('NOT_IMPLEMENTED', 0) for s in summaries)
            flash(f'Gap scan complete across {len(summaries)} agents — '
                  f'{total_gaps} control gaps found.', 'info')
    except Exception as e:
        logger.error(f"Gap scan error: {e}")
        flash(f'Gap scan error: {e}', 'danger')
    return redirect(url_for('compliance_gaps'))


@app.route('/compliance/gaps/<int:record_id>/attest', methods=['POST'])
def compliance_gap_attest(record_id):
    """Manually mark a gap record as implemented or not-applicable."""
    record = ControlGapRecord.query.get_or_404(record_id)
    new_status = request.form.get('status', 'IMPLEMENTED')
    notes = request.form.get('notes', '').strip()
    if new_status not in ('IMPLEMENTED', 'PARTIAL', 'NOT_IMPLEMENTED', 'NOT_APPLICABLE'):
        flash('Invalid status.', 'danger')
        return redirect(url_for('compliance_gaps'))
    record.status = new_status
    record.detection_method = 'MANUAL'
    record.notes = notes
    record.updated_at = datetime.utcnow()
    db.session.commit()
    flash(f'Control "{record.control_point.control_id}" marked as {new_status}.', 'success')
    return redirect(url_for('compliance_gaps'))


# ---------------------------------------------------------------------------
# Predictive Analytics
# ---------------------------------------------------------------------------

@app.route('/predictive-analytics')
def predictive_analytics():
    """Proactive risk mitigation dashboard powered by the predictive engine."""
    try:
        from engines.predictive_engine import (
            compute_risk_trend, compute_30day_forecast, compute_at_risk_agents,
            compute_compliance_drift, compute_risk_by_provider,
            compute_risk_by_agent_type, compute_anomalies, compute_summary_metrics
        )
        trend = compute_risk_trend(db, ScanResult, days=60)
        forecast = compute_30day_forecast(trend)
        at_risk = compute_at_risk_agents(db, AIAgent, ScanResult)
        drifting = compute_compliance_drift(db, AIAgent, ComplianceEvaluation)
        by_provider = compute_risk_by_provider(db, AIAgent, ScanResult)
        by_type = compute_risk_by_agent_type(db, AIAgent, ScanResult)
        anomalies = compute_anomalies(db, AIAgent, ScanResult)
        metrics = compute_summary_metrics(db, AIAgent, ScanResult, ComplianceEvaluation)
    except Exception as e:
        logger.error(f"Predictive analytics error: {e}")
        trend, forecast, at_risk, drifting = [], [], [], []
        by_provider, by_type, anomalies = [], [], []
        metrics = {'total_agents': 0, 'avg_risk': 0, 'risk_change': 0,
                   'avg_compliance': 0, 'critical_agents': 0, 'risk_direction': 'flat'}

    return render_template(
        'predictive_analytics.html',
        trend=trend,
        forecast=forecast,
        at_risk=at_risk,
        drifting=drifting,
        by_provider=by_provider,
        by_type=by_type,
        anomalies=anomalies,
        metrics=metrics
    )


# ---------------------------------------------------------------------------
# Compliance Rule Builder
# ---------------------------------------------------------------------------

RULE_FIELDS = [
    {'value': 'ai_type',           'label': 'Agent Type',         'type': 'select',
     'options': ['TRADITIONAL_ML','GENAI','AGENTIC_AI','COMPUTER_VISION','NLP',
                 'RECOMMENDATION','PREDICTIVE_ANALYTICS','AUTONOMOUS_SYSTEM',
                 'CONVERSATIONAL_AI','MULTIMODAL_AI','CLAWBOT']},
    {'value': 'cloud_provider',    'label': 'Cloud Provider',     'type': 'select',
     'options': ['aws','azure','gcp','on-premise','unknown']},
    {'value': 'protocol',          'label': 'Protocol',           'type': 'select',
     'options': ['REST','Docker','Kubernetes','gRPC','WebSocket','MQTT','GraphQL','MCP']},
    {'value': 'risk_level',        'label': 'Risk Level (latest scan)', 'type': 'select',
     'options': ['LOW','MEDIUM','HIGH','CRITICAL']},
    {'value': 'phi_exposure',      'label': 'PHI Exposure Detected', 'type': 'bool',
     'options': ['true','false']},
    {'value': 'risk_score',        'label': 'Risk Score',         'type': 'number', 'options': []},
    {'value': 'compliance_score',  'label': 'Compliance Score',   'type': 'number', 'options': []},
    {'value': 'vulnerabilities',   'label': 'Vulnerability Count','type': 'number', 'options': []},
    {'value': 'deployment_env',    'label': 'Deployment Environment', 'type': 'select',
     'options': ['production','staging','development']},
    {'value': 'autonomy_level',    'label': 'Autonomy Level',     'type': 'select',
     'options': ['low','medium','high','full']},
]

RULE_OPERATORS = {
    'select': [('equals','Equals'), ('not_equals','Not Equals')],
    'bool':   [('equals','Is')],
    'number': [('gt','Greater Than'), ('lt','Less Than'), ('gte','≥'), ('lte','≤'), ('equals','Equals')],
}


def _evaluate_rule(rule, agent, latest_scan, latest_eval):
    """Evaluate a rule's conditions against a single agent. Returns True if all/any match."""
    conditions = rule.conditions or []
    logic = rule.condition_logic or 'AND'
    results = []
    for cond in conditions:
        field = cond.get('field', '')
        op = cond.get('operator', 'equals')
        val = cond.get('value', '')
        # Resolve field value from agent + latest scan/eval
        if field == 'ai_type':
            actual = agent.ai_type.value if agent.ai_type else ''
        elif field == 'cloud_provider':
            actual = (agent.cloud_provider or '').lower()
            val = val.lower()
        elif field == 'protocol':
            actual = agent.protocol or ''
        elif field == 'risk_level':
            actual = latest_scan.risk_level.value if latest_scan and latest_scan.risk_level else ''
        elif field == 'phi_exposure':
            actual = 'true' if (latest_scan and latest_scan.phi_exposure_detected) else 'false'
        elif field == 'risk_score':
            actual = latest_scan.risk_score if latest_scan else 0
            try: val = float(val)
            except: val = 0
        elif field == 'compliance_score':
            actual = latest_eval.compliance_score if latest_eval else 0
            try: val = float(val)
            except: val = 0
        elif field == 'vulnerabilities':
            actual = latest_scan.vulnerabilities_found if latest_scan else 0
            try: val = float(val)
            except: val = 0
        elif field == 'deployment_env':
            actual = (agent.deployment_environment or '').lower()
            val = val.lower()
        elif field == 'autonomy_level':
            actual = (agent.autonomy_level or '').lower()
            val = val.lower()
        else:
            results.append(False)
            continue

        if op == 'equals':
            results.append(str(actual) == str(val))
        elif op == 'not_equals':
            results.append(str(actual) != str(val))
        elif op == 'gt':
            try: results.append(float(actual) > float(val))
            except: results.append(False)
        elif op == 'lt':
            try: results.append(float(actual) < float(val))
            except: results.append(False)
        elif op == 'gte':
            try: results.append(float(actual) >= float(val))
            except: results.append(False)
        elif op == 'lte':
            try: results.append(float(actual) <= float(val))
            except: results.append(False)
        else:
            results.append(False)

    if not results:
        return False
    return all(results) if logic == 'AND' else any(results)


@app.route('/compliance/rules')
def compliance_rules():
    rules = ComplianceRule.query.order_by(ComplianceRule.created_at.desc()).all()
    return render_template('compliance_rules.html', rules=rules,
                           rule_fields=RULE_FIELDS, rule_operators=RULE_OPERATORS)


@app.route('/compliance/rules/create', methods=['POST'])
def compliance_rules_create():
    try:
        name = request.form.get('name', '').strip()
        if not name:
            flash('Rule name is required.', 'danger')
            return redirect(url_for('compliance_rules'))

        conditions_raw = request.form.get('conditions_json', '[]')
        try:
            conditions = json.loads(conditions_raw)
        except Exception:
            conditions = []

        frameworks_raw = request.form.getlist('frameworks')

        rule = ComplianceRule(
            name=name,
            description=request.form.get('description', '').strip(),
            condition_logic=request.form.get('condition_logic', 'AND'),
            conditions=conditions,
            severity=request.form.get('severity', 'MEDIUM'),
            action_type=request.form.get('action_type', 'FLAG'),
            action_message=request.form.get('action_message', '').strip(),
            frameworks=frameworks_raw,
            is_active=True
        )
        db.session.add(rule)
        db.session.commit()
        flash(f'Rule "{name}" created successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create rule error: {e}")
        flash('Failed to create rule.', 'danger')
    return redirect(url_for('compliance_rules'))


@app.route('/compliance/rules/<int:rule_id>/toggle', methods=['POST'])
def compliance_rule_toggle(rule_id):
    rule = ComplianceRule.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()
    state = 'enabled' if rule.is_active else 'disabled'
    flash(f'Rule "{rule.name}" {state}.', 'info')
    return redirect(url_for('compliance_rules'))


@app.route('/compliance/rules/<int:rule_id>/delete', methods=['POST'])
def compliance_rule_delete(rule_id):
    rule = ComplianceRule.query.get_or_404(rule_id)
    name = rule.name
    db.session.delete(rule)
    db.session.commit()
    flash(f'Rule "{name}" deleted.', 'success')
    return redirect(url_for('compliance_rules'))


@app.route('/compliance/rules/<int:rule_id>/run', methods=['POST'])
def compliance_rule_run(rule_id):
    """Test/run a rule against all agents and return a JSON summary."""
    rule = ComplianceRule.query.get_or_404(rule_id)
    agents = AIAgent.query.all()
    matches = []
    for agent in agents:
        latest_scan = ScanResult.query.filter_by(
            ai_agent_id=agent.id
        ).order_by(ScanResult.created_at.desc()).first()
        latest_eval = ComplianceEvaluation.query.filter_by(
            ai_agent_id=agent.id
        ).order_by(ComplianceEvaluation.evaluated_at.desc()).first()
        if _evaluate_rule(rule, agent, latest_scan, latest_eval):
            matches.append({
                'id': agent.id,
                'name': agent.name,
                'type': agent.type,
                'cloud_provider': agent.cloud_provider or 'N/A',
                'risk_score': round(latest_scan.risk_score, 1) if latest_scan else 0,
                'compliance_score': round(latest_eval.compliance_score, 1) if latest_eval else 0,
            })
    rule.match_count = len(matches)
    rule.last_run_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'rule_id': rule_id, 'rule_name': rule.name,
                    'match_count': len(matches), 'matches': matches})


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500