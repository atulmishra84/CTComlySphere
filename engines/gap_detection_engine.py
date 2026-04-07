"""
Control Gap Detection Engine
============================
Automatically determines whether each compliance control point is
implemented on a given AI agent by inspecting agent properties,
scan results, and compliance evaluations as evidence.

Status values:
  IMPLEMENTED      – evidence confirms the control is in place
  PARTIAL          – some evidence exists but not complete
  NOT_IMPLEMENTED  – no evidence found; gap confirmed
  NOT_APPLICABLE   – control does not apply to this agent type
"""

from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Keyword → evidence mapping
# Each entry is a tuple: (keywords_in_control_title_or_category, check_fn)
# check_fn(agent, latest_scan, latest_eval, all_scans) → (status, evidence_dict)
# ---------------------------------------------------------------------------

def _check_audit_logging(agent, scan, eval_, scans):
    if agent.audit_logging:
        return 'IMPLEMENTED', {'audit_logging': True}
    if agent.compliance_controls and any(
        'audit' in str(k).lower() for k in (agent.compliance_controls or {})
    ):
        return 'PARTIAL', {'compliance_controls_mention': True, 'audit_logging_field': False}
    return 'NOT_IMPLEMENTED', {'audit_logging': False, 'hint': 'Set audit_logging=True on the agent'}


def _check_access_control(agent, scan, eval_, scans):
    if agent.authentication_method and agent.authentication_method.lower() not in ('none', 'unknown', ''):
        return 'IMPLEMENTED', {'authentication_method': agent.authentication_method}
    if agent.authorization_scope:
        return 'PARTIAL', {'authorization_scope_set': True, 'auth_method_missing': True}
    return 'NOT_IMPLEMENTED', {'authentication_method': None,
                               'hint': 'No authentication method recorded for this agent'}


def _check_encryption(agent, scan, eval_, scans):
    enc = getattr(agent, 'encryption_status', None)
    if enc and enc.lower() not in ('none', 'disabled', 'unknown', ''):
        return 'IMPLEMENTED', {'encryption_status': enc}
    if agent.compliance_controls and any(
        'encrypt' in str(v).lower() for v in (agent.compliance_controls or {}).values()
    ):
        return 'PARTIAL', {'mentioned_in_compliance_controls': True, 'encryption_status_field': enc}
    return 'NOT_IMPLEMENTED', {'encryption_status': enc,
                               'hint': 'No encryption status recorded; verify TLS/at-rest encryption'}


def _check_phi_protection(agent, scan, eval_, scans):
    if not scans:
        return 'NOT_APPLICABLE', {'reason': 'No scans available to assess PHI exposure'}
    phi_exposures = [s for s in scans if s.phi_exposure_detected]
    if not phi_exposures:
        return 'IMPLEMENTED', {'phi_exposures_detected': 0, 'scans_checked': len(scans)}
    return 'NOT_IMPLEMENTED', {
        'phi_exposures_detected': len(phi_exposures),
        'scans_checked': len(scans),
        'hint': f'PHI exposure detected in {len(phi_exposures)} scan(s)'
    }


def _check_risk_assessment(agent, scan, eval_, scans):
    if scans:
        latest = scans[-1]
        return 'IMPLEMENTED', {
            'scan_count': len(scans),
            'latest_risk_score': round(latest.risk_score, 1),
            'latest_scan_date': str(latest.created_at.date()) if latest.created_at else None
        }
    return 'NOT_IMPLEMENTED', {'scan_count': 0,
                                'hint': 'Run a security scan to satisfy risk assessment requirement'}


def _check_vulnerability_management(agent, scan, eval_, scans):
    if not scan:
        return 'NOT_IMPLEMENTED', {'hint': 'No scan results available'}
    if scan.vulnerabilities_found == 0:
        return 'IMPLEMENTED', {'vulnerabilities_found': 0}
    if scan.vulnerabilities_found <= 3:
        return 'PARTIAL', {'vulnerabilities_found': scan.vulnerabilities_found,
                           'hint': 'Low vulnerability count; remediation recommended'}
    return 'NOT_IMPLEMENTED', {'vulnerabilities_found': scan.vulnerabilities_found,
                                'hint': 'Unresolved vulnerabilities detected'}


def _check_incident_response(agent, scan, eval_, scans):
    from models import RemediationWorkflow
    workflows = RemediationWorkflow.query.filter_by(agent_id=agent.id).count() if hasattr(RemediationWorkflow, 'agent_id') else 0
    if agent.safety_measures:
        measures = agent.safety_measures if isinstance(agent.safety_measures, list) else list(agent.safety_measures)
        incident_related = [m for m in measures if any(
            kw in str(m).lower() for kw in ('incident', 'response', 'alert', 'notify', 'escalat')
        )]
        if incident_related:
            return 'IMPLEMENTED', {'safety_measures': incident_related}
        return 'PARTIAL', {'safety_measures_count': len(measures),
                           'hint': 'Safety measures present but none specifically for incident response'}
    return 'NOT_IMPLEMENTED', {'hint': 'No incident response safety measures recorded on agent'}


def _check_data_minimisation(agent, scan, eval_, scans):
    if agent.data_access_permissions:
        perms = agent.data_access_permissions
        count = len(perms) if isinstance(perms, (list, dict)) else 0
        return ('IMPLEMENTED' if count < 5 else 'PARTIAL'), {
            'data_access_permissions_count': count,
            'hint': 'Permissions recorded; validate scope is minimal'
        }
    return 'NOT_IMPLEMENTED', {'hint': 'No data access permissions recorded; cannot verify minimisation'}


def _check_safety_measures(agent, scan, eval_, scans):
    if agent.safety_measures:
        measures = agent.safety_measures if isinstance(agent.safety_measures, list) else list(agent.safety_measures)
        return 'IMPLEMENTED', {'safety_measures': measures}
    return 'NOT_IMPLEMENTED', {'hint': 'No safety measures recorded on this agent'}


def _check_compliance_evaluation(agent, scan, eval_, scans):
    if eval_ and eval_.compliance_score >= 80:
        return 'IMPLEMENTED', {'compliance_score': round(eval_.compliance_score, 1)}
    if eval_ and eval_.compliance_score >= 50:
        return 'PARTIAL', {'compliance_score': round(eval_.compliance_score, 1),
                           'hint': 'Compliance score below 80%; improvements needed'}
    if eval_:
        return 'NOT_IMPLEMENTED', {'compliance_score': round(eval_.compliance_score, 1),
                                    'hint': 'Compliance score critically low'}
    return 'NOT_IMPLEMENTED', {'hint': 'No compliance evaluation has been run for this agent'}


def _check_monitoring(agent, scan, eval_, scans):
    thirty_ago = datetime.utcnow() - timedelta(days=30)
    recent = [s for s in scans if s.created_at and s.created_at >= thirty_ago]
    if len(recent) >= 3:
        return 'IMPLEMENTED', {'scans_last_30_days': len(recent)}
    if recent:
        return 'PARTIAL', {'scans_last_30_days': len(recent),
                           'hint': 'Some recent scans found; increase scan frequency'}
    return 'NOT_IMPLEMENTED', {'scans_last_30_days': 0,
                                'hint': 'No scans in last 30 days; enable continuous monitoring'}


def _check_resource_limits(agent, scan, eval_, scans):
    if agent.resource_limits:
        limits = agent.resource_limits
        return 'IMPLEMENTED', {'resource_limits': limits}
    return 'NOT_IMPLEMENTED', {'hint': 'No resource limits (CPU/memory/rate) recorded on agent'}


def _check_network_security(agent, scan, eval_, scans):
    if agent.network_access:
        return 'PARTIAL', {'network_access_defined': True,
                           'hint': 'Network access documented; verify firewall rules are enforced'}
    return 'NOT_IMPLEMENTED', {'hint': 'No network access rules documented for this agent'}


# ---------------------------------------------------------------------------
# Keyword routing table
# Each entry: (keyword_list, check_function)
# The engine scores keywords against the control's title + category text.
# ---------------------------------------------------------------------------
KEYWORD_CHECKS = [
    (['audit', 'logging', 'log trail', 'activity log'],         _check_audit_logging),
    (['access control', 'authentication', 'authorization',
      'identity', 'user access', 'least privilege'],            _check_access_control),
    (['encrypt', 'transmission security', 'tls', 'at-rest'],    _check_encryption),
    (['phi', 'protected health', 'data protection',
      'personal data', 'sensitive data'],                        _check_phi_protection),
    (['risk assessment', 'risk analysis', 'risk management'],   _check_risk_assessment),
    (['vulnerability', 'patch', 'security scan'],               _check_vulnerability_management),
    (['incident', 'response plan', 'breach', 'contingency'],    _check_incident_response),
    (['data minim', 'data retention', 'data access', 'scope'],  _check_data_minimisation),
    (['safety', 'guardrail', 'safeguard', 'control measure'],   _check_safety_measures),
    (['compliance score', 'evaluation', 'assessment result'],   _check_compliance_evaluation),
    (['monitor', 'continuous scan', 'surveillance', 'alert'],   _check_monitoring),
    (['resource limit', 'rate limit', 'throttl', 'quota'],      _check_resource_limits),
    (['network', 'firewall', 'connectivity', 'endpoint security'], _check_network_security),
]

_FALLBACK_NOT_APPLICABLE_KEYWORDS = [
    'training', 'workforce', 'physical safeguard', 'facility',
    'contingency plan', 'disaster recovery', 'business continuity',
    'sanction policy', 'documentation policy',
]


def _pick_check(control_point):
    """Return the best matching check function for a ControlPoint."""
    text = f"{control_point.title} {control_point.category or ''}".lower()
    best_fn = None
    best_score = 0
    for keywords, fn in KEYWORD_CHECKS:
        score = sum(1 for kw in keywords if kw in text)
        if score > best_score:
            best_score = score
            best_fn = fn
    if best_score == 0:
        # Check if it's inherently not auto-detectable
        for kw in _FALLBACK_NOT_APPLICABLE_KEYWORDS:
            if kw in text:
                return None, True   # (no fn, is_not_applicable)
        return None, False          # (no fn, not not_applicable)
    return best_fn, False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_gaps_for_agent(agent, db, ScanResult, ComplianceEvaluation, ControlPoint,
                           FrameworkConfig, ControlGapRecord, framework_ids=None):
    """
    Run gap detection for a single agent across all enabled control points.
    Upserts ControlGapRecord rows.
    Returns a summary dict.
    """
    # Fetch evidence once
    all_scans   = ScanResult.query.filter_by(ai_agent_id=agent.id).order_by(ScanResult.created_at).all()
    latest_scan = all_scans[-1] if all_scans else None
    latest_eval = ComplianceEvaluation.query.filter_by(
        ai_agent_id=agent.id).order_by(ComplianceEvaluation.evaluated_at.desc()).first()

    # Get enabled frameworks (optionally filtered)
    fw_query = FrameworkConfig.query.filter_by(is_enabled=True)
    if framework_ids:
        fw_query = fw_query.filter(FrameworkConfig.id.in_(framework_ids))
    frameworks = fw_query.all()

    counts = {'IMPLEMENTED': 0, 'PARTIAL': 0, 'NOT_IMPLEMENTED': 0, 'NOT_APPLICABLE': 0}

    for fw in frameworks:
        controls = ControlPoint.query.filter_by(
            framework_id=fw.id, is_enabled=True).all()

        for cp in controls:
            check_fn, is_na = _pick_check(cp)

            if is_na:
                status, evidence = 'NOT_APPLICABLE', {'reason': 'Cannot be auto-detected; requires manual attestation'}
            elif check_fn is None:
                status, evidence = 'NOT_IMPLEMENTED', {'reason': 'No automated check available; manual review required'}
            else:
                try:
                    status, evidence = check_fn(agent, latest_scan, latest_eval, all_scans)
                except Exception as e:
                    status, evidence = 'NOT_IMPLEMENTED', {'error': str(e)}

            # Upsert
            record = ControlGapRecord.query.filter_by(
                ai_agent_id=agent.id, control_point_id=cp.id
            ).first()
            if record:
                record.status      = status
                record.evidence    = evidence
                record.detected_at = datetime.utcnow()
                record.updated_at  = datetime.utcnow()
            else:
                record = ControlGapRecord(
                    ai_agent_id=agent.id,
                    framework_id=fw.id,
                    control_point_id=cp.id,
                    status=status,
                    detection_method='AUTO',
                    evidence=evidence,
                    detected_at=datetime.utcnow()
                )
                db.session.add(record)

            counts[status] = counts.get(status, 0) + 1

    db.session.commit()
    total = sum(counts.values())
    return {
        'agent_id': agent.id,
        'agent_name': agent.name,
        'total_controls': total,
        **counts,
        'gap_pct': round(counts['NOT_IMPLEMENTED'] / total * 100, 1) if total else 0
    }


def detect_gaps_all_agents(app_context, db, AIAgent, ScanResult,
                            ComplianceEvaluation, ControlPoint,
                            FrameworkConfig, ControlGapRecord):
    """Run gap detection for every agent. Returns list of per-agent summaries."""
    agents = AIAgent.query.all()
    summaries = []
    for agent in agents:
        try:
            summary = detect_gaps_for_agent(
                agent, db, ScanResult, ComplianceEvaluation,
                ControlPoint, FrameworkConfig, ControlGapRecord
            )
            summaries.append(summary)
        except Exception as e:
            summaries.append({'agent_id': agent.id, 'agent_name': agent.name, 'error': str(e)})
    return summaries


def get_gap_summary(db, ControlGapRecord, FrameworkConfig, ControlPoint, AIAgent):
    """Aggregate gap statistics across all agents for the dashboard."""
    from sqlalchemy import func

    total      = ControlGapRecord.query.count()
    not_impl   = ControlGapRecord.query.filter_by(status='NOT_IMPLEMENTED').count()
    partial    = ControlGapRecord.query.filter_by(status='PARTIAL').count()
    implemented = ControlGapRecord.query.filter_by(status='IMPLEMENTED').count()
    not_app    = ControlGapRecord.query.filter_by(status='NOT_APPLICABLE').count()

    # Top agents with most gaps
    top_gaps = db.session.query(
        AIAgent.id, AIAgent.name,
        func.count(ControlGapRecord.id).label('gap_count')
    ).join(ControlGapRecord, ControlGapRecord.ai_agent_id == AIAgent.id
    ).filter(ControlGapRecord.status == 'NOT_IMPLEMENTED'
    ).group_by(AIAgent.id, AIAgent.name
    ).order_by(func.count(ControlGapRecord.id).desc()
    ).limit(8).all()

    # Most commonly unimplemented controls
    top_controls = db.session.query(
        ControlPoint.control_id, ControlPoint.title,
        func.count(ControlGapRecord.id).label('gap_count')
    ).join(ControlGapRecord, ControlGapRecord.control_point_id == ControlPoint.id
    ).filter(ControlGapRecord.status == 'NOT_IMPLEMENTED'
    ).group_by(ControlPoint.id, ControlPoint.control_id, ControlPoint.title
    ).order_by(func.count(ControlGapRecord.id).desc()
    ).limit(10).all()

    # Gap % by framework
    fw_gaps = []
    for fw in FrameworkConfig.query.filter_by(is_enabled=True).all():
        fw_total = ControlGapRecord.query.filter_by(framework_id=fw.id).count()
        fw_not_impl = ControlGapRecord.query.filter_by(
            framework_id=fw.id, status='NOT_IMPLEMENTED').count()
        if fw_total:
            fw_gaps.append({
                'name': fw.display_name,
                'total': fw_total,
                'not_implemented': fw_not_impl,
                'gap_pct': round(fw_not_impl / fw_total * 100, 1)
            })

    return {
        'total': total,
        'implemented': implemented,
        'partial': partial,
        'not_implemented': not_impl,
        'not_applicable': not_app,
        'impl_pct': round(implemented / total * 100, 1) if total else 0,
        'top_agent_gaps': [
            {'id': r.id, 'name': r.name, 'gap_count': r.gap_count} for r in top_gaps
        ],
        'top_control_gaps': [
            {'control_id': r.control_id, 'title': r.title, 'gap_count': r.gap_count}
            for r in top_controls
        ],
        'framework_gaps': fw_gaps
    }
