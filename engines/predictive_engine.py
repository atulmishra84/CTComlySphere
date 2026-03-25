"""
Predictive Analytics Engine
Computes risk forecasts, trend analysis, and proactive risk mitigation signals
from real scan and compliance data stored in the database.
"""
from datetime import datetime, timedelta
from collections import defaultdict

def _linear_regression(xs, ys):
    """Simple least-squares linear regression. Returns (slope, intercept)."""
    n = len(xs)
    if n < 2:
        return 0.0, (ys[0] if ys else 0.0)
    sx = sum(xs)
    sy = sum(ys)
    sxy = sum(x * y for x, y in zip(xs, ys))
    sxx = sum(x * x for x in xs)
    denom = n * sxx - sx * sx
    if denom == 0:
        return 0.0, sy / n
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    return slope, intercept


def compute_risk_trend(db, ScanResult, days=60):
    """
    Returns daily average risk score for the last `days` days.
    Each item: {date, avg_risk, scan_count}
    """
    from datetime import datetime, timedelta
    start = datetime.utcnow() - timedelta(days=days)
    rows = []
    for i in range(days):
        day = start + timedelta(days=i)
        day_end = day + timedelta(days=1)
        avg = db.session.query(db.func.avg(ScanResult.risk_score)).filter(
            ScanResult.created_at >= day,
            ScanResult.created_at < day_end
        ).scalar()
        cnt = ScanResult.query.filter(
            ScanResult.created_at >= day,
            ScanResult.created_at < day_end
        ).count()
        rows.append({
            'date': day.strftime('%Y-%m-%d'),
            'avg_risk': round(float(avg or 0), 2),
            'scan_count': cnt
        })
    return rows


def compute_30day_forecast(risk_trend):
    """
    Uses linear regression on the last 30 days of actual risk trend to project
    the next 30 days. Returns a list of {date, predicted_risk}.
    """
    actuals = [r for r in risk_trend if r['scan_count'] > 0]
    if not actuals:
        return []
    xs = list(range(len(actuals)))
    ys = [r['avg_risk'] for r in actuals]
    slope, intercept = _linear_regression(xs, ys)
    last_date = datetime.strptime(actuals[-1]['date'], '%Y-%m-%d')
    forecast = []
    for i in range(1, 31):
        predicted = intercept + slope * (len(actuals) - 1 + i)
        predicted = max(0.0, min(100.0, round(predicted, 2)))
        forecast.append({
            'date': (last_date + timedelta(days=i)).strftime('%Y-%m-%d'),
            'predicted_risk': predicted
        })
    return forecast


def compute_at_risk_agents(db, AIAgent, ScanResult, top_n=8):
    """
    Identifies agents whose risk scores are trending upward over the last 30 days.
    Returns top_n agents sorted by slope (steepest upward trend first).
    """
    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    agents = AIAgent.query.all()
    scored = []
    for agent in agents:
        scans = ScanResult.query.filter(
            ScanResult.ai_agent_id == agent.id,
            ScanResult.created_at >= thirty_days_ago
        ).order_by(ScanResult.created_at).all()
        if len(scans) < 2:
            if scans:
                latest = scans[-1]
                scored.append({
                    'agent': agent,
                    'latest_risk': round(latest.risk_score, 1),
                    'slope': 0.0,
                    'scan_count': 1,
                    'risk_level': latest.risk_level.value if latest.risk_level else 'UNKNOWN'
                })
            continue
        xs = list(range(len(scans)))
        ys = [s.risk_score for s in scans]
        slope, _ = _linear_regression(xs, ys)
        scored.append({
            'agent': agent,
            'latest_risk': round(scans[-1].risk_score, 1),
            'slope': round(slope, 3),
            'scan_count': len(scans),
            'risk_level': scans[-1].risk_level.value if scans[-1].risk_level else 'UNKNOWN'
        })
    scored.sort(key=lambda x: (-x['slope'], -x['latest_risk']))
    return scored[:top_n]


def compute_compliance_drift(db, AIAgent, ComplianceEvaluation, top_n=8):
    """
    Identifies agents whose compliance scores are declining (drifting out of compliance).
    Returns top_n agents with steepest downward compliance trend.
    """
    from datetime import datetime, timedelta
    sixty_days_ago = datetime.utcnow() - timedelta(days=60)
    agents = AIAgent.query.all()
    drifting = []
    for agent in agents:
        evals = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.ai_agent_id == agent.id,
            ComplianceEvaluation.evaluated_at >= sixty_days_ago
        ).order_by(ComplianceEvaluation.evaluated_at).all()
        if len(evals) < 2:
            continue
        xs = list(range(len(evals)))
        ys = [e.compliance_score for e in evals]
        slope, _ = _linear_regression(xs, ys)
        if slope < 0:
            latest = evals[-1]
            drifting.append({
                'agent': agent,
                'latest_score': round(latest.compliance_score, 1),
                'slope': round(slope, 3),
                'framework': latest.framework.value if latest.framework else '',
                'eval_count': len(evals)
            })
    drifting.sort(key=lambda x: x['slope'])
    return drifting[:top_n]


def compute_risk_by_provider(db, AIAgent, ScanResult):
    """Returns average risk score grouped by cloud_provider."""
    from sqlalchemy import func
    rows = db.session.query(
        AIAgent.cloud_provider,
        func.avg(ScanResult.risk_score).label('avg_risk'),
        func.count(ScanResult.id).label('scan_count')
    ).join(ScanResult, ScanResult.ai_agent_id == AIAgent.id).group_by(
        AIAgent.cloud_provider
    ).all()
    result = []
    for r in rows:
        result.append({
            'provider': r.cloud_provider or 'Unknown',
            'avg_risk': round(float(r.avg_risk or 0), 2),
            'scan_count': r.scan_count
        })
    result.sort(key=lambda x: -x['avg_risk'])
    return result


def compute_risk_by_agent_type(db, AIAgent, ScanResult):
    """Returns average risk score grouped by ai_type."""
    from sqlalchemy import func
    rows = db.session.query(
        AIAgent.ai_type,
        func.avg(ScanResult.risk_score).label('avg_risk'),
        func.count(ScanResult.id).label('scan_count')
    ).join(ScanResult, ScanResult.ai_agent_id == AIAgent.id).group_by(
        AIAgent.ai_type
    ).all()
    result = []
    for r in rows:
        label = r.ai_type.value.replace('_', ' ').title() if r.ai_type else 'Unknown'
        result.append({
            'ai_type': label,
            'avg_risk': round(float(r.avg_risk or 0), 2),
            'scan_count': r.scan_count
        })
    result.sort(key=lambda x: -x['avg_risk'])
    return result


def compute_anomalies(db, AIAgent, ScanResult, threshold_z=2.0):
    """
    Detects agents with recent risk scores significantly above their own historical mean
    (simple z-score anomaly detection).
    """
    from datetime import datetime, timedelta
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    agents = AIAgent.query.all()
    anomalies = []
    for agent in agents:
        all_scans = ScanResult.query.filter_by(ai_agent_id=agent.id).all()
        if len(all_scans) < 5:
            continue
        scores = [s.risk_score for s in all_scans]
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std = variance ** 0.5
        if std == 0:
            continue
        recent = [s for s in all_scans if s.created_at and s.created_at >= seven_days_ago]
        for scan in recent:
            z = (scan.risk_score - mean) / std
            if z >= threshold_z:
                anomalies.append({
                    'agent': agent,
                    'risk_score': round(scan.risk_score, 1),
                    'mean_risk': round(mean, 1),
                    'z_score': round(z, 2),
                    'detected_at': scan.created_at
                })
    anomalies.sort(key=lambda x: -x['z_score'])
    return anomalies[:10]


def compute_summary_metrics(db, AIAgent, ScanResult, ComplianceEvaluation):
    """High-level summary KPIs for the predictive dashboard header."""
    from sqlalchemy import func
    from datetime import datetime, timedelta
    total_agents = AIAgent.query.count()
    avg_risk = db.session.query(func.avg(ScanResult.risk_score)).scalar() or 0
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    sixty_days_ago = datetime.utcnow() - timedelta(days=60)
    recent_avg = db.session.query(func.avg(ScanResult.risk_score)).filter(
        ScanResult.created_at >= thirty_days_ago
    ).scalar() or 0
    older_avg = db.session.query(func.avg(ScanResult.risk_score)).filter(
        ScanResult.created_at >= sixty_days_ago,
        ScanResult.created_at < thirty_days_ago
    ).scalar() or 0
    risk_change = round(float(recent_avg) - float(older_avg), 1)
    avg_compliance = db.session.query(func.avg(ComplianceEvaluation.compliance_score)).scalar() or 0
    critical_agents = ScanResult.query.filter(
        ScanResult.risk_level.in_(['CRITICAL'])
    ).with_entities(ScanResult.ai_agent_id).distinct().count()
    return {
        'total_agents': total_agents,
        'avg_risk': round(float(avg_risk), 1),
        'risk_change': risk_change,
        'avg_compliance': round(float(avg_compliance), 1),
        'critical_agents': critical_agents,
        'risk_direction': 'up' if risk_change > 0 else ('down' if risk_change < 0 else 'flat')
    }
