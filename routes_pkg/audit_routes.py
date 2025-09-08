"""
Audit Trail Routes

Provides audit trail dashboard, reporting, and management capabilities.
Similar to enterprise audit systems like those in aiauthshield.com.
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from datetime import datetime, timedelta
import json

from audit.audit_service import audit_logger
from models import AuditTrail, RiskLevel

audit_bp = Blueprint('audit', __name__, url_prefix='/audit')

@audit_bp.route('/')
def audit_dashboard():
    """Audit trail dashboard with overview and recent activity"""
    try:
        # Get recent audit events (last 30 days)
        start_date = datetime.utcnow() - timedelta(days=30)
        recent_events = audit_logger.get_audit_trail(start_date=start_date, limit=50)
        
        # Get security events
        security_events = audit_logger.get_security_events(days=7)
        
        # Get compliance events
        compliance_events = audit_logger.get_compliance_events(days=7)
        
        # Calculate summary statistics
        total_events_30d = len(audit_logger.get_audit_trail(start_date=start_date, limit=10000))
        
        # Count events by category
        category_counts = {}
        risk_level_counts = {}
        outcome_counts = {}
        
        for event in recent_events:
            # Count by category
            category_counts[event.event_category] = category_counts.get(event.event_category, 0) + 1
            
            # Count by risk level
            if event.risk_level:
                risk_level_counts[event.risk_level.value] = risk_level_counts.get(event.risk_level.value, 0) + 1
            
            # Count by outcome
            outcome_counts[event.outcome] = outcome_counts.get(event.outcome, 0) + 1
        
        # Format recent events for display
        formatted_events = []
        for event in recent_events[:20]:  # Show only last 20
            formatted_events.append({
                'id': event.id,
                'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'event_type': event.event_type,
                'event_category': event.event_category,
                'action': event.action,
                'description': event.event_description,
                'user_id': event.user_id or 'System',
                'resource_type': event.resource_type,
                'resource_id': event.resource_id,
                'outcome': event.outcome,
                'risk_level': event.risk_level.value if event.risk_level else 'LOW',
                'ip_address': event.ip_address,
                'compliance_relevant': event.compliance_relevant,
                'frameworks_affected': event.frameworks_affected or []
            })
        
        # Log dashboard access
        audit_logger.log_user_action(
            action='view',
            description='Viewed audit trail dashboard',
            resource_type='audit_dashboard'
        )
        
        return render_template('audit/audit_dashboard.html',
                             recent_events=formatted_events,
                             security_events=len(security_events),
                             compliance_events=len(compliance_events),
                             total_events_30d=total_events_30d,
                             category_counts=category_counts,
                             risk_level_counts=risk_level_counts,
                             outcome_counts=outcome_counts)
        
    except Exception as e:
        flash(f'Error loading audit dashboard: {str(e)}', 'error')
        return render_template('audit/audit_dashboard.html',
                             recent_events=[],
                             security_events=0,
                             compliance_events=0,
                             total_events_30d=0,
                             category_counts={},
                             risk_level_counts={},
                             outcome_counts={})

@audit_bp.route('/search')
def audit_search():
    """Advanced audit trail search and filtering"""
    
    # Get filter parameters
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    event_types = request.args.getlist('event_type')
    event_categories = request.args.getlist('event_category')
    user_id = request.args.get('user_id')
    resource_type = request.args.get('resource_type')
    outcome = request.args.get('outcome')
    risk_level = request.args.get('risk_level')
    compliance_only = request.args.get('compliance_only') == 'true'
    
    # Set default date range (last 7 days)
    if not start_date_str:
        start_date = datetime.utcnow() - timedelta(days=7)
    else:
        start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
    
    if not end_date_str:
        end_date = datetime.utcnow()
    else:
        end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
    
    try:
        # Build query filters
        events = audit_logger.get_audit_trail(
            start_date=start_date,
            end_date=end_date,
            event_types=event_types if event_types else None,
            user_id=user_id if user_id else None,
            resource_type=resource_type if resource_type else None,
            outcome=outcome if outcome else None,
            limit=1000
        )
        
        # Apply additional filters
        filtered_events = []
        for event in events:
            # Filter by category
            if event_categories and event.event_category not in event_categories:
                continue
            
            # Filter by risk level
            if risk_level and (not event.risk_level or event.risk_level.value != risk_level):
                continue
            
            # Filter compliance events only
            if compliance_only and not event.compliance_relevant:
                continue
            
            filtered_events.append(event)
        
        # Format events for display
        formatted_events = []
        for event in filtered_events:
            formatted_events.append({
                'id': event.id,
                'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'event_type': event.event_type,
                'event_category': event.event_category,
                'action': event.action,
                'description': event.event_description,
                'user_id': event.user_id or 'System',
                'resource_type': event.resource_type,
                'resource_id': event.resource_id,
                'outcome': event.outcome,
                'risk_level': event.risk_level.value if event.risk_level else 'LOW',
                'ip_address': event.ip_address,
                'compliance_relevant': event.compliance_relevant,
                'frameworks_affected': event.frameworks_affected or [],
                'duration_ms': event.duration_ms,
                'correlation_id': event.correlation_id
            })
        
        # Log search activity
        audit_logger.log_user_action(
            action='search',
            description=f'Searched audit trail: {len(formatted_events)} results',
            resource_type='audit_trail'
        )
        
        return render_template('audit/audit_search.html',
                             events=formatted_events,
                             total_results=len(formatted_events),
                             start_date=start_date.strftime('%Y-%m-%d'),
                             end_date=end_date.strftime('%Y-%m-%d'),
                             filters={
                                 'event_types': event_types,
                                 'event_categories': event_categories,
                                 'user_id': user_id,
                                 'resource_type': resource_type,
                                 'outcome': outcome,
                                 'risk_level': risk_level,
                                 'compliance_only': compliance_only
                             })
        
    except Exception as e:
        flash(f'Error searching audit trail: {str(e)}', 'error')
        return render_template('audit/audit_search.html',
                             events=[],
                             total_results=0,
                             start_date=(datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d'),
                             end_date=datetime.utcnow().strftime('%Y-%m-%d'),
                             filters={})

@audit_bp.route('/report')
def audit_report():
    """Generate comprehensive audit reports"""
    
    # Get report parameters
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    report_format = request.args.get('format', 'html')
    
    # Set default date range (last 30 days)
    if not start_date_str:
        start_date = datetime.utcnow() - timedelta(days=30)
    else:
        start_date = datetime.fromisoformat(start_date_str)
    
    if not end_date_str:
        end_date = datetime.utcnow()
    else:
        end_date = datetime.fromisoformat(end_date_str)
    
    try:
        # Generate comprehensive report
        report = audit_logger.generate_audit_report(start_date, end_date, include_summary=True)
        
        # Log report generation
        audit_logger.log_user_action(
            action='generate',
            description=f'Generated audit report: {report["report_period"]["total_events"]} events',
            resource_type='audit_report'
        )
        
        if report_format == 'json':
            return jsonify(report)
        else:
            return render_template('audit/audit_report.html',
                                 report=report,
                                 start_date=start_date.strftime('%Y-%m-%d'),
                                 end_date=end_date.strftime('%Y-%m-%d'))
        
    except Exception as e:
        flash(f'Error generating audit report: {str(e)}', 'error')
        return render_template('audit/audit_report.html',
                             report=None,
                             start_date=start_date.strftime('%Y-%m-%d'),
                             end_date=end_date.strftime('%Y-%m-%d'))

@audit_bp.route('/event/<int:event_id>')
def audit_event_detail(event_id):
    """Show detailed information for a specific audit event"""
    try:
        event = AuditTrail.query.get_or_404(event_id)
        
        # Format event data
        event_data = {
            'id': event.id,
            'timestamp': event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'event_type': event.event_type,
            'event_category': event.event_category,
            'action': event.action,
            'description': event.event_description,
            'user_id': event.user_id,
            'session_id': event.session_id,
            'ip_address': event.ip_address,
            'user_agent': event.user_agent,
            'resource_type': event.resource_type,
            'resource_id': event.resource_id,
            'resource_name': event.resource_name,
            'outcome': event.outcome,
            'risk_level': event.risk_level.value if event.risk_level else None,
            'compliance_relevant': event.compliance_relevant,
            'frameworks_affected': event.frameworks_affected,
            'duration_ms': event.duration_ms,
            'correlation_id': event.correlation_id,
            'authentication_method': event.authentication_method,
            'authorization_context': event.authorization_context,
            'sensitive_data_accessed': event.sensitive_data_accessed,
            'event_data': event.event_data,
            'retention_period_days': event.retention_period_days
        }
        
        # Log event detail access
        audit_logger.log_user_action(
            action='view',
            description=f'Viewed audit event details: {event_id}',
            resource_type='audit_event',
            resource_id=str(event_id)
        )
        
        return render_template('audit/audit_event_detail.html', event=event_data)
        
    except Exception as e:
        flash(f'Error loading audit event: {str(e)}', 'error')
        return redirect(url_for('audit.audit_dashboard'))

@audit_bp.route('/api/events')
def api_audit_events():
    """API endpoint for fetching audit events (for AJAX/charts)"""
    try:
        # Get parameters
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        event_type = request.args.get('event_type')
        limit = int(request.args.get('limit', 100))
        
        # Set date range
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str)
        else:
            start_date = datetime.utcnow() - timedelta(days=7)
        
        if end_date_str:
            end_date = datetime.fromisoformat(end_date_str)
        else:
            end_date = datetime.utcnow()
        
        # Get events
        events = audit_logger.get_audit_trail(
            start_date=start_date,
            end_date=end_date,
            event_types=[event_type] if event_type else None,
            limit=limit
        )
        
        # Format for API response
        formatted_events = []
        for event in events:
            formatted_events.append({
                'id': event.id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'event_category': event.event_category,
                'action': event.action,
                'description': event.event_description,
                'user_id': event.user_id,
                'resource_type': event.resource_type,
                'outcome': event.outcome,
                'risk_level': event.risk_level.value if event.risk_level else 'LOW',
                'compliance_relevant': event.compliance_relevant
            })
        
        return jsonify({
            'events': formatted_events,
            'total': len(formatted_events),
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@audit_bp.route('/api/summary')
def api_audit_summary():
    """API endpoint for audit summary statistics"""
    try:
        # Get date range
        days = int(request.args.get('days', 7))
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get events for summary
        events = audit_logger.get_audit_trail(start_date=start_date, limit=10000)
        
        # Calculate summary
        summary = {
            'total_events': len(events),
            'security_events': len([e for e in events if e.event_category == 'security']),
            'compliance_events': len([e for e in events if e.compliance_relevant]),
            'failed_events': len([e for e in events if e.outcome == 'failure']),
            'unique_users': len(set([e.user_id for e in events if e.user_id])),
            'categories': {},
            'risk_levels': {},
            'event_types': {}
        }
        
        # Count by categories
        for event in events:
            summary['categories'][event.event_category] = summary['categories'].get(event.event_category, 0) + 1
            summary['event_types'][event.event_type] = summary['event_types'].get(event.event_type, 0) + 1
            if event.risk_level:
                summary['risk_levels'][event.risk_level.value] = summary['risk_levels'].get(event.risk_level.value, 0) + 1
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500