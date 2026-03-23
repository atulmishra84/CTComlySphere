"""
Comprehensive Audit Trail Service

Provides comprehensive audit logging for all user actions, system events,
compliance activities, and security events in the CT ComplySphere Visibility & Governance Platform.
Similar to enterprise audit systems like those in aiauthshield.com.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from flask import request, g, session
from functools import wraps
import uuid

from app import db
from models import AuditTrail, RiskLevel

# Configure logging
logger = logging.getLogger(__name__)

class AuditLogger:
    """Centralized audit logging service for comprehensive activity tracking"""
    
    def __init__(self):
        self.logger = logger
        self.session_context = {}
        
    def log_event(self, 
                  event_type: str,
                  action: str,
                  event_description: str,
                  event_category: str = 'user_action',
                  resource_type: Optional[str] = None,
                  resource_id: Optional[str] = None,
                  resource_name: Optional[str] = None,
                  outcome: str = 'success',
                  risk_level: RiskLevel = RiskLevel.LOW,
                  compliance_relevant: bool = False,
                  frameworks_affected: Optional[List[str]] = None,
                  event_data: Optional[Dict[str, Any]] = None,
                  duration_ms: Optional[int] = None,
                  sensitive_data_accessed: bool = False) -> AuditTrail:
        """
        Log a comprehensive audit event
        
        Args:
            event_type: Type of event (login, scan, compliance_check, etc.)
            action: Action performed (create, read, update, delete, execute)
            event_description: Human-readable description of the event
            event_category: Category (security, compliance, user_action, system)
            resource_type: Type of resource affected (agent, scan, evaluation, etc.)
            resource_id: ID of the affected resource
            resource_name: Human-readable resource name
            outcome: Event outcome (success, failure, warning)
            risk_level: Security risk level of the event
            compliance_relevant: Whether event affects compliance
            frameworks_affected: List of compliance frameworks affected
            event_data: Additional event-specific data
            duration_ms: Event duration in milliseconds
            sensitive_data_accessed: Whether sensitive data was accessed
            
        Returns:
            Created AuditTrail record
        """
        
        try:
            # Extract request context
            user_context = self._extract_user_context()
            
            # Create audit trail record
            audit_record = AuditTrail(
                event_type=event_type,
                event_category=event_category,
                action=action,
                event_description=event_description,
                
                # User context
                user_id=user_context.get('user_id'),
                session_id=user_context.get('session_id'),
                ip_address=user_context.get('ip_address'),
                user_agent=user_context.get('user_agent'),
                
                # Resource information
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                resource_name=resource_name,
                
                # Event details
                event_data=event_data or {},
                outcome=outcome,
                duration_ms=duration_ms,
                correlation_id=self._generate_correlation_id(),
                
                # Risk and compliance
                risk_level=risk_level,
                compliance_relevant=compliance_relevant,
                frameworks_affected=frameworks_affected or [],
                
                # Security context
                authentication_method=user_context.get('auth_method'),
                authorization_context=user_context.get('auth_context'),
                sensitive_data_accessed=sensitive_data_accessed,
                
                # Timestamp
                timestamp=datetime.utcnow()
            )
            
            # Save to database
            db.session.add(audit_record)
            db.session.commit()
            
            # Log to application logs as well
            self.logger.info(f"AUDIT: {event_type} - {action} - {event_description} - {outcome}")
            
            return audit_record
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
            # Don't let audit logging failures break the main application
            db.session.rollback()
            return None
    
    def log_security_event(self, event_description: str, risk_level: RiskLevel = RiskLevel.MEDIUM, 
                          event_data: Optional[Dict] = None) -> AuditTrail:
        """Log security-related events"""
        return self.log_event(
            event_type='security_event',
            action='detect',
            event_description=event_description,
            event_category='security',
            risk_level=risk_level,
            compliance_relevant=True,
            event_data=event_data
        )
    
    def log_compliance_event(self, framework: str, action: str, description: str, 
                           resource_id: Optional[str] = None, outcome: str = 'success') -> AuditTrail:
        """Log compliance-related events"""
        return self.log_event(
            event_type='compliance_assessment',
            action=action,
            event_description=description,
            event_category='compliance',
            resource_id=resource_id,
            risk_level=RiskLevel.MEDIUM,
            compliance_relevant=True,
            frameworks_affected=[framework],
            outcome=outcome
        )
    
    def log_user_action(self, action: str, description: str, resource_type: Optional[str] = None,
                       resource_id: Optional[str] = None, sensitive: bool = False) -> AuditTrail:
        """Log user actions"""
        return self.log_event(
            event_type='user_action',
            action=action,
            event_description=description,
            event_category='user_action',
            resource_type=resource_type,
            resource_id=resource_id,
            sensitive_data_accessed=sensitive
        )
    
    def log_system_event(self, event_type: str, description: str, outcome: str = 'success',
                        event_data: Optional[Dict] = None) -> AuditTrail:
        """Log system events"""
        return self.log_event(
            event_type=event_type,
            action='execute',
            event_description=description,
            event_category='system',
            outcome=outcome,
            event_data=event_data
        )
    
    def log_data_access(self, data_type: str, action: str, resource_id: Optional[str] = None,
                       sensitive: bool = True) -> AuditTrail:
        """Log data access events"""
        return self.log_event(
            event_type='data_access',
            action=action,
            event_description=f"Accessed {data_type} data",
            event_category='data',
            resource_type=data_type,
            resource_id=resource_id,
            sensitive_data_accessed=sensitive,
            compliance_relevant=sensitive
        )
    
    def get_audit_trail(self, 
                       start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       event_types: Optional[List[str]] = None,
                       user_id: Optional[str] = None,
                       resource_type: Optional[str] = None,
                       outcome: Optional[str] = None,
                       limit: int = 1000) -> List[AuditTrail]:
        """
        Retrieve audit trail records with filtering
        
        Args:
            start_date: Start date for filtering
            end_date: End date for filtering
            event_types: List of event types to include
            user_id: Filter by user ID
            resource_type: Filter by resource type
            outcome: Filter by outcome
            limit: Maximum number of records to return
            
        Returns:
            List of AuditTrail records
        """
        
        query = AuditTrail.query
        
        # Apply filters
        if start_date:
            query = query.filter(AuditTrail.timestamp >= start_date)
        if end_date:
            query = query.filter(AuditTrail.timestamp <= end_date)
        if event_types:
            query = query.filter(AuditTrail.event_type.in_(event_types))
        if user_id:
            query = query.filter(AuditTrail.user_id == user_id)
        if resource_type:
            query = query.filter(AuditTrail.resource_type == resource_type)
        if outcome:
            query = query.filter(AuditTrail.outcome == outcome)
        
        # Order by timestamp (most recent first) and limit
        return query.order_by(AuditTrail.timestamp.desc()).limit(limit).all()
    
    def get_security_events(self, days: int = 30, risk_level: Optional[RiskLevel] = None) -> List[AuditTrail]:
        """Get security events from the last N days"""
        start_date = datetime.utcnow() - timedelta(days=days)
        query = AuditTrail.query.filter(
            AuditTrail.timestamp >= start_date,
            AuditTrail.event_category == 'security'
        )
        
        if risk_level:
            query = query.filter(AuditTrail.risk_level == risk_level)
        
        return query.order_by(AuditTrail.timestamp.desc()).all()
    
    def get_compliance_events(self, framework: Optional[str] = None, days: int = 30) -> List[AuditTrail]:
        """Get compliance-related events"""
        start_date = datetime.utcnow() - timedelta(days=days)
        query = AuditTrail.query.filter(
            AuditTrail.timestamp >= start_date,
            AuditTrail.compliance_relevant == True
        )
        
        if framework:
            query = query.filter(AuditTrail.frameworks_affected.contains([framework]))
        
        return query.order_by(AuditTrail.timestamp.desc()).all()
    
    def generate_audit_report(self, 
                             start_date: datetime, 
                             end_date: datetime,
                             include_summary: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive audit report for a date range
        
        Args:
            start_date: Report start date
            end_date: Report end date
            include_summary: Whether to include summary statistics
            
        Returns:
            Comprehensive audit report
        """
        
        # Get all events in date range
        events = self.get_audit_trail(start_date=start_date, end_date=end_date, limit=10000)
        
        report = {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'total_events': len(events)
            },
            'events': []
        }
        
        # Convert events to dictionaries
        for event in events:
            event_dict = {
                'id': event.id,
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'event_category': event.event_category,
                'action': event.action,
                'description': event.event_description,
                'user_id': event.user_id,
                'resource_type': event.resource_type,
                'resource_id': event.resource_id,
                'outcome': event.outcome,
                'risk_level': event.risk_level.value if event.risk_level else None,
                'compliance_relevant': event.compliance_relevant,
                'frameworks_affected': event.frameworks_affected,
                'ip_address': event.ip_address
            }
            report['events'].append(event_dict)
        
        if include_summary:
            report['summary'] = self._generate_audit_summary(events)
        
        return report
    
    def _extract_user_context(self) -> Dict[str, Any]:
        """Extract user context from current request/session"""
        context = {
            'user_id': None,
            'session_id': None,
            'ip_address': None,
            'user_agent': None,
            'auth_method': None,
            'auth_context': {}
        }
        
        try:
            # Extract from Flask request context if available
            if request:
                context['ip_address'] = request.remote_addr
                context['user_agent'] = request.headers.get('User-Agent', '')[:500]  # Truncate
                
            # Extract from Flask session if available
            if session:
                context['session_id'] = session.get('_id') or session.get('session_id')
                context['user_id'] = session.get('user_id')
                
            # Extract from Flask-Login current_user if available
            try:
                from flask_login import current_user
                if hasattr(current_user, 'id') and current_user.is_authenticated:
                    context['user_id'] = str(current_user.id)
                    context['auth_method'] = 'session'
            except ImportError:
                pass
                
        except Exception as e:
            self.logger.debug(f"Could not extract full user context: {e}")
        
        return context
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID for event tracking"""
        return str(uuid.uuid4())
    
    def _generate_audit_summary(self, events: List[AuditTrail]) -> Dict[str, Any]:
        """Generate summary statistics for audit events"""
        if not events:
            return {}
        
        # Count by category
        categories = {}
        event_types = {}
        outcomes = {}
        risk_levels = {}
        users = {}
        
        for event in events:
            # Count categories
            categories[event.event_category] = categories.get(event.event_category, 0) + 1
            
            # Count event types
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            # Count outcomes
            outcomes[event.outcome] = outcomes.get(event.outcome, 0) + 1
            
            # Count risk levels
            if event.risk_level:
                risk_levels[event.risk_level.value] = risk_levels.get(event.risk_level.value, 0) + 1
            
            # Count unique users
            if event.user_id:
                users[event.user_id] = users.get(event.user_id, 0) + 1
        
        return {
            'total_events': len(events),
            'unique_users': len(users),
            'categories': categories,
            'event_types': event_types,
            'outcomes': outcomes,
            'risk_levels': risk_levels,
            'most_active_users': sorted(users.items(), key=lambda x: x[1], reverse=True)[:10],
            'compliance_events': len([e for e in events if e.compliance_relevant]),
            'security_events': len([e for e in events if e.event_category == 'security']),
            'failed_events': len([e for e in events if e.outcome == 'failure'])
        }


# Global audit logger instance
audit_logger = AuditLogger()


def audit_action(event_type: str, action: str, description: str = None, 
                resource_type: str = None, sensitive: bool = False,
                compliance_relevant: bool = False):
    """
    Decorator for automatically auditing function calls
    
    Args:
        event_type: Type of event being audited
        action: Action being performed
        description: Description template (can use function name if None)
        resource_type: Type of resource being affected
        sensitive: Whether sensitive data is involved
        compliance_relevant: Whether this affects compliance
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = datetime.utcnow()
            outcome = 'success'
            error = None
            
            try:
                # Execute the function
                result = func(*args, **kwargs)
                return result
                
            except Exception as e:
                outcome = 'failure'
                error = str(e)
                raise
                
            finally:
                # Calculate duration
                duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                
                # Generate description
                event_description = description or f"Executed {func.__name__}"
                if error:
                    event_description += f" - Error: {error}"
                
                # Log the audit event
                audit_logger.log_event(
                    event_type=event_type,
                    action=action,
                    event_description=event_description,
                    resource_type=resource_type,
                    outcome=outcome,
                    duration_ms=duration_ms,
                    sensitive_data_accessed=sensitive,
                    compliance_relevant=compliance_relevant,
                    event_data={'function': func.__name__, 'error': error} if error else None
                )
        
        return wrapper
    return decorator