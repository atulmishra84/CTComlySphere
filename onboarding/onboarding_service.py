"""
Customer Onboarding Service

Comprehensive onboarding workflow management similar to aiauthshield.com
providing guided setup for healthcare AI compliance platform customers.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from flask import request, session
import uuid

from app import db
from models import CustomerOnboarding, OnboardingStep, CustomerProgress
from audit.audit_service import audit_logger

# Configure logging
logger = logging.getLogger(__name__)

class OnboardingService:
    """Comprehensive customer onboarding service"""
    
    def __init__(self):
        self.logger = logger
        self._ensure_default_steps()
    
    def start_customer_onboarding(self, 
                                organization_name: str,
                                primary_contact_email: str,
                                industry_type: str = None,
                                company_size: str = None,
                                expected_agent_count: int = None) -> CustomerOnboarding:
        """
        Start the onboarding process for a new customer
        
        Args:
            organization_name: Name of the customer organization
            primary_contact_email: Primary contact email
            industry_type: Type of industry (healthcare, fintech, etc.)
            company_size: Size of company (startup, small, medium, enterprise)
            expected_agent_count: Expected number of AI agents
            
        Returns:
            CustomerOnboarding record
        """
        
        try:
            # Generate unique customer ID
            customer_id = f"cust_{uuid.uuid4().hex[:12]}"
            
            # Create onboarding record
            customer = CustomerOnboarding(
                customer_id=customer_id,
                organization_name=organization_name,
                primary_contact_email=primary_contact_email,
                industry_type=industry_type,
                company_size=company_size,
                expected_agent_count=expected_agent_count,
                onboarding_status='started',
                current_step='welcome',
                completion_percentage=0.0,
                started_at=datetime.utcnow()
            )
            
            db.session.add(customer)
            db.session.commit()
            
            # Initialize progress records for required steps
            self._initialize_progress_records(customer_id)
            
            # Log audit event
            audit_logger.log_user_action(
                action='create',
                description=f"Started onboarding for {organization_name}",
                resource_type='customer_onboarding',
                resource_id=customer_id
            )
            
            self.logger.info(f"Started onboarding for customer {customer_id} - {organization_name}")
            return customer
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to start customer onboarding: {e}")
            raise
    
    def get_customer_onboarding(self, customer_id: str) -> Optional[CustomerOnboarding]:
        """Get customer onboarding record"""
        return CustomerOnboarding.query.filter_by(customer_id=customer_id).first()
    
    def get_onboarding_progress(self, customer_id: str) -> Dict[str, Any]:
        """
        Get comprehensive onboarding progress for a customer
        
        Args:
            customer_id: Customer ID
            
        Returns:
            Comprehensive progress information
        """
        
        customer = self.get_customer_onboarding(customer_id)
        if not customer:
            return None
        
        # Get all progress records
        progress_records = CustomerProgress.query.filter_by(customer_id=customer_id).all()
        progress_by_step = {p.step_key: p for p in progress_records}
        
        # Get all onboarding steps
        steps = OnboardingStep.query.filter_by(is_active=True).order_by(OnboardingStep.step_order).all()
        
        # Build progress information
        steps_info = []
        completed_steps = 0
        total_required_steps = 0
        
        for step in steps:
            progress = progress_by_step.get(step.step_key)
            
            step_info = {
                'step_key': step.step_key,
                'step_name': step.step_name,
                'step_description': step.step_description,
                'step_order': step.step_order,
                'step_type': step.step_type,
                'is_required': step.is_required,
                'estimated_time_minutes': step.estimated_time_minutes,
                'category': step.category,
                'instructions': step.instructions,
                'help_content': step.help_content,
                'video_url': step.video_url,
                'documentation_links': step.documentation_links,
                'status': 'not_started',
                'started_at': None,
                'completed_at': None,
                'time_spent_minutes': None,
                'attempts': 0,
                'can_access': True  # Will be updated based on prerequisites
            }
            
            if progress:
                step_info.update({
                    'status': progress.status,
                    'started_at': progress.started_at.isoformat() if progress.started_at else None,
                    'completed_at': progress.completed_at.isoformat() if progress.completed_at else None,
                    'time_spent_minutes': progress.time_spent_minutes,
                    'attempts': progress.attempts,
                    'completion_data': progress.completion_data
                })
            
            # Check if step can be accessed (prerequisites met)
            step_info['can_access'] = self._check_step_prerequisites(customer_id, step, progress_by_step)
            
            # Count progress
            if step.is_required:
                total_required_steps += 1
                if progress and progress.status == 'completed':
                    completed_steps += 1
            
            steps_info.append(step_info)
        
        # Calculate completion percentage
        completion_percentage = (completed_steps / total_required_steps * 100) if total_required_steps > 0 else 0
        
        # Update customer record with latest progress
        customer.completion_percentage = completion_percentage
        customer.last_activity = datetime.utcnow()
        
        # Determine current step
        current_step = self._determine_current_step(steps_info)
        if current_step:
            customer.current_step = current_step
        
        # Check if onboarding is complete
        if completion_percentage >= 100 and customer.onboarding_status != 'completed':
            customer.onboarding_status = 'completed'
            customer.completed_at = datetime.utcnow()
            
            # Log completion event
            audit_logger.log_user_action(
                action='complete',
                description=f"Completed onboarding for {customer.organization_name}",
                resource_type='customer_onboarding',
                resource_id=customer_id
            )
        
        db.session.commit()
        
        return {
            'customer': {
                'customer_id': customer.customer_id,
                'organization_name': customer.organization_name,
                'primary_contact_email': customer.primary_contact_email,
                'industry_type': customer.industry_type,
                'company_size': customer.company_size,
                'onboarding_status': customer.onboarding_status,
                'current_step': customer.current_step,
                'completion_percentage': completion_percentage,
                'started_at': customer.started_at.isoformat(),
                'completed_at': customer.completed_at.isoformat() if customer.completed_at else None,
                'estimated_completion': customer.estimated_completion.isoformat() if customer.estimated_completion else None,
                'expected_agent_count': customer.expected_agent_count,
                'security_level': customer.security_level
            },
            'progress': {
                'steps': steps_info,
                'completed_steps': completed_steps,
                'total_required_steps': total_required_steps,
                'completion_percentage': completion_percentage,
                'next_step': current_step,
                'estimated_time_remaining': self._calculate_estimated_time_remaining(steps_info)
            }
        }
    
    def complete_onboarding_step(self, 
                                customer_id: str, 
                                step_key: str, 
                                completion_data: Dict[str, Any] = None,
                                feedback: str = None,
                                difficulty_rating: int = None) -> bool:
        """
        Mark an onboarding step as completed
        
        Args:
            customer_id: Customer ID
            step_key: Step key to complete
            completion_data: Data collected/submitted in this step
            feedback: Customer feedback
            difficulty_rating: 1-5 difficulty rating
            
        Returns:
            Success status
        """
        
        try:
            # Get or create progress record
            progress = CustomerProgress.query.filter_by(
                customer_id=customer_id, 
                step_key=step_key
            ).first()
            
            if not progress:
                progress = CustomerProgress(
                    customer_id=customer_id,
                    step_key=step_key,
                    started_at=datetime.utcnow()
                )
                db.session.add(progress)
            
            # Update progress
            progress.status = 'completed'
            progress.completed_at = datetime.utcnow()
            progress.completion_data = completion_data or {}
            progress.feedback = feedback
            progress.difficulty_rating = difficulty_rating
            
            # Calculate time spent if we have start time
            if progress.started_at:
                time_spent = datetime.utcnow() - progress.started_at
                progress.time_spent_minutes = time_spent.total_seconds() / 60
            
            db.session.commit()
            
            # Log audit event
            step = OnboardingStep.query.filter_by(step_key=step_key).first()
            step_name = step.step_name if step else step_key
            
            audit_logger.log_user_action(
                action='complete',
                description=f"Completed onboarding step: {step_name}",
                resource_type='onboarding_step',
                resource_id=step_key
            )
            
            self.logger.info(f"Customer {customer_id} completed step {step_key}")
            return True
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to complete onboarding step {step_key} for customer {customer_id}: {e}")
            return False
    
    def start_onboarding_step(self, customer_id: str, step_key: str) -> bool:
        """Start an onboarding step"""
        try:
            # Get or create progress record
            progress = CustomerProgress.query.filter_by(
                customer_id=customer_id, 
                step_key=step_key
            ).first()
            
            if not progress:
                progress = CustomerProgress(
                    customer_id=customer_id,
                    step_key=step_key
                )
                db.session.add(progress)
            
            # Update progress
            if progress.status in ['not_started', 'failed']:
                progress.status = 'in_progress'
                progress.started_at = datetime.utcnow()
                progress.attempts += 1
            
            db.session.commit()
            return True
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to start onboarding step {step_key} for customer {customer_id}: {e}")
            return False
    
    def pause_onboarding(self, customer_id: str, reason: str = None) -> bool:
        """Pause customer onboarding"""
        try:
            customer = self.get_customer_onboarding(customer_id)
            if customer:
                customer.onboarding_status = 'paused'
                db.session.commit()
                
                audit_logger.log_user_action(
                    action='pause',
                    description=f"Paused onboarding: {reason or 'No reason provided'}",
                    resource_type='customer_onboarding',
                    resource_id=customer_id
                )
                return True
            return False
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to pause onboarding for customer {customer_id}: {e}")
            return False
    
    def resume_onboarding(self, customer_id: str) -> bool:
        """Resume paused customer onboarding"""
        try:
            customer = self.get_customer_onboarding(customer_id)
            if customer and customer.onboarding_status == 'paused':
                customer.onboarding_status = 'in_progress'
                customer.last_activity = datetime.utcnow()
                db.session.commit()
                
                audit_logger.log_user_action(
                    action='resume',
                    description="Resumed onboarding",
                    resource_type='customer_onboarding',
                    resource_id=customer_id
                )
                return True
            return False
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to resume onboarding for customer {customer_id}: {e}")
            return False
    
    def get_onboarding_analytics(self) -> Dict[str, Any]:
        """Get onboarding analytics and metrics"""
        try:
            # Get all customers
            customers = CustomerOnboarding.query.all()
            
            # Calculate metrics
            total_customers = len(customers)
            completed_customers = len([c for c in customers if c.onboarding_status == 'completed'])
            in_progress_customers = len([c for c in customers if c.onboarding_status == 'in_progress'])
            paused_customers = len([c for c in customers if c.onboarding_status == 'paused'])
            
            # Calculate average completion time
            completed = [c for c in customers if c.completed_at]
            avg_completion_days = 0
            if completed:
                total_days = sum([(c.completed_at - c.started_at).days for c in completed])
                avg_completion_days = total_days / len(completed)
            
            # Step completion rates
            steps = OnboardingStep.query.filter_by(is_active=True).all()
            step_completion_rates = {}
            
            for step in steps:
                total_attempts = CustomerProgress.query.filter_by(step_key=step.step_key).count()
                completed_attempts = CustomerProgress.query.filter_by(
                    step_key=step.step_key, 
                    status='completed'
                ).count()
                
                completion_rate = (completed_attempts / total_attempts * 100) if total_attempts > 0 else 0
                step_completion_rates[step.step_key] = {
                    'step_name': step.step_name,
                    'total_attempts': total_attempts,
                    'completed': completed_attempts,
                    'completion_rate': completion_rate
                }
            
            return {
                'overview': {
                    'total_customers': total_customers,
                    'completed_customers': completed_customers,
                    'in_progress_customers': in_progress_customers,
                    'paused_customers': paused_customers,
                    'completion_rate': (completed_customers / total_customers * 100) if total_customers > 0 else 0,
                    'average_completion_days': round(avg_completion_days, 1)
                },
                'step_analytics': step_completion_rates,
                'recent_activity': self._get_recent_onboarding_activity()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get onboarding analytics: {e}")
            return {}
    
    def _ensure_default_steps(self):
        """Ensure default onboarding steps exist"""
        default_steps = [
            {
                'step_key': 'welcome',
                'step_name': 'Welcome & Overview',
                'step_description': 'Introduction to the Healthcare AI Compliance Platform',
                'step_order': 1,
                'step_type': 'introduction',
                'category': 'setup',
                'is_required': True,
                'estimated_time_minutes': 5,
                'instructions': 'Welcome to the Healthcare AI Compliance Platform. Let\'s get you started!'
            },
            {
                'step_key': 'organization_setup',
                'step_name': 'Organization Setup',
                'step_description': 'Configure your organization details and preferences',
                'step_order': 2,
                'step_type': 'form',
                'category': 'setup',
                'is_required': True,
                'estimated_time_minutes': 10,
                'instructions': 'Please provide details about your organization and compliance requirements.'
            },
            {
                'step_key': 'compliance_requirements',
                'step_name': 'Compliance Requirements',
                'step_description': 'Select your required compliance frameworks',
                'step_order': 3,
                'step_type': 'form',
                'category': 'setup',
                'is_required': True,
                'estimated_time_minutes': 15,
                'instructions': 'Choose the compliance frameworks relevant to your organization.'
            },
            {
                'step_key': 'security_setup',
                'step_name': 'Security Configuration',
                'step_description': 'Configure security settings and access controls',
                'step_order': 4,
                'step_type': 'form',
                'category': 'security',
                'is_required': True,
                'estimated_time_minutes': 20,
                'instructions': 'Set up your security preferences and access controls.'
            },
            {
                'step_key': 'integration_setup',
                'step_name': 'Integration Setup',
                'step_description': 'Connect your AI systems and cloud environments',
                'step_order': 5,
                'step_type': 'integration',
                'category': 'integration',
                'is_required': True,
                'estimated_time_minutes': 30,
                'instructions': 'Connect your existing AI systems and cloud environments for monitoring.'
            },
            {
                'step_key': 'first_scan',
                'step_name': 'First Compliance Scan',
                'step_description': 'Run your first AI agent discovery and compliance assessment',
                'step_order': 6,
                'step_type': 'verification',
                'category': 'integration',
                'is_required': True,
                'estimated_time_minutes': 25,
                'instructions': 'Let\'s discover your AI agents and run your first compliance assessment.'
            },
            {
                'step_key': 'training',
                'step_name': 'Platform Training',
                'step_description': 'Learn how to use the platform effectively',
                'step_order': 7,
                'step_type': 'training',
                'category': 'training',
                'is_required': False,
                'estimated_time_minutes': 45,
                'instructions': 'Optional training on advanced platform features and best practices.'
            }
        ]
        
        try:
            for step_data in default_steps:
                existing = OnboardingStep.query.filter_by(step_key=step_data['step_key']).first()
                if not existing:
                    step = OnboardingStep(**step_data)
                    db.session.add(step)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to create default onboarding steps: {e}")
    
    def _initialize_progress_records(self, customer_id: str):
        """Initialize progress records for all required steps"""
        try:
            required_steps = OnboardingStep.query.filter_by(is_required=True, is_active=True).all()
            
            for step in required_steps:
                existing = CustomerProgress.query.filter_by(
                    customer_id=customer_id,
                    step_key=step.step_key
                ).first()
                
                if not existing:
                    progress = CustomerProgress(
                        customer_id=customer_id,
                        step_key=step.step_key,
                        status='not_started'
                    )
                    db.session.add(progress)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to initialize progress records for {customer_id}: {e}")
    
    def _check_step_prerequisites(self, customer_id: str, step: OnboardingStep, 
                                 progress_by_step: Dict[str, CustomerProgress]) -> bool:
        """Check if step prerequisites are met"""
        if not step.prerequisites:
            return True
        
        for prereq_step_key in step.prerequisites:
            prereq_progress = progress_by_step.get(prereq_step_key)
            if not prereq_progress or prereq_progress.status != 'completed':
                return False
        
        return True
    
    def _determine_current_step(self, steps_info: List[Dict]) -> Optional[str]:
        """Determine the current step customer should work on"""
        for step in steps_info:
            if step['is_required'] and step['can_access'] and step['status'] in ['not_started', 'in_progress']:
                return step['step_key']
        return None
    
    def _calculate_estimated_time_remaining(self, steps_info: List[Dict]) -> int:
        """Calculate estimated time remaining in minutes"""
        remaining_time = 0
        for step in steps_info:
            if step['is_required'] and step['status'] in ['not_started', 'in_progress']:
                remaining_time += step['estimated_time_minutes']
        return remaining_time
    
    def _get_recent_onboarding_activity(self) -> List[Dict]:
        """Get recent onboarding activity"""
        try:
            # Get recent progress updates
            recent_progress = CustomerProgress.query.filter(
                CustomerProgress.updated_at >= datetime.utcnow() - timedelta(days=7)
            ).order_by(CustomerProgress.updated_at.desc()).limit(20).all()
            
            activity = []
            for progress in recent_progress:
                customer = CustomerOnboarding.query.filter_by(customer_id=progress.customer_id).first()
                step = OnboardingStep.query.filter_by(step_key=progress.step_key).first()
                
                if customer and step:
                    activity.append({
                        'customer_name': customer.organization_name,
                        'step_name': step.step_name,
                        'status': progress.status,
                        'updated_at': progress.updated_at.isoformat()
                    })
            
            return activity
            
        except Exception as e:
            self.logger.error(f"Failed to get recent onboarding activity: {e}")
            return []


# Global onboarding service instance
onboarding_service = OnboardingService()