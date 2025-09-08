"""
Customer Onboarding Routes

Provides customer onboarding workflow management and tracking.
Similar to onboarding systems like those in aiauthshield.com.
"""

from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash
from datetime import datetime
import json

from onboarding.onboarding_service import onboarding_service
from audit.audit_service import audit_logger
from models import CustomerOnboarding, OnboardingStep

onboarding_bp = Blueprint('onboarding', __name__, url_prefix='/onboarding')

@onboarding_bp.route('/')
def onboarding_dashboard():
    """Onboarding management dashboard"""
    try:
        # Get onboarding analytics
        analytics = onboarding_service.get_onboarding_analytics()
        
        # Get recent customers
        recent_customers = CustomerOnboarding.query.order_by(
            CustomerOnboarding.created_at.desc()
        ).limit(10).all()
        
        # Format recent customers
        formatted_customers = []
        for customer in recent_customers:
            formatted_customers.append({
                'customer_id': customer.customer_id,
                'organization_name': customer.organization_name,
                'primary_contact_email': customer.primary_contact_email,
                'industry_type': customer.industry_type,
                'onboarding_status': customer.onboarding_status,
                'completion_percentage': customer.completion_percentage,
                'started_at': customer.started_at.strftime('%Y-%m-%d'),
                'current_step': customer.current_step
            })
        
        # Log dashboard access
        audit_logger.log_user_action(
            action='view',
            description='Viewed onboarding dashboard',
            resource_type='onboarding_dashboard'
        )
        
        return render_template('onboarding/onboarding_dashboard.html',
                             analytics=analytics,
                             recent_customers=formatted_customers)
        
    except Exception as e:
        flash(f'Error loading onboarding dashboard: {str(e)}', 'error')
        return render_template('onboarding/onboarding_dashboard.html',
                             analytics={},
                             recent_customers=[])

@onboarding_bp.route('/start', methods=['GET', 'POST'])
def start_onboarding():
    """Start new customer onboarding"""
    if request.method == 'POST':
        try:
            # Get form data
            organization_name = request.form.get('organization_name')
            primary_contact_email = request.form.get('primary_contact_email')
            industry_type = request.form.get('industry_type')
            company_size = request.form.get('company_size')
            expected_agent_count = request.form.get('expected_agent_count')
            
            # Validate required fields
            if not organization_name or not primary_contact_email:
                flash('Organization name and contact email are required', 'error')
                return render_template('onboarding/start_onboarding.html')
            
            # Convert expected agent count to integer
            try:
                expected_agent_count = int(expected_agent_count) if expected_agent_count else None
            except ValueError:
                expected_agent_count = None
            
            # Start onboarding
            customer = onboarding_service.start_customer_onboarding(
                organization_name=organization_name,
                primary_contact_email=primary_contact_email,
                industry_type=industry_type,
                company_size=company_size,
                expected_agent_count=expected_agent_count
            )
            
            # Store customer ID in session for onboarding flow
            session['onboarding_customer_id'] = customer.customer_id
            
            flash(f'Onboarding started for {organization_name}!', 'success')
            return redirect(url_for('onboarding.onboarding_progress', customer_id=customer.customer_id))
            
        except Exception as e:
            flash(f'Error starting onboarding: {str(e)}', 'error')
            return render_template('onboarding/start_onboarding.html')
    
    return render_template('onboarding/start_onboarding.html')

@onboarding_bp.route('/customer/<customer_id>')
def onboarding_progress(customer_id):
    """Show customer onboarding progress"""
    try:
        # Get onboarding progress
        progress_data = onboarding_service.get_onboarding_progress(customer_id)
        
        if not progress_data:
            flash('Customer not found', 'error')
            return redirect(url_for('onboarding.onboarding_dashboard'))
        
        # Log progress view
        audit_logger.log_user_action(
            action='view',
            description=f'Viewed onboarding progress for {progress_data["customer"]["organization_name"]}',
            resource_type='customer_onboarding',
            resource_id=customer_id
        )
        
        return render_template('onboarding/onboarding_progress.html',
                             customer=progress_data['customer'],
                             progress=progress_data['progress'])
        
    except Exception as e:
        flash(f'Error loading onboarding progress: {str(e)}', 'error')
        return redirect(url_for('onboarding.onboarding_dashboard'))

@onboarding_bp.route('/step/<customer_id>/<step_key>')
def onboarding_step(customer_id, step_key):
    """Show specific onboarding step"""
    try:
        # Get progress data
        progress_data = onboarding_service.get_onboarding_progress(customer_id)
        
        if not progress_data:
            flash('Customer not found', 'error')
            return redirect(url_for('onboarding.onboarding_dashboard'))
        
        # Find the specific step
        step_info = None
        for step in progress_data['progress']['steps']:
            if step['step_key'] == step_key:
                step_info = step
                break
        
        if not step_info:
            flash('Step not found', 'error')
            return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))
        
        # Check if step can be accessed
        if not step_info['can_access']:
            flash('Please complete previous steps first', 'warning')
            return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))
        
        # Start the step if not already started
        if step_info['status'] == 'not_started':
            onboarding_service.start_onboarding_step(customer_id, step_key)
        
        # Log step access
        audit_logger.log_user_action(
            action='start',
            description=f'Started onboarding step: {step_info["step_name"]}',
            resource_type='onboarding_step',
            resource_id=step_key
        )
        
        return render_template('onboarding/onboarding_step.html',
                             customer=progress_data['customer'],
                             step=step_info,
                             customer_id=customer_id)
        
    except Exception as e:
        flash(f'Error loading onboarding step: {str(e)}', 'error')
        return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))

@onboarding_bp.route('/complete-step/<customer_id>/<step_key>', methods=['POST'])
def complete_onboarding_step(customer_id, step_key):
    """Complete an onboarding step"""
    try:
        # Get form data
        completion_data = {}
        feedback = request.form.get('feedback')
        difficulty_rating = request.form.get('difficulty_rating')
        
        # Collect step-specific data based on step type
        step = OnboardingStep.query.filter_by(step_key=step_key).first()
        if step:
            if step.step_type == 'form':
                # Collect all form fields
                for key, value in request.form.items():
                    if key not in ['feedback', 'difficulty_rating']:
                        completion_data[key] = value
            elif step.step_type == 'integration':
                # Handle integration setup data
                completion_data['integration_type'] = request.form.get('integration_type')
                completion_data['configuration'] = request.form.get('configuration')
            elif step.step_type == 'verification':
                # Handle verification results
                completion_data['verification_status'] = request.form.get('verification_status')
                completion_data['verification_details'] = request.form.get('verification_details')
        
        # Convert difficulty rating
        try:
            difficulty_rating = int(difficulty_rating) if difficulty_rating else None
        except ValueError:
            difficulty_rating = None
        
        # Complete the step
        success = onboarding_service.complete_onboarding_step(
            customer_id=customer_id,
            step_key=step_key,
            completion_data=completion_data,
            feedback=feedback,
            difficulty_rating=difficulty_rating
        )
        
        if success:
            flash('Step completed successfully!', 'success')
        else:
            flash('Error completing step', 'error')
        
        return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))
        
    except Exception as e:
        flash(f'Error completing step: {str(e)}', 'error')
        return redirect(url_for('onboarding.onboarding_step', 
                               customer_id=customer_id, step_key=step_key))

@onboarding_bp.route('/pause/<customer_id>', methods=['POST'])
def pause_onboarding(customer_id):
    """Pause customer onboarding"""
    try:
        reason = request.form.get('reason', 'User requested pause')
        
        success = onboarding_service.pause_onboarding(customer_id, reason)
        
        if success:
            flash('Onboarding paused', 'info')
        else:
            flash('Error pausing onboarding', 'error')
        
        return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))
        
    except Exception as e:
        flash(f'Error pausing onboarding: {str(e)}', 'error')
        return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))

@onboarding_bp.route('/resume/<customer_id>', methods=['POST'])
def resume_onboarding(customer_id):
    """Resume paused customer onboarding"""
    try:
        success = onboarding_service.resume_onboarding(customer_id)
        
        if success:
            flash('Onboarding resumed', 'success')
        else:
            flash('Error resuming onboarding', 'error')
        
        return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))
        
    except Exception as e:
        flash(f'Error resuming onboarding: {str(e)}', 'error')
        return redirect(url_for('onboarding.onboarding_progress', customer_id=customer_id))

@onboarding_bp.route('/api/progress/<customer_id>')
def api_onboarding_progress(customer_id):
    """API endpoint for onboarding progress data"""
    try:
        progress_data = onboarding_service.get_onboarding_progress(customer_id)
        
        if not progress_data:
            return jsonify({'error': 'Customer not found'}), 404
        
        return jsonify(progress_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@onboarding_bp.route('/api/analytics')
def api_onboarding_analytics():
    """API endpoint for onboarding analytics"""
    try:
        analytics = onboarding_service.get_onboarding_analytics()
        return jsonify(analytics)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@onboarding_bp.route('/customers')
def customer_list():
    """List all customers with their onboarding status"""
    try:
        # Get all customers
        customers = CustomerOnboarding.query.order_by(
            CustomerOnboarding.created_at.desc()
        ).all()
        
        # Format customer data
        formatted_customers = []
        for customer in customers:
            formatted_customers.append({
                'customer_id': customer.customer_id,
                'organization_name': customer.organization_name,
                'primary_contact_email': customer.primary_contact_email,
                'industry_type': customer.industry_type,
                'company_size': customer.company_size,
                'onboarding_status': customer.onboarding_status,
                'completion_percentage': customer.completion_percentage,
                'current_step': customer.current_step,
                'started_at': customer.started_at.strftime('%Y-%m-%d'),
                'completed_at': customer.completed_at.strftime('%Y-%m-%d') if customer.completed_at else None,
                'expected_agent_count': customer.expected_agent_count
            })
        
        # Log customer list access
        audit_logger.log_user_action(
            action='view',
            description='Viewed customer list',
            resource_type='customer_list'
        )
        
        return render_template('onboarding/customer_list.html',
                             customers=formatted_customers)
        
    except Exception as e:
        flash(f'Error loading customer list: {str(e)}', 'error')
        return render_template('onboarding/customer_list.html',
                             customers=[])

@onboarding_bp.route('/steps')
def manage_steps():
    """Manage onboarding steps configuration"""
    try:
        # Get all onboarding steps
        steps = OnboardingStep.query.order_by(OnboardingStep.step_order).all()
        
        # Format steps data
        formatted_steps = []
        for step in steps:
            formatted_steps.append({
                'step_key': step.step_key,
                'step_name': step.step_name,
                'step_description': step.step_description,
                'step_order': step.step_order,
                'step_type': step.step_type,
                'category': step.category,
                'is_required': step.is_required,
                'is_active': step.is_active,
                'estimated_time_minutes': step.estimated_time_minutes,
                'instructions': step.instructions,
                'help_content': step.help_content,
                'video_url': step.video_url,
                'documentation_links': step.documentation_links
            })
        
        # Log steps management access
        audit_logger.log_user_action(
            action='view',
            description='Viewed onboarding steps management',
            resource_type='onboarding_steps'
        )
        
        return render_template('onboarding/manage_steps.html',
                             steps=formatted_steps)
        
    except Exception as e:
        flash(f'Error loading onboarding steps: {str(e)}', 'error')
        return render_template('onboarding/manage_steps.html',
                             steps=[])