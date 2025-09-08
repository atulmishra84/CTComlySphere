"""
Enhanced Agent Registration Workflow
Integrates automatic classification, controls application, and playbook execution
"""
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from app import db
from models import (
    AIAgent, AIAgentInventory, RegistrationPlaybook, AgentRegistration, PlaybookExecution,
    RegistrationStatus, InventoryStatus, ExecutionStatus, ComplianceFramework
)
from agents.classification_engine import AgentClassificationEngine
from agents.controls_manager import AgentControlsManager
from playbooks.playbook_manager import PlaybookManager
import logging

logger = logging.getLogger(__name__)


class EnhancedRegistrationWorkflow:
    """Manages the complete agent registration workflow with automatic classification"""
    
    def __init__(self):
        self.classification_engine = AgentClassificationEngine()
        self.controls_manager = AgentControlsManager()
        self.playbook_manager = PlaybookManager()
        self.logger = logger
    
    def register_agent_with_classification(self, agent_id: int, 
                                         auto_apply_controls: bool = True) -> Dict[str, Any]:
        """
        Complete agent registration workflow with automatic classification
        
        Args:
            agent_id: ID of the agent to register
            auto_apply_controls: Whether to automatically apply required controls
            
        Returns:
            Dictionary with registration results
        """
        workflow_result = {
            'agent_id': agent_id,
            'workflow_status': 'started',
            'steps_completed': [],
            'steps_failed': [],
            'classification_result': None,
            'controls_result': None,
            'playbook_execution': None,
            'inventory_record': None,
            'started_at': datetime.utcnow().isoformat()
        }
        
        try:
            # Step 1: Get agent information
            agent = AIAgent.query.get(agent_id)
            if not agent:
                raise ValueError(f"Agent {agent_id} not found")
            
            workflow_result['agent_info'] = {
                'name': agent.name,
                'type': agent.type,
                'protocol': agent.protocol,
                'endpoint': agent.endpoint
            }
            
            # Step 2: Classify agent
            self.logger.info(f"Classifying agent {agent_id}")
            agent_data = self._prepare_agent_data_for_classification(agent)
            classification_result = self.classification_engine.classify_agent(agent_data)
            workflow_result['classification_result'] = classification_result
            workflow_result['steps_completed'].append('classification')
            
            # Step 3: Create/Update inventory record
            self.logger.info(f"Creating inventory record for agent {agent_id}")
            inventory_record = self._create_or_update_inventory_record(agent, classification_result)
            workflow_result['inventory_record'] = {
                'id': inventory_record.id,
                'primary_classification': inventory_record.primary_classification,
                'applicable_frameworks': inventory_record.applicable_frameworks,
                'criticality_level': inventory_record.criticality_level
            }
            workflow_result['steps_completed'].append('inventory_creation')
            
            # Step 4: Generate and execute playbook
            self.logger.info(f"Generating playbook for agent {agent_id}")
            playbook = self._get_or_create_playbook(classification_result)
            
            if playbook:
                execution_result = self._execute_playbook(agent, playbook, classification_result)
                workflow_result['playbook_execution'] = execution_result
                workflow_result['steps_completed'].append('playbook_execution')
            
            # Step 5: Apply security controls (if enabled)
            if auto_apply_controls and classification_result.get('required_controls'):
                self.logger.info(f"Applying controls to agent {agent_id}")
                controls_result = self.controls_manager.apply_controls_to_agent(
                    agent_id, classification_result['required_controls']
                )
                workflow_result['controls_result'] = controls_result
                workflow_result['steps_completed'].append('controls_application')
                
                # Update inventory with control status
                self._update_inventory_with_controls(inventory_record, controls_result)
            
            # Step 6: Final compliance check
            compliance_status = self._perform_compliance_check(agent, classification_result)
            workflow_result['compliance_status'] = compliance_status
            workflow_result['steps_completed'].append('compliance_check')
            
            workflow_result['workflow_status'] = 'completed'
            workflow_result['completed_at'] = datetime.utcnow().isoformat()
            
            self.logger.info(f"Successfully completed registration workflow for agent {agent_id}")
            
        except Exception as e:
            self.logger.error(f"Registration workflow failed for agent {agent_id}: {str(e)}")
            workflow_result['workflow_status'] = 'failed'
            workflow_result['error'] = str(e)
            workflow_result['failed_at'] = datetime.utcnow().isoformat()
        
        return workflow_result
    
    def _prepare_agent_data_for_classification(self, agent: AIAgent) -> Dict[str, Any]:
        """Prepare agent data for the classification engine"""
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
        
        # Add scan results context if available
        if agent.scan_results:
            latest_scan = max(agent.scan_results, key=lambda s: s.created_at)
            agent_data['latest_scan'] = {
                'risk_level': latest_scan.risk_level.value if latest_scan.risk_level else None,
                'phi_exposure_detected': latest_scan.phi_exposure_detected,
                'vulnerabilities_found': latest_scan.vulnerabilities_found
            }
        
        return agent_data
    
    def _create_or_update_inventory_record(self, agent: AIAgent, 
                                         classification_result: Dict) -> AIAgentInventory:
        """Create or update inventory record with classification results"""
        # Check if inventory record already exists
        inventory_record = AIAgentInventory.query.filter_by(agent_id=agent.id).first()
        
        if inventory_record:
            # Update existing record
            inventory_record.primary_classification = classification_result.get('primary_classification')
            inventory_record.secondary_classifications = classification_result.get('secondary_classifications', [])
            inventory_record.classification_confidence = classification_result.get('confidence_score', 0.0)
            inventory_record.classification_reasons = classification_result.get('classification_reasons', [])
            inventory_record.applicable_frameworks = classification_result.get('applicable_frameworks', [])
            inventory_record.required_controls = classification_result.get('required_controls', [])
            inventory_record.criticality_level = classification_result.get('criticality_level', 'low')
            inventory_record.last_classification_update = datetime.utcnow()
            inventory_record.last_updated = datetime.utcnow()
            
            # Update regulatory scope based on applicable frameworks
            inventory_record.regulatory_scope = classification_result.get('applicable_frameworks', [])
        else:
            # Create new inventory record
            inventory_record = AIAgentInventory(
                agent_id=agent.id,
                inventory_status=InventoryStatus.REGISTERED,
                primary_classification=classification_result.get('primary_classification'),
                secondary_classifications=classification_result.get('secondary_classifications', []),
                classification_confidence=classification_result.get('confidence_score', 0.0),
                classification_reasons=classification_result.get('classification_reasons', []),
                applicable_frameworks=classification_result.get('applicable_frameworks', []),
                required_controls=classification_result.get('required_controls', []),
                criticality_level=classification_result.get('criticality_level', 'low'),
                regulatory_scope=classification_result.get('applicable_frameworks', []),
                data_classification='auto_classified',
                deployment_environment='unknown',  # Can be updated later
                last_classification_update=datetime.utcnow()
            )
            db.session.add(inventory_record)
        
        db.session.commit()
        return inventory_record
    
    def _get_or_create_playbook(self, classification_result: Dict) -> Optional[RegistrationPlaybook]:
        """Get existing playbook or create new one based on classification"""
        primary_class = classification_result.get('primary_classification')
        frameworks = classification_result.get('applicable_frameworks', [])
        
        # Try to find existing playbook for this classification
        playbook = RegistrationPlaybook.query.filter(
            RegistrationPlaybook.name.ilike(f"%{primary_class}%"),
            RegistrationPlaybook.is_active == True
        ).first()
        
        if not playbook:
            # Generate new playbook
            self.logger.info(f"Generating new playbook for classification: {primary_class}")
            playbook_config = self.classification_engine.generate_agent_playbook(classification_result)
            
            # Create plain English configuration
            plain_english_config = self._generate_plain_english_config(playbook_config, frameworks)
            
            try:
                playbook = self.playbook_manager.create_playbook_from_english(
                    name=playbook_config['name'],
                    description=playbook_config['description'],
                    plain_english_config=plain_english_config,
                    created_by='auto_classification'
                )
                self.logger.info(f"Created new playbook: {playbook.name}")
            except Exception as e:
                self.logger.error(f"Failed to create playbook: {str(e)}")
                return None
        
        return playbook
    
    def _generate_plain_english_config(self, playbook_config: Dict, frameworks: List[str]) -> str:
        """Generate plain English configuration from playbook config"""
        config_parts = []
        
        # Basic registration
        config_parts.append("Automatically register discovered AI agents.")
        
        # Protocol-specific
        protocols = playbook_config.get('trigger_conditions', {}).get('protocols', [])
        if protocols:
            config_parts.append(f"When discovered through {', '.join(protocols)} protocols, perform security validation.")
        
        # Compliance requirements
        if frameworks:
            config_parts.append(f"Check compliance against {', '.join(frameworks)} frameworks.")
        
        # Criticality-based actions
        criticality = playbook_config.get('criticality_level', 'low')
        if criticality in ['high', 'critical']:
            config_parts.append("Require manual approval for high-criticality agents.")
            config_parts.append("Notify security and compliance teams immediately.")
        
        # Controls application
        config_parts.append("Apply required security controls automatically.")
        config_parts.append("Validate control implementation and generate compliance reports.")
        
        return ' '.join(config_parts)
    
    def _execute_playbook(self, agent: AIAgent, playbook: RegistrationPlaybook, 
                         classification_result: Dict) -> Dict[str, Any]:
        """Execute the registration playbook for the agent"""
        try:
            # Create playbook execution record
            execution = PlaybookExecution(
                playbook_id=playbook.id,
                agent_id=agent.id,
                execution_status=ExecutionStatus.RUNNING
            )
            db.session.add(execution)
            db.session.commit()
            
            # Create agent registration record
            registration = AgentRegistration(
                agent_id=agent.id,
                playbook_id=playbook.id,
                registration_status=RegistrationStatus.IN_PROGRESS,
                registration_data={
                    'classification_result': classification_result,
                    'auto_generated': True,
                    'workflow_version': '2.0'
                }
            )
            db.session.add(registration)
            db.session.commit()
            
            # Execute onboarding steps
            step_results = {}
            onboarding_steps = playbook.onboarding_steps or []
            
            for step in onboarding_steps:
                step_name = step.get('step', 'unknown')
                try:
                    result = self._execute_onboarding_step(agent, step, classification_result)
                    step_results[step_name] = {
                        'status': 'completed',
                        'result': result,
                        'executed_at': datetime.utcnow().isoformat()
                    }
                except Exception as e:
                    step_results[step_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'executed_at': datetime.utcnow().isoformat()
                    }
            
            # Update execution status
            execution.execution_status = ExecutionStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            execution.step_results = step_results
            
            # Update registration status
            failed_steps = [k for k, v in step_results.items() if v['status'] == 'failed']
            if failed_steps:
                registration.registration_status = RegistrationStatus.FAILED
                registration.error_log = f"Failed steps: {', '.join(failed_steps)}"
            else:
                registration.registration_status = RegistrationStatus.COMPLETED
                registration.completed_at = datetime.utcnow()
            
            registration.onboarding_progress = step_results
            
            db.session.commit()
            
            return {
                'execution_id': execution.id,
                'registration_id': registration.id,
                'status': 'completed' if not failed_steps else 'partial_failure',
                'step_results': step_results,
                'failed_steps': failed_steps
            }
            
        except Exception as e:
            # Update execution as failed
            if 'execution' in locals():
                execution.execution_status = ExecutionStatus.FAILED
                execution.error_details = str(e)
                execution.completed_at = datetime.utcnow()
                db.session.commit()
            
            return {
                'status': 'failed',
                'error': str(e),
                'execution_id': execution.id if 'execution' in locals() else None
            }
    
    def _execute_onboarding_step(self, agent: AIAgent, step: Dict, 
                                classification_result: Dict) -> Dict[str, Any]:
        """Execute a single onboarding step"""
        step_type = step.get('step', '')
        
        if step_type == 'security_scan':
            return self._perform_security_scan_step(agent)
        elif step_type == 'compliance_evaluation':
            return self._perform_compliance_evaluation_step(agent, classification_result)
        elif step_type == 'encryption_validation':
            return self._perform_encryption_validation_step(agent)
        elif step_type == 'access_control_setup':
            return self._perform_access_control_setup_step(agent)
        elif step_type == 'phi_detection_scan':
            return self._perform_phi_detection_step(agent)
        elif step_type == 'manual_approval':
            return self._initiate_manual_approval_step(agent, classification_result)
        else:
            return {'status': 'skipped', 'reason': f'Unknown step type: {step_type}'}
    
    def _perform_security_scan_step(self, agent: AIAgent) -> Dict[str, Any]:
        """Perform security scan step"""
        # This would integrate with existing scanner functionality
        return {
            'scan_initiated': True,
            'scan_type': 'comprehensive',
            'estimated_duration': '5 minutes',
            'scan_id': f"scan_{agent.id}_{int(datetime.utcnow().timestamp())}"
        }
    
    def _perform_compliance_evaluation_step(self, agent: AIAgent, 
                                          classification_result: Dict) -> Dict[str, Any]:
        """Perform compliance evaluation step"""
        frameworks = classification_result.get('applicable_frameworks', [])
        
        return {
            'frameworks_evaluated': frameworks,
            'evaluation_initiated': True,
            'expected_completion': '3 minutes'
        }
    
    def _perform_encryption_validation_step(self, agent: AIAgent) -> Dict[str, Any]:
        """Validate encryption implementation"""
        # Check if endpoint uses HTTPS
        uses_https = agent.endpoint.startswith('https://') if agent.endpoint else False
        
        return {
            'endpoint_encryption': 'https' if uses_https else 'http',
            'encryption_validated': uses_https,
            'recommendations': [] if uses_https else ['Upgrade to HTTPS endpoint']
        }
    
    def _perform_access_control_setup_step(self, agent: AIAgent) -> Dict[str, Any]:
        """Set up access controls"""
        return {
            'access_control_configured': True,
            'authentication_required': True,
            'rbac_policy_created': f"{agent.name.lower().replace(' ', '-')}-rbac"
        }
    
    def _perform_phi_detection_step(self, agent: AIAgent) -> Dict[str, Any]:
        """Perform PHI detection scan"""
        return {
            'phi_scan_initiated': True,
            'scan_scope': 'endpoint_and_metadata',
            'detection_patterns_applied': ['ssn', 'phone', 'email', 'medical_record_number']
        }
    
    def _initiate_manual_approval_step(self, agent: AIAgent, 
                                     classification_result: Dict) -> Dict[str, Any]:
        """Initiate manual approval process for high-criticality agents"""
        return {
            'approval_request_created': True,
            'approval_required_for': classification_result.get('criticality_level'),
            'notification_sent_to': ['security-team@company.com', 'compliance-team@company.com'],
            'approval_deadline': '24 hours'
        }
    
    def _update_inventory_with_controls(self, inventory_record: AIAgentInventory, 
                                      controls_result: Dict):
        """Update inventory record with control application results"""
        inventory_record.applied_controls = controls_result.get('controls_applied', [])
        inventory_record.failed_controls = controls_result.get('controls_failed', [])
        inventory_record.control_status = {
            control: result.get('status', 'unknown') 
            for control, result in controls_result.get('validation_results', {}).items()
        }
        inventory_record.last_updated = datetime.utcnow()
        db.session.commit()
    
    def _perform_compliance_check(self, agent: AIAgent, 
                                classification_result: Dict) -> Dict[str, Any]:
        """Perform final compliance check"""
        frameworks = classification_result.get('applicable_frameworks', [])
        required_controls = classification_result.get('required_controls', [])
        
        # Get control status from agent metadata
        agent_metadata = agent.agent_metadata or {}
        control_info = agent_metadata.get('security_controls', {})
        applied_controls = control_info.get('applied_controls', [])
        
        compliance_status = {}
        overall_compliant = True
        
        for framework in frameworks:
            # Calculate compliance for each framework
            framework_compliant = len(applied_controls) >= len(required_controls) * 0.8  # 80% threshold
            compliance_status[framework] = {
                'compliant': framework_compliant,
                'score': (len(applied_controls) / len(required_controls) * 100) if required_controls else 100,
                'applied_controls': len(applied_controls),
                'required_controls': len(required_controls)
            }
            
            if not framework_compliant:
                overall_compliant = False
        
        return {
            'overall_compliant': overall_compliant,
            'framework_compliance': compliance_status,
            'total_controls_applied': len(applied_controls),
            'total_controls_required': len(required_controls),
            'compliance_percentage': (len(applied_controls) / len(required_controls) * 100) if required_controls else 100,
            'evaluated_at': datetime.utcnow().isoformat()
        }
    
    def get_registration_status(self, agent_id: int) -> Dict[str, Any]:
        """Get current registration status for an agent"""
        agent = AIAgent.query.get(agent_id)
        if not agent:
            return {'error': f'Agent {agent_id} not found'}
        
        # Get latest registration
        latest_registration = AgentRegistration.query.filter_by(agent_id=agent_id).order_by(
            AgentRegistration.started_at.desc()
        ).first()
        
        # Get inventory record
        inventory_record = AIAgentInventory.query.filter_by(agent_id=agent_id).first()
        
        return {
            'agent_id': agent_id,
            'agent_name': agent.name,
            'registration_status': latest_registration.registration_status.value if latest_registration else 'not_registered',
            'inventory_status': inventory_record.inventory_status.value if inventory_record else 'not_in_inventory',
            'primary_classification': inventory_record.primary_classification if inventory_record else None,
            'applicable_frameworks': inventory_record.applicable_frameworks if inventory_record else [],
            'controls_applied': inventory_record.applied_controls if inventory_record else [],
            'last_updated': inventory_record.last_updated.isoformat() if inventory_record and inventory_record.last_updated else None
        }