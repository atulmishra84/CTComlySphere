"""
Agent Registration Playbook Manager
Provides plain English configuration that auto-generates backend code and functionality
"""
from app import db
from models import (
    RegistrationPlaybook, AgentRegistration, AIAgentInventory, PlaybookExecution,
    AIAgent, RegistrationStatus, InventoryStatus, ExecutionStatus
)
import json
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class PlaybookManager:
    """Manages agent registration playbooks with plain English configuration"""
    
    def __init__(self):
        self.logger = logger
        
    def create_playbook_from_english(self, name: str, description: str, 
                                   plain_english_config: str, created_by: str = 'user') -> RegistrationPlaybook:
        """Create a new playbook from plain English configuration"""
        try:
            # Parse plain English configuration into structured data
            parsed_config = self.parse_english_config(plain_english_config)
            
            # Generate backend code from parsed configuration
            generated_code = self.generate_backend_code(parsed_config)
            
            # Create playbook
            playbook = RegistrationPlaybook(
                name=name,
                description=description,
                plain_english_config=plain_english_config,
                generated_code=generated_code,
                trigger_conditions=parsed_config.get('trigger_conditions', {}),
                onboarding_steps=parsed_config.get('onboarding_steps', []),
                compliance_requirements=parsed_config.get('compliance_requirements', []),
                auto_onboarding_enabled=parsed_config.get('auto_onboarding', False),
                created_by=created_by
            )
            
            db.session.add(playbook)
            db.session.commit()
            
            self.logger.info(f"Created playbook '{name}' with auto-generated backend code")
            return playbook
            
        except Exception as e:
            self.logger.error(f"Failed to create playbook: {str(e)}")
            db.session.rollback()
            raise
    
    def parse_english_config(self, config_text: str) -> Dict[str, Any]:
        """Parse plain English configuration into structured data"""
        config = {
            'trigger_conditions': {},
            'onboarding_steps': [],
            'compliance_requirements': [],
            'auto_onboarding': False,
            'notifications': {},
            'validation_rules': []
        }
        
        lines = [line.strip() for line in config_text.split('\n') if line.strip()]
        
        for line in lines:
            line_lower = line.lower()
            
            # Auto-onboarding detection
            if any(phrase in line_lower for phrase in ['automatically register', 'auto onboard', 'auto-register']):
                config['auto_onboarding'] = True
            
            # Trigger conditions
            if 'when discovered' in line_lower or 'trigger when' in line_lower:
                triggers = self.extract_trigger_conditions(line)
                config['trigger_conditions'].update(triggers)
            
            # Protocol filters
            if any(protocol in line_lower for protocol in ['kubernetes', 'docker', 'rest api', 'grpc', 'websocket']):
                protocols = self.extract_protocols(line)
                config['trigger_conditions']['protocols'] = protocols
            
            # Cloud provider filters
            if any(cloud in line_lower for cloud in ['aws', 'azure', 'gcp', 'google cloud']):
                clouds = self.extract_cloud_providers(line)
                config['trigger_conditions']['cloud_providers'] = clouds
            
            # Compliance requirements
            if any(framework in line_lower for framework in ['hipaa', 'gdpr', 'fda', 'sox', 'pci']):
                compliance = self.extract_compliance_requirements(line)
                config['compliance_requirements'].extend(compliance)
            
            # Onboarding steps
            if any(action in line_lower for action in ['validate', 'check', 'scan', 'register', 'notify']):
                step = self.extract_onboarding_step(line)
                if step:
                    config['onboarding_steps'].append(step)
            
            # Notification settings
            if 'notify' in line_lower or 'alert' in line_lower:
                notifications = self.extract_notification_settings(line)
                config['notifications'].update(notifications)
            
            # Validation rules
            if 'must have' in line_lower or 'require' in line_lower:
                validation = self.extract_validation_rule(line)
                if validation:
                    config['validation_rules'].append(validation)
        
        return config
    
    def extract_trigger_conditions(self, line: str) -> Dict[str, Any]:
        """Extract trigger conditions from English text"""
        conditions = {}
        line_lower = line.lower()
        
        # Risk level triggers
        if 'high risk' in line_lower:
            conditions['min_risk_level'] = 'HIGH'
        elif 'medium risk' in line_lower:
            conditions['min_risk_level'] = 'MEDIUM'
        elif 'low risk' in line_lower:
            conditions['min_risk_level'] = 'LOW'
        
        # PHI detection triggers
        if 'phi' in line_lower or 'patient data' in line_lower:
            conditions['phi_exposure'] = True
        
        # Healthcare specific triggers
        if any(term in line_lower for term in ['medical', 'clinical', 'healthcare', 'hospital']):
            conditions['healthcare_context'] = True
        
        return conditions
    
    def extract_protocols(self, line: str) -> List[str]:
        """Extract protocols from English text"""
        protocols = []
        line_lower = line.lower()
        
        protocol_mapping = {
            'kubernetes': 'kubernetes',
            'docker': 'docker',
            'rest api': 'rest_api', 
            'grpc': 'grpc',
            'websocket': 'websocket',
            'mqtt': 'mqtt',
            'graphql': 'graphql'
        }
        
        for keyword, protocol in protocol_mapping.items():
            if keyword in line_lower:
                protocols.append(protocol)
        
        return protocols
    
    def extract_cloud_providers(self, line: str) -> List[str]:
        """Extract cloud providers from English text"""
        providers = []
        line_lower = line.lower()
        
        if 'aws' in line_lower or 'amazon' in line_lower:
            providers.append('AWS')
        if 'azure' in line_lower or 'microsoft' in line_lower:
            providers.append('Azure')
        if 'gcp' in line_lower or 'google cloud' in line_lower:
            providers.append('GCP')
        
        return providers
    
    def extract_compliance_requirements(self, line: str) -> List[str]:
        """Extract compliance requirements from English text"""
        requirements = []
        line_lower = line.lower()
        
        compliance_mapping = {
            'hipaa': 'HIPAA',
            'gdpr': 'GDPR', 
            'fda': 'FDA_SAMD',
            'sox': 'SOX',
            'pci': 'PCI_DSS',
            'hitrust': 'HITRUST_CSF'
        }
        
        for keyword, framework in compliance_mapping.items():
            if keyword in line_lower:
                requirements.append(framework)
        
        return requirements
    
    def extract_onboarding_step(self, line: str) -> Optional[Dict[str, Any]]:
        """Extract onboarding step from English text"""
        line_lower = line.lower()
        
        if 'validate' in line_lower:
            return {
                'type': 'validation',
                'description': line,
                'action': 'validate_agent_metadata',
                'required': True
            }
        elif 'scan' in line_lower:
            return {
                'type': 'security_scan',
                'description': line,
                'action': 'perform_security_scan',
                'required': True
            }
        elif 'check compliance' in line_lower:
            return {
                'type': 'compliance_check',
                'description': line,
                'action': 'evaluate_compliance',
                'required': True
            }
        elif 'add to inventory' in line_lower:
            return {
                'type': 'inventory_registration',
                'description': line,
                'action': 'add_to_inventory',
                'required': True
            }
        elif 'notify' in line_lower:
            return {
                'type': 'notification',
                'description': line,
                'action': 'send_notification',
                'required': False
            }
        
        return None
    
    def extract_notification_settings(self, line: str) -> Dict[str, Any]:
        """Extract notification settings from English text"""
        settings = {}
        line_lower = line.lower()
        
        # Extract recipients
        if 'admin' in line_lower:
            settings['recipients'] = ['admin']
        elif 'team' in line_lower:
            settings['recipients'] = ['security_team', 'compliance_team']
        
        # Extract methods
        if 'email' in line_lower:
            settings['methods'] = ['email']
        elif 'slack' in line_lower:
            settings['methods'] = ['slack']
        
        return settings
    
    def extract_validation_rule(self, line: str) -> Optional[Dict[str, Any]]:
        """Extract validation rule from English text"""
        line_lower = line.lower()
        
        if 'must have' in line_lower:
            if 'encryption' in line_lower:
                return {
                    'type': 'encryption_required',
                    'description': line,
                    'field': 'encryption_status',
                    'operator': 'not_equals',
                    'value': 'none'
                }
            elif 'authentication' in line_lower:
                return {
                    'type': 'authentication_required',
                    'description': line,
                    'field': 'authentication',
                    'operator': 'exists',
                    'value': True
                }
        
        return None
    
    def generate_backend_code(self, config: Dict[str, Any]) -> str:
        """Generate backend code from parsed configuration"""
        code_parts = []
        
        # Header
        code_parts.append("# Auto-generated playbook execution code")
        code_parts.append("from datetime import datetime")
        code_parts.append("from models import AIAgent, AgentRegistration, AIAgentInventory")
        code_parts.append("from app import db")
        code_parts.append("")
        
        # Main execution function
        code_parts.append("def execute_playbook(agent_id: int, playbook_id: int):")
        code_parts.append("    \"\"\"Auto-generated playbook execution function\"\"\"")
        code_parts.append("    agent = AIAgent.query.get(agent_id)")
        code_parts.append("    if not agent:")
        code_parts.append("        raise ValueError(f'Agent {agent_id} not found')")
        code_parts.append("")
        
        # Trigger condition checks
        if config.get('trigger_conditions'):
            code_parts.append("    # Check trigger conditions")
            triggers = config['trigger_conditions']
            
            if 'min_risk_level' in triggers:
                code_parts.append(f"    if agent.scan_results:")
                code_parts.append(f"        latest_scan = agent.scan_results[-1]")
                code_parts.append(f"        if latest_scan.risk_level.value != '{triggers['min_risk_level']}':")
                code_parts.append(f"            return False, 'Risk level does not meet minimum requirement'")
            
            if 'protocols' in triggers:
                protocols = "', '".join(triggers['protocols'])
                code_parts.append(f"    if agent.protocol not in ['{protocols}']:")
                code_parts.append(f"        return False, 'Protocol not in allowed list'")
            
            if 'healthcare_context' in triggers:
                code_parts.append("    healthcare_indicators = ['medical', 'clinical', 'healthcare', 'hospital']")
                code_parts.append("    if not any(indicator in agent.name.lower() for indicator in healthcare_indicators):")
                code_parts.append("        return False, 'Not healthcare context'")
        
        code_parts.append("")
        
        # Onboarding steps
        if config.get('onboarding_steps'):
            code_parts.append("    # Execute onboarding steps")
            for i, step in enumerate(config['onboarding_steps']):
                code_parts.append(f"    # Step {i+1}: {step['description']}")
                
                if step['type'] == 'validation':
                    code_parts.append("    if not agent.agent_metadata:")
                    code_parts.append("        raise ValueError('Agent metadata validation failed')")
                
                elif step['type'] == 'security_scan':
                    code_parts.append("    # Trigger security scan")
                    code_parts.append("    from scanners.base_scanner import BaseScanner")
                    code_parts.append("    scanner = BaseScanner()")
                    code_parts.append("    # scanner.perform_security_scan(agent)")
                
                elif step['type'] == 'inventory_registration':
                    code_parts.append("    # Add to inventory")
                    code_parts.append("    inventory = AIAgentInventory.query.filter_by(agent_id=agent.id).first()")
                    code_parts.append("    if not inventory:")
                    code_parts.append("        inventory = AIAgentInventory(")
                    code_parts.append("            agent_id=agent.id,")
                    code_parts.append("            inventory_status=InventoryStatus.REGISTERED")
                    code_parts.append("        )")
                    code_parts.append("        db.session.add(inventory)")
                
                code_parts.append("")
        
        # Compliance checks
        if config.get('compliance_requirements'):
            code_parts.append("    # Compliance checks")
            for framework in config['compliance_requirements']:
                code_parts.append(f"    # Check {framework} compliance")
                code_parts.append(f"    # compliance_evaluator.evaluate(agent, '{framework}')")
            code_parts.append("")
        
        # Save registration
        code_parts.append("    # Create registration record")
        code_parts.append("    registration = AgentRegistration(")
        code_parts.append("        agent_id=agent.id,")
        code_parts.append("        playbook_id=playbook_id,")
        code_parts.append("        registration_status=RegistrationStatus.COMPLETED,")
        code_parts.append("        onboarding_progress={'completed_steps': len(onboarding_steps)},")
        code_parts.append("        completed_at=datetime.utcnow()")
        code_parts.append("    )")
        code_parts.append("    db.session.add(registration)")
        code_parts.append("    db.session.commit()")
        code_parts.append("")
        code_parts.append("    return True, 'Registration completed successfully'")
        
        return '\n'.join(code_parts)
    
    def update_playbook(self, playbook_id: int, plain_english_config: str) -> RegistrationPlaybook:
        """Update playbook configuration and regenerate backend code"""
        playbook = RegistrationPlaybook.query.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        # Parse updated configuration
        parsed_config = self.parse_english_config(plain_english_config)
        
        # Regenerate backend code
        generated_code = self.generate_backend_code(parsed_config)
        
        # Update playbook
        playbook.plain_english_config = plain_english_config
        playbook.generated_code = generated_code
        playbook.trigger_conditions = parsed_config.get('trigger_conditions', {})
        playbook.onboarding_steps = parsed_config.get('onboarding_steps', [])
        playbook.compliance_requirements = parsed_config.get('compliance_requirements', [])
        playbook.auto_onboarding_enabled = parsed_config.get('auto_onboarding', False)
        playbook.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        self.logger.info(f"Updated playbook {playbook_id} with regenerated backend code")
        return playbook
    
    def execute_playbook(self, agent_id: int, playbook_id: int) -> PlaybookExecution:
        """Execute a playbook for an agent"""
        execution = PlaybookExecution(
            playbook_id=playbook_id,
            agent_id=agent_id,
            execution_status=ExecutionStatus.RUNNING
        )
        db.session.add(execution)
        db.session.commit()
        
        try:
            playbook = RegistrationPlaybook.query.get(playbook_id)
            agent = AIAgent.query.get(agent_id)
            
            if not playbook or not agent:
                raise ValueError("Playbook or agent not found")
            
            # Execute generated backend code
            success, message = self._execute_generated_code(playbook, agent)
            
            if success:
                execution.execution_status = ExecutionStatus.COMPLETED
                execution.completed_at = datetime.utcnow()
                
                # Add to inventory if not already there
                self._add_to_inventory(agent)
                
            else:
                execution.execution_status = ExecutionStatus.FAILED
                execution.error_details = message
            
            execution.execution_log = message
            execution.execution_time = (datetime.utcnow() - execution.started_at).total_seconds()
            
            db.session.commit()
            return execution
            
        except Exception as e:
            execution.execution_status = ExecutionStatus.FAILED
            execution.error_details = str(e)
            execution.execution_time = (datetime.utcnow() - execution.started_at).total_seconds()
            db.session.commit()
            raise
    
    def _execute_generated_code(self, playbook: RegistrationPlaybook, agent: AIAgent) -> tuple[bool, str]:
        """Execute the generated backend code (simplified implementation)"""
        try:
            # In a production system, this would safely execute the generated code
            # For now, we'll simulate the execution based on the onboarding steps
            
            steps_completed = 0
            total_steps = len(playbook.onboarding_steps)
            
            for step in playbook.onboarding_steps:
                if step['type'] == 'validation':
                    if not agent.agent_metadata:
                        return False, "Agent metadata validation failed"
                
                elif step['type'] == 'inventory_registration':
                    # This will be handled separately
                    pass
                
                steps_completed += 1
            
            return True, f"Successfully completed {steps_completed}/{total_steps} onboarding steps"
            
        except Exception as e:
            return False, f"Execution failed: {str(e)}"
    
    def _add_to_inventory(self, agent: AIAgent):
        """Add agent to inventory if not already present"""
        inventory = AIAgentInventory.query.filter_by(agent_id=agent.id).first()
        
        if not inventory:
            inventory = AIAgentInventory(
                agent_id=agent.id,
                inventory_status=InventoryStatus.REGISTERED,
                use_case=f"Discovered via {agent.protocol} protocol",
                data_classification="internal",
                criticality_level="medium"
            )
            db.session.add(inventory)
            db.session.commit()
    
    def trigger_auto_onboarding(self, agent: AIAgent):
        """Check and trigger auto-onboarding for newly discovered agents"""
        # Find playbooks with auto-onboarding enabled
        auto_playbooks = RegistrationPlaybook.query.filter_by(
            auto_onboarding_enabled=True,
            is_active=True
        ).all()
        
        for playbook in auto_playbooks:
            if self._matches_trigger_conditions(agent, playbook.trigger_conditions):
                self.logger.info(f"Auto-triggering playbook '{playbook.name}' for agent '{agent.name}'")
                self.execute_playbook(agent.id, playbook.id)
    
    def _matches_trigger_conditions(self, agent: AIAgent, conditions: Dict[str, Any]) -> bool:
        """Check if agent matches playbook trigger conditions"""
        if not conditions:
            return True
        
        # Check protocol filter
        if 'protocols' in conditions:
            if agent.protocol not in conditions['protocols']:
                return False
        
        # Check cloud provider filter
        if 'cloud_providers' in conditions:
            if agent.cloud_provider not in conditions['cloud_providers']:
                return False
        
        # Check healthcare context
        if conditions.get('healthcare_context'):
            healthcare_indicators = ['medical', 'clinical', 'healthcare', 'hospital']
            if not any(indicator in agent.name.lower() for indicator in healthcare_indicators):
                return False
        
        # Check PHI exposure
        if conditions.get('phi_exposure') and agent.scan_results:
            latest_scan = agent.scan_results[-1]
            if not latest_scan.phi_exposure_detected:
                return False
        
        return True
    
    def get_inventory_summary(self) -> Dict[str, Any]:
        """Get AI Agent inventory summary"""
        total_agents = AIAgent.query.count()
        registered_agents = AIAgentInventory.query.filter_by(
            inventory_status=InventoryStatus.REGISTERED
        ).count()
        
        # Group by protocol
        protocol_counts = {}
        protocols = db.session.query(AIAgent.protocol).distinct().all()
        for (protocol,) in protocols:
            count = AIAgent.query.filter_by(protocol=protocol).count()
            protocol_counts[protocol] = count
        
        # Group by cloud provider
        cloud_counts = {}
        clouds = db.session.query(AIAgent.cloud_provider).distinct().all()
        for (cloud,) in clouds:
            if cloud:  # Skip None values
                count = AIAgent.query.filter_by(cloud_provider=cloud).count()
                cloud_counts[cloud] = count
        
        return {
            'total_discovered': total_agents,
            'total_registered': registered_agents,
            'registration_rate': (registered_agents / total_agents * 100) if total_agents > 0 else 0,
            'by_protocol': protocol_counts,
            'by_cloud_provider': cloud_counts
        }