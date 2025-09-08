from app import db
from datetime import datetime
from sqlalchemy import JSON
import enum

class ComplianceFramework(enum.Enum):
    HIPAA = "HIPAA"
    HITRUST_CSF = "HITRUST_CSF"
    FDA_SAMD = "FDA_SAMD"
    GDPR = "GDPR"
    SOC2_TYPE_II = "SOC2_TYPE_II"

class ScanStatus(enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RegistrationStatus(enum.Enum):
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


class InventoryStatus(enum.Enum):
    DISCOVERED = 'discovered'
    REGISTERED = 'registered'
    ACTIVE = 'active'
    INACTIVE = 'inactive'
    DEPRECATED = 'deprecated'
    DECOMMISSIONED = 'decommissioned'


class ExecutionStatus(enum.Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

class RiskLevel(enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AIAgent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(100), nullable=False)  # GenAI, Agentic AI, etc.
    protocol = db.Column(db.String(50), nullable=False)
    endpoint = db.Column(db.String(500), nullable=False)
    version = db.Column(db.String(50))
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    cloud_provider = db.Column(db.String(50))
    region = db.Column(db.String(100))
    agent_metadata = db.Column(JSON)
    
    # Relationships
    scan_results = db.relationship('ScanResult', backref='ai_agent', lazy=True)
    compliance_evaluations = db.relationship('ComplianceEvaluation', backref='ai_agent', lazy=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ai_agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'), nullable=False)
    scan_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Enum(ScanStatus), nullable=False)
    risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.Enum(RiskLevel), nullable=False)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    phi_exposure_detected = db.Column(db.Boolean, default=False)
    scan_duration = db.Column(db.Float)  # in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_data = db.Column(JSON)
    recommendations = db.Column(JSON)

class ComplianceEvaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ai_agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'), nullable=False)
    framework = db.Column(db.Enum(ComplianceFramework), nullable=False)
    compliance_score = db.Column(db.Float, nullable=False)  # 0-100
    is_compliant = db.Column(db.Boolean, nullable=False)
    findings = db.Column(JSON)
    recommendations = db.Column(JSON)
    evaluated_at = db.Column(db.DateTime, default=datetime.utcnow)
    evaluator_version = db.Column(db.String(50))

class WebhookConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    scan_frequency = db.Column(db.Integer, default=3600)  # seconds
    protocols = db.Column(JSON)  # list of protocols to scan
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_triggered = db.Column(db.DateTime)

class CloudDeployment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)  # AWS, Azure, GCP
    region = db.Column(db.String(100), nullable=False)
    deployment_status = db.Column(db.String(50), default='ACTIVE')
    api_key = db.Column(db.String(500))
    configuration = db.Column(JSON)
    last_health_check = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DataFlowMap(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'))
    destination_agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'))
    data_type = db.Column(db.String(100))  # PHI, PII, Clinical Data, etc.
    flow_volume = db.Column(db.Float)
    encryption_status = db.Column(db.String(50))
    compliance_status = db.Column(db.String(50))
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    flow_metadata = db.Column(JSON)
    
    # Relationships
    source_agent = db.relationship('AIAgent', foreign_keys=[source_agent_id], backref='outgoing_flows')
    destination_agent = db.relationship('AIAgent', foreign_keys=[destination_agent_id], backref='incoming_flows')


class RegistrationPlaybook(db.Model):
    """Agent registration playbooks with plain English configuration"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    plain_english_config = db.Column(db.Text, nullable=False)  # User-friendly configuration
    generated_code = db.Column(db.Text)  # Auto-generated backend code
    is_active = db.Column(db.Boolean, default=True)
    auto_onboarding_enabled = db.Column(db.Boolean, default=False)
    trigger_conditions = db.Column(JSON)  # Conditions for auto-triggering
    onboarding_steps = db.Column(JSON)  # Structured onboarding workflow
    compliance_requirements = db.Column(JSON)  # Required compliance checks
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.String(100), default='system')
    
    # Relationships
    agent_registrations = db.relationship('AgentRegistration', backref='playbook', lazy=True)


class AgentRegistration(db.Model):
    """Agent registration records using playbooks"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'), nullable=False)
    playbook_id = db.Column(db.Integer, db.ForeignKey('registration_playbook.id'), nullable=False)
    registration_status = db.Column(db.Enum(RegistrationStatus), default=RegistrationStatus.PENDING)
    onboarding_progress = db.Column(JSON)  # Step-by-step progress tracking
    compliance_status = db.Column(JSON)  # Compliance check results
    registration_data = db.Column(JSON)  # Custom registration fields
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    error_log = db.Column(db.Text)
    
    # Relationships
    agent = db.relationship('AIAgent', backref='registrations')


class AIAgentInventory(db.Model):
    """Centralized AI Agent inventory with comprehensive tracking"""
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'), nullable=False, unique=True)
    inventory_status = db.Column(db.Enum(InventoryStatus), default=InventoryStatus.DISCOVERED)
    business_owner = db.Column(db.String(200))
    technical_owner = db.Column(db.String(200))
    department = db.Column(db.String(100))
    use_case = db.Column(db.Text)
    data_classification = db.Column(db.String(50))  # public, internal, confidential, restricted
    criticality_level = db.Column(db.String(20))  # low, medium, high, critical
    regulatory_scope = db.Column(JSON)  # HIPAA, GDPR, FDA, etc.
    deployment_environment = db.Column(db.String(50))  # dev, staging, prod
    backup_strategy = db.Column(db.Text)
    disaster_recovery = db.Column(db.Text)
    monitoring_alerts = db.Column(JSON)
    maintenance_schedule = db.Column(JSON)
    cost_center = db.Column(db.String(100))
    budget_allocation = db.Column(db.Float)
    vendor_info = db.Column(JSON)
    license_info = db.Column(JSON)
    documentation_links = db.Column(JSON)
    added_to_inventory = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    agent = db.relationship('AIAgent', backref='inventory_record')


class PlaybookExecution(db.Model):
    """Track playbook execution history and results"""
    id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.Integer, db.ForeignKey('registration_playbook.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'), nullable=False)
    execution_status = db.Column(db.Enum(ExecutionStatus), default=ExecutionStatus.RUNNING)
    execution_log = db.Column(db.Text)
    step_results = db.Column(JSON)  # Results for each step
    error_details = db.Column(db.Text)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    execution_time = db.Column(db.Float)  # seconds
    
    # Relationships
    playbook = db.relationship('RegistrationPlaybook', backref='executions')
    agent = db.relationship('AIAgent', backref='playbook_executions')
