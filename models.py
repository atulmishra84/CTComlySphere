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
    NIST_AI_RMF = "NIST_AI_RMF"
    OWASP_AI = "OWASP_AI"
    MITRE_ATLAS = "MITRE_ATLAS"
    DATABRICKS_AI_GOVERNANCE = "DATABRICKS_AI_GOVERNANCE"
    DASF = "DASF"
    SAIF_GOOGLE = "SAIF_GOOGLE"

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

class AIAgentType(enum.Enum):
    TRADITIONAL_ML = "TRADITIONAL_ML"
    GENAI = "GENAI"
    AGENTIC_AI = "AGENTIC_AI"
    COMPUTER_VISION = "COMPUTER_VISION"
    NLP = "NLP"
    RECOMMENDATION = "RECOMMENDATION"
    PREDICTIVE_ANALYTICS = "PREDICTIVE_ANALYTICS"
    AUTONOMOUS_SYSTEM = "AUTONOMOUS_SYSTEM"
    CONVERSATIONAL_AI = "CONVERSATIONAL_AI"
    MULTIMODAL_AI = "MULTIMODAL_AI"
    CLAWBOT = "CLAWBOT"

class AIAgent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(100), nullable=False)  # GenAI, Agentic AI, etc.
    ai_type = db.Column(db.Enum(AIAgentType), default=AIAgentType.TRADITIONAL_ML)
    protocol = db.Column(db.String(50), nullable=False)
    endpoint = db.Column(db.String(500), nullable=False)
    version = db.Column(db.String(50))
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    cloud_provider = db.Column(db.String(50))
    region = db.Column(db.String(100))
    agent_metadata = db.Column(JSON)
    
    # GenAI and Agentic AI specific fields
    model_family = db.Column(db.String(100))  # GPT, Claude, LLaMA, etc.
    model_size = db.Column(db.String(50))  # 7B, 13B, 70B, etc.
    capabilities = db.Column(JSON)  # text, image, audio, video, code, etc.
    training_data_sources = db.Column(JSON)  # known training data sources
    fine_tuned = db.Column(db.Boolean, default=False)
    multimodal = db.Column(db.Boolean, default=False)
    
    # Agentic AI specific fields
    agent_framework = db.Column(db.String(100))  # LangChain, AutoGPT, CrewAI, etc.
    autonomy_level = db.Column(db.String(50))  # low, medium, high, full
    planning_capability = db.Column(db.Boolean, default=False)
    memory_enabled = db.Column(db.Boolean, default=False)
    tool_access = db.Column(JSON)  # list of tools/APIs the agent can access
    safety_measures = db.Column(JSON)  # implemented safety measures
    
    # Enhanced Agent Details - Owner/Operator Information
    owner_organization = db.Column(db.String(255))  # Organization that owns/operates the agent
    owner_contact = db.Column(db.String(255))  # Contact person or email
    deployment_environment = db.Column(db.String(100))  # production, staging, development
    deployment_method = db.Column(db.String(100))  # kubernetes, docker, serverless, etc.
    service_account = db.Column(db.String(255))  # Service account running the agent
    process_owner = db.Column(db.String(255))  # Process or team that owns the agent
    
    # Current Actions and Operations
    current_actions = db.Column(JSON)  # List of current/recent actions being performed
    active_sessions = db.Column(db.Integer, default=0)  # Number of active user sessions
    last_activity = db.Column(db.DateTime)  # Timestamp of last recorded activity
    operation_mode = db.Column(db.String(50))  # interactive, batch, autonomous, scheduled
    current_workload = db.Column(JSON)  # Current tasks/jobs being processed
    performance_metrics = db.Column(JSON)  # CPU, memory, response time metrics
    
    # Detailed Access and Permissions
    data_access_permissions = db.Column(JSON)  # Specific data sources the agent can access
    api_permissions = db.Column(JSON)  # External APIs and their permission levels
    network_access = db.Column(JSON)  # Network endpoints and firewall rules
    authentication_method = db.Column(db.String(100))  # OAuth, API key, certificate, etc.
    authorization_scope = db.Column(JSON)  # Specific permissions and scopes granted
    resource_limits = db.Column(JSON)  # CPU, memory, storage, rate limits
    compliance_controls = db.Column(JSON)  # HIPAA, GDPR controls in place
    audit_logging = db.Column(db.Boolean, default=False)  # Whether actions are logged
    
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
    
    # Enhanced fields for automatic classification and controls
    primary_classification = db.Column(db.String(100))
    secondary_classifications = db.Column(JSON)  # List of secondary classifications
    classification_confidence = db.Column(db.Float)  # 0.0 to 1.0
    classification_reasons = db.Column(JSON)  # List of classification reasons
    applicable_frameworks = db.Column(JSON)  # List of applicable compliance frameworks
    required_controls = db.Column(JSON)  # List of required security controls
    applied_controls = db.Column(JSON)  # List of successfully applied controls
    failed_controls = db.Column(JSON)  # List of failed control implementations
    control_status = db.Column(JSON)  # Status of each control (compliant/non-compliant/unknown)
    last_classification_update = db.Column(db.DateTime)
    classification_version = db.Column(db.String(50), default='1.0')
    
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


class ModelVersion(db.Model):
    """Track model versions in model registry"""
    id = db.Column(db.Integer, primary_key=True)
    model_name = db.Column(db.String(255), nullable=False, index=True)
    version = db.Column(db.String(50), nullable=False)
    stage = db.Column(db.String(50), default='None')  # None, Staging, Production, Archived
    description = db.Column(db.Text)
    created_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Model metadata
    framework = db.Column(db.String(100))  # tensorflow, pytorch, sklearn, etc.
    model_type = db.Column(db.String(100))  # classification, regression, nlp, etc.
    input_schema = db.Column(JSON)


# Remediation Workflow Models
class RemediationWorkflowStatus(enum.Enum):
    """Status of remediation workflow execution"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PARTIALLY_COMPLETED = "partially_completed"


class RemediationActionType(enum.Enum):
    """Types of remediation actions"""
    UPDATE_CONFIGURATION = "update_configuration"
    APPLY_SECURITY_PATCH = "apply_security_patch"
    ROTATE_CREDENTIALS = "rotate_credentials"
    ENABLE_ENCRYPTION = "enable_encryption"
    UPDATE_ACCESS_CONTROLS = "update_access_controls"
    BACKUP_DATA = "backup_data"
    NOTIFY_STAKEHOLDERS = "notify_stakeholders"
    RESTART_SERVICE = "restart_service"
    SCALE_RESOURCES = "scale_resources"
    RUN_COMPLIANCE_SCAN = "run_compliance_scan"
    UPDATE_MONITORING = "update_monitoring"
    QUARANTINE_SYSTEM = "quarantine_system"


class RemediationTriggerType(enum.Enum):
    """What triggered the remediation workflow"""
    COMPLIANCE_VIOLATION = "compliance_violation"
    SECURITY_ALERT = "security_alert"
    MANUAL_REQUEST = "manual_request"
    SCHEDULED_MAINTENANCE = "scheduled_maintenance"
    RISK_THRESHOLD_EXCEEDED = "risk_threshold_exceeded"
    AUDIT_FINDING = "audit_finding"
    POLICY_UPDATE = "policy_update"


class RemediationWorkflow(db.Model):
    """Automated remediation workflow definitions"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    workflow_type = db.Column(db.String(100), nullable=False)  # compliance, security, maintenance
    trigger_conditions = db.Column(JSON)  # Conditions that trigger this workflow
    trigger_type = db.Column(db.Enum(RemediationTriggerType), nullable=False)
    
    # Workflow configuration
    actions = db.Column(JSON)  # List of remediation actions to execute
    execution_order = db.Column(JSON)  # Order of action execution
    parallel_execution = db.Column(db.Boolean, default=False)
    timeout_minutes = db.Column(db.Integer, default=60)
    retry_attempts = db.Column(db.Integer, default=3)
    
    # Approval and safety settings
    requires_approval = db.Column(db.Boolean, default=False)
    auto_rollback = db.Column(db.Boolean, default=True)
    safety_checks = db.Column(JSON)  # Pre-execution safety validations
    
    # Targeting
    target_frameworks = db.Column(JSON)  # HIPAA, GDPR, etc.
    target_protocols = db.Column(JSON)  # REST, gRPC, etc.
    target_risk_levels = db.Column(JSON)  # HIGH, CRITICAL
    
    # Metadata
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_executed = db.Column(db.DateTime)
    execution_count = db.Column(db.Integer, default=0)
    
    # Relationships
    executions = db.relationship('RemediationExecution', backref='workflow', lazy=True)


class RemediationExecution(db.Model):
    """Record of workflow execution instances"""
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('remediation_workflow.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('ai_agent.id'), nullable=False)
    
    # Execution details
    status = db.Column(db.Enum(RemediationWorkflowStatus), default=RemediationWorkflowStatus.PENDING)
    trigger_data = db.Column(JSON)  # Data that triggered this execution
    execution_context = db.Column(JSON)  # Runtime context and variables
    
    # Timing
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Float)
    
    # Results
    actions_completed = db.Column(JSON)  # List of successfully completed actions
    actions_failed = db.Column(JSON)  # List of failed actions with error details
    rollback_actions = db.Column(JSON)  # Actions taken during rollback
    execution_log = db.Column(db.Text)
    error_message = db.Column(db.Text)
    
    # Approval workflow
    approval_requested = db.Column(db.Boolean, default=False)
    approval_granted_by = db.Column(db.String(100))
    approval_granted_at = db.Column(db.DateTime)
    
    # Relationships
    agent = db.relationship('AIAgent', backref='remediation_executions')
    action_executions = db.relationship('RemediationActionExecution', backref='execution', lazy=True)


class RemediationActionExecution(db.Model):
    """Individual action execution within a workflow"""
    id = db.Column(db.Integer, primary_key=True)
    execution_id = db.Column(db.Integer, db.ForeignKey('remediation_execution.id'), nullable=False)
    
    # Action details
    action_type = db.Column(db.Enum(RemediationActionType), nullable=False)
    action_name = db.Column(db.String(200), nullable=False)
    action_config = db.Column(JSON)  # Configuration for this specific action
    execution_order = db.Column(db.Integer, nullable=False)
    
    # Execution state
    status = db.Column(db.Enum(RemediationWorkflowStatus), default=RemediationWorkflowStatus.PENDING)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Float)
    retry_count = db.Column(db.Integer, default=0)
    
    # Results
    success = db.Column(db.Boolean)
    result_data = db.Column(JSON)  # Output data from action execution
    error_message = db.Column(db.Text)
    rollback_data = db.Column(JSON)  # Data needed for rollback
    
    # Before/after state for verification
    pre_execution_state = db.Column(JSON)
    post_execution_state = db.Column(JSON)


class RemediationTemplate(db.Model):
    """Pre-built remediation workflow templates"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))  # compliance, security, performance
    framework = db.Column(db.String(50))  # HIPAA, GDPR, etc.
    
    # Template configuration
    template_config = db.Column(JSON)  # Template workflow configuration
    required_parameters = db.Column(JSON)  # Parameters that must be provided
    optional_parameters = db.Column(JSON)  # Optional configuration parameters
    
    # Usage tracking
    usage_count = db.Column(db.Integer, default=0)
    created_by = db.Column(db.String(100), default='system')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    training_run_id = db.Column(db.String(255))
    experiment_id = db.Column(db.String(255))
    training_dataset = db.Column(db.String(500))
    training_samples = db.Column(db.Integer)
    validation_samples = db.Column(db.Integer)
    training_duration = db.Column(db.Float)  # hours
    
    # Performance metrics
    accuracy = db.Column(db.Float)
    precision = db.Column(db.Float)
    recall = db.Column(db.Float)
    f1_score = db.Column(db.Float)
    custom_metrics = db.Column(JSON)
    
    # Healthcare compliance
    processes_phi = db.Column(db.Boolean, default=False)
    hipaa_compliant = db.Column(db.Boolean, default=False)
    fda_cleared = db.Column(db.Boolean, default=False)
    gdpr_compliant = db.Column(db.Boolean, default=False)
    regulatory_approval = db.Column(db.String(255))
    data_classification = db.Column(db.String(100))
    compliance_frameworks = db.Column(JSON)
    
    # Deployment information
    deployment_config = db.Column(JSON)
    serving_endpoint = db.Column(db.String(500))
    deployment_status = db.Column(db.String(50))  # deployed, pending, failed
    last_deployed = db.Column(db.DateTime)
    
    


class ModelDeployment(db.Model):
    """Track model deployments across environments"""
    id = db.Column(db.Integer, primary_key=True)
    model_version_id = db.Column(db.Integer, db.ForeignKey('model_version.id'), nullable=False)
    deployment_id = db.Column(db.String(255), unique=True, nullable=False)
    environment = db.Column(db.String(100), nullable=False)  # dev, staging, prod
    deployment_target = db.Column(db.String(100))  # kubernetes, docker, lambda, etc.
    
    # Endpoint information
    endpoint_url = db.Column(db.String(500))
    health_check_url = db.Column(db.String(500))
    api_version = db.Column(db.String(50))
    
    # Deployment configuration
    deployment_config = db.Column(JSON)
    resource_requirements = db.Column(JSON)
    scaling_config = db.Column(JSON)
    security_config = db.Column(JSON)
    
    # Status tracking
    deployment_status = db.Column(db.String(50), default='pending')  # pending, active, failed, terminated
    health_status = db.Column(db.String(50), default='unknown')  # healthy, unhealthy, unknown
    
    # Timestamps
    deployed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_health_check = db.Column(db.DateTime)
    terminated_at = db.Column(db.DateTime)
    
    # Performance metrics
    request_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    average_response_time = db.Column(db.Float)
    last_prediction_time = db.Column(db.DateTime)
    
    # Compliance tracking
    compliance_scan_status = db.Column(db.String(50), default='pending')
    security_scan_results = db.Column(JSON)
    audit_logs_enabled = db.Column(db.Boolean, default=False)


class ModelLineage(db.Model):
    """Track model lineage and dependencies"""
    id = db.Column(db.Integer, primary_key=True)
    model_version_id = db.Column(db.Integer, db.ForeignKey('model_version.id'), nullable=False)
    
    # Lineage information
    parent_model_name = db.Column(db.String(255))
    parent_model_version = db.Column(db.String(50))
    training_run_id = db.Column(db.String(255))
    experiment_name = db.Column(db.String(255))
    
    # Data sources
    data_sources = db.Column(JSON)  # List of data source references
    feature_dependencies = db.Column(JSON)  # List of feature engineering dependencies
    code_version = db.Column(db.String(255))  # Git commit hash or version
    
    # Training artifacts
    training_artifacts = db.Column(JSON)  # List of training artifacts (logs, checkpoints, etc.)
    model_artifacts = db.Column(JSON)  # List of model artifacts (weights, config, etc.)
    
    # Dependencies
    framework_dependencies = db.Column(JSON)  # ML framework versions
    library_dependencies = db.Column(JSON)  # Python/R library versions
    infrastructure_dependencies = db.Column(JSON)  # Hardware, cloud resources
    
    # Provenance
    created_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lineage_extracted_at = db.Column(db.DateTime, default=datetime.utcnow)
    lineage_source = db.Column(db.String(100))  # mlflow, manual, api, etc.


class ModelRegistrySync(db.Model):
    """Track synchronization with external model registries"""
    id = db.Column(db.Integer, primary_key=True)
    registry_type = db.Column(db.String(50), nullable=False)  # mlflow, sagemaker, etc.
    registry_url = db.Column(db.String(500), nullable=False)
    
    # Sync status
    last_sync_at = db.Column(db.DateTime)
    sync_status = db.Column(db.String(50), default='pending')  # success, failed, in_progress
    sync_error = db.Column(db.Text)
    models_synced = db.Column(db.Integer, default=0)
    models_failed = db.Column(db.Integer, default=0)
    
    # Sync configuration
    sync_frequency = db.Column(db.String(50), default='daily')  # hourly, daily, weekly
    auto_sync_enabled = db.Column(db.Boolean, default=True)
    sync_filters = db.Column(JSON)  # Filters for what to sync
    
    # Connection info
    connection_validated = db.Column(db.Boolean, default=False)
    last_connection_check = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditTrail(db.Model):
    """Comprehensive audit trail for all user actions and system events"""
    id = db.Column(db.Integer, primary_key=True)
    
    # Event identification
    event_type = db.Column(db.String(50), nullable=False)  # login, scan, compliance_check, etc.
    event_category = db.Column(db.String(50), nullable=False)  # security, compliance, user_action, system
    action = db.Column(db.String(100), nullable=False)  # create, read, update, delete, execute
    
    # User and session information
    user_id = db.Column(db.String(255))  # User identifier
    session_id = db.Column(db.String(255))  # Session identifier
    ip_address = db.Column(db.String(45))  # IPv4/IPv6 address
    user_agent = db.Column(db.Text)  # Browser/client information
    
    # Resource information
    resource_type = db.Column(db.String(50))  # agent, scan, evaluation, etc.
    resource_id = db.Column(db.String(100))  # ID of the affected resource
    resource_name = db.Column(db.String(255))  # Human-readable resource name
    
    # Event details
    event_description = db.Column(db.Text, nullable=False)
    event_data = db.Column(JSON)  # Additional event-specific data
    outcome = db.Column(db.String(20), nullable=False)  # success, failure, warning
    
    # Risk and compliance
    risk_level = db.Column(db.Enum(RiskLevel), default=RiskLevel.LOW)
    compliance_relevant = db.Column(db.Boolean, default=False)
    frameworks_affected = db.Column(JSON)  # List of compliance frameworks affected
    
    # Timing and metadata
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    duration_ms = db.Column(db.Integer)  # Event duration in milliseconds
    correlation_id = db.Column(db.String(255))  # For correlating related events
    
    # Security context
    authentication_method = db.Column(db.String(50))  # how user authenticated
    authorization_context = db.Column(JSON)  # roles, permissions at time of event
    sensitive_data_accessed = db.Column(db.Boolean, default=False)
    
    # Retention and archival
    retention_period_days = db.Column(db.Integer, default=2555)  # 7 years default for compliance
    archived = db.Column(db.Boolean, default=False)
    archived_at = db.Column(db.DateTime)


class CustomerOnboarding(db.Model):
    """Track customer onboarding progress and configuration"""
    id = db.Column(db.Integer, primary_key=True)
    
    # Customer identification
    customer_id = db.Column(db.String(255), unique=True, nullable=False)
    organization_name = db.Column(db.String(255), nullable=False)
    primary_contact_email = db.Column(db.String(255), nullable=False)
    industry_type = db.Column(db.String(100))  # healthcare, fintech, government, etc.
    
    # Onboarding status
    onboarding_status = db.Column(db.String(50), default='started')  # started, in_progress, completed, paused
    current_step = db.Column(db.String(100), default='welcome')
    completion_percentage = db.Column(db.Float, default=0.0)
    
    # Configuration preferences
    deployment_type = db.Column(db.String(50))  # cloud, on_premise, hybrid
    cloud_providers = db.Column(JSON)  # List of cloud providers used
    compliance_requirements = db.Column(JSON)  # Required compliance frameworks
    ai_use_cases = db.Column(JSON)  # Types of AI systems they use
    
    # Security and access
    security_level = db.Column(db.String(20), default='standard')  # basic, standard, enterprise
    sso_enabled = db.Column(db.Boolean, default=False)
    mfa_enabled = db.Column(db.Boolean, default=False)
    api_access_enabled = db.Column(db.Boolean, default=False)
    
    # Setup progress tracking
    steps_completed = db.Column(JSON, default=list)  # List of completed onboarding steps
    configuration_data = db.Column(JSON)  # Customer-specific configuration
    integration_status = db.Column(JSON)  # Status of various integrations
    
    # Timeline tracking
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    estimated_completion = db.Column(db.DateTime)
    
    # Support and assistance
    assigned_specialist = db.Column(db.String(255))  # Customer success manager
    support_tickets = db.Column(JSON)  # List of related support tickets
    training_sessions = db.Column(JSON)  # Scheduled training sessions
    
    # Business context
    company_size = db.Column(db.String(50))  # startup, small, medium, enterprise
    expected_agent_count = db.Column(db.Integer)
    budget_tier = db.Column(db.String(50))  # basic, professional, enterprise
    go_live_target = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OnboardingStep(db.Model):
    """Define onboarding steps and workflow"""
    id = db.Column(db.Integer, primary_key=True)
    
    # Step identification
    step_key = db.Column(db.String(100), unique=True, nullable=False)
    step_name = db.Column(db.String(255), nullable=False)
    step_description = db.Column(db.Text)
    step_order = db.Column(db.Integer, nullable=False)
    
    # Step configuration
    step_type = db.Column(db.String(50), nullable=False)  # form, integration, verification, training
    is_required = db.Column(db.Boolean, default=True)
    estimated_time_minutes = db.Column(db.Integer, default=5)
    
    # Dependencies and prerequisites
    prerequisites = db.Column(JSON)  # List of required previous steps
    conditional_logic = db.Column(JSON)  # Conditions for showing this step
    
    # Content and guidance
    instructions = db.Column(db.Text)
    help_content = db.Column(db.Text)
    video_url = db.Column(db.String(500))
    documentation_links = db.Column(JSON)
    
    # Validation and completion
    validation_rules = db.Column(JSON)  # Rules for step completion
    completion_criteria = db.Column(JSON)  # What constitutes completion
    
    # Metadata
    category = db.Column(db.String(50))  # setup, security, integration, training
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CustomerProgress(db.Model):
    """Track individual customer progress through onboarding steps"""
    id = db.Column(db.Integer, primary_key=True)
    
    # References
    customer_id = db.Column(db.String(255), db.ForeignKey('customer_onboarding.customer_id'), nullable=False)
    step_key = db.Column(db.String(100), db.ForeignKey('onboarding_step.step_key'), nullable=False)
    
    # Progress tracking
    status = db.Column(db.String(50), default='not_started')  # not_started, in_progress, completed, skipped, failed
    attempts = db.Column(db.Integer, default=0)
    completion_data = db.Column(JSON)  # Data submitted/collected in this step
    
    # Timing
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    time_spent_minutes = db.Column(db.Float)
    
    # Support and feedback
    feedback = db.Column(db.Text)  # Customer feedback on this step
    support_notes = db.Column(db.Text)  # Internal support notes
    difficulty_rating = db.Column(db.Integer)  # 1-5 difficulty rating from customer
    
    # Relationships
    customer = db.relationship('CustomerOnboarding', backref='progress_records')
    step = db.relationship('OnboardingStep', backref='progress_records')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint to prevent duplicate progress records
    __table_args__ = (db.UniqueConstraint('customer_id', 'step_key'),)


class DeployedAgent(db.Model):
    """Tracks collector agents deployed into customer environments"""
    __tablename__ = 'deployed_agent'

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), unique=True, nullable=False)
    customer_name = db.Column(db.String(255), nullable=False)
    environment_label = db.Column(db.String(255))
    api_token = db.Column(db.String(128), unique=True, nullable=False)
    token_created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Status & connectivity
    status = db.Column(db.String(32), default='pending')   # pending, active, lost, revoked
    last_heartbeat = db.Column(db.DateTime)
    agent_version = db.Column(db.String(32))
    hostname = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    os_info = db.Column(db.String(255))

    # Scan configuration
    scan_interval_minutes = db.Column(db.Integer, default=60)
    enabled_scanners = db.Column(JSON)      # list of scanner names
    scan_targets = db.Column(JSON)          # network ranges / endpoints

    # Reporting stats
    total_reports = db.Column(db.Integer, default=0)
    last_report_at = db.Column(db.DateTime)
    agents_discovered_total = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
