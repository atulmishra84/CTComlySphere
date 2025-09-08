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
