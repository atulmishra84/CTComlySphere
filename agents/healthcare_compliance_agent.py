"""
Healthcare Compliance AI Agent
Autonomous agent for managing healthcare AI compliance across organizations
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

from app import db
from models import AIAgent, ComplianceEvaluation, ScanResult, ComplianceFramework, RiskLevel
from agents.classification_engine import AgentClassificationEngine
from agents.enhanced_decision_engine import enhanced_decision_engine, DecisionContext, RiskPrediction
from agents.memory_system import agent_memory_system, MemoryType, MemoryImportance
from agents.remediation_integration import agent_remediation_integration, RemediationRequest


class AgentAction(Enum):
    """Actions the compliance agent can take"""
    DISCOVER_SYSTEMS = "discover_systems"
    ASSESS_COMPLIANCE = "assess_compliance"
    GENERATE_REPORT = "generate_report"
    REMEDIATE_ISSUES = "remediate_issues"
    MONITOR_CHANGES = "monitor_changes"
    ALERT_STAKEHOLDERS = "alert_stakeholders"
    UPDATE_POLICIES = "update_policies"
    SCHEDULE_AUDIT = "schedule_audit"


class Priority(Enum):
    """Priority levels for agent actions"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AgentTask:
    """Task for the compliance agent to execute"""
    id: str
    action: AgentAction
    priority: Priority
    context: Dict[str, Any]
    created_at: datetime
    scheduled_for: Optional[datetime] = None
    completed: bool = False
    result: Optional[Dict[str, Any]] = None


class HealthcareComplianceAgent:
    """
    Autonomous AI Agent for Healthcare Compliance Management
    
    This agent proactively:
    - Discovers new AI systems in healthcare environments
    - Assesses compliance against regulatory frameworks
    - Identifies and prioritizes risks
    - Generates compliance reports and recommendations
    - Takes autonomous remediation actions
    - Learns from compliance patterns and decisions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.classifier = AgentClassificationEngine()
        self.task_queue: List[AgentTask] = []
        self.knowledge_base: Dict[str, Any] = {}
        self.decision_history: List[Dict[str, Any]] = []
        self.running = False
        
        # Enhanced AI capabilities
        self.decision_engine = enhanced_decision_engine
        self.memory_system = agent_memory_system
        
        # Advanced performance tracking
        self.performance_metrics = {
            "accuracy_score": 0.0,
            "prediction_confidence": 0.0,
            "processing_speed": 0.0,
            "compliance_detection_rate": 0.0,
            "false_positive_rate": 0.0
        }
        
        # Enhanced predictive analytics
        self.risk_predictions: Dict[str, RiskPrediction] = {}
        self.learning_mode = True
        self.adaptive_threshold = 0.85  # Dynamic threshold adjustment
        
        # Advanced security scanning capabilities
        self.security_scanners = {
            "vulnerability_scanner": None,
            "threat_intelligence": None,
            "behavioral_analysis": None,
            "anomaly_detector": None
        }
        
        # External service integrations
        self.external_services = {
            "threat_feeds": [],
            "compliance_apis": [],
            "security_tools": [],
            "notification_channels": []
        }
        
        # Remediation integration
        self.remediation_integration = agent_remediation_integration
        
        # Initialize agent capabilities
        self.initialize_knowledge_base()
        self.initialize_enhanced_capabilities()
        self.initialize_advanced_security()
        self.initialize_external_integrations()
        self.logger.info("Enhanced Healthcare Compliance AI Agent initialized with advanced capabilities")
    
    def initialize_enhanced_capabilities(self):
        """Initialize enhanced AI capabilities including decision engine and memory system"""
        try:
            # Initialize memory system with performance optimization
            self.memory_system.load_critical_memories()
            
            # Load agent preferences and patterns
            self.load_agent_learning_data()
            
            # Initialize performance optimization features
            self.initialize_performance_optimization()
            
            # Setup accuracy improvement mechanisms
            self.setup_accuracy_improvements()
            
            self.logger.info("Enhanced AI capabilities initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing enhanced capabilities: {str(e)}")
            # Fallback to basic functionality
            self.learning_mode = False
    
    def initialize_advanced_security(self):
        """Initialize advanced security scanning capabilities"""
        try:
            # Enhanced vulnerability detection
            self.security_scanners["vulnerability_scanner"] = {
                "engine": "advanced_vuln_scanner",
                "signatures": self._load_vulnerability_signatures(),
                "zero_day_detection": True,
                "behavioral_analysis": True
            }
            
            # Threat intelligence integration
            self.security_scanners["threat_intelligence"] = {
                "feeds": ["mitre_attack", "cisa_advisories", "healthcare_threats"],
                "real_time_updates": True,
                "contextual_analysis": True
            }
            
            # Advanced behavioral analysis
            self.security_scanners["behavioral_analysis"] = {
                "baseline_learning": True,
                "anomaly_threshold": 0.95,
                "ml_models": ["isolation_forest", "lstm_autoencoder"],
                "real_time_monitoring": True
            }
            
            self.logger.info("Advanced security scanning capabilities initialized")
        except Exception as e:
            self.logger.error(f"Error initializing security capabilities: {str(e)}")
    
    def initialize_external_integrations(self):
        """Initialize external service integrations"""
        try:
            # Threat intelligence feeds
            self.external_services["threat_feeds"] = [
                {"name": "MITRE ATT&CK", "endpoint": "https://attack.mitre.org/", "active": True},
                {"name": "CISA Advisories", "endpoint": "https://us-cert.cisa.gov/", "active": True},
                {"name": "Healthcare Cybersecurity", "endpoint": "https://healthsectorcouncil.org/", "active": True}
            ]
            
            # Compliance validation APIs
            self.external_services["compliance_apis"] = [
                {"name": "HIPAA Validator", "service": "hipaa_compliance_api", "active": True},
                {"name": "FDA Validator", "service": "fda_compliance_api", "active": True},
                {"name": "GDPR Validator", "service": "gdpr_compliance_api", "active": True}
            ]
            
            # Security tool integrations
            self.external_services["security_tools"] = [
                {"name": "SIEM Integration", "type": "log_analytics", "active": True},
                {"name": "Vulnerability Scanner", "type": "security_scan", "active": True},
                {"name": "Cloud Security", "type": "cloud_posture", "active": True}
            ]
            
            self.logger.info("External service integrations initialized")
        except Exception as e:
            self.logger.error(f"Error initializing external integrations: {str(e)}")
    
    def initialize_performance_optimization(self):
        """Initialize performance optimization features"""
        try:
            # Caching strategies
            self.performance_cache = {
                "scan_results": {},
                "compliance_evaluations": {},
                "risk_assessments": {},
                "ttl": 3600  # 1 hour cache TTL
            }
            
            # Parallel processing configuration
            self.parallel_config = {
                "max_workers": 4,
                "batch_size": 10,
                "async_enabled": True
            }
            
            # Performance monitoring
            self.performance_monitor = {
                "response_times": [],
                "throughput_metrics": [],
                "resource_usage": [],
                "error_rates": []
            }
            
            self.logger.info("Performance optimization features initialized")
        except Exception as e:
            self.logger.error(f"Error initializing performance optimization: {str(e)}")
    
    def setup_accuracy_improvements(self):
        """Setup accuracy improvement mechanisms"""
        try:
            # Enhanced pattern recognition
            self.accuracy_config = {
                "confidence_threshold": 0.9,
                "validation_rounds": 3,
                "cross_validation": True,
                "ensemble_methods": True
            }
            
            # Machine learning model optimization
            self.ml_optimization = {
                "auto_tuning": True,
                "feature_selection": True,
                "model_ensemble": True,
                "continuous_learning": True
            }
            
            # Data quality improvements
            self.data_quality = {
                "preprocessing": True,
                "anomaly_detection": True,
                "data_validation": True,
                "bias_detection": True
            }
            
            self.logger.info("Accuracy improvement mechanisms configured")
        except Exception as e:
            self.logger.error(f"Error setting up accuracy improvements: {str(e)}")
    
    def load_agent_learning_data(self):
        """Load historical learning data and patterns from memory system"""
        # Load decision patterns
        decision_memories = self.memory_system.search_memories(
            memory_type=MemoryType.DECISION,
            limit=100
        )
        
        for memory in decision_memories:
            decision_data = memory.content
            if decision_data.get("effectiveness_score", 0) > 0.7:
                # Learn from successful decisions
                pattern_data = {
                    "context": decision_data.get("decision_context", {}),
                    "outcome": decision_data.get("decision_outcome", {}),
                    "success_factors": decision_data.get("success_factors", []),
                    "confidence": decision_data.get("effectiveness_score", 0.5)
                }
                
                self.memory_system.learn_patterns("successful_decision", pattern_data)
        
        self.logger.info(f"Loaded {len(decision_memories)} decision patterns for learning")
    
    def _load_vulnerability_signatures(self):
        """Load vulnerability signatures for enhanced security scanning"""
        try:
            return {
                "healthcare_specific": [
                    "phi_exposure_patterns",
                    "medical_device_vulnerabilities", 
                    "ehr_system_weaknesses",
                    "healthcare_api_misconfigurations"
                ],
                "general_security": [
                    "sql_injection_patterns",
                    "xss_vulnerabilities",
                    "authentication_bypasses",
                    "privilege_escalation"
                ],
                "ai_ml_specific": [
                    "model_poisoning_indicators",
                    "adversarial_attack_patterns",
                    "data_poisoning_signatures",
                    "model_extraction_attempts"
                ],
                "compliance_violations": [
                    "hipaa_violations",
                    "gdpr_violations", 
                    "fda_non_compliance",
                    "soc2_control_failures"
                ]
            }
        except Exception as e:
            self.logger.error(f"Error loading vulnerability signatures: {str(e)}")
            return {}
    
    def initialize_knowledge_base(self):
        """Initialize the agent's knowledge base with compliance rules and patterns"""
        self.knowledge_base = {
            "compliance_frameworks": {
                "HIPAA": {
                    "critical_controls": [
                        "access_controls",
                        "audit_logs",
                        "encryption",
                        "phi_protection"
                    ],
                    "risk_threshold": 85,
                    "auto_remediation": True
                },
                "FDA_SAMD": {
                    "critical_controls": [
                        "clinical_validation",
                        "risk_management",
                        "quality_management",
                        "post_market_surveillance"
                    ],
                    "risk_threshold": 90,
                    "auto_remediation": False
                },
                "HITRUST_CSF": {
                    "critical_controls": [
                        "security_management",
                        "access_control",
                        "cryptography",
                        "vulnerability_management"
                    ],
                    "risk_threshold": 80,
                    "auto_remediation": True
                }
            },
            "genai_specific_rules": {
                "prompt_injection_protection": "required",
                "output_validation": "required",
                "bias_testing": "required_for_clinical",
                "model_transparency": "recommended"
            },
            "agentic_ai_rules": {
                "human_oversight": "required_for_critical_decisions",
                "decision_logging": "required",
                "tool_access_controls": "required",
                "planning_transparency": "required"
            },
            "risk_patterns": {
                "phi_exposure": {"severity": "critical", "immediate_action": True},
                "unauthorized_access": {"severity": "high", "immediate_action": True},
                "model_drift": {"severity": "medium", "immediate_action": False},
                "compliance_drift": {"severity": "medium", "immediate_action": False}
            }
        }
    
    async def start_agent(self):
        """Start the autonomous agent execution loop"""
        self.running = True
        self.logger.info("Healthcare Compliance Agent starting autonomous operations")
        
        # Schedule initial discovery
        await self.schedule_task(
            AgentAction.DISCOVER_SYSTEMS,
            Priority.HIGH,
            {"scope": "full_environment"}
        )
        
        # Start enhanced execution loop
        while self.running:
            await self.process_task_queue()
            await self.monitor_compliance_status()
            await self.proactive_monitoring()  # Enhanced proactive monitoring
            await self.learn_from_decisions()
            await asyncio.sleep(300)  # 5-minute cycle
    
    async def schedule_task(self, action: AgentAction, priority: Priority, context: Dict[str, Any], 
                          schedule_time: Optional[datetime] = None):
        """Schedule a task for the agent to execute"""
        task = AgentTask(
            id=f"{action.value}_{datetime.utcnow().timestamp()}",
            action=action,
            priority=priority,
            context=context,
            created_at=datetime.utcnow(),
            scheduled_for=schedule_time
        )
        
        self.task_queue.append(task)
        self.task_queue.sort(key=lambda t: (t.priority.value, t.created_at))
        
        self.logger.info(f"Scheduled task: {action.value} with priority {priority.value}")
    
    async def process_task_queue(self):
        """Process tasks in the queue based on priority and scheduling"""
        current_time = datetime.utcnow()
        
        for task in self.task_queue[:]:
            if task.completed:
                continue
                
            # Check if task is ready to execute
            if task.scheduled_for and task.scheduled_for > current_time:
                continue
            
            try:
                result = await self.execute_task(task)
                task.result = result
                task.completed = True
                
                # Record decision for learning
                self.decision_history.append({
                    "task_id": task.id,
                    "action": task.action.value,
                    "context": task.context,
                    "result": result,
                    "timestamp": current_time.isoformat()
                })
                
                self.logger.info(f"Completed task: {task.id}")
                
            except Exception as e:
                self.logger.error(f"Task execution failed: {task.id} - {str(e)}")
    
    async def execute_task(self, task: AgentTask) -> Dict[str, Any]:
        """Execute a specific task based on its action type"""
        if task.action == AgentAction.DISCOVER_SYSTEMS:
            return await self.discover_ai_systems(task.context)
        elif task.action == AgentAction.ASSESS_COMPLIANCE:
            return await self.assess_compliance(task.context)
        elif task.action == AgentAction.GENERATE_REPORT:
            return await self.generate_compliance_report(task.context)
        elif task.action == AgentAction.REMEDIATE_ISSUES:
            return await self.remediate_compliance_issues(task.context)
        elif task.action == AgentAction.MONITOR_CHANGES:
            return await self.monitor_system_changes(task.context)
        elif task.action == AgentAction.ALERT_STAKEHOLDERS:
            return await self.alert_stakeholders(task.context)
        elif task.action == AgentAction.UPDATE_POLICIES:
            return await self.update_compliance_policies(task.context)
        elif task.action == AgentAction.SCHEDULE_AUDIT:
            return await self.schedule_compliance_audit(task.context)
        else:
            raise ValueError(f"Unknown action: {task.action}")
    
    async def discover_ai_systems(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Autonomously discover AI systems in the environment"""
        from scanners.scanner_manager import ScannerManager
        
        self.logger.info("Agent initiating AI system discovery")
        
        # Initialize scanner manager
        scanner_manager = ScannerManager()
        
        # Determine scan scope based on context
        scope = context.get("scope", "incremental")
        protocols = context.get("protocols", ["rest_api", "kubernetes", "docker"])
        
        discovery_results = {}
        new_systems_found = 0
        
        for protocol in protocols:
            try:
                results = await scanner_manager.run_protocol_scan(protocol)
                discovery_results[protocol] = results
                
                # Process and classify discovered systems
                for agent_data in results.get("agents", []):
                    # Check if this is a new system
                    existing = AIAgent.query.filter_by(endpoint=agent_data["endpoint"]).first()
                    if not existing:
                        # Classify the new agent
                        classification = self.classifier.classify_agent(None, agent_data.get("metadata", {}))
                        
                        # Schedule compliance assessment for new system
                        await self.schedule_task(
                            AgentAction.ASSESS_COMPLIANCE,
                            Priority.HIGH,
                            {"agent_data": agent_data, "classification": classification}
                        )
                        
                        new_systems_found += 1
                        
            except Exception as e:
                self.logger.error(f"Discovery failed for protocol {protocol}: {str(e)}")
        
        # Schedule next discovery
        next_discovery = datetime.utcnow() + timedelta(hours=6)
        await self.schedule_task(
            AgentAction.DISCOVER_SYSTEMS,
            Priority.MEDIUM,
            {"scope": "incremental"},
            next_discovery
        )
        
        return {
            "systems_discovered": discovery_results,
            "new_systems": new_systems_found,
            "next_discovery_scheduled": next_discovery.isoformat()
        }
    
    async def assess_compliance(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance for AI systems"""
        agent_data = context.get("agent_data")
        classification = context.get("classification", {})
        
        self.logger.info(f"Agent assessing compliance for: {agent_data.get('name', 'Unknown')}")
        
        compliance_results = {}
        critical_issues = []
        
        # Determine applicable frameworks based on classification
        applicable_frameworks = self.determine_applicable_frameworks(classification)
        
        for framework in applicable_frameworks:
            try:
                assessment = await self.perform_framework_assessment(agent_data, framework, classification)
                compliance_results[framework] = assessment
                
                # Check for critical issues
                if assessment["score"] < self.knowledge_base["compliance_frameworks"][framework]["risk_threshold"]:
                    critical_issues.append({
                        "framework": framework,
                        "score": assessment["score"],
                        "issues": assessment["issues"]
                    })
                    
            except Exception as e:
                self.logger.error(f"Compliance assessment failed for {framework}: {str(e)}")
        
        # Schedule remediation if critical issues found
        if critical_issues:
            await self.schedule_task(
                AgentAction.REMEDIATE_ISSUES,
                Priority.CRITICAL,
                {"agent_data": agent_data, "critical_issues": critical_issues}
            )
        
        return {
            "compliance_results": compliance_results,
            "critical_issues": critical_issues,
            "recommendations": await self.generate_recommendations(compliance_results, classification)
        }
    
    async def generate_compliance_report(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance reports"""
        report_type = context.get("type", "summary")
        timeframe = context.get("timeframe", "monthly")
        
        self.logger.info(f"Agent generating {report_type} compliance report")
        
        # Gather compliance data
        agents = AIAgent.query.all()
        evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.created_at >= datetime.utcnow() - timedelta(days=30)
        ).all()
        
        report_data = {
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": report_type,
            "timeframe": timeframe,
            "summary": {
                "total_agents": len(agents),
                "compliant_agents": 0,
                "critical_issues": 0,
                "recommendations": []
            },
            "framework_compliance": {},
            "risk_analysis": {},
            "trends": {}
        }
        
        # Analyze compliance by framework
        for framework in ComplianceFramework:
            framework_evals = [e for e in evaluations if e.framework == framework]
            if framework_evals:
                avg_score = sum(e.compliance_score for e in framework_evals) / len(framework_evals)
                compliant_count = sum(1 for e in framework_evals if e.compliance_score >= 80)
                
                report_data["framework_compliance"][framework.value] = {
                    "average_score": round(avg_score, 2),
                    "compliant_percentage": round((compliant_count / len(framework_evals)) * 100, 2),
                    "total_assessments": len(framework_evals)
                }
        
        return report_data
    
    async def remediate_compliance_issues(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically remediate compliance issues where possible"""
        agent_data = context.get("agent_data")
        critical_issues = context.get("critical_issues", [])
        
        self.logger.info(f"Agent remediating issues for: {agent_data.get('name', 'Unknown')}")
        
        remediation_results = []
        
        for issue in critical_issues:
            framework = issue["framework"]
            framework_config = self.knowledge_base["compliance_frameworks"].get(framework, {})
            
            if framework_config.get("auto_remediation", False):
                try:
                    remediation = await self.apply_auto_remediation(agent_data, issue)
                    remediation_results.append({
                        "framework": framework,
                        "issue": issue,
                        "remediation": remediation,
                        "status": "completed"
                    })
                except Exception as e:
                    remediation_results.append({
                        "framework": framework,
                        "issue": issue,
                        "error": str(e),
                        "status": "failed"
                    })
            else:
                # Schedule manual review
                await self.schedule_task(
                    AgentAction.ALERT_STAKEHOLDERS,
                    Priority.HIGH,
                    {"issue": issue, "agent_data": agent_data, "requires_manual_review": True}
                )
                
                remediation_results.append({
                    "framework": framework,
                    "issue": issue,
                    "status": "requires_manual_review"
                })
        
        return {"remediation_results": remediation_results}
    
    async def monitor_compliance_status(self):
        """Continuously monitor compliance status and detect changes"""
        # Check for systems that haven't been scanned recently
        stale_threshold = datetime.utcnow() - timedelta(hours=24)
        stale_agents = AIAgent.query.filter(
            AIAgent.last_scanned < stale_threshold
        ).all()
        
        for agent in stale_agents:
            await self.schedule_task(
                AgentAction.ASSESS_COMPLIANCE,
                Priority.MEDIUM,
                {"agent_id": agent.id, "reason": "stale_scan"}
            )
        
        # Check for compliance score deterioration
        recent_evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.created_at >= datetime.utcnow() - timedelta(hours=6)
        ).all()
        
        for evaluation in recent_evaluations:
            if evaluation.compliance_score < 70:  # Threshold for concern
                await self.schedule_task(
                    AgentAction.REMEDIATE_ISSUES,
                    Priority.HIGH,
                    {"evaluation_id": evaluation.id, "urgent": True}
                )
    
    async def learn_from_decisions(self):
        """Enhanced learning from past decisions using memory system and pattern analysis"""
        if not self.learning_mode:
            return
        
        try:
            # Analyze decision patterns using enhanced capabilities
            recent_decisions = self.decision_history[-100:]  # Last 100 decisions
            
            # Store decisions in memory system for learning
            for decision in recent_decisions[-10:]:  # Process recent decisions
                effectiveness_score = decision.get("effectiveness_score")
                if effectiveness_score is not None:
                    self.memory_system.store_decision_memory(
                        decision_context=decision.get("context", {}),
                        decision_outcome=decision.get("result", {}),
                        effectiveness_score=effectiveness_score
                    )
            
            # Learn patterns from successful decisions
            successful_patterns = []
            for decision in recent_decisions:
                if decision.get("effectiveness_score", 0) > 0.8:
                    pattern_data = {
                        "action": decision.get("action"),
                        "context": decision.get("context"),
                        "success_factors": decision.get("success_factors", []),
                        "confidence": decision.get("effectiveness_score")
                    }
                    successful_patterns.append(pattern_data)
            
            # Update knowledge base with learned patterns
            if successful_patterns:
                await self.update_knowledge_base_from_patterns(successful_patterns)
            
            self.logger.info(f"Enhanced learning completed: analyzed {len(recent_decisions)} decisions, found {len(successful_patterns)} successful patterns")
            
        except Exception as e:
            self.logger.error(f"Enhanced learning failed: {str(e)}")
            # Fallback to basic learning
            if recent_decisions:
                self.logger.info(f"Basic learning from {len(recent_decisions)} recent decisions")
    
    async def update_knowledge_base_from_patterns(self, patterns: List[Dict[str, Any]]):
        """Update knowledge base based on learned patterns"""
        for pattern in patterns:
            action = pattern.get("action")
            context = pattern.get("context", {})
            
            # Update risk thresholds based on successful interventions
            framework = context.get("compliance_framework")
            if framework and framework in self.knowledge_base["compliance_frameworks"]:
                current_threshold = self.knowledge_base["compliance_frameworks"][framework]["risk_threshold"]
                
                # Adjust threshold based on pattern success
                if pattern.get("confidence", 0) > 0.9:
                    # Very successful pattern - can be more aggressive
                    new_threshold = max(current_threshold - 2, 60)
                    self.knowledge_base["compliance_frameworks"][framework]["risk_threshold"] = new_threshold
                    
                    self.logger.info(f"Updated {framework} risk threshold to {new_threshold} based on successful pattern")
    
    async def predict_compliance_risks(self, agent_id: str, frameworks: List[str] = None) -> Dict[str, RiskPrediction]:
        """Predict compliance risks for specific agent across frameworks"""
        predictions = {}
        
        try:
            agent = AIAgent.query.get(agent_id)
            if not agent:
                return predictions
            
            # Use provided frameworks or detect from agent
            target_frameworks = frameworks or self._detect_applicable_frameworks(agent)
            
            for framework in target_frameworks:
                # Create decision context
                context = DecisionContext(
                    agent_id=agent_id,
                    compliance_framework=framework,
                    current_risk_level=agent.risk_level or RiskLevel.MEDIUM,
                    historical_patterns=await self._get_historical_patterns(agent_id, framework),
                    environmental_factors=await self._get_environmental_factors(),
                    business_impact=await self._assess_business_impact(agent),
                    regulatory_changes=await self._get_regulatory_changes(framework)
                )
                
                # Get risk prediction
                prediction = await self.decision_engine.predict_compliance_risk(context)
                predictions[framework] = prediction
                
                # Store prediction for tracking
                self.risk_predictions[f"{agent_id}_{framework}"] = prediction
                
                # Schedule remediation if high risk predicted
                await self._handle_risk_prediction(agent_id, framework, prediction)
            
            self.logger.info(f"Generated risk predictions for agent {agent_id} across {len(target_frameworks)} frameworks")
            
        except Exception as e:
            self.logger.error(f"Risk prediction failed for agent {agent_id}: {str(e)}")
        
        return predictions
    
    async def _handle_risk_prediction(self, agent_id: str, framework: str, prediction: RiskPrediction):
        """Handle risk prediction by scheduling appropriate actions"""
        
        if prediction.predicted_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            # Schedule immediate assessment
            await self.schedule_task(
                AgentAction.ASSESS_COMPLIANCE,
                Priority.HIGH if prediction.predicted_risk_level == RiskLevel.HIGH else Priority.CRITICAL,
                {
                    "agent_id": agent_id,
                    "framework": framework,
                    "predicted_risk": prediction.predicted_risk_level.value,
                    "confidence": prediction.confidence.value,
                    "reason": "high_risk_predicted"
                }
            )
            
            # Schedule remediation if auto-remediation enabled
            framework_config = self.knowledge_base["compliance_frameworks"].get(framework, {})
            if framework_config.get("auto_remediation", False):
                await self.schedule_task(
                    AgentAction.REMEDIATE_ISSUES,
                    Priority.HIGH,
                    {
                        "agent_id": agent_id,
                        "framework": framework,
                        "predicted_issues": prediction.contributing_factors,
                        "recommended_actions": prediction.recommended_actions,
                        "auto_triggered": True
                    }
                )
        
        elif prediction.predicted_risk_level == RiskLevel.MEDIUM:
            # Schedule monitoring
            await self.schedule_task(
                AgentAction.MONITOR_CHANGES,
                Priority.MEDIUM,
                {
                    "agent_id": agent_id,
                    "framework": framework,
                    "monitoring_focus": prediction.contributing_factors,
                    "prediction_horizon": prediction.prediction_horizon
                }
            )
    
    def _detect_applicable_frameworks(self, agent: AIAgent) -> List[str]:
        """Detect which compliance frameworks apply to an agent"""
        frameworks = []
        
        # Basic framework detection logic
        if agent.healthcare_related:
            frameworks.append("HIPAA")
        
        if agent.ai_type and "medical" in str(agent.ai_type).lower():
            frameworks.append("FDA")
        
        if agent.data_processing_eu:
            frameworks.append("GDPR")
        
        # Default frameworks for all healthcare AI
        if not frameworks:
            frameworks = ["HIPAA", "SOC2"]
        
        return frameworks
    
    async def _get_historical_patterns(self, agent_id: str, framework: str) -> Dict[str, Any]:
        """Get historical patterns for agent and framework"""
        try:
            # Search for historical decision patterns
            historical_memories = self.memory_system.search_memories(
                memory_type=MemoryType.PATTERN,
                tags=[f"agent:{agent_id}", f"framework:{framework}"],
                limit=10
            )
            
            patterns = {}
            for memory in historical_memories:
                pattern_data = memory.content
                pattern_type = pattern_data.get("pattern_type", "unknown")
                patterns[pattern_type] = pattern_data
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error getting historical patterns: {str(e)}")
            return {}
    
    async def _get_environmental_factors(self) -> Dict[str, Any]:
        """Get current environmental factors affecting compliance"""
        return {
            "system_load": 0.6,  # Would be detected from monitoring
            "network_issues": False,
            "resource_constraints": False,
            "maintenance_window": False
        }
    
    async def _assess_business_impact(self, agent: AIAgent) -> Dict[str, Any]:
        """Assess business impact of compliance issues"""
        return {
            "criticality": "high" if agent.healthcare_related else "medium",
            "patient_facing": agent.healthcare_related,
            "data_sensitivity": "high" if agent.healthcare_related else "medium",
            "regulatory_visibility": "high"
        }
    
    async def _get_regulatory_changes(self, framework: str) -> List[Dict[str, Any]]:
        """Get recent regulatory changes for framework"""
        # This would integrate with regulatory monitoring services
        return []
    
    async def proactive_monitoring(self):
        """Enhanced proactive monitoring with predictive capabilities"""
        try:
            # Get all agents for monitoring
            agents = AIAgent.query.all()
            
            for agent in agents:
                # Predict risks for each agent
                predictions = await self.predict_compliance_risks(agent.id)
                
                # Check for immediate actions needed
                for framework, prediction in predictions.items():
                    if prediction.confidence.value in ["high", "very_high"]:
                        if prediction.predicted_risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                            # Immediate attention needed
                            await self.schedule_task(
                                AgentAction.ALERT_STAKEHOLDERS,
                                Priority.HIGH,
                                {
                                    "agent_id": agent.id,
                                    "framework": framework,
                                    "alert_type": "predicted_compliance_risk",
                                    "risk_level": prediction.predicted_risk_level.value,
                                    "recommendations": prediction.recommended_actions,
                                    "time_horizon": prediction.prediction_horizon
                                }
                            )
            
            # Analyze system-wide trends
            await self._analyze_system_trends()
            
            self.logger.info(f"Proactive monitoring completed for {len(agents)} agents")
            
        except Exception as e:
            self.logger.error(f"Proactive monitoring failed: {str(e)}")
    
    async def _analyze_system_trends(self):
        """Analyze system-wide compliance trends"""
        try:
            # Get recent evaluations for trend analysis
            recent_evaluations = ComplianceEvaluation.query.filter(
                ComplianceEvaluation.created_at >= datetime.utcnow() - timedelta(days=30)
            ).all()
            
            if len(recent_evaluations) < 10:
                return  # Insufficient data for trend analysis
            
            # Group by framework
            framework_trends = {}
            for eval in recent_evaluations:
                framework = eval.framework.value
                if framework not in framework_trends:
                    framework_trends[framework] = []
                framework_trends[framework].append({
                    "score": eval.compliance_score,
                    "date": eval.created_at,
                    "agent_id": eval.agent_id
                })
            
            # Analyze trends for each framework
            for framework, evaluations in framework_trends.items():
                if len(evaluations) >= 5:  # Minimum for trend analysis
                    scores = [e["score"] for e in evaluations]
                    avg_score = sum(scores) / len(scores)
                    
                    # Simple trend detection
                    recent_scores = scores[-5:]  # Last 5 scores
                    older_scores = scores[:-5] if len(scores) > 5 else scores[:len(scores)//2]
                    
                    if older_scores and recent_scores:
                        recent_avg = sum(recent_scores) / len(recent_scores)
                        older_avg = sum(older_scores) / len(older_scores)
                        
                        if recent_avg < older_avg - 5:  # Declining trend
                            await self.schedule_task(
                                AgentAction.ALERT_STAKEHOLDERS,
                                Priority.HIGH,
                                {
                                    "alert_type": "declining_compliance_trend",
                                    "framework": framework,
                                    "current_avg": recent_avg,
                                    "previous_avg": older_avg,
                                    "affected_agents": len(set(e["agent_id"] for e in evaluations))
                                }
                            )
                            
                            self.logger.warning(f"Declining compliance trend detected for {framework}: {recent_avg:.1f} vs {older_avg:.1f}")
        
        except Exception as e:
            self.logger.error(f"System trend analysis failed: {str(e)}")
    
    async def set_remediation_engine(self, remediation_engine):
        """Set the remediation engine for integration"""
        self.remediation_engine = remediation_engine
        self.logger.info("Remediation engine integrated with AI agent")
    
    async def trigger_automated_remediation(self, agent_id: str, framework: str, 
                                          issues: List[str], remediation_context: Dict[str, Any]):
        """Trigger automated remediation using enhanced integration"""
        try:
            # Create remediation request
            request = RemediationRequest(
                agent_id=agent_id,
                framework=framework,
                issues=issues,
                severity=remediation_context.get("severity", "medium"),
                triggered_by="ai_agent_enhanced",
                context=remediation_context,
                auto_approve=remediation_context.get("auto_approve", False)
            )
            
            # Execute intelligent remediation
            result = await self.remediation_integration.trigger_intelligent_remediation(request)
            
            # Store enhanced remediation outcome in memory
            self.memory_system.store_memory(
                memory_type=MemoryType.EXPERIENCE,
                content={
                    "action": "enhanced_automated_remediation",
                    "request": request.__dict__,
                    "result": result,
                    "success": result.get("success", False),
                    "intelligent_features": ["context_analysis", "template_selection", "risk_assessment"]
                },
                context={
                    "agent_id": agent_id,
                    "framework": framework,
                    "timestamp": datetime.utcnow().isoformat()
                },
                importance=MemoryImportance.HIGH,
                tags=["enhanced_remediation", f"framework:{framework}", f"agent:{agent_id}"]
            )
            
            self.logger.info(f"Enhanced automated remediation triggered for agent {agent_id}: {result.get('success', False)}")
            return result.get("success", False)
            
        except Exception as e:
            self.logger.error(f"Enhanced automated remediation failed: {str(e)}")
            return False
    
    def determine_applicable_frameworks(self, classification: Dict[str, Any]) -> List[str]:
        """Determine which compliance frameworks apply to an AI system"""
        frameworks = ["HIPAA"]  # Base framework for healthcare
        
        ai_type = classification.get("ai_type")
        if ai_type == "GENAI":
            frameworks.extend(["FDA_SAMD"])
        elif ai_type == "AGENTIC_AI":
            frameworks.extend(["HITRUST_CSF"])
        
        # Add based on function
        if "clinical" in classification.get("capabilities", []):
            frameworks.append("FDA_SAMD")
        
        return list(set(frameworks))
    
    async def perform_framework_assessment(self, agent_data: Dict[str, Any], 
                                         framework: str, classification: Dict[str, Any]) -> Dict[str, Any]:
        """Perform compliance assessment for a specific framework"""
        framework_config = self.knowledge_base["compliance_frameworks"].get(framework, {})
        controls = framework_config.get("critical_controls", [])
        
        assessment_score = 85.0  # Placeholder scoring logic
        issues = []
        
        # Framework-specific assessment logic would go here
        # For now, return a basic assessment
        
        return {
            "score": assessment_score,
            "issues": issues,
            "controls_assessed": controls,
            "assessment_date": datetime.utcnow().isoformat()
        }
    
    async def generate_recommendations(self, compliance_results: Dict[str, Any], 
                                     classification: Dict[str, Any]) -> List[str]:
        """Generate intelligent recommendations based on compliance results"""
        recommendations = []
        
        for framework, result in compliance_results.items():
            if result["score"] < 80:
                recommendations.append(f"Improve {framework} compliance - current score: {result['score']}")
        
        if classification.get("ai_type") == "GENAI":
            recommendations.append("Implement bias testing for GenAI system")
            recommendations.append("Add prompt injection protection")
        
        if classification.get("ai_type") == "AGENTIC_AI":
            recommendations.append("Ensure human oversight for autonomous decisions")
            recommendations.append("Implement comprehensive decision logging")
        
        return recommendations
    
    async def apply_auto_remediation(self, agent_data: Dict[str, Any], 
                                   issue: Dict[str, Any]) -> Dict[str, Any]:
        """Apply automatic remediation for specific compliance issues"""
        # Placeholder for auto-remediation logic
        # Would implement specific fixes based on issue type
        
        return {
            "action_taken": "placeholder_remediation",
            "timestamp": datetime.utcnow().isoformat(),
            "success": True
        }
    
    async def alert_stakeholders(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Alert relevant stakeholders about compliance issues"""
        # Placeholder for alerting logic
        # Would integrate with email, Slack, etc.
        
        self.logger.info("Agent alerting stakeholders about compliance issue")
        return {"alert_sent": True, "timestamp": datetime.utcnow().isoformat()}
    
    async def monitor_system_changes(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor for changes in AI systems"""
        # Placeholder for change monitoring
        return {"changes_detected": False}
    
    async def update_compliance_policies(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Update compliance policies based on learned patterns"""
        # Placeholder for policy updates
        return {"policies_updated": True}
    
    async def schedule_compliance_audit(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Schedule comprehensive compliance audits"""
        # Placeholder for audit scheduling
        return {"audit_scheduled": True}
    
    def stop_agent(self):
        """Stop the autonomous agent"""
        self.running = False
        self.logger.info("Healthcare Compliance Agent stopped")
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get current status of the compliance agent"""
        return {
            "running": self.running,
            "task_queue_size": len([t for t in self.task_queue if not t.completed]),
            "completed_tasks": len([t for t in self.task_queue if t.completed]),
            "decisions_made": len(self.decision_history),
            "knowledge_base_size": len(self.knowledge_base),
            "last_activity": datetime.utcnow().isoformat()
        }


# Global agent instance
healthcare_compliance_agent = HealthcareComplianceAgent()