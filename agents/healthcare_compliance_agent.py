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
        
        # Initialize agent capabilities
        self.initialize_knowledge_base()
        self.logger.info("Healthcare Compliance AI Agent initialized")
    
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
        
        # Start main execution loop
        while self.running:
            await self.process_task_queue()
            await self.monitor_compliance_status()
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
        """Learn from past decisions to improve future actions"""
        # Analyze decision patterns
        recent_decisions = self.decision_history[-100:]  # Last 100 decisions
        
        # Pattern analysis would go here
        # For now, log learning activity
        if recent_decisions:
            self.logger.info(f"Agent learning from {len(recent_decisions)} recent decisions")
    
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