"""
Natural Language Interface for Healthcare Compliance AI Agent
Enables conversational interaction with the compliance agent
"""

import re
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass

from agents.healthcare_compliance_agent import healthcare_compliance_agent, AgentAction, Priority


@dataclass
class UserIntent:
    """Represents a user's intent parsed from natural language"""
    action: str
    entities: Dict[str, Any]
    confidence: float
    original_query: str


class HealthcareComplianceAgentInterface:
    """
    Natural language interface for the Healthcare Compliance AI Agent
    Enables users to interact with the agent using conversational language
    """
    
    def __init__(self):
        self.agent = healthcare_compliance_agent
        self.intent_patterns = self._initialize_intent_patterns()
    
    def _initialize_intent_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize patterns for intent recognition"""
        return {
            "discover_systems": {
                "patterns": [
                    r"discover|find|scan|search.*(?:ai|systems|agents)",
                    r"what.*(?:ai|systems|agents).*(?:running|deployed|active)",
                    r"show.*(?:ai|systems|agents)",
                    r"list.*(?:ai|systems|agents)"
                ],
                "action": AgentAction.DISCOVER_SYSTEMS,
                "priority": Priority.HIGH
            },
            "check_compliance": {
                "patterns": [
                    r"check|assess|evaluate.*compliance",
                    r"compliance.*(?:status|score|report)",
                    r"(?:hipaa|fda|hitrust).*compliance",
                    r"are.*compliant"
                ],
                "action": AgentAction.ASSESS_COMPLIANCE,
                "priority": Priority.HIGH
            },
            "generate_report": {
                "patterns": [
                    r"generate|create|produce.*report",
                    r"report.*(?:compliance|security|audit)",
                    r"show.*(?:dashboard|summary|overview)",
                    r"what.*(?:status|summary)"
                ],
                "action": AgentAction.GENERATE_REPORT,
                "priority": Priority.MEDIUM
            },
            "fix_issues": {
                "patterns": [
                    r"fix|resolve|remediate.*(?:issues|problems|violations)",
                    r"auto.*(?:fix|remediate|correct)",
                    r"solve.*(?:compliance|security).*(?:issues|problems)"
                ],
                "action": AgentAction.REMEDIATE_ISSUES,
                "priority": Priority.CRITICAL
            },
            "monitor_systems": {
                "patterns": [
                    r"monitor|watch|track.*(?:systems|agents|compliance)",
                    r"continuous.*(?:monitoring|surveillance)",
                    r"alert.*(?:changes|issues|violations)"
                ],
                "action": AgentAction.MONITOR_CHANGES,
                "priority": Priority.MEDIUM
            },
            "agent_status": {
                "patterns": [
                    r"agent.*status",
                    r"what.*(?:doing|working|running)",
                    r"(?:status|health).*agent",
                    r"how.*agent.*(?:performing|working)"
                ],
                "action": "get_status",
                "priority": Priority.LOW
            }
        }
    
    async def process_query(self, query: str, user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process a natural language query and interact with the compliance agent
        
        Args:
            query: Natural language query from the user
            user_context: Additional context about the user/session
            
        Returns:
            Response containing agent actions and results
        """
        # Parse user intent
        intent = self._parse_intent(query)
        
        if not intent:
            return {
                "success": False,
                "message": "I didn't understand your request. Could you please rephrase?",
                "suggestions": [
                    "Check compliance status",
                    "Discover AI systems",
                    "Generate compliance report",
                    "Fix compliance issues",
                    "Show agent status"
                ]
            }
        
        # Execute the appropriate action
        try:
            result = await self._execute_intent(intent, user_context or {})
            return {
                "success": True,
                "intent": intent.action,
                "confidence": intent.confidence,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "intent": intent.action,
                "message": "I encountered an error while processing your request."
            }
    
    def _parse_intent(self, query: str) -> Optional[UserIntent]:
        """Parse user intent from natural language query"""
        query_lower = query.lower()
        best_match = None
        best_confidence = 0.0
        
        for intent_name, intent_config in self.intent_patterns.items():
            for pattern in intent_config["patterns"]:
                if re.search(pattern, query_lower):
                    # Simple confidence scoring based on pattern match
                    confidence = len(re.findall(pattern, query_lower)) * 0.3
                    confidence = min(confidence, 1.0)
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = UserIntent(
                            action=intent_name,
                            entities=self._extract_entities(query, pattern),
                            confidence=confidence,
                            original_query=query
                        )
        
        return best_match if best_confidence > 0.1 else None
    
    def _extract_entities(self, query: str, pattern: str) -> Dict[str, Any]:
        """Extract entities from the query based on the matched pattern"""
        entities = {}
        query_lower = query.lower()
        
        # Extract framework mentions
        frameworks = ["hipaa", "fda", "hitrust", "gdpr", "soc2"]
        for framework in frameworks:
            if framework in query_lower:
                entities["framework"] = framework.upper()
        
        # Extract timeframe mentions
        timeframes = {
            "today": 1, "yesterday": 1, "week": 7, "month": 30, 
            "quarter": 90, "year": 365
        }
        for timeframe, days in timeframes.items():
            if timeframe in query_lower:
                entities["timeframe"] = timeframe
                entities["days"] = days
        
        # Extract urgency indicators
        urgent_keywords = ["urgent", "critical", "immediate", "asap", "now"]
        if any(keyword in query_lower for keyword in urgent_keywords):
            entities["urgent"] = True
        
        # Extract AI type mentions
        ai_types = ["genai", "agentic", "traditional", "computer vision", "nlp"]
        for ai_type in ai_types:
            if ai_type in query_lower:
                entities["ai_type"] = ai_type
        
        return entities
    
    async def _execute_intent(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the parsed intent using the compliance agent"""
        
        if intent.action == "discover_systems":
            return await self._handle_discover_systems(intent, user_context)
        elif intent.action == "check_compliance":
            return await self._handle_check_compliance(intent, user_context)
        elif intent.action == "generate_report":
            return await self._handle_generate_report(intent, user_context)
        elif intent.action == "fix_issues":
            return await self._handle_fix_issues(intent, user_context)
        elif intent.action == "monitor_systems":
            return await self._handle_monitor_systems(intent, user_context)
        elif intent.action == "agent_status":
            return await self._handle_agent_status(intent, user_context)
        else:
            raise ValueError(f"Unknown intent action: {intent.action}")
    
    async def _handle_discover_systems(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle system discovery requests"""
        context = {
            "scope": "full_environment" if intent.entities.get("urgent") else "incremental",
            "initiated_by": "user_request",
            "user_query": intent.original_query
        }
        
        # Schedule discovery task
        await self.agent.schedule_task(
            AgentAction.DISCOVER_SYSTEMS,
            Priority.CRITICAL if intent.entities.get("urgent") else Priority.HIGH,
            context
        )
        
        return {
            "message": "I've started discovering AI systems in your environment. This may take a few minutes.",
            "action": "discovery_initiated",
            "estimated_completion": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        }
    
    async def _handle_check_compliance(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle compliance check requests"""
        framework = intent.entities.get("framework")
        
        # Get current compliance status
        from models import ComplianceEvaluation, AIAgent
        
        query = ComplianceEvaluation.query
        if framework:
            from models import ComplianceFramework
            framework_enum = getattr(ComplianceFramework, framework, None)
            if framework_enum:
                query = query.filter_by(framework=framework_enum)
        
        recent_evaluations = query.filter(
            ComplianceEvaluation.created_at >= datetime.utcnow() - timedelta(days=7)
        ).all()
        
        if recent_evaluations:
            avg_score = sum(e.compliance_score for e in recent_evaluations) / len(recent_evaluations)
            compliant_count = sum(1 for e in recent_evaluations if e.compliance_score >= 80)
            
            result = {
                "message": f"Current compliance status: {avg_score:.1f}% average score",
                "average_score": avg_score,
                "compliant_percentage": (compliant_count / len(recent_evaluations)) * 100,
                "total_evaluations": len(recent_evaluations),
                "framework": framework or "All frameworks"
            }
        else:
            # Schedule new compliance assessment
            await self.agent.schedule_task(
                AgentAction.ASSESS_COMPLIANCE,
                Priority.HIGH,
                {"scope": "full_assessment", "framework": framework}
            )
            
            result = {
                "message": "No recent compliance data available. I've initiated a new assessment.",
                "action": "assessment_initiated"
            }
        
        return result
    
    async def _handle_generate_report(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle report generation requests"""
        timeframe = intent.entities.get("timeframe", "monthly")
        
        context = {
            "type": "comprehensive",
            "timeframe": timeframe,
            "user_request": True,
            "include_recommendations": True
        }
        
        await self.agent.schedule_task(
            AgentAction.GENERATE_REPORT,
            Priority.MEDIUM,
            context
        )
        
        return {
            "message": f"I'm generating a {timeframe} compliance report. It will be ready shortly.",
            "action": "report_generation_initiated",
            "timeframe": timeframe
        }
    
    async def _handle_fix_issues(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle issue remediation requests"""
        # Find current high-priority issues
        from models import ScanResult, RiskLevel
        
        critical_scans = ScanResult.query.filter_by(risk_level=RiskLevel.CRITICAL).all()
        high_risk_scans = ScanResult.query.filter_by(risk_level=RiskLevel.HIGH).all()
        
        issues_found = len(critical_scans) + len(high_risk_scans)
        
        if issues_found > 0:
            context = {
                "auto_remediation": True,
                "critical_issues": len(critical_scans),
                "high_risk_issues": len(high_risk_scans)
            }
            
            await self.agent.schedule_task(
                AgentAction.REMEDIATE_ISSUES,
                Priority.CRITICAL,
                context
            )
            
            return {
                "message": f"Found {issues_found} compliance issues. Starting automatic remediation.",
                "critical_issues": len(critical_scans),
                "high_risk_issues": len(high_risk_scans),
                "action": "remediation_initiated"
            }
        else:
            return {
                "message": "Great news! No critical compliance issues found.",
                "issues_found": 0
            }
    
    async def _handle_monitor_systems(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle monitoring requests"""
        context = {
            "continuous_monitoring": True,
            "alert_threshold": "medium",
            "user_initiated": True
        }
        
        await self.agent.schedule_task(
            AgentAction.MONITOR_CHANGES,
            Priority.MEDIUM,
            context
        )
        
        return {
            "message": "I've activated continuous monitoring for your AI systems. You'll be alerted of any compliance changes.",
            "action": "monitoring_activated"
        }
    
    async def _handle_agent_status(self, intent: UserIntent, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle agent status requests"""
        status = self.agent.get_agent_status()
        
        # Create a user-friendly status message
        if status["running"]:
            message = f"I'm actively running and monitoring your systems. "
            message += f"I have {status['task_queue_size']} tasks in queue and have completed {status['completed_tasks']} tasks. "
            message += f"I've made {status['decisions_made']} compliance decisions so far."
        else:
            message = "I'm currently not running. Would you like me to start monitoring your systems?"
        
        return {
            "message": message,
            "status": status,
            "running": status["running"]
        }
    
    def generate_suggestions(self, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """Generate contextual suggestions for user interaction"""
        base_suggestions = [
            "Check compliance status for all systems",
            "Discover new AI systems in the environment",
            "Generate a monthly compliance report",
            "Fix any critical compliance issues",
            "Show me the agent status",
            "Monitor systems for compliance changes"
        ]
        
        # Add contextual suggestions based on recent activity
        if context and context.get("recent_issues"):
            base_suggestions.insert(0, "Fix the recently discovered compliance issues")
        
        if context and context.get("new_systems"):
            base_suggestions.insert(0, "Assess compliance for newly discovered systems")
        
        return base_suggestions[:6]  # Limit to top 6 suggestions


# Global interface instance
agent_interface = HealthcareComplianceAgentInterface()