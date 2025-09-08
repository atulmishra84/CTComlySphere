"""
Remediation Integration for Enhanced Healthcare Compliance AI Agent

This module provides seamless integration between the AI agent and
the automated remediation workflow system.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from agents.memory_system import agent_memory_system, MemoryType, MemoryImportance


@dataclass
class RemediationRequest:
    """Request for automated remediation"""
    agent_id: str
    framework: str
    issues: List[str]
    severity: str
    triggered_by: str
    context: Dict[str, Any]
    auto_approve: bool = False


class AgentRemediationIntegration:
    """
    Integration layer between the AI agent and remediation workflows
    
    This class provides:
    - Intelligent remediation workflow selection
    - Context-aware remediation triggering
    - Outcome tracking and learning
    - Risk-based approval routing
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.memory_system = agent_memory_system
        
        # Remediation workflow engine (will be injected)
        self.workflow_engine = None
        
        # Learning data
        self.remediation_patterns = {}
        self.success_rates = {}
        
        # Integration settings
        self.auto_approval_thresholds = {
            "low_risk_actions": ["update_monitoring", "notify_stakeholders"],
            "medium_risk_actions": ["update_configuration", "restart_service"],
            "high_risk_actions": ["apply_security_patch", "rotate_credentials"],
            "critical_actions": ["quarantine_system", "emergency_shutdown"]
        }
        
        self.logger.info("Agent Remediation Integration initialized")
    
    def set_workflow_engine(self, workflow_engine):
        """Set the remediation workflow engine"""
        self.workflow_engine = workflow_engine
        self.logger.info("Remediation workflow engine connected")
    
    async def trigger_intelligent_remediation(self, request: RemediationRequest) -> Dict[str, Any]:
        """
        Trigger intelligent remediation based on agent analysis
        """
        try:
            # Analyze remediation context
            analysis = await self._analyze_remediation_context(request)
            
            # Select appropriate workflow template
            workflow_template = await self._select_optimal_workflow(request, analysis)
            
            if not workflow_template:
                return {
                    "success": False,
                    "error": "No suitable workflow template found",
                    "recommendations": await self._generate_manual_recommendations(request)
                }
            
            # Customize workflow based on context
            customized_workflow = await self._customize_workflow(workflow_template, request, analysis)
            
            # Determine approval requirements
            approval_needed = await self._assess_approval_requirements(customized_workflow, request)
            
            # Execute or queue for approval
            if approval_needed and not request.auto_approve:
                return await self._queue_for_approval(customized_workflow, request)
            else:
                return await self._execute_remediation_workflow(customized_workflow, request)
                
        except Exception as e:
            self.logger.error(f"Intelligent remediation failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "fallback_recommendations": ["Manual intervention required", "Contact compliance team"]
            }
    
    async def _analyze_remediation_context(self, request: RemediationRequest) -> Dict[str, Any]:
        """Analyze context for intelligent remediation decisions"""
        
        analysis = {
            "risk_level": self._assess_remediation_risk(request),
            "business_impact": await self._assess_business_impact(request),
            "historical_success": await self._get_historical_success_rate(request),
            "environmental_factors": await self._get_environmental_context(request),
            "dependencies": await self._analyze_dependencies(request),
            "timing_factors": await self._analyze_timing_factors(request)
        }
        
        return analysis
    
    def _assess_remediation_risk(self, request: RemediationRequest) -> str:
        """Assess risk level of proposed remediation"""
        
        # Risk factors
        risk_score = 0
        
        # Framework-specific risk
        framework_risks = {
            "FDA": 3,  # High regulatory risk
            "HIPAA": 2,  # Medium regulatory risk
            "GDPR": 2,   # Medium regulatory risk
            "SOC2": 1    # Lower regulatory risk
        }
        risk_score += framework_risks.get(request.framework, 1)
        
        # Issue severity
        severity_risks = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }
        risk_score += severity_risks.get(request.severity.lower(), 2)
        
        # Issue complexity
        if len(request.issues) > 3:
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 7:
            return "critical"
        elif risk_score >= 5:
            return "high"
        elif risk_score >= 3:
            return "medium"
        else:
            return "low"
    
    async def _assess_business_impact(self, request: RemediationRequest) -> Dict[str, Any]:
        """Assess potential business impact of remediation"""
        
        return {
            "operational_impact": "medium",  # Would be determined by agent context
            "user_impact": "low",
            "downtime_risk": "minimal",
            "data_risk": "controlled",
            "compliance_urgency": request.severity
        }
    
    async def _get_historical_success_rate(self, request: RemediationRequest) -> float:
        """Get historical success rate for similar remediations"""
        
        # Search for similar past remediations
        similar_memories = self.memory_system.search_memories(
            memory_type=MemoryType.EXPERIENCE,
            tags=["remediation", f"framework:{request.framework}"],
            limit=20
        )
        
        if not similar_memories:
            return 0.7  # Default moderate confidence
        
        successful_count = 0
        total_count = 0
        
        for memory in similar_memories:
            if memory.content.get("action") == "automated_remediation":
                total_count += 1
                if memory.content.get("success", False):
                    successful_count += 1
        
        return successful_count / total_count if total_count > 0 else 0.7
    
    async def _get_environmental_context(self, request: RemediationRequest) -> Dict[str, Any]:
        """Get environmental context affecting remediation"""
        
        return {
            "maintenance_window": False,  # Would check actual schedule
            "system_load": "normal",
            "active_incidents": 0,
            "recent_changes": False,
            "backup_status": "current"
        }
    
    async def _analyze_dependencies(self, request: RemediationRequest) -> List[str]:
        """Analyze dependencies that might affect remediation"""
        
        # This would analyze actual system dependencies
        dependencies = []
        
        if "encryption" in str(request.issues):
            dependencies.append("data_access_services")
        
        if "access_control" in str(request.issues):
            dependencies.append("authentication_services")
        
        return dependencies
    
    async def _analyze_timing_factors(self, request: RemediationRequest) -> Dict[str, Any]:
        """Analyze timing factors for remediation"""
        
        return {
            "optimal_time": "now",  # Would consider maintenance windows
            "urgency_level": request.severity,
            "delay_tolerance": "low" if request.severity in ["critical", "high"] else "medium",
            "business_hours": "outside" if datetime.now().hour < 8 or datetime.now().hour > 18 else "during"
        }
    
    async def _select_optimal_workflow(self, request: RemediationRequest, 
                                     analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Select the most appropriate workflow template"""
        
        if not self.workflow_engine:
            return None
        
        try:
            # Get available templates
            available_templates = await self._get_available_templates(request.framework)
            
            if not available_templates:
                return None
            
            # Score templates based on context
            template_scores = {}
            for template in available_templates:
                score = await self._score_template_fit(template, request, analysis)
                template_scores[template["id"]] = score
            
            # Select best template
            best_template_id = max(template_scores, key=template_scores.get)
            best_template = next((t for t in available_templates if t["id"] == best_template_id), None)
            
            self.logger.info(f"Selected workflow template: {best_template_id} (score: {template_scores[best_template_id]:.2f})")
            
            return best_template
            
        except Exception as e:
            self.logger.error(f"Template selection failed: {str(e)}")
            return None
    
    async def _get_available_templates(self, framework: str) -> List[Dict[str, Any]]:
        """Get available remediation templates for framework"""
        
        # This would interface with the remediation template system
        mock_templates = [
            {
                "id": "hipaa_encryption_fix",
                "name": "HIPAA Encryption Enforcement",
                "framework": "HIPAA",
                "risk_level": "high",
                "actions": ["backup_data", "enable_encryption", "verify_compliance"],
                "success_rate": 0.92,
                "average_duration": 15
            },
            {
                "id": "security_patch_deployment",
                "name": "Security Patch Deployment",
                "framework": "general",
                "risk_level": "medium",
                "actions": ["backup_system", "apply_patch", "restart_services"],
                "success_rate": 0.87,
                "average_duration": 30
            },
            {
                "id": "access_control_update",
                "name": "Access Control Remediation",
                "framework": "general",
                "risk_level": "medium",
                "actions": ["update_access_controls", "verify_permissions", "notify_stakeholders"],
                "success_rate": 0.94,
                "average_duration": 10
            }
        ]
        
        # Filter by framework
        if framework != "general":
            return [t for t in mock_templates if t["framework"] in [framework, "general"]]
        
        return mock_templates
    
    async def _score_template_fit(self, template: Dict[str, Any], request: RemediationRequest,
                                analysis: Dict[str, Any]) -> float:
        """Score how well a template fits the remediation request"""
        
        score = 0.0
        
        # Framework match
        if template["framework"] == request.framework:
            score += 0.4
        elif template["framework"] == "general":
            score += 0.2
        
        # Risk level compatibility
        template_risk = template.get("risk_level", "medium")
        request_risk = analysis["risk_level"]
        
        risk_compatibility = {
            ("low", "low"): 0.3,
            ("low", "medium"): 0.2,
            ("medium", "medium"): 0.3,
            ("medium", "high"): 0.2,
            ("high", "high"): 0.3,
            ("high", "critical"): 0.25
        }
        score += risk_compatibility.get((template_risk, request_risk), 0.1)
        
        # Historical success rate
        score += template.get("success_rate", 0.5) * 0.2
        
        # Issue type match
        template_actions = set(template.get("actions", []))
        issue_keywords = set(word.lower() for issue in request.issues for word in issue.split())
        action_keywords = set(action.lower() for action in template_actions)
        
        if issue_keywords & action_keywords:
            score += 0.1
        
        return min(score, 1.0)
    
    async def _customize_workflow(self, template: Dict[str, Any], request: RemediationRequest,
                                analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Customize workflow template based on specific context"""
        
        customized = template.copy()
        
        # Add context-specific parameters
        customized["context"] = {
            "agent_id": request.agent_id,
            "framework": request.framework,
            "triggered_by": request.triggered_by,
            "severity": request.severity,
            "business_impact": analysis["business_impact"],
            "custom_parameters": await self._generate_custom_parameters(request, analysis)
        }
        
        # Adjust timeouts based on urgency
        if request.severity == "critical":
            customized["timeout_minutes"] = template.get("average_duration", 30) // 2
        elif request.severity == "low":
            customized["timeout_minutes"] = template.get("average_duration", 30) * 2
        
        # Add monitoring and rollback settings
        customized["enhanced_monitoring"] = analysis["risk_level"] in ["high", "critical"]
        customized["auto_rollback"] = analysis["risk_level"] != "critical"  # Critical issues shouldn't auto-rollback
        
        return customized
    
    async def _generate_custom_parameters(self, request: RemediationRequest,
                                        analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate custom parameters for workflow execution"""
        
        return {
            "notification_recipients": await self._get_stakeholder_contacts(request.framework),
            "backup_required": analysis["risk_level"] in ["medium", "high", "critical"],
            "verification_level": "enhanced" if analysis["risk_level"] in ["high", "critical"] else "standard",
            "documentation_level": "detailed" if request.framework == "FDA" else "standard"
        }
    
    async def _get_stakeholder_contacts(self, framework: str) -> List[str]:
        """Get stakeholder contacts for framework"""
        
        contacts = {
            "HIPAA": ["compliance@organization.com", "privacy-officer@organization.com"],
            "FDA": ["regulatory@organization.com", "quality-assurance@organization.com"],
            "GDPR": ["dpo@organization.com", "legal@organization.com"],
            "SOC2": ["security@organization.com", "audit@organization.com"]
        }
        
        return contacts.get(framework, ["compliance@organization.com"])
    
    async def _assess_approval_requirements(self, workflow: Dict[str, Any], 
                                          request: RemediationRequest) -> bool:
        """Determine if manual approval is required"""
        
        # Always require approval for critical actions
        if request.severity == "critical":
            return True
        
        # Check for high-risk actions
        workflow_actions = workflow.get("actions", [])
        critical_actions = self.auto_approval_thresholds["critical_actions"]
        
        if any(action in critical_actions for action in workflow_actions):
            return True
        
        # Framework-specific approval requirements
        if request.framework == "FDA":
            return True  # FDA changes always need approval
        
        return False
    
    async def _queue_for_approval(self, workflow: Dict[str, Any], 
                                request: RemediationRequest) -> Dict[str, Any]:
        """Queue remediation for manual approval"""
        
        # Store approval request in memory
        approval_request = {
            "workflow": workflow,
            "request": request.__dict__,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending_approval"
        }
        
        self.memory_system.store_memory(
            memory_type=MemoryType.EXPERIENCE,
            content=approval_request,
            context={
                "action": "approval_request",
                "agent_id": request.agent_id,
                "framework": request.framework
            },
            importance=MemoryImportance.HIGH,
            tags=["approval", "remediation", f"framework:{request.framework}"]
        )
        
        return {
            "success": True,
            "status": "queued_for_approval",
            "approval_id": approval_request["timestamp"],
            "message": f"Remediation workflow queued for approval due to {request.severity} severity and framework requirements",
            "estimated_approval_time": "2-4 hours during business hours"
        }
    
    async def _execute_remediation_workflow(self, workflow: Dict[str, Any], 
                                          request: RemediationRequest) -> Dict[str, Any]:
        """Execute the remediation workflow"""
        
        if not self.workflow_engine:
            return {
                "success": False,
                "error": "Workflow engine not available",
                "status": "engine_unavailable"
            }
        
        try:
            # Execute workflow
            execution_result = await self.workflow_engine.execute_workflow(workflow, request.__dict__)
            
            # Store execution result
            self.memory_system.store_memory(
                memory_type=MemoryType.EXPERIENCE,
                content={
                    "action": "automated_remediation",
                    "workflow": workflow,
                    "request": request.__dict__,
                    "result": execution_result,
                    "success": execution_result.get("success", False),
                    "duration": execution_result.get("duration_seconds", 0)
                },
                context={
                    "agent_id": request.agent_id,
                    "framework": request.framework,
                    "timestamp": datetime.utcnow().isoformat()
                },
                importance=MemoryImportance.HIGH,
                tags=["remediation", "execution", f"framework:{request.framework}"]
            )
            
            # Update success rates
            await self._update_success_rates(workflow["id"], execution_result.get("success", False))
            
            return execution_result
            
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "status": "execution_failed"
            }
    
    async def _update_success_rates(self, workflow_id: str, success: bool):
        """Update success rate tracking for workflow"""
        
        if workflow_id not in self.success_rates:
            self.success_rates[workflow_id] = {"total": 0, "successful": 0}
        
        self.success_rates[workflow_id]["total"] += 1
        if success:
            self.success_rates[workflow_id]["successful"] += 1
        
        # Log performance metrics
        rate = self.success_rates[workflow_id]["successful"] / self.success_rates[workflow_id]["total"]
        self.logger.info(f"Workflow {workflow_id} success rate: {rate:.2f} ({self.success_rates[workflow_id]['successful']}/{self.success_rates[workflow_id]['total']})")
    
    async def _generate_manual_recommendations(self, request: RemediationRequest) -> List[str]:
        """Generate manual remediation recommendations when automation isn't available"""
        
        recommendations = []
        
        for issue in request.issues:
            if "encryption" in issue.lower():
                recommendations.append("Review and enable encryption for data at rest and in transit")
            elif "access" in issue.lower():
                recommendations.append("Audit and update access control policies")
            elif "audit" in issue.lower():
                recommendations.append("Enable comprehensive audit logging")
            elif "patch" in issue.lower():
                recommendations.append("Apply latest security patches during maintenance window")
            else:
                recommendations.append(f"Review and address: {issue}")
        
        recommendations.append("Document remediation actions for compliance audit trail")
        recommendations.append(f"Verify {request.framework} compliance after implementing fixes")
        
        return recommendations
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get status of remediation integration"""
        
        return {
            "workflow_engine_connected": self.workflow_engine is not None,
            "total_remediations": sum(sr["total"] for sr in self.success_rates.values()),
            "overall_success_rate": self._calculate_overall_success_rate(),
            "active_patterns": len(self.remediation_patterns),
            "memory_entries": len(self.memory_system.search_memories(
                memory_type=MemoryType.EXPERIENCE,
                tags=["remediation"],
                limit=1000
            ))
        }
    
    def _calculate_overall_success_rate(self) -> float:
        """Calculate overall success rate across all workflows"""
        
        if not self.success_rates:
            return 0.0
        
        total_executions = sum(sr["total"] for sr in self.success_rates.values())
        total_successful = sum(sr["successful"] for sr in self.success_rates.values())
        
        return total_successful / total_executions if total_executions > 0 else 0.0


# Global instance
agent_remediation_integration = AgentRemediationIntegration()