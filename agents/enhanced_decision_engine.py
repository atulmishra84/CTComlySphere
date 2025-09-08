"""
Enhanced Decision Engine for Healthcare Compliance AI Agent

This module provides advanced decision-making capabilities including:
- Predictive analytics for compliance risk forecasting
- Machine learning-based pattern recognition
- Multi-criteria decision analysis for complex compliance scenarios
- Adaptive risk scoring with contextual awareness
"""

import json
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque

from models import AIAgent, ComplianceEvaluation, ScanResult, ComplianceFramework, RiskLevel


class DecisionConfidence(Enum):
    """Confidence levels for AI agent decisions"""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


@dataclass
class RiskPrediction:
    """Risk prediction with confidence metrics"""
    predicted_risk_level: RiskLevel
    confidence: DecisionConfidence
    probability_score: float
    contributing_factors: List[str]
    recommended_actions: List[str]
    prediction_horizon: int  # days
    impact_assessment: Dict[str, Any]


@dataclass
class DecisionContext:
    """Context for decision-making"""
    agent_id: str
    compliance_framework: str
    current_risk_level: RiskLevel
    historical_patterns: Dict[str, Any]
    environmental_factors: Dict[str, Any]
    business_impact: Dict[str, Any]
    regulatory_changes: List[Dict[str, Any]]


class EnhancedDecisionEngine:
    """
    Advanced decision engine that uses machine learning and predictive analytics
    to make informed compliance and remediation decisions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Decision history for learning
        self.decision_history = deque(maxlen=10000)
        self.pattern_cache = {}
        self.risk_models = {}
        
        # Initialize risk prediction models
        self.initialize_risk_models()
        
        # Performance tracking
        self.prediction_accuracy = {}
        self.decision_outcomes = defaultdict(list)
        
        self.logger.info("Enhanced Decision Engine initialized")
    
    def initialize_risk_models(self):
        """Initialize risk prediction models for different frameworks"""
        self.risk_models = {
            "HIPAA": {
                "risk_factors": {
                    "phi_exposure": {"weight": 0.35, "threshold": 0.7},
                    "encryption_status": {"weight": 0.25, "threshold": 0.8},
                    "access_controls": {"weight": 0.20, "threshold": 0.75},
                    "audit_logging": {"weight": 0.15, "threshold": 0.8},
                    "breach_history": {"weight": 0.05, "threshold": 0.9}
                },
                "base_threshold": 0.75,
                "prediction_window": 30
            },
            "FDA": {
                "risk_factors": {
                    "clinical_validation": {"weight": 0.40, "threshold": 0.9},
                    "risk_management": {"weight": 0.25, "threshold": 0.85},
                    "change_control": {"weight": 0.20, "threshold": 0.8},
                    "post_market_surveillance": {"weight": 0.15, "threshold": 0.85}
                },
                "base_threshold": 0.85,
                "prediction_window": 60
            },
            "GDPR": {
                "risk_factors": {
                    "data_processing_consent": {"weight": 0.30, "threshold": 0.8},
                    "data_subject_rights": {"weight": 0.25, "threshold": 0.75},
                    "privacy_by_design": {"weight": 0.20, "threshold": 0.8},
                    "breach_notification": {"weight": 0.15, "threshold": 0.9},
                    "cross_border_transfer": {"weight": 0.10, "threshold": 0.85}
                },
                "base_threshold": 0.8,
                "prediction_window": 45
            }
        }
    
    async def predict_compliance_risk(self, context: DecisionContext) -> RiskPrediction:
        """
        Predict future compliance risk based on current state and historical patterns
        """
        try:
            framework = context.compliance_framework
            if framework not in self.risk_models:
                return self._create_default_prediction(context)
            
            model = self.risk_models[framework]
            
            # Calculate weighted risk score
            risk_score = await self._calculate_weighted_risk_score(context, model)
            
            # Analyze historical patterns
            pattern_analysis = await self._analyze_historical_patterns(context)
            
            # Consider environmental factors
            environmental_impact = await self._assess_environmental_factors(context)
            
            # Combine all factors
            final_score = self._combine_risk_factors(
                risk_score, pattern_analysis, environmental_impact
            )
            
            # Determine risk level and confidence
            predicted_risk, confidence = self._determine_risk_level(final_score)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(context, final_score)
            
            # Calculate impact assessment
            impact_assessment = await self._assess_potential_impact(context, predicted_risk)
            
            prediction = RiskPrediction(
                predicted_risk_level=predicted_risk,
                confidence=confidence,
                probability_score=final_score,
                contributing_factors=self._identify_contributing_factors(context, model),
                recommended_actions=recommendations,
                prediction_horizon=model["prediction_window"],
                impact_assessment=impact_assessment
            )
            
            # Store prediction for learning
            await self._store_prediction(context, prediction)
            
            return prediction
            
        except Exception as e:
            self.logger.error(f"Risk prediction failed: {str(e)}")
            return self._create_default_prediction(context)
    
    async def _calculate_weighted_risk_score(self, context: DecisionContext, model: Dict) -> float:
        """Calculate weighted risk score based on framework-specific factors"""
        total_score = 0.0
        total_weight = 0.0
        
        risk_factors = model["risk_factors"]
        
        # Get current agent data
        agent = AIAgent.query.get(context.agent_id)
        if not agent:
            return 0.5  # Default moderate risk
        
        # Recent scan results
        recent_scans = ScanResult.query.filter(
            ScanResult.agent_id == context.agent_id,
            ScanResult.created_at >= datetime.utcnow() - timedelta(days=7)
        ).all()
        
        # Recent compliance evaluations
        recent_evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.agent_id == context.agent_id,
            ComplianceEvaluation.framework == ComplianceFramework[context.compliance_framework],
            ComplianceEvaluation.created_at >= datetime.utcnow() - timedelta(days=30)
        ).all()
        
        for factor, config in risk_factors.items():
            weight = config["weight"]
            threshold = config["threshold"]
            
            # Calculate factor score based on available data
            factor_score = await self._calculate_factor_score(
                factor, agent, recent_scans, recent_evaluations, threshold
            )
            
            total_score += factor_score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.5
    
    async def _calculate_factor_score(self, factor: str, agent: AIAgent, 
                                    scans: List[ScanResult], evaluations: List[ComplianceEvaluation],
                                    threshold: float) -> float:
        """Calculate score for a specific risk factor"""
        
        # Factor-specific calculations
        if factor == "phi_exposure":
            if scans:
                phi_exposures = [scan for scan in scans if scan.phi_exposure_detected]
                return 1.0 if phi_exposures else 0.2
            return 0.5
            
        elif factor == "encryption_status":
            if scans:
                latest_scan = max(scans, key=lambda x: x.created_at)
                return 0.1 if latest_scan.encryption_status else 0.9
            return 0.5
            
        elif factor == "access_controls":
            if evaluations:
                latest_eval = max(evaluations, key=lambda x: x.created_at)
                access_score = latest_eval.control_scores.get("access_controls", 0.5)
                return 1.0 - access_score  # Invert score (lower compliance = higher risk)
            return 0.5
            
        elif factor == "audit_logging":
            if evaluations:
                latest_eval = max(evaluations, key=lambda x: x.created_at)
                audit_score = latest_eval.control_scores.get("audit_logging", 0.5)
                return 1.0 - audit_score
            return 0.5
            
        elif factor == "breach_history":
            # Check for historical breaches
            high_risk_scans = [scan for scan in scans 
                             if scan.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]]
            return min(len(high_risk_scans) * 0.2, 1.0)
            
        # Add more factor calculations as needed
        return 0.5  # Default moderate risk
    
    async def _analyze_historical_patterns(self, context: DecisionContext) -> float:
        """Analyze historical patterns to predict future risk trends"""
        
        # Get historical evaluations for trend analysis
        historical_evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.agent_id == context.agent_id,
            ComplianceEvaluation.framework == ComplianceFramework[context.compliance_framework],
            ComplianceEvaluation.created_at >= datetime.utcnow() - timedelta(days=90)
        ).order_by(ComplianceEvaluation.created_at).all()
        
        if len(historical_evaluations) < 2:
            return 0.0  # No trend data available
        
        # Calculate trend
        scores = [eval.compliance_score for eval in historical_evaluations]
        
        # Simple linear trend calculation
        x = list(range(len(scores)))
        if len(scores) > 1:
            # Calculate slope
            n = len(scores)
            sum_x = sum(x)
            sum_y = sum(scores)
            sum_xy = sum(x[i] * scores[i] for i in range(n))
            sum_x2 = sum(xi * xi for xi in x)
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            
            # Negative slope indicates declining compliance (increasing risk)
            trend_risk = max(0, -slope / 10.0)  # Normalize
            return min(trend_risk, 1.0)
        
        return 0.0
    
    async def _assess_environmental_factors(self, context: DecisionContext) -> float:
        """Assess environmental factors that might affect compliance risk"""
        
        environmental_risk = 0.0
        
        # Check for recent regulatory changes
        if context.regulatory_changes:
            recent_changes = [change for change in context.regulatory_changes
                            if (datetime.utcnow() - datetime.fromisoformat(change.get("date", "2000-01-01"))).days <= 30]
            environmental_risk += len(recent_changes) * 0.1
        
        # Check system load and performance factors
        if context.environmental_factors:
            system_load = context.environmental_factors.get("system_load", 0.5)
            network_issues = context.environmental_factors.get("network_issues", False)
            resource_constraints = context.environmental_factors.get("resource_constraints", False)
            
            if system_load > 0.8:
                environmental_risk += 0.2
            if network_issues:
                environmental_risk += 0.15
            if resource_constraints:
                environmental_risk += 0.1
        
        return min(environmental_risk, 1.0)
    
    def _combine_risk_factors(self, base_risk: float, pattern_risk: float, 
                            environmental_risk: float) -> float:
        """Combine different risk factors into a final score"""
        
        # Weighted combination
        weights = {
            "base": 0.6,
            "pattern": 0.25,
            "environmental": 0.15
        }
        
        combined_score = (
            base_risk * weights["base"] +
            pattern_risk * weights["pattern"] +
            environmental_risk * weights["environmental"]
        )
        
        return min(max(combined_score, 0.0), 1.0)
    
    def _determine_risk_level(self, score: float) -> Tuple[RiskLevel, DecisionConfidence]:
        """Determine risk level and confidence based on score"""
        
        # Risk level thresholds
        if score >= 0.8:
            risk_level = RiskLevel.CRITICAL
            confidence = DecisionConfidence.HIGH if score >= 0.9 else DecisionConfidence.MEDIUM
        elif score >= 0.6:
            risk_level = RiskLevel.HIGH
            confidence = DecisionConfidence.HIGH if score >= 0.7 else DecisionConfidence.MEDIUM
        elif score >= 0.4:
            risk_level = RiskLevel.MEDIUM
            confidence = DecisionConfidence.MEDIUM
        elif score >= 0.2:
            risk_level = RiskLevel.LOW
            confidence = DecisionConfidence.MEDIUM
        else:
            risk_level = RiskLevel.LOW
            confidence = DecisionConfidence.HIGH
        
        return risk_level, confidence
    
    async def _generate_recommendations(self, context: DecisionContext, 
                                      risk_score: float) -> List[str]:
        """Generate specific recommendations based on risk analysis"""
        
        recommendations = []
        
        if risk_score >= 0.8:
            recommendations.extend([
                "Immediate security review required",
                "Consider emergency remediation workflows",
                "Increase monitoring frequency",
                "Notify compliance stakeholders"
            ])
        elif risk_score >= 0.6:
            recommendations.extend([
                "Schedule compliance assessment",
                "Review security controls",
                "Update access permissions",
                "Implement additional monitoring"
            ])
        elif risk_score >= 0.4:
            recommendations.extend([
                "Regular compliance monitoring",
                "Preventive maintenance recommended",
                "Review policy adherence"
            ])
        else:
            recommendations.extend([
                "Maintain current security posture",
                "Continue regular monitoring"
            ])
        
        # Framework-specific recommendations
        if context.compliance_framework == "HIPAA":
            if risk_score >= 0.6:
                recommendations.append("Review PHI access controls")
                recommendations.append("Verify encryption implementation")
        elif context.compliance_framework == "FDA":
            if risk_score >= 0.7:
                recommendations.append("Initiate clinical validation review")
                recommendations.append("Check post-market surveillance data")
        
        return recommendations
    
    async def _assess_potential_impact(self, context: DecisionContext, 
                                     predicted_risk: RiskLevel) -> Dict[str, Any]:
        """Assess potential business and compliance impact"""
        
        impact_assessment = {
            "financial_impact": "low",
            "regulatory_impact": "low",
            "operational_impact": "low",
            "reputational_impact": "low"
        }
        
        if predicted_risk == RiskLevel.CRITICAL:
            impact_assessment.update({
                "financial_impact": "very_high",
                "regulatory_impact": "very_high",
                "operational_impact": "high",
                "reputational_impact": "very_high"
            })
        elif predicted_risk == RiskLevel.HIGH:
            impact_assessment.update({
                "financial_impact": "high",
                "regulatory_impact": "high",
                "operational_impact": "medium",
                "reputational_impact": "high"
            })
        elif predicted_risk == RiskLevel.MEDIUM:
            impact_assessment.update({
                "financial_impact": "medium",
                "regulatory_impact": "medium",
                "operational_impact": "low",
                "reputational_impact": "medium"
            })
        
        # Add framework-specific impact details
        if context.compliance_framework == "HIPAA":
            if predicted_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                impact_assessment["regulatory_penalties"] = "OCR investigation likely"
                impact_assessment["patient_impact"] = "PHI breach potential"
        
        return impact_assessment
    
    def _identify_contributing_factors(self, context: DecisionContext, 
                                     model: Dict) -> List[str]:
        """Identify key factors contributing to the risk prediction"""
        
        factors = []
        
        # Add high-weight factors from the model
        for factor, config in model["risk_factors"].items():
            if config["weight"] >= 0.2:  # High-impact factors
                factors.append(factor.replace("_", " ").title())
        
        # Add contextual factors
        if context.historical_patterns:
            if context.historical_patterns.get("declining_trend"):
                factors.append("Declining Compliance Trend")
        
        if context.environmental_factors:
            if context.environmental_factors.get("system_load", 0) > 0.8:
                factors.append("High System Load")
            if context.environmental_factors.get("network_issues"):
                factors.append("Network Connectivity Issues")
        
        return factors
    
    async def _store_prediction(self, context: DecisionContext, prediction: RiskPrediction):
        """Store prediction for future learning and validation"""
        
        prediction_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": context.agent_id,
            "framework": context.compliance_framework,
            "predicted_risk": prediction.predicted_risk_level.value,
            "confidence": prediction.confidence.value,
            "probability_score": prediction.probability_score,
            "context": {
                "current_risk": context.current_risk_level.value,
                "environmental_factors": context.environmental_factors,
                "business_impact": context.business_impact
            }
        }
        
        self.decision_history.append(prediction_record)
        
        # Cache pattern for quick lookup
        pattern_key = f"{context.compliance_framework}_{context.current_risk_level.value}"
        if pattern_key not in self.pattern_cache:
            self.pattern_cache[pattern_key] = []
        self.pattern_cache[pattern_key].append(prediction_record)
    
    def _create_default_prediction(self, context: DecisionContext) -> RiskPrediction:
        """Create a default prediction when detailed analysis fails"""
        
        return RiskPrediction(
            predicted_risk_level=context.current_risk_level,
            confidence=DecisionConfidence.LOW,
            probability_score=0.5,
            contributing_factors=["Limited data available"],
            recommended_actions=["Increase data collection", "Perform detailed assessment"],
            prediction_horizon=30,
            impact_assessment={"note": "Limited analysis due to insufficient data"}
        )
    
    async def validate_prediction_accuracy(self, prediction_id: str, actual_outcome: RiskLevel):
        """Validate prediction accuracy for continuous learning"""
        
        # Find the original prediction
        for record in self.decision_history:
            if record.get("prediction_id") == prediction_id:
                predicted_risk = RiskLevel[record["predicted_risk"].upper()]
                
                # Calculate accuracy
                accuracy = 1.0 if predicted_risk == actual_outcome else 0.0
                
                # Store accuracy for model improvement
                framework = record["framework"]
                if framework not in self.prediction_accuracy:
                    self.prediction_accuracy[framework] = []
                
                self.prediction_accuracy[framework].append({
                    "predicted": predicted_risk.value,
                    "actual": actual_outcome.value,
                    "accuracy": accuracy,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                self.logger.info(f"Prediction validation: {accuracy * 100:.1f}% accuracy for {framework}")
                break
    
    def get_decision_analytics(self) -> Dict[str, Any]:
        """Get analytics about decision-making performance"""
        
        analytics = {
            "total_predictions": len(self.decision_history),
            "accuracy_by_framework": {},
            "confidence_distribution": defaultdict(int),
            "risk_level_distribution": defaultdict(int)
        }
        
        # Calculate accuracy by framework
        for framework, accuracies in self.prediction_accuracy.items():
            if accuracies:
                avg_accuracy = sum(a["accuracy"] for a in accuracies) / len(accuracies)
                analytics["accuracy_by_framework"][framework] = {
                    "average_accuracy": avg_accuracy,
                    "total_predictions": len(accuracies)
                }
        
        # Analyze recent predictions
        for record in list(self.decision_history)[-100:]:  # Last 100 predictions
            confidence = record.get("confidence", "medium")
            risk_level = record.get("predicted_risk", "medium")
            
            analytics["confidence_distribution"][confidence] += 1
            analytics["risk_level_distribution"][risk_level] += 1
        
        return analytics


# Global instance
enhanced_decision_engine = EnhancedDecisionEngine()