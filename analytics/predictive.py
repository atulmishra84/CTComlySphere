"""
Predictive Analytics Engine for Healthcare AI Compliance Platform
Provides predictive insights for security threats and compliance trends
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy import func, and_
from app import db
from models import AIAgent, ScanResult, ComplianceEvaluation, RiskLevel
import statistics
import json
from collections import defaultdict

class PredictiveAnalytics:
    """Predictive analytics engine for security and compliance insights"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.prediction_horizon_days = 30
    
    def generate_security_predictions(self):
        """Generate comprehensive security predictions"""
        try:
            # Get historical data for analysis
            historical_data = self._get_historical_data()
            
            # Generate various predictions
            breach_risk = self._predict_breach_risk(historical_data)
            compliance_trends = self._predict_compliance_trends()
            vulnerability_trends = self._predict_vulnerability_trends()
            phi_exposure_risk = self._predict_phi_exposure_risk()
            
            return {
                'prediction_date': datetime.utcnow().isoformat(),
                'prediction_horizon_days': self.prediction_horizon_days,
                'breach_risk_prediction': breach_risk,
                'compliance_trends': compliance_trends,
                'vulnerability_trends': vulnerability_trends,
                'phi_exposure_risk': phi_exposure_risk,
                'recommendations': self._generate_predictive_recommendations(
                    breach_risk, compliance_trends, vulnerability_trends, phi_exposure_risk
                )
            }
            
        except Exception as e:
            self.logger.error(f"Predictive analytics generation failed: {str(e)}")
            raise
    
    def _get_historical_data(self, days=90):
        """Get historical scan and compliance data"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get scan results
        scans = ScanResult.query.filter(
            ScanResult.created_at >= start_date
        ).order_by(ScanResult.created_at).all()
        
        # Get compliance evaluations
        evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.evaluated_at >= start_date
        ).order_by(ComplianceEvaluation.evaluated_at).all()
        
        return {
            'scans': scans,
            'evaluations': evaluations,
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            }
        }
    
    def _predict_breach_risk(self, historical_data):
        """Predict likelihood of security breach"""
        scans = historical_data['scans']
        
        if not scans:
            return {
                'risk_level': 'unknown',
                'probability': 0.0,
                'confidence': 0.0,
                'factors': []
            }
        
        # Analyze risk factors
        total_scans = len(scans)
        high_risk_scans = sum(1 for scan in scans if scan.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL])
        phi_exposures = sum(1 for scan in scans if scan.phi_exposure_detected)
        avg_vulnerabilities = statistics.mean([scan.vulnerabilities_found for scan in scans])
        
        # Calculate breach probability based on risk factors
        risk_factors = []
        base_probability = 0.1  # 10% base probability
        
        # High-risk systems factor
        if total_scans > 0:
            high_risk_ratio = high_risk_scans / total_scans
            if high_risk_ratio > 0.3:
                base_probability += 0.25
                risk_factors.append(f"High proportion of high-risk systems ({high_risk_ratio:.1%})")
        
        # PHI exposure factor
        if phi_exposures > 0:
            phi_ratio = phi_exposures / total_scans
            base_probability += phi_ratio * 0.3
            risk_factors.append(f"PHI exposure detected in {phi_ratio:.1%} of systems")
        
        # Vulnerability factor
        if avg_vulnerabilities > 3:
            base_probability += 0.2
            risk_factors.append(f"High average vulnerability count ({avg_vulnerabilities:.1f})")
        
        # Recent trend factor
        recent_scans = [scan for scan in scans if scan.created_at >= datetime.utcnow() - timedelta(days=14)]
        if recent_scans:
            recent_avg_risk = statistics.mean([scan.risk_score for scan in recent_scans])
            if recent_avg_risk > 70:
                base_probability += 0.15
                risk_factors.append(f"Rising risk trend in recent scans (avg: {recent_avg_risk:.1f})")
        
        # Cap probability at 0.9
        probability = min(0.9, base_probability)
        
        # Determine risk level
        if probability >= 0.7:
            risk_level = 'critical'
        elif probability >= 0.5:
            risk_level = 'high'
        elif probability >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Calculate confidence based on data quality
        confidence = min(0.9, len(scans) / 100.0)  # More data = higher confidence
        
        return {
            'risk_level': risk_level,
            'probability': round(probability, 3),
            'confidence': round(confidence, 2),
            'factors': risk_factors,
            'recommendation': self._get_breach_risk_recommendation(risk_level, probability)
        }
    
    def _predict_compliance_trends(self):
        """Predict compliance trends across frameworks"""
        # Get compliance evaluations from last 60 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=60)
        
        evaluations = ComplianceEvaluation.query.filter(
            ComplianceEvaluation.evaluated_at >= start_date
        ).order_by(ComplianceEvaluation.evaluated_at).all()
        
        if not evaluations:
            return {
                'trend': 'unknown',
                'frameworks': {},
                'overall_prediction': 'insufficient_data'
            }
        
        # Group by framework
        framework_data = defaultdict(list)
        for eval in evaluations:
            framework_data[eval.framework.value].append({
                'score': eval.compliance_score,
                'date': eval.evaluated_at
            })
        
        framework_trends = {}
        overall_scores = []
        
        for framework, data in framework_data.items():
            if len(data) < 2:
                continue
            
            # Sort by date
            data.sort(key=lambda x: x['date'])
            scores = [item['score'] for item in data]
            
            # Calculate trend
            trend = self._calculate_trend(scores)
            predicted_score = self._predict_future_score(scores)
            
            framework_trends[framework] = {
                'current_avg_score': round(statistics.mean(scores), 2),
                'trend': trend,
                'predicted_score_30d': round(predicted_score, 2),
                'data_points': len(scores)
            }
            
            overall_scores.extend(scores)
        
        # Overall prediction
        if overall_scores:
            overall_trend = self._calculate_trend(overall_scores)
            overall_predicted = self._predict_future_score(overall_scores)
        else:
            overall_trend = 'unknown'
            overall_predicted = 0.0
        
        return {
            'trend': overall_trend,
            'frameworks': framework_trends,
            'overall_prediction': {
                'trend': overall_trend,
                'predicted_score_30d': round(overall_predicted, 2),
                'current_avg_score': round(statistics.mean(overall_scores), 2) if overall_scores else 0.0
            }
        }
    
    def _predict_vulnerability_trends(self):
        """Predict vulnerability trends"""
        # Get scan results from last 45 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=45)
        
        scans = ScanResult.query.filter(
            ScanResult.created_at >= start_date
        ).order_by(ScanResult.created_at).all()
        
        if not scans:
            return {
                'trend': 'unknown',
                'predicted_vulnerabilities': 0,
                'recommendation': 'Insufficient data for prediction'
            }
        
        # Analyze vulnerability trends by protocol
        protocol_data = defaultdict(list)
        for scan in scans:
            agent = AIAgent.query.get(scan.ai_agent_id)
            if agent:
                protocol_data[agent.protocol].append(scan.vulnerabilities_found)
        
        protocol_trends = {}
        all_vulnerabilities = []
        
        for protocol, vuln_counts in protocol_data.items():
            if vuln_counts:
                avg_vulns = statistics.mean(vuln_counts)
                trend = self._calculate_trend(vuln_counts)
                predicted = self._predict_future_value(vuln_counts)
                
                protocol_trends[protocol] = {
                    'current_avg_vulnerabilities': round(avg_vulns, 2),
                    'trend': trend,
                    'predicted_vulnerabilities_30d': max(0, round(predicted, 1))
                }
                
                all_vulnerabilities.extend(vuln_counts)
        
        # Overall vulnerability prediction
        if all_vulnerabilities:
            overall_trend = self._calculate_trend(all_vulnerabilities)
            overall_predicted = self._predict_future_value(all_vulnerabilities)
            current_avg = statistics.mean(all_vulnerabilities)
        else:
            overall_trend = 'unknown'
            overall_predicted = 0
            current_avg = 0
        
        return {
            'trend': overall_trend,
            'current_avg_vulnerabilities': round(current_avg, 2),
            'predicted_vulnerabilities_30d': max(0, round(overall_predicted, 1)),
            'protocol_breakdown': protocol_trends,
            'recommendation': self._get_vulnerability_recommendation(overall_trend, overall_predicted)
        }
    
    def _predict_phi_exposure_risk(self):
        """Predict PHI exposure risk trends"""
        # Get recent scans
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        scans = ScanResult.query.filter(
            ScanResult.created_at >= start_date
        ).all()
        
        if not scans:
            return {
                'risk_level': 'unknown',
                'exposure_probability': 0.0,
                'recommendation': 'Insufficient data'
            }
        
        # Analyze PHI exposure patterns
        total_scans = len(scans)
        phi_exposures = sum(1 for scan in scans if scan.phi_exposure_detected)
        
        # Calculate exposure rate
        exposure_rate = phi_exposures / total_scans if total_scans > 0 else 0
        
        # Analyze by agent type
        healthcare_agents = []
        for scan in scans:
            agent = AIAgent.query.get(scan.ai_agent_id)
            if agent and any(term in agent.type.lower() for term in ['medical', 'clinical', 'health', 'patient']):
                healthcare_agents.append(scan)
        
        healthcare_phi_rate = 0
        if healthcare_agents:
            healthcare_phi_exposures = sum(1 for scan in healthcare_agents if scan.phi_exposure_detected)
            healthcare_phi_rate = healthcare_phi_exposures / len(healthcare_agents)
        
        # Predict future risk
        risk_factors = []
        base_risk = exposure_rate
        
        if healthcare_phi_rate > 0.5:
            base_risk += 0.3
            risk_factors.append("High PHI exposure rate in healthcare-specific AI systems")
        
        if exposure_rate > 0.2:
            base_risk += 0.2
            risk_factors.append("Elevated overall PHI exposure rate")
        
        # Determine risk level
        if base_risk >= 0.7:
            risk_level = 'critical'
        elif base_risk >= 0.5:
            risk_level = 'high'
        elif base_risk >= 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'current_exposure_rate': round(exposure_rate, 3),
            'healthcare_exposure_rate': round(healthcare_phi_rate, 3),
            'predicted_exposure_probability': round(min(0.9, base_risk), 3),
            'risk_factors': risk_factors,
            'recommendation': self._get_phi_risk_recommendation(risk_level, base_risk)
        }
    
    def _calculate_trend(self, values):
        """Calculate trend direction from a series of values"""
        if len(values) < 2:
            return 'unknown'
        
        # Simple linear trend
        n = len(values)
        x = list(range(n))
        
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(values)
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 'stable'
        
        slope = numerator / denominator
        
        if slope > 1:
            return 'increasing'
        elif slope < -1:
            return 'decreasing'
        else:
            return 'stable'
    
    def _predict_future_score(self, scores):
        """Predict future compliance score based on trend"""
        if len(scores) < 2:
            return scores[0] if scores else 0
        
        # Simple linear extrapolation
        n = len(scores)
        x = list(range(n))
        
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(scores)
        
        numerator = sum((x[i] - x_mean) * (scores[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return y_mean
        
        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
        
        # Predict 30 days into future (assume 1 data point per day)
        future_x = n + 30
        predicted = slope * future_x + intercept
        
        # Bound between 0 and 100 for compliance scores
        return max(0, min(100, predicted))
    
    def _predict_future_value(self, values):
        """Predict future value for general metrics"""
        if len(values) < 2:
            return values[0] if values else 0
        
        # Use same linear extrapolation but don't bound to 0-100
        n = len(values)
        x = list(range(n))
        
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(values)
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return y_mean
        
        slope = numerator / denominator
        intercept = y_mean - slope * x_mean
        
        future_x = n + 30
        return slope * future_x + intercept
    
    def _generate_predictive_recommendations(self, breach_risk, compliance_trends, vulnerability_trends, phi_exposure_risk):
        """Generate recommendations based on predictions"""
        recommendations = []
        
        # Breach risk recommendations
        if breach_risk['risk_level'] in ['critical', 'high']:
            recommendations.append({
                'priority': 'critical',
                'category': 'breach_prevention',
                'description': f"High breach risk predicted ({breach_risk['probability']:.1%})",
                'action': 'Immediate security review and implementation of additional safeguards required'
            })
        
        # Compliance trend recommendations
        overall_compliance = compliance_trends.get('overall_prediction', {})
        if overall_compliance.get('trend') == 'decreasing':
            recommendations.append({
                'priority': 'high',
                'category': 'compliance_management',
                'description': 'Declining compliance trend detected',
                'action': 'Review and strengthen compliance controls across all frameworks'
            })
        
        # Vulnerability trend recommendations
        if vulnerability_trends.get('trend') == 'increasing':
            recommendations.append({
                'priority': 'high',
                'category': 'vulnerability_management',
                'description': 'Increasing vulnerability trend predicted',
                'action': 'Implement enhanced vulnerability scanning and remediation processes'
            })
        
        # PHI exposure recommendations
        if phi_exposure_risk['risk_level'] in ['critical', 'high']:
            recommendations.append({
                'priority': 'critical',
                'category': 'data_protection',
                'description': f"High PHI exposure risk ({phi_exposure_risk['predicted_exposure_probability']:.1%})",
                'action': 'Implement additional PHI protection measures and access controls'
            })
        
        return recommendations
    
    def _get_breach_risk_recommendation(self, risk_level, probability):
        """Get specific recommendation for breach risk"""
        if risk_level == 'critical':
            return "Immediate action required: Implement emergency security measures and consider system isolation"
        elif risk_level == 'high':
            return "High priority: Strengthen security controls and increase monitoring"
        elif risk_level == 'medium':
            return "Monitor closely and consider additional security measures"
        else:
            return "Maintain current security posture and continue regular monitoring"
    
    def _get_vulnerability_recommendation(self, trend, predicted_count):
        """Get recommendation for vulnerability trends"""
        if trend == 'increasing' and predicted_count > 5:
            return "Critical: Implement aggressive vulnerability remediation program"
        elif trend == 'increasing':
            return "Enhance vulnerability scanning frequency and remediation processes"
        elif predicted_count > 3:
            return "Focus on reducing existing vulnerability backlog"
        else:
            return "Maintain current vulnerability management practices"
    
    def _get_phi_risk_recommendation(self, risk_level, probability):
        """Get recommendation for PHI exposure risk"""
        if risk_level == 'critical':
            return "Emergency PHI protection review required - consider data access restrictions"
        elif risk_level == 'high':
            return "Implement enhanced PHI monitoring and access controls immediately"
        elif risk_level == 'medium':
            return "Review PHI handling procedures and implement additional safeguards"
        else:
            return "Continue current PHI protection measures with regular review"
