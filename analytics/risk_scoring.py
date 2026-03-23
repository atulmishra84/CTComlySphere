"""
Risk Scoring Engine for CT ComplySphere Visibility & Governance Platform
Provides advanced risk scoring and trending analytics
"""

import logging
from datetime import datetime, timedelta
from sqlalchemy import func, and_
from app import db
from models import AIAgent, ScanResult, ComplianceEvaluation, RiskLevel
import statistics
import json

class RiskScorer:
    """Advanced risk scoring engine for AI agents"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.risk_weights = {
            'vulnerability_count': 0.25,
            'phi_exposure': 0.30,
            'encryption_status': 0.20,
            'compliance_score': 0.15,
            'agent_criticality': 0.10
        }
    
    def calculate_comprehensive_risk_score(self, agent_id):
        """Calculate comprehensive risk score for an AI agent"""
        try:
            agent = AIAgent.query.get(agent_id)
            if not agent:
                raise ValueError(f"Agent {agent_id} not found")
            
            # Get latest scan result
            latest_scan = ScanResult.query.filter_by(ai_agent_id=agent_id)\
                                        .order_by(ScanResult.created_at.desc()).first()
            
            # Get latest compliance evaluations
            compliance_evals = ComplianceEvaluation.query.filter_by(ai_agent_id=agent_id)\
                                                        .order_by(ComplianceEvaluation.evaluated_at.desc()).all()
            
            # Calculate individual risk components
            vulnerability_risk = self._calculate_vulnerability_risk(latest_scan)
            phi_risk = self._calculate_phi_risk(latest_scan, agent)
            encryption_risk = self._calculate_encryption_risk(latest_scan)
            compliance_risk = self._calculate_compliance_risk(compliance_evals)
            criticality_risk = self._calculate_criticality_risk(agent)
            
            # Calculate weighted risk score
            total_risk = (
                vulnerability_risk * self.risk_weights['vulnerability_count'] +
                phi_risk * self.risk_weights['phi_exposure'] +
                encryption_risk * self.risk_weights['encryption_status'] +
                compliance_risk * self.risk_weights['compliance_score'] +
                criticality_risk * self.risk_weights['agent_criticality']
            )
            
            risk_level = self._determine_risk_level(total_risk)
            
            return {
                'agent_id': agent_id,
                'total_risk_score': round(total_risk, 2),
                'risk_level': risk_level,
                'risk_components': {
                    'vulnerability_risk': round(vulnerability_risk, 2),
                    'phi_risk': round(phi_risk, 2),
                    'encryption_risk': round(encryption_risk, 2),
                    'compliance_risk': round(compliance_risk, 2),
                    'criticality_risk': round(criticality_risk, 2)
                },
                'calculated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Risk scoring failed for agent {agent_id}: {str(e)}")
            raise
    
    def _calculate_vulnerability_risk(self, scan_result):
        """Calculate risk based on vulnerabilities found"""
        if not scan_result:
            return 80.0  # High risk if no scan data
        
        vuln_count = scan_result.vulnerabilities_found
        
        if vuln_count == 0:
            return 10.0
        elif vuln_count <= 2:
            return 30.0
        elif vuln_count <= 5:
            return 60.0
        else:
            return 90.0
    
    def _calculate_phi_risk(self, scan_result, agent):
        """Calculate risk based on PHI exposure"""
        base_risk = 20.0
        
        if scan_result and scan_result.phi_exposure_detected:
            base_risk = 70.0
        
        # Increase risk for healthcare AI types
        healthcare_types = ['Medical Imaging AI', 'Clinical Decision Support', 'EHR AI Assistant']
        if agent.type in healthcare_types:
            base_risk += 20.0
        
        return min(100.0, base_risk)
    
    def _calculate_encryption_risk(self, scan_result):
        """Calculate risk based on encryption status"""
        if not scan_result or not scan_result.scan_data:
            return 70.0
        
        encryption_status = scan_result.scan_data.get('encryption_status', 'none')
        
        if encryption_status == 'tls':
            return 15.0
        elif encryption_status == 'weak':
            return 50.0
        else:
            return 85.0
    
    def _calculate_compliance_risk(self, compliance_evaluations):
        """Calculate risk based on compliance scores"""
        if not compliance_evaluations:
            return 80.0
        
        # Use average compliance score across all frameworks
        avg_compliance = sum(eval.compliance_score for eval in compliance_evaluations) / len(compliance_evaluations)
        
        # Convert compliance score to risk score (inverse relationship)
        return 100.0 - avg_compliance
    
    def _calculate_criticality_risk(self, agent):
        """Calculate risk based on agent criticality"""
        critical_types = [
            'Medical Imaging AI',
            'Clinical Decision Support',
            'Patient Monitoring AI',
            'Drug Discovery AI'
        ]
        
        if agent.type in critical_types:
            return 80.0
        elif 'Healthcare' in agent.type or 'Medical' in agent.type:
            return 60.0
        else:
            return 40.0
    
    def _determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def get_risk_trends(self, days=30):
        """Get risk trends over specified time period"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get scan results within date range
        scans = ScanResult.query.filter(
            and_(
                ScanResult.created_at >= start_date,
                ScanResult.created_at <= end_date
            )
        ).order_by(ScanResult.created_at).all()
        
        # Group by date and calculate daily risk metrics
        daily_risks = {}
        
        for scan in scans:
            date_key = scan.created_at.strftime('%Y-%m-%d')
            
            if date_key not in daily_risks:
                daily_risks[date_key] = {
                    'risk_scores': [],
                    'phi_exposures': 0,
                    'vulnerability_count': 0,
                    'scan_count': 0
                }
            
            daily_risks[date_key]['risk_scores'].append(scan.risk_score)
            daily_risks[date_key]['scan_count'] += 1
            daily_risks[date_key]['vulnerability_count'] += scan.vulnerabilities_found
            
            if scan.phi_exposure_detected:
                daily_risks[date_key]['phi_exposures'] += 1
        
        # Calculate trends
        trend_data = []
        for date_key, metrics in daily_risks.items():
            avg_risk = statistics.mean(metrics['risk_scores']) if metrics['risk_scores'] else 0
            
            trend_data.append({
                'date': date_key,
                'average_risk_score': round(avg_risk, 2),
                'phi_exposure_rate': round((metrics['phi_exposures'] / metrics['scan_count']) * 100, 2),
                'total_vulnerabilities': metrics['vulnerability_count'],
                'scan_count': metrics['scan_count']
            })
        
        # Sort by date
        trend_data.sort(key=lambda x: x['date'])
        
        return trend_data
    
    def get_risk_distribution(self):
        """Get current risk distribution across all agents"""
        # Get latest scan for each agent
        subquery = db.session.query(
            ScanResult.ai_agent_id,
            func.max(ScanResult.created_at).label('latest_scan')
        ).group_by(ScanResult.ai_agent_id).subquery()
        
        latest_scans = db.session.query(ScanResult).join(
            subquery,
            and_(
                ScanResult.ai_agent_id == subquery.c.ai_agent_id,
                ScanResult.created_at == subquery.c.latest_scan
            )
        ).all()
        
        # Count by risk level
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        for scan in latest_scans:
            risk_level = scan.risk_level.value if scan.risk_level else 'MEDIUM'
            risk_counts[risk_level] += 1
        
        total_agents = sum(risk_counts.values())
        
        return {
            'total_agents': total_agents,
            'distribution': risk_counts,
            'percentages': {
                level: round((count / total_agents) * 100, 2) if total_agents > 0 else 0
                for level, count in risk_counts.items()
            }
        }
    
    def get_high_risk_agents(self, limit=10):
        """Get agents with highest risk scores"""
        # Get latest scan for each agent with high risk
        subquery = db.session.query(
            ScanResult.ai_agent_id,
            func.max(ScanResult.created_at).label('latest_scan')
        ).group_by(ScanResult.ai_agent_id).subquery()
        
        high_risk_scans = db.session.query(
            ScanResult, AIAgent
        ).join(
            AIAgent, ScanResult.ai_agent_id == AIAgent.id
        ).join(
            subquery,
            and_(
                ScanResult.ai_agent_id == subquery.c.ai_agent_id,
                ScanResult.created_at == subquery.c.latest_scan
            )
        ).filter(
            ScanResult.risk_level.in_([RiskLevel.HIGH, RiskLevel.CRITICAL])
        ).order_by(
            ScanResult.risk_score.desc()
        ).limit(limit).all()
        
        high_risk_agents = []
        for scan, agent in high_risk_scans:
            high_risk_agents.append({
                'agent_id': agent.id,
                'agent_name': agent.name,
                'agent_type': agent.type,
                'protocol': agent.protocol,
                'cloud_provider': agent.cloud_provider,
                'risk_score': scan.risk_score,
                'risk_level': scan.risk_level.value,
                'vulnerabilities': scan.vulnerabilities_found,
                'phi_exposure': scan.phi_exposure_detected,
                'last_scanned': scan.created_at.isoformat()
            })
        
        return high_risk_agents
    
    def calculate_risk_velocity(self, agent_id, days=7):
        """Calculate how quickly risk is changing for an agent"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        scans = ScanResult.query.filter(
            and_(
                ScanResult.ai_agent_id == agent_id,
                ScanResult.created_at >= start_date
            )
        ).order_by(ScanResult.created_at).all()
        
        if len(scans) < 2:
            return {
                'velocity': 0.0,
                'trend': 'stable',
                'data_points': len(scans)
            }
        
        # Calculate risk score changes
        risk_scores = [scan.risk_score for scan in scans]
        
        # Simple linear trend calculation
        n = len(risk_scores)
        x = list(range(n))
        
        # Calculate slope (risk velocity)
        x_mean = statistics.mean(x)
        y_mean = statistics.mean(risk_scores)
        
        numerator = sum((x[i] - x_mean) * (risk_scores[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        velocity = numerator / denominator if denominator != 0 else 0.0
        
        # Determine trend
        if velocity > 5:
            trend = 'increasing'
        elif velocity < -5:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'velocity': round(velocity, 2),
            'trend': trend,
            'data_points': len(scans),
            'current_risk': risk_scores[-1],
            'initial_risk': risk_scores[0]
        }
    
    def generate_risk_report(self, agent_id=None):
        """Generate comprehensive risk report"""
        if agent_id:
            # Single agent report
            risk_data = self.calculate_comprehensive_risk_score(agent_id)
            velocity = self.calculate_risk_velocity(agent_id)
            
            return {
                'report_type': 'single_agent',
                'agent_id': agent_id,
                'risk_assessment': risk_data,
                'risk_velocity': velocity,
                'generated_at': datetime.utcnow().isoformat()
            }
        else:
            # System-wide report
            distribution = self.get_risk_distribution()
            high_risk = self.get_high_risk_agents()
            trends = self.get_risk_trends()
            
            return {
                'report_type': 'system_wide',
                'risk_distribution': distribution,
                'high_risk_agents': high_risk,
                'risk_trends': trends,
                'summary': {
                    'total_agents': distribution['total_agents'],
                    'critical_agents': distribution['distribution']['CRITICAL'],
                    'high_risk_agents': distribution['distribution']['HIGH'],
                    'risk_trend': self._analyze_overall_trend(trends)
                },
                'generated_at': datetime.utcnow().isoformat()
            }
    
    def _analyze_overall_trend(self, trend_data):
        """Analyze overall risk trend from trend data"""
        if len(trend_data) < 2:
            return 'insufficient_data'
        
        recent_scores = [item['average_risk_score'] for item in trend_data[-7:]]
        
        if len(recent_scores) < 2:
            return 'insufficient_data'
        
        # Calculate trend over last week
        first_score = recent_scores[0]
        last_score = recent_scores[-1]
        
        change = last_score - first_score
        
        if change > 10:
            return 'increasing'
        elif change < -10:
            return 'decreasing'
        else:
            return 'stable'
