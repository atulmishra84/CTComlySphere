"""
Healthcare Compliance Evaluator
Evaluates AI agents against various healthcare compliance frameworks
"""

import logging
from datetime import datetime
from app import db
from models import AIAgent, ComplianceEvaluation, ComplianceFramework, ScanResult
from .frameworks import ComplianceFrameworks
import json

class ComplianceEvaluator:
    """Evaluates AI agents for compliance with healthcare frameworks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.frameworks = ComplianceFrameworks()
    
    def evaluate_agent(self, agent, framework_type):
        """Evaluate an AI agent against a specific compliance framework"""
        try:
            framework = self.frameworks.get_framework(framework_type)
            if not framework:
                raise ValueError(f"Unknown compliance framework: {framework_type}")
            
            # Get latest scan results for the agent
            latest_scan = ScanResult.query.filter_by(ai_agent_id=agent.id)\
                                        .order_by(ScanResult.created_at.desc()).first()
            
            # Perform compliance evaluation
            evaluation_results = self._evaluate_framework_categories(agent, framework, latest_scan)
            
            # Calculate overall compliance score
            overall_score = self._calculate_overall_score(evaluation_results, framework)
            
            # Determine compliance status
            is_compliant = overall_score >= framework['minimum_score']
            
            # Generate findings and recommendations
            findings = self._generate_findings(evaluation_results, framework)
            recommendations = self._generate_recommendations(evaluation_results, framework, is_compliant)
            
            # Save evaluation to database
            evaluation = ComplianceEvaluation(
                ai_agent_id=agent.id,
                framework=framework_type,
                compliance_score=overall_score,
                is_compliant=is_compliant,
                findings=findings,
                recommendations=recommendations,
                evaluator_version="1.0.0"
            )
            
            db.session.add(evaluation)
            db.session.commit()
            
            return {
                'agent_id': agent.id,
                'framework': framework_type.value,
                'compliance_score': overall_score,
                'is_compliant': is_compliant,
                'findings': findings,
                'recommendations': recommendations,
                'evaluation_date': evaluation.evaluated_at.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Compliance evaluation failed for agent {agent.id}: {str(e)}")
            raise
    
    def _evaluate_framework_categories(self, agent, framework, latest_scan):
        """Evaluate each category within a compliance framework"""
        results = {}
        
        for category_name, category_config in framework['categories'].items():
            category_score = self._evaluate_category(agent, category_name, category_config, latest_scan)
            results[category_name] = {
                'score': category_score,
                'weight': category_config['weight'],
                'controls': category_config['controls']
            }
        
        return results
    
    def _evaluate_category(self, agent, category_name, category_config, latest_scan):
        """Evaluate a specific compliance category"""
        controls = category_config['controls']
        control_scores = []
        
        for control in controls:
            score = self._evaluate_control(agent, control, category_name, latest_scan)
            control_scores.append(score)
        
        # Calculate average score for the category
        return sum(control_scores) / len(control_scores) if control_scores else 0.0
    
    def _evaluate_control(self, agent, control, category, latest_scan):
        """Evaluate a specific compliance control"""
        # Get agent metadata and scan results
        metadata = agent.metadata or {}
        scan_data = latest_scan.scan_data if latest_scan else {}
        
        # Evaluate based on control type and available data
        if control == 'access_control':
            return self._evaluate_access_control(agent, metadata, scan_data)
        elif control == 'encryption' or control == 'transmission_security':
            return self._evaluate_encryption(agent, metadata, scan_data)
        elif control == 'audit_controls' or control == 'audit_trails':
            return self._evaluate_audit_controls(agent, metadata, scan_data)
        elif control == 'data_classification':
            return self._evaluate_data_classification(agent, metadata, scan_data)
        elif control == 'vulnerability_management':
            return self._evaluate_vulnerability_management(agent, metadata, scan_data)
        elif control == 'algorithm_validation':
            return self._evaluate_algorithm_validation(agent, metadata, scan_data)
        elif control == 'consent_management':
            return self._evaluate_consent_management(agent, metadata, scan_data)
        elif control == 'data_minimization':
            return self._evaluate_data_minimization(agent, metadata, scan_data)
        elif control == 'breach_notification':
            return self._evaluate_breach_notification(agent, metadata, scan_data)
        else:
            # Default evaluation for other controls
            return self._evaluate_generic_control(agent, control, metadata, scan_data)
    
    def _evaluate_access_control(self, agent, metadata, scan_data):
        """Evaluate access control implementation"""
        score = 0.0
        
        # Check for authentication requirements
        if scan_data.get('authentication_required', False):
            score += 40.0
        
        # Check for encryption status
        encryption_status = scan_data.get('encryption_status', 'none')
        if encryption_status == 'tls':
            score += 30.0
        elif encryption_status == 'weak':
            score += 15.0
        
        # Check for secure protocols
        if agent.protocol in ['kubernetes', 'grpc'] and metadata.get('tls_enabled'):
            score += 20.0
        elif agent.endpoint and agent.endpoint.startswith('https://'):
            score += 20.0
        
        # Penalize for vulnerabilities
        vulnerabilities = scan_data.get('vulnerabilities_found', 0) if scan_data else 0
        score -= min(vulnerabilities * 5, 30)
        
        return max(0.0, min(100.0, score))
    
    def _evaluate_encryption(self, agent, metadata, scan_data):
        """Evaluate encryption implementation"""
        score = 0.0
        
        encryption_status = scan_data.get('encryption_status', 'none')
        if encryption_status == 'tls':
            score = 85.0
        elif encryption_status == 'weak':
            score = 50.0
        else:
            score = 10.0
        
        # Bonus for PHI handling with encryption
        if scan_data.get('phi_exposure_detected') and encryption_status == 'tls':
            score = min(100.0, score + 15.0)
        
        # Check for additional encryption indicators
        if metadata.get('encryption') or 'encryption' in str(metadata).lower():
            score = min(100.0, score + 10.0)
        
        return score
    
    def _evaluate_audit_controls(self, agent, metadata, scan_data):
        """Evaluate audit and logging controls"""
        score = 20.0  # Base score for having scan data
        
        # Check for logging capabilities
        if 'logging' in str(metadata).lower() or 'audit' in str(metadata).lower():
            score += 30.0
        
        # Check for monitoring capabilities
        if agent.type in ['Patient Monitoring AI', 'Clinical Decision Support']:
            score += 25.0
        
        # Check for comprehensive scan data
        if scan_data and len(scan_data) > 3:
            score += 25.0
        
        return min(100.0, score)
    
    def _evaluate_data_classification(self, agent, metadata, scan_data):
        """Evaluate data classification practices"""
        score = 30.0  # Base score
        
        # Check for PHI handling indicators
        if scan_data.get('phi_exposure_detected'):
            # PHI detected but properly classified
            score += 40.0
        
        # Check for healthcare-specific AI types
        healthcare_types = ['Medical Imaging AI', 'Clinical Decision Support', 'Healthcare NLP AI']
        if agent.type in healthcare_types:
            score += 30.0
        
        return min(100.0, score)
    
    def _evaluate_vulnerability_management(self, agent, metadata, scan_data):
        """Evaluate vulnerability management practices"""
        vulnerabilities = scan_data.get('vulnerabilities_found', 0) if scan_data else 5
        
        # Score inversely related to vulnerabilities found
        if vulnerabilities == 0:
            score = 100.0
        elif vulnerabilities == 1:
            score = 80.0
        elif vulnerabilities == 2:
            score = 60.0
        elif vulnerabilities <= 5:
            score = 40.0
        else:
            score = 20.0
        
        # Bonus for recent scanning
        if scan_data:
            score = min(100.0, score + 10.0)
        
        return score
    
    def _evaluate_algorithm_validation(self, agent, metadata, scan_data):
        """Evaluate algorithm validation for AI/ML systems"""
        score = 20.0  # Base score for being an AI system
        
        # Check for model validation indicators
        if 'validation' in str(metadata).lower() or 'model' in str(metadata).lower():
            score += 30.0
        
        # Check for healthcare AI types that require validation
        if agent.type in ['Medical Imaging AI', 'Clinical Decision Support', 'Drug Discovery AI']:
            score += 25.0
        
        # Check for version information (indicates managed deployment)
        if agent.version or metadata.get('version'):
            score += 25.0
        
        return min(100.0, score)
    
    def _evaluate_consent_management(self, agent, metadata, scan_data):
        """Evaluate consent management for GDPR compliance"""
        score = 40.0  # Base score
        
        # Check for PHI/PII handling
        if scan_data.get('phi_exposure_detected'):
            # PHI handling requires consent management
            score += 30.0
        
        # Check for patient-facing systems
        if 'patient' in agent.type.lower() or 'telemedicine' in agent.type.lower():
            score += 30.0
        
        return min(100.0, score)
    
    def _evaluate_data_minimization(self, agent, metadata, scan_data):
        """Evaluate data minimization practices"""
        score = 50.0  # Base score
        
        # Check for specific healthcare AI types (should implement minimization)
        if agent.type in ['Healthcare NLP AI', 'EHR AI Assistant']:
            score += 25.0
        
        # Bonus for secure protocols (indicates data protection awareness)
        if scan_data.get('encryption_status') == 'tls':
            score += 25.0
        
        return min(100.0, score)
    
    def _evaluate_breach_notification(self, agent, metadata, scan_data):
        """Evaluate breach notification capabilities"""
        score = 30.0  # Base score
        
        # Check for monitoring and alerting capabilities
        if 'monitoring' in agent.type.lower() or 'alert' in str(metadata).lower():
            score += 40.0
        
        # Check for healthcare context
        if any(term in agent.type.lower() for term in ['medical', 'clinical', 'health']):
            score += 30.0
        
        return min(100.0, score)
    
    def _evaluate_generic_control(self, agent, control, metadata, scan_data):
        """Generic evaluation for other controls"""
        score = 50.0  # Base score
        
        # Adjust based on risk level
        if scan_data:
            risk_score = scan_data.get('risk_score', 50)
            score = 100 - risk_score
        
        # Bonus for healthcare-specific systems
        if any(term in agent.type.lower() for term in ['medical', 'clinical', 'health']):
            score = min(100.0, score + 20.0)
        
        return max(0.0, score)
    
    def _calculate_overall_score(self, evaluation_results, framework):
        """Calculate weighted overall compliance score"""
        weighted_score = 0.0
        total_weight = 0.0
        
        for category_name, results in evaluation_results.items():
            category_score = results['score']
            category_weight = results['weight']
            
            weighted_score += category_score * category_weight
            total_weight += category_weight
        
        return weighted_score / total_weight if total_weight > 0 else 0.0
    
    def _generate_findings(self, evaluation_results, framework):
        """Generate detailed compliance findings"""
        findings = {
            'summary': {
                'total_categories': len(evaluation_results),
                'categories_passed': 0,
                'categories_failed': 0,
                'critical_issues': []
            },
            'category_details': {}
        }
        
        critical_controls = framework.get('critical_controls', [])
        
        for category_name, results in evaluation_results.items():
            category_score = results['score']
            category_passed = category_score >= 70.0  # 70% threshold for category pass
            
            if category_passed:
                findings['summary']['categories_passed'] += 1
            else:
                findings['summary']['categories_failed'] += 1
            
            # Check for critical control failures
            for control in results['controls']:
                if control in critical_controls and category_score < 60.0:
                    findings['summary']['critical_issues'].append({
                        'control': control,
                        'category': category_name,
                        'score': category_score
                    })
            
            findings['category_details'][category_name] = {
                'score': category_score,
                'status': 'PASS' if category_passed else 'FAIL',
                'controls': results['controls'],
                'weight': results['weight']
            }
        
        return findings
    
    def _generate_recommendations(self, evaluation_results, framework, is_compliant):
        """Generate compliance recommendations"""
        recommendations = []
        
        if not is_compliant:
            recommendations.append({
                'priority': 'critical',
                'category': 'overall_compliance',
                'description': f'System does not meet minimum compliance score of {framework["minimum_score"]}%',
                'action': 'Immediate review and remediation of all failed controls required'
            })
        
        # Category-specific recommendations
        for category_name, results in evaluation_results.items():
            category_score = results['score']
            
            if category_score < 70.0:
                recommendations.append({
                    'priority': 'high',
                    'category': category_name,
                    'description': f'Category "{category_name}" scored {category_score:.1f}% (below 70% threshold)',
                    'action': f'Review and strengthen {category_name} controls: {", ".join(results["controls"])}'
                })
            elif category_score < 85.0:
                recommendations.append({
                    'priority': 'medium',
                    'category': category_name,
                    'description': f'Category "{category_name}" has room for improvement ({category_score:.1f}%)',
                    'action': f'Consider enhancing {category_name} controls for better compliance posture'
                })
        
        # Critical control recommendations
        critical_controls = framework.get('critical_controls', [])
        for control in critical_controls:
            # Find category containing this control
            for category_name, results in evaluation_results.items():
                if control in results['controls'] and results['score'] < 80.0:
                    recommendations.append({
                        'priority': 'high',
                        'category': category_name,
                        'description': f'Critical control "{control}" requires attention',
                        'action': f'Prioritize implementation and validation of {control} control'
                    })
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 3))
        
        return recommendations
    
    def evaluate_all_frameworks(self, agent):
        """Evaluate an agent against all compliance frameworks"""
        results = {}
        
        for framework_type in ComplianceFramework:
            try:
                evaluation = self.evaluate_agent(agent, framework_type)
                results[framework_type.value] = evaluation
            except Exception as e:
                self.logger.error(f"Failed to evaluate {framework_type.value}: {str(e)}")
                results[framework_type.value] = {
                    'error': str(e),
                    'compliance_score': 0.0,
                    'is_compliant': False
                }
        
        return results
    
    def get_compliance_summary(self):
        """Get overall compliance summary across all agents and frameworks"""
        summary = {
            'total_agents': AIAgent.query.count(),
            'total_evaluations': ComplianceEvaluation.query.count(),
            'framework_summaries': {}
        }
        
        for framework_type in ComplianceFramework:
            evaluations = ComplianceEvaluation.query.filter_by(framework=framework_type).all()
            
            if evaluations:
                avg_score = sum(e.compliance_score for e in evaluations) / len(evaluations)
                compliant_count = sum(1 for e in evaluations if e.is_compliant)
                compliance_rate = (compliant_count / len(evaluations)) * 100
                
                summary['framework_summaries'][framework_type.value] = {
                    'total_evaluations': len(evaluations),
                    'average_score': round(avg_score, 2),
                    'compliance_rate': round(compliance_rate, 2),
                    'compliant_agents': compliant_count,
                    'non_compliant_agents': len(evaluations) - compliant_count
                }
            else:
                summary['framework_summaries'][framework_type.value] = {
                    'total_evaluations': 0,
                    'average_score': 0.0,
                    'compliance_rate': 0.0,
                    'compliant_agents': 0,
                    'non_compliant_agents': 0
                }
        
        return summary
