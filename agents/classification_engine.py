"""
Agent Classification Engine
Automatically classifies AI agents based on functionality and determines applicable regulatory frameworks
Enhanced with GenAI and Agentic AI detection capabilities
"""
import re
import json
from typing import Dict, List, Set, Any, Optional
from datetime import datetime
from models import ComplianceFramework, AIAgentType


class AgentClassificationEngine:
    """Classifies AI agents and determines applicable regulatory frameworks"""
    
    def __init__(self):
        self.classification_rules = self._load_classification_rules()
        self.framework_mappings = self._load_framework_mappings()
        
    def _load_classification_rules(self) -> Dict[str, Dict]:
        """Load enhanced agent classification rules with work engine analysis, data sources, outputs, and departmental usage"""
        return {
            'healthcare_ai': {
                'keywords': [
                    'medical', 'clinical', 'healthcare', 'hospital', 'patient', 'phi', 'hipaa',
                    'diagnosis', 'radiology', 'imaging', 'pathology', 'oncology', 'cardiology',
                    'ehr', 'emr', 'fhir', 'hl7', 'dicom', 'icd', 'cpt', 'snomed', 'loinc',
                    'prescription', 'medication', 'drug', 'therapy', 'treatment', 'clinical-trial'
                ],
                'protocols': ['fhir', 'hl7', 'dicom'],
                'data_types': ['phi', 'clinical', 'medical'],
                'frameworks': [ComplianceFramework.HIPAA, ComplianceFramework.FDA_SAMD, ComplianceFramework.HITRUST_CSF],
                'criticality': 'high',
                'description': 'AI systems processing healthcare data or providing medical functionality',
                # Enhanced Classification Parameters
                'work_engines': {
                    'diagnostic_imaging': ['chest_xray', 'mri_analysis', 'ct_scan', 'mammography', 'ultrasound'],
                    'clinical_decision_support': ['treatment_recommendation', 'drug_interaction', 'clinical_pathway'],
                    'patient_monitoring': ['vital_signs', 'wearable_data', 'telemetry', 'remote_monitoring'],
                    'medical_coding': ['icd_coding', 'cpt_coding', 'medical_billing', 'documentation'],
                    'drug_discovery': ['molecular_analysis', 'compound_screening', 'clinical_trials'],
                    'genomics': ['dna_sequencing', 'genetic_analysis', 'precision_medicine']
                },
                'data_sources': {
                    'primary': ['ehr_systems', 'pacs', 'lis', 'his', 'ris'],
                    'secondary': ['wearables', 'iot_devices', 'mobile_health', 'research_databases'],
                    'external': ['public_health_data', 'clinical_registries', 'medical_literature']
                },
                'output_types': {
                    'diagnostic': ['diagnosis_prediction', 'risk_scores', 'abnormality_detection'],
                    'therapeutic': ['treatment_plans', 'drug_recommendations', 'dosage_optimization'],
                    'administrative': ['coding_suggestions', 'billing_codes', 'documentation_assistance'],
                    'research': ['clinical_insights', 'population_analytics', 'outcome_predictions']
                },
                'department_usage': {
                    'clinical': ['radiology', 'pathology', 'cardiology', 'oncology', 'emergency'],
                    'administrative': ['health_information', 'medical_coding', 'billing', 'compliance'],
                    'research': ['clinical_research', 'biomedical_research', 'epidemiology'],
                    'operational': ['it_operations', 'quality_assurance', 'risk_management']
                }
            },
            'financial_ai': {
                'keywords': [
                    'financial', 'banking', 'payment', 'credit', 'loan', 'investment', 'trading',
                    'fraud', 'kyc', 'aml', 'pci', 'sox', 'risk', 'compliance', 'audit',
                    'transaction', 'account', 'portfolio', 'insurance', 'fintech'
                ],
                'protocols': ['rest_api', 'grpc'],
                'data_types': ['pii', 'financial', 'transaction'],
                'frameworks': [ComplianceFramework.SOC2_TYPE_II, ComplianceFramework.GDPR],
                'criticality': 'high',
                'description': 'AI systems processing financial data or providing financial services',
                'work_engines': {
                    'fraud_detection': ['transaction_monitoring', 'anomaly_detection', 'pattern_analysis'],
                    'credit_assessment': ['credit_scoring', 'risk_modeling', 'loan_approval'],
                    'investment_analysis': ['portfolio_optimization', 'market_prediction', 'algo_trading'],
                    'regulatory_compliance': ['aml_monitoring', 'kyc_verification', 'compliance_reporting'],
                    'customer_service': ['chatbots', 'robo_advisors', 'personalized_recommendations']
                },
                'data_sources': {
                    'primary': ['core_banking', 'trading_systems', 'crm', 'loan_origination'],
                    'secondary': ['credit_bureaus', 'market_data', 'social_media', 'alternative_data'],
                    'external': ['regulatory_databases', 'news_feeds', 'economic_indicators']
                },
                'output_types': {
                    'risk_assessment': ['credit_scores', 'fraud_alerts', 'risk_ratings'],
                    'trading_signals': ['buy_sell_recommendations', 'price_predictions', 'portfolio_rebalancing'],
                    'compliance_reports': ['aml_reports', 'regulatory_filings', 'audit_trails'],
                    'customer_insights': ['behavior_analysis', 'product_recommendations', 'churn_prediction']
                },
                'department_usage': {
                    'risk_management': ['credit_risk', 'market_risk', 'operational_risk'],
                    'trading': ['algorithmic_trading', 'quantitative_analysis', 'portfolio_management'],
                    'compliance': ['aml_team', 'regulatory_affairs', 'internal_audit'],
                    'customer_operations': ['customer_service', 'sales', 'marketing']
                }
            },
            'personal_data_ai': {
                'keywords': [
                    'personal', 'pii', 'gdpr', 'privacy', 'consent', 'profile', 'user',
                    'biometric', 'location', 'behavioral', 'demographic', 'identity'
                ],
                'protocols': ['rest_api', 'websocket', 'graphql'],
                'data_types': ['pii', 'personal'],
                'frameworks': [ComplianceFramework.GDPR],
                'criticality': 'medium',
                'description': 'AI systems processing personal identifiable information',
                'work_engines': {
                    'personalization': ['content_personalization', 'product_recommendations', 'user_profiling'],
                    'identity_verification': ['biometric_authentication', 'identity_matching', 'fraud_prevention'],
                    'behavioral_analysis': ['user_behavior_tracking', 'pattern_recognition', 'engagement_analysis'],
                    'privacy_protection': ['data_anonymization', 'consent_management', 'privacy_scoring'],
                    'customer_insights': ['segmentation', 'lifetime_value', 'churn_prediction']
                },
                'data_sources': {
                    'primary': ['user_profiles', 'interaction_logs', 'behavioral_data', 'demographic_data'],
                    'secondary': ['social_media', 'device_data', 'location_data', 'purchase_history'],
                    'external': ['public_records', 'third_party_data', 'partner_data']
                },
                'output_types': {
                    'profiles': ['user_segments', 'persona_profiles', 'risk_profiles'],
                    'recommendations': ['personalized_content', 'product_suggestions', 'targeted_offers'],
                    'insights': ['behavioral_insights', 'preference_analysis', 'trend_predictions'],
                    'privacy_controls': ['consent_status', 'data_usage_reports', 'privacy_scores']
                },
                'department_usage': {
                    'marketing': ['customer_segmentation', 'campaign_personalization', 'lead_scoring'],
                    'product': ['user_experience', 'feature_usage', 'product_optimization'],
                    'privacy': ['consent_management', 'data_protection', 'compliance_monitoring'],
                    'customer_service': ['personalized_support', 'customer_insights', 'satisfaction_analysis']
                }
            },
            'operational_ai': {
                'keywords': [
                    'monitoring', 'analytics', 'optimization', 'automation', 'workflow',
                    'process', 'operation', 'maintenance', 'performance', 'efficiency'
                ],
                'protocols': ['mqtt', 'websocket', 'amqp'],
                'data_types': ['operational', 'telemetry'],
                'frameworks': [ComplianceFramework.SOC2_TYPE_II],
                'criticality': 'low',
                'description': 'AI systems for operational efficiency and monitoring',
                'work_engines': {
                    'infrastructure_monitoring': ['server_monitoring', 'network_analysis', 'performance_tracking'],
                    'process_optimization': ['workflow_optimization', 'resource_allocation', 'efficiency_analysis'],
                    'predictive_maintenance': ['equipment_monitoring', 'failure_prediction', 'maintenance_scheduling'],
                    'quality_assurance': ['defect_detection', 'quality_metrics', 'process_control'],
                    'supply_chain': ['inventory_optimization', 'demand_forecasting', 'logistics_planning']
                },
                'data_sources': {
                    'primary': ['sensor_data', 'log_files', 'metrics_databases', 'monitoring_systems'],
                    'secondary': ['erp_systems', 'manufacturing_systems', 'iot_devices'],
                    'external': ['weather_data', 'market_conditions', 'supplier_data']
                },
                'output_types': {
                    'alerts': ['threshold_alerts', 'anomaly_notifications', 'predictive_warnings'],
                    'dashboards': ['kpi_dashboards', 'real_time_metrics', 'trend_analysis'],
                    'recommendations': ['optimization_suggestions', 'maintenance_schedules', 'resource_planning'],
                    'reports': ['performance_reports', 'efficiency_analysis', 'operational_insights']
                },
                'department_usage': {
                    'operations': ['production_monitoring', 'quality_control', 'process_optimization'],
                    'maintenance': ['predictive_maintenance', 'asset_management', 'repair_scheduling'],
                    'supply_chain': ['inventory_management', 'logistics', 'procurement'],
                    'it_operations': ['infrastructure_monitoring', 'performance_management', 'capacity_planning']
                }
            },
            'research_ai': {
                'keywords': [
                    'research', 'experiment', 'model', 'training', 'development', 'prototype',
                    'academic', 'science', 'analysis', 'discovery', 'innovation'
                ],
                'protocols': ['kubernetes', 'docker'],
                'data_types': ['research', 'experimental'],
                'frameworks': [],
                'criticality': 'low',
                'description': 'AI systems for research and development purposes',
                'work_engines': {
                    'data_analysis': ['statistical_analysis', 'pattern_discovery', 'hypothesis_testing'],
                    'model_development': ['algorithm_research', 'model_training', 'hyperparameter_tuning'],
                    'simulation': ['monte_carlo_simulation', 'scenario_modeling', 'predictive_simulation'],
                    'knowledge_discovery': ['literature_analysis', 'trend_identification', 'insight_generation'],
                    'experimentation': ['a_b_testing', 'controlled_experiments', 'causal_inference']
                },
                'data_sources': {
                    'primary': ['research_datasets', 'experimental_data', 'survey_data', 'observational_data'],
                    'secondary': ['public_datasets', 'academic_databases', 'collaborative_research'],
                    'external': ['published_papers', 'conference_proceedings', 'open_source_data']
                },
                'output_types': {
                    'research_findings': ['statistical_results', 'correlation_analysis', 'trend_reports'],
                    'models': ['trained_models', 'algorithms', 'prototypes'],
                    'publications': ['research_papers', 'technical_reports', 'conference_presentations'],
                    'insights': ['discovery_reports', 'hypothesis_validation', 'future_research_directions']
                },
                'department_usage': {
                    'research_and_development': ['algorithm_research', 'product_innovation', 'feasibility_studies'],
                    'academic_research': ['university_research', 'grant_projects', 'collaborative_studies'],
                    'data_science': ['exploratory_analysis', 'model_development', 'methodology_research'],
                    'product_development': ['prototype_testing', 'concept_validation', 'user_research']
                }
            },
            'genai': {
                'keywords': [
                    'gpt', 'llm', 'large language model', 'generative', 'openai', 'claude', 'anthropic',
                    'palm', 'bard', 'gemini', 'llama', 'mistral', 'claude', 'text-generation', 'completion',
                    'chat', 'conversation', 'prompt', 'fine-tune', 'embedding', 'transformer',
                    'bert', 'roberta', 'bloom', 'alpaca', 'vicuna', 'chatgpt', 'gpt-3', 'gpt-4',
                    'content-generation', 'text-to-image', 'image-generation', 'dalle', 'midjourney',
                    'stable-diffusion', 'diffusion', 'gan', 'vae', 'multimodal', 'vision-language'
                ],
                'protocols': ['rest_api', 'grpc', 'websocket', 'graphql'],
                'data_types': ['text', 'generated_content', 'prompts', 'embeddings'],
                'frameworks': [
                    ComplianceFramework.NIST_AI_RMF, 
                    ComplianceFramework.OWASP_AI,
                    ComplianceFramework.MITRE_ATLAS,
                    ComplianceFramework.SAIF_GOOGLE
                ],
                'criticality': 'high',
                'description': 'Generative AI systems capable of creating text, images, code, or other content',
                'ai_type': AIAgentType.GENAI,
                'specific_risks': [
                    'bias_amplification', 'misinformation_generation', 'privacy_leakage',
                    'hallucinations', 'prompt_injection', 'data_poisoning', 'model_extraction'
                ],
                'work_engines': {
                    'content_creation': ['text_generation', 'article_writing', 'creative_writing', 'code_generation'],
                    'document_processing': ['summarization', 'translation', 'extraction', 'analysis'],
                    'customer_interaction': ['chatbots', 'virtual_assistants', 'support_automation'],
                    'knowledge_work': ['research_assistance', 'data_analysis', 'report_generation'],
                    'creative_design': ['image_generation', 'logo_design', 'marketing_materials'],
                    'code_assistance': ['code_completion', 'bug_fixing', 'code_review', 'documentation']
                },
                'data_sources': {
                    'primary': ['user_prompts', 'chat_history', 'document_uploads', 'api_inputs'],
                    'secondary': ['knowledge_bases', 'vector_databases', 'fine_tuning_data'],
                    'external': ['web_scraping', 'public_datasets', 'api_integrations', 'real_time_feeds']
                },
                'output_types': {
                    'textual': ['responses', 'summaries', 'translations', 'code', 'articles'],
                    'visual': ['images', 'diagrams', 'charts', 'design_assets'],
                    'structured': ['json_data', 'api_responses', 'formatted_reports'],
                    'interactive': ['conversational_responses', 'dynamic_content', 'personalized_outputs']
                },
                'department_usage': {
                    'marketing': ['content_creation', 'social_media', 'advertising', 'copywriting'],
                    'customer_service': ['support_chatbots', 'ticket_routing', 'response_automation'],
                    'product_development': ['code_assistance', 'documentation', 'testing', 'prototyping'],
                    'research': ['literature_review', 'data_analysis', 'report_writing'],
                    'sales': ['proposal_generation', 'lead_qualification', 'email_automation'],
                    'hr': ['resume_screening', 'interview_scheduling', 'policy_drafting']
                }
            },
            'agentic_ai': {
                'keywords': [
                    'agent', 'autonomous', 'langchain', 'autogpt', 'crew', 'swarm', 'multi-agent',
                    'planning', 'reasoning', 'tool-use', 'function-calling', 'workflow', 'orchestration',
                    'decision-making', 'goal-oriented', 'task-execution', 'memory', 'context',
                    'retrieval', 'rag', 'knowledge-base', 'vector', 'embedding', 'search',
                    'api-calling', 'external-tools', 'browser', 'code-execution', 'interpreter'
                ],
                'protocols': ['rest_api', 'grpc', 'websocket', 'mqtt', 'graphql'],
                'data_types': ['instructions', 'goals', 'tool_responses', 'memory_state'],
                'frameworks': [
                    ComplianceFramework.NIST_AI_RMF,
                    ComplianceFramework.OWASP_AI,
                    ComplianceFramework.MITRE_ATLAS,
                    ComplianceFramework.SAIF_GOOGLE,
                    ComplianceFramework.SOC2_TYPE_II
                ],
                'criticality': 'critical',
                'description': 'Autonomous AI agents capable of planning, reasoning, and executing tasks with tool access',
                'ai_type': AIAgentType.AGENTIC_AI,
                'specific_risks': [
                    'uncontrolled_autonomy', 'goal_misalignment', 'tool_misuse', 'escalation_privileges',
                    'resource_consumption', 'infinite_loops', 'unauthorized_actions', 'data_exfiltration',
                    'system_compromise', 'social_engineering'
                ],
                'work_engines': {
                    'task_automation': ['workflow_orchestration', 'process_automation', 'task_delegation'],
                    'research_agents': ['data_gathering', 'analysis_automation', 'report_compilation'],
                    'software_engineering': ['code_review', 'testing_automation', 'deployment_management'],
                    'business_intelligence': ['data_mining', 'trend_analysis', 'predictive_modeling'],
                    'customer_operations': ['intelligent_routing', 'escalation_management', 'response_automation'],
                    'system_management': ['infrastructure_monitoring', 'incident_response', 'capacity_planning']
                },
                'data_sources': {
                    'primary': ['api_endpoints', 'databases', 'file_systems', 'message_queues'],
                    'secondary': ['web_interfaces', 'cloud_services', 'monitoring_systems'],
                    'external': ['third_party_apis', 'web_scraping', 'public_data_sources', 'partner_systems']
                },
                'output_types': {
                    'operational': ['task_completions', 'status_updates', 'error_reports', 'performance_metrics'],
                    'analytical': ['insights', 'recommendations', 'forecasts', 'optimization_suggestions'],
                    'transactional': ['api_calls', 'database_updates', 'file_modifications', 'system_changes'],
                    'communicative': ['notifications', 'alerts', 'reports', 'dashboard_updates']
                },
                'department_usage': {
                    'it_operations': ['system_monitoring', 'incident_management', 'deployment_automation'],
                    'business_operations': ['process_automation', 'workflow_management', 'quality_assurance'],
                    'data_science': ['automated_analysis', 'model_deployment', 'data_pipeline_management'],
                    'security': ['threat_detection', 'compliance_monitoring', 'vulnerability_management'],
                    'finance': ['automated_reporting', 'reconciliation', 'risk_assessment'],
                    'supply_chain': ['inventory_management', 'logistics_optimization', 'supplier_monitoring']
                }
            },
            'multimodal_ai': {
                'keywords': [
                    'multimodal', 'vision-language', 'video-understanding', 'audio-processing',
                    'speech-to-text', 'text-to-speech', 'image-captioning', 'visual-qa',
                    'ocr', 'document-analysis', 'multimedia', 'cross-modal', 'fusion',
                    'gpt-4v', 'clip', 'align', 'blip', 'flamingo', 'kosmos'
                ],
                'protocols': ['rest_api', 'grpc', 'websocket'],
                'data_types': ['images', 'audio', 'video', 'text', 'documents'],
                'frameworks': [
                    ComplianceFramework.NIST_AI_RMF,
                    ComplianceFramework.OWASP_AI,
                    ComplianceFramework.GDPR
                ],
                'criticality': 'high',
                'description': 'AI systems processing multiple data modalities (text, image, audio, video)',
                'ai_type': AIAgentType.MULTIMODAL_AI,
                'specific_risks': [
                    'cross_modal_bias', 'deepfake_generation', 'privacy_inference',
                    'content_manipulation', 'biometric_exposure'
                ]
            }
        }
    
    def _load_framework_mappings(self) -> Dict[str, Dict]:
        """Load framework-specific requirements and mappings"""
        return {
            ComplianceFramework.HIPAA.value: {
                'required_controls': [
                    'encryption_at_rest', 'encryption_in_transit', 'access_control',
                    'audit_logging', 'phi_protection', 'authentication'
                ],
                'data_handling': ['phi_detection', 'anonymization', 'consent_management'],
                'risk_threshold': 'medium',
                'mandatory': True
            },
            ComplianceFramework.FDA_SAMD.value: {
                'required_controls': [
                    'model_validation', 'clinical_evaluation', 'risk_management',
                    'quality_assurance', 'version_control', 'documentation'
                ],
                'data_handling': ['clinical_data_validation', 'adverse_event_reporting'],
                'risk_threshold': 'high',
                'mandatory': True
            },
            ComplianceFramework.GDPR.value: {
                'required_controls': [
                    'consent_management', 'data_minimization', 'right_to_erasure',
                    'data_portability', 'privacy_by_design', 'breach_notification'
                ],
                'data_handling': ['anonymization', 'pseudonymization', 'consent_tracking'],
                'risk_threshold': 'medium',
                'mandatory': True
            },
            ComplianceFramework.SOC2_TYPE_II.value: {
                'required_controls': [
                    'access_control', 'system_monitoring', 'change_management',
                    'availability', 'processing_integrity', 'confidentiality'
                ],
                'data_handling': ['data_classification', 'backup_recovery'],
                'risk_threshold': 'low',
                'mandatory': False
            },
            ComplianceFramework.HITRUST_CSF.value: {
                'required_controls': [
                    'information_security_governance', 'endpoint_protection',
                    'portable_media_security', 'mobile_device_security',
                    'wireless_access_management', 'network_protection'
                ],
                'data_handling': ['phi_protection', 'secure_communications'],
                'risk_threshold': 'high',
                'mandatory': True
            },
            ComplianceFramework.NIST_AI_RMF.value: {
                'required_controls': [
                    'ai_governance_structure', 'risk_assessment_ai', 'bias_testing',
                    'model_documentation', 'performance_monitoring', 'human_oversight',
                    'explainability_requirements', 'ai_system_validation'
                ],
                'data_handling': ['training_data_governance', 'model_lineage', 'bias_mitigation'],
                'risk_threshold': 'high',
                'mandatory': True,
                'genai_specific': [
                    'prompt_injection_protection', 'content_filtering', 'safety_alignment',
                    'hallucination_detection', 'output_monitoring', 'responsible_disclosure'
                ],
                'agentic_specific': [
                    'autonomy_limits', 'goal_alignment_verification', 'tool_access_controls',
                    'action_logging', 'override_mechanisms', 'resource_limits'
                ]
            },
            ComplianceFramework.OWASP_AI.value: {
                'required_controls': [
                    'prompt_injection_defense', 'training_data_poisoning_protection',
                    'model_dos_prevention', 'model_theft_protection', 'supply_chain_vulnerabilities',
                    'output_handling_controls', 'ai_system_monitoring', 'plugin_validation'
                ],
                'data_handling': ['secure_model_storage', 'input_validation', 'output_sanitization'],
                'risk_threshold': 'high',
                'mandatory': True,
                'genai_specific': [
                    'prompt_firewall', 'output_content_scanning', 'model_endpoint_security',
                    'inference_monitoring', 'api_rate_limiting'
                ],
                'agentic_specific': [
                    'tool_sandbox_execution', 'action_authorization', 'capability_restrictions',
                    'memory_isolation', 'external_api_validation'
                ]
            },
            ComplianceFramework.MITRE_ATLAS.value: {
                'required_controls': [
                    'adversarial_robustness_testing', 'model_evasion_protection',
                    'data_integrity_verification', 'model_backdoor_detection',
                    'inference_attack_prevention', 'membership_inference_protection'
                ],
                'data_handling': ['differential_privacy', 'federated_learning_security'],
                'risk_threshold': 'critical',
                'mandatory': True,
                'genai_specific': [
                    'adversarial_prompt_detection', 'model_extraction_prevention',
                    'watermarking_implementation', 'synthetic_data_labeling'
                ],
                'agentic_specific': [
                    'behavioral_anomaly_detection', 'goal_manipulation_prevention',
                    'reward_hacking_detection', 'agent_communication_security'
                ]
            },
            ComplianceFramework.SAIF_GOOGLE.value: {
                'required_controls': [
                    'secure_ai_development', 'secure_ai_deployment', 'secure_ai_usage',
                    'ai_risk_management', 'ai_incident_response', 'ai_supply_chain_security'
                ],
                'data_handling': ['privacy_preserving_ml', 'federated_analytics'],
                'risk_threshold': 'high',
                'mandatory': True,
                'genai_specific': [
                    'responsible_ai_practices', 'content_authenticity', 'safety_evaluations',
                    'red_team_testing', 'alignment_verification'
                ],
                'agentic_specific': [
                    'agent_safety_measures', 'containment_protocols', 'escalation_prevention',
                    'human_in_the_loop', 'shutdown_procedures'
                ]
            }
        }
    
    def classify_agent(self, agent_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an AI agent based on its functionality and metadata
        Enhanced with GenAI and Agentic AI detection
        
        Args:
            agent_data: Dictionary containing agent information (name, type, protocol, metadata, etc.)
            
        Returns:
            Dictionary with classification results and applicable frameworks
        """
        classification_result = {
            'agent_id': agent_data.get('id'),
            'primary_classification': None,
            'secondary_classifications': [],
            'applicable_frameworks': [],
            'required_controls': [],
            'criticality_level': 'low',
            'confidence_score': 0.0,
            'classification_reasons': [],
            'data_types_detected': [],
            'protocols_analyzed': [],
            'ai_type': AIAgentType.TRADITIONAL_ML,
            'specific_risks': [],
            'genai_capabilities': [],
            'agentic_features': [],
            'classified_at': datetime.utcnow().isoformat(),
            # Enhanced classification analysis
            'work_engine_analysis': {},
            'data_source_analysis': {},
            'output_type_analysis': {},
            'department_usage_analysis': {},
            'functional_purpose': '',
            'business_impact': '',
            'integration_points': []
        }
        
        # Analyze agent characteristics
        agent_text = self._extract_text_for_analysis(agent_data)
        protocol = agent_data.get('protocol', '').lower()
        
        # Score each classification type with enhanced analysis
        classification_scores = {}
        
        for class_type, rules in self.classification_rules.items():
            score = self._calculate_classification_score(agent_text, protocol, rules, agent_data)
            if score > 0:
                classification_scores[class_type] = score
        
        # Determine primary and secondary classifications
        if classification_scores:
            sorted_scores = sorted(classification_scores.items(), key=lambda x: x[1], reverse=True)
            
            # Primary classification (highest score)
            primary_class, primary_score = sorted_scores[0]
            classification_result['primary_classification'] = primary_class
            classification_result['confidence_score'] = primary_score
            
            # Set AI type and specific features
            primary_rules = self.classification_rules[primary_class]
            if 'ai_type' in primary_rules:
                classification_result['ai_type'] = primary_rules['ai_type']
            
            if 'specific_risks' in primary_rules:
                classification_result['specific_risks'] = primary_rules['specific_risks']
            
            # Detect GenAI capabilities
            if primary_class == 'genai' or 'genai' in [s['type'] for s in classification_result.get('secondary_classifications', [])]:
                classification_result['genai_capabilities'] = self._detect_genai_capabilities(agent_data)
            
            # Detect Agentic AI features
            if primary_class == 'agentic_ai' or 'agentic_ai' in [s['type'] for s in classification_result.get('secondary_classifications', [])]:
                classification_result['agentic_features'] = self._detect_agentic_features(agent_data)
            
            # Secondary classifications (score > threshold)
            secondary_threshold = 0.3
            for class_type, score in sorted_scores[1:]:
                if score > secondary_threshold:
                    classification_result['secondary_classifications'].append({
                        'type': class_type,
                        'score': score
                    })
            
            # Determine applicable frameworks
            frameworks = set()
            controls = set()
            max_criticality = 'low'
            
            # Add frameworks from primary classification
            primary_rules = self.classification_rules[primary_class]
            frameworks.update(primary_rules['frameworks'])
            max_criticality = primary_rules['criticality']
            
            # Add frameworks from secondary classifications
            for secondary in classification_result['secondary_classifications']:
                secondary_rules = self.classification_rules[secondary['type']]
                frameworks.update(secondary_rules['frameworks'])
                if self._criticality_priority(secondary_rules['criticality']) > self._criticality_priority(max_criticality):
                    max_criticality = secondary_rules['criticality']
            
            # Collect required controls
            for framework in frameworks:
                framework_key = framework.value if hasattr(framework, 'value') else str(framework)
                if framework_key in self.framework_mappings:
                    controls.update(self.framework_mappings[framework_key]['required_controls'])
                    
                    # Add specialized controls based on AI type
                    framework_mapping = self.framework_mappings[framework_key]
                    if classification_result['ai_type'] == AIAgentType.GENAI and 'genai_specific' in framework_mapping:
                        controls.update(framework_mapping['genai_specific'])
                    elif classification_result['ai_type'] == AIAgentType.AGENTIC_AI and 'agentic_specific' in framework_mapping:
                        controls.update(framework_mapping['agentic_specific'])
            
            classification_result['applicable_frameworks'] = [f.value for f in frameworks]
            classification_result['required_controls'] = list(controls)
            classification_result['criticality_level'] = max_criticality
            
            # Enhanced analysis for primary classification
            primary_rules = self.classification_rules[primary_class]
            classification_result['work_engine_analysis'] = self._detailed_work_engine_analysis(
                agent_text, agent_data, primary_rules.get('work_engines', {})
            )
            classification_result['data_source_analysis'] = self._detailed_data_source_analysis(
                agent_text, agent_data, primary_rules.get('data_sources', {})
            )
            classification_result['output_type_analysis'] = self._detailed_output_analysis(
                agent_text, agent_data, primary_rules.get('output_types', {})
            )
            classification_result['department_usage_analysis'] = self._detailed_department_analysis(
                agent_text, agent_data, primary_rules.get('department_usage', {})
            )
            
            # Generate enhanced reasoning
            classification_result['classification_reasons'] = self._generate_enhanced_reasoning(
                agent_data, primary_class, primary_rules, classification_scores, classification_result
            )
            
            # Determine functional purpose and business impact
            classification_result['functional_purpose'] = self._determine_functional_purpose(
                classification_result, primary_class
            )
            classification_result['business_impact'] = self._assess_business_impact(
                classification_result, primary_class
            )
        
        return classification_result
    
    def _extract_text_for_analysis(self, agent_data: Dict[str, Any]) -> str:
        """Extract relevant text from agent data for analysis"""
        text_parts = []
        
        # Basic fields
        for field in ['name', 'type', 'endpoint']:
            if field in agent_data and agent_data[field]:
                text_parts.append(str(agent_data[field]))
        
        # Metadata
        if 'agent_metadata' in agent_data and agent_data['agent_metadata']:
            metadata = agent_data['agent_metadata']
            if isinstance(metadata, dict):
                # Extract values from metadata
                for key, value in metadata.items():
                    text_parts.append(f"{key}: {value}")
            else:
                text_parts.append(str(metadata))
        
        # Cloud provider and region
        if 'cloud_provider' in agent_data:
            text_parts.append(agent_data['cloud_provider'])
        if 'region' in agent_data:
            text_parts.append(agent_data['region'])
        
        return ' '.join(text_parts).lower()
    
    def _calculate_classification_score(self, agent_text: str, protocol: str, rules: Dict, agent_data: Dict = None) -> float:
        """Enhanced classification score calculation with work engine, data source, output, and department analysis"""
        score = 0.0
        
        # Basic keyword matching (reduced weight to make room for new factors)
        keyword_matches = 0
        for keyword in rules['keywords']:
            if keyword.lower() in agent_text:
                keyword_matches += 1
        
        if rules['keywords']:
            keyword_score = (keyword_matches / len(rules['keywords'])) * 0.35  # Reduced from 0.7
            score += keyword_score
        
        # Work engine analysis (new - 25% weight)
        work_engine_score = self._analyze_work_engines(agent_text, agent_data, rules.get('work_engines', {}))
        score += work_engine_score * 0.25
        
        # Data source analysis (new - 15% weight)
        data_source_score = self._analyze_data_sources(agent_text, agent_data, rules.get('data_sources', {}))
        score += data_source_score * 0.15
        
        # Output type analysis (new - 15% weight)
        output_score = self._analyze_output_types(agent_text, agent_data, rules.get('output_types', {}))
        score += output_score * 0.15
        
        # Department usage analysis (new - 10% weight)
        department_score = self._analyze_department_usage(agent_text, agent_data, rules.get('department_usage', {}))
        score += department_score * 0.10
        
        # Protocol matching (reduced weight)
        if protocol in rules.get('protocols', []):
            score += 0.05  # Reduced from 0.2
        
        # Data type inference (legacy - reduced weight)
        data_type_keywords = rules.get('data_types', [])
        for data_type in data_type_keywords:
            if data_type.lower() in agent_text:
                score += 0.05  # Reduced from 0.1
                break
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _analyze_work_engines(self, agent_text: str, agent_data: Dict, work_engines: Dict) -> float:
        """Analyze what specific work the AI engine is performing"""
        if not work_engines:
            return 0.0
            
        total_engines = 0
        matches = 0
        
        for engine_category, engine_types in work_engines.items():
            total_engines += len(engine_types)
            for engine_type in engine_types:
                # Check in agent text and metadata
                if engine_type.lower().replace('_', ' ') in agent_text:
                    matches += 1
                    continue
                    
                # Check in specific metadata fields that indicate functionality
                if agent_data and 'agent_metadata' in agent_data:
                    metadata = agent_data['agent_metadata']
                    if isinstance(metadata, dict):
                        # Check environment variables for work indicators
                        env = metadata.get('environment', {})
                        if isinstance(env, dict):
                            for key, value in env.items():
                                if engine_type.lower() in str(value).lower() or engine_type.lower() in key.lower():
                                    matches += 1
                                    break
                        
                        # Check labels for work indicators
                        labels = metadata.get('labels', {})
                        if isinstance(labels, dict):
                            for key, value in labels.items():
                                if engine_type.lower() in str(value).lower() or engine_type.lower() in key.lower():
                                    matches += 1
                                    break
        
        return matches / total_engines if total_engines > 0 else 0.0
    
    def _analyze_data_sources(self, agent_text: str, agent_data: Dict, data_sources: Dict) -> float:
        """Analyze what data sources the AI is connecting to"""
        if not data_sources:
            return 0.0
            
        total_sources = 0
        matches = 0
        
        for source_category, source_types in data_sources.items():
            total_sources += len(source_types)
            for source_type in source_types:
                # Check in agent text
                if source_type.lower().replace('_', ' ') in agent_text:
                    matches += 1
                    continue
                    
                # Check endpoint for data source indicators
                if agent_data and 'endpoint' in agent_data:
                    endpoint = str(agent_data['endpoint']).lower()
                    if source_type.lower() in endpoint:
                        matches += 1
                        continue
                        
                # Check metadata for data connection indicators
                if agent_data and 'agent_metadata' in agent_data:
                    metadata = agent_data['agent_metadata']
                    if isinstance(metadata, dict):
                        # Check environment variables for data source connections
                        env = metadata.get('environment', {})
                        if isinstance(env, dict):
                            for key, value in env.items():
                                if ('database' in key.lower() or 'data' in key.lower() or 'source' in key.lower()):
                                    if source_type.lower() in str(value).lower():
                                        matches += 1
                                        break
        
        return matches / total_sources if total_sources > 0 else 0.0
    
    def _analyze_output_types(self, agent_text: str, agent_data: Dict, output_types: Dict) -> float:
        """Analyze what types of outputs the AI is providing"""
        if not output_types:
            return 0.0
            
        total_outputs = 0
        matches = 0
        
        for output_category, output_list in output_types.items():
            total_outputs += len(output_list)
            for output_type in output_list:
                # Check in agent text
                if output_type.lower().replace('_', ' ') in agent_text:
                    matches += 1
                    continue
                    
                # Check in agent name/type for output indicators
                if agent_data:
                    agent_name = str(agent_data.get('name', '')).lower()
                    agent_type = str(agent_data.get('type', '')).lower()
                    
                    if output_type.lower() in agent_name or output_type.lower() in agent_type:
                        matches += 1
                        continue
                        
                # Check metadata for output type indicators
                if agent_data and 'agent_metadata' in agent_data:
                    metadata = agent_data['agent_metadata']
                    if isinstance(metadata, dict):
                        # Check annotations for output descriptions
                        annotations = metadata.get('annotations', {})
                        if isinstance(annotations, dict):
                            for key, value in annotations.items():
                                if 'output' in key.lower() or 'result' in key.lower():
                                    if output_type.lower() in str(value).lower():
                                        matches += 1
                                        break
        
        return matches / total_outputs if total_outputs > 0 else 0.0
    
    def _analyze_department_usage(self, agent_text: str, agent_data: Dict, department_usage: Dict) -> float:
        """Analyze which departments are using the AI system"""
        if not department_usage:
            return 0.0
            
        total_departments = 0
        matches = 0
        
        for dept_category, dept_list in department_usage.items():
            total_departments += len(dept_list)
            for department in dept_list:
                # Check in agent text
                if department.lower().replace('_', ' ') in agent_text:
                    matches += 1
                    continue
                    
                # Check namespace/region for department indicators (common in K8s)
                if agent_data:
                    namespace = str(agent_data.get('region', '')).lower()
                    if department.lower() in namespace:
                        matches += 1
                        continue
                        
                # Check metadata for department/organizational indicators
                if agent_data and 'agent_metadata' in agent_data:
                    metadata = agent_data['agent_metadata']
                    if isinstance(metadata, dict):
                        # Check namespace field
                        k8s_namespace = metadata.get('namespace', '')
                        if isinstance(k8s_namespace, str) and department.lower() in k8s_namespace.lower():
                            matches += 1
                            continue
                            
                        # Check labels for organizational indicators
                        labels = metadata.get('labels', {})
                        if isinstance(labels, dict):
                            for key, value in labels.items():
                                if ('team' in key.lower() or 'dept' in key.lower() or 'org' in key.lower()):
                                    if department.lower() in str(value).lower():
                                        matches += 1
                                        break
        
        return matches / total_departments if total_departments > 0 else 0.0
    
    def _criticality_priority(self, criticality: str) -> int:
        """Convert criticality to priority number for comparison"""
        priorities = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return priorities.get(criticality, 1)
    
    def _generate_reasoning(self, agent_data: Dict, primary_class: str, 
                          primary_rules: Dict, all_scores: Dict) -> List[str]:
        """Generate human-readable reasoning for classification"""
        reasons = []
        
        reasons.append(f"Primary classification: {primary_class.replace('_', ' ').title()}")
        reasons.append(f"Confidence: {all_scores[primary_class]:.2f}")
        reasons.append(f"Criticality: {primary_rules['criticality']}")
        
        # Keyword matches
        agent_text = self._extract_text_for_analysis(agent_data)
        matching_keywords = [kw for kw in primary_rules['keywords'] if kw.lower() in agent_text]
        if matching_keywords:
            reasons.append(f"Matched keywords: {', '.join(matching_keywords[:5])}")
        
        # Protocol match
        protocol = agent_data.get('protocol', '').lower()
        if protocol in primary_rules.get('protocols', []):
            reasons.append(f"Protocol match: {protocol}")
        
        return reasons
    
    def _detailed_work_engine_analysis(self, agent_text: str, agent_data: Dict, work_engines: Dict) -> Dict:
        """Detailed analysis of work engine matches"""
        analysis = {'matched_engines': [], 'engine_confidence': 0.0, 'primary_function': ''}
        
        for engine_category, engine_types in work_engines.items():
            for engine_type in engine_types:
                if (engine_type.lower().replace('_', ' ') in agent_text or 
                    self._check_metadata_for_pattern(agent_data, engine_type)):
                    analysis['matched_engines'].append({
                        'category': engine_category,
                        'type': engine_type,
                        'confidence': 0.8
                    })
        
        if analysis['matched_engines']:
            analysis['engine_confidence'] = len(analysis['matched_engines']) / sum(len(engines) for engines in work_engines.values())
            analysis['primary_function'] = analysis['matched_engines'][0]['category']
        
        return analysis
    
    def _detailed_data_source_analysis(self, agent_text: str, agent_data: Dict, data_sources: Dict) -> Dict:
        """Detailed analysis of data source connections"""
        analysis = {'connected_sources': [], 'source_types': [], 'data_flow_direction': 'bidirectional'}
        
        for source_category, source_types in data_sources.items():
            for source_type in source_types:
                if (source_type.lower().replace('_', ' ') in agent_text or 
                    self._check_endpoint_for_pattern(agent_data, source_type)):
                    analysis['connected_sources'].append({
                        'category': source_category,
                        'type': source_type,
                        'access_level': 'read_write'
                    })
                    if source_category not in analysis['source_types']:
                        analysis['source_types'].append(source_category)
        
        return analysis
    
    def _detailed_output_analysis(self, agent_text: str, agent_data: Dict, output_types: Dict) -> Dict:
        """Detailed analysis of output types"""
        analysis = {'output_formats': [], 'delivery_methods': [], 'target_consumers': []}
        
        for output_category, output_list in output_types.items():
            for output_type in output_list:
                if (output_type.lower().replace('_', ' ') in agent_text or 
                    self._check_metadata_for_pattern(agent_data, output_type)):
                    analysis['output_formats'].append({
                        'category': output_category,
                        'type': output_type,
                        'format': 'structured_data'
                    })
        
        return analysis
    
    def _detailed_department_analysis(self, agent_text: str, agent_data: Dict, department_usage: Dict) -> Dict:
        """Detailed analysis of department usage"""
        analysis = {'using_departments': [], 'primary_stakeholder': '', 'access_patterns': []}
        
        for dept_category, dept_list in department_usage.items():
            for department in dept_list:
                if (department.lower().replace('_', ' ') in agent_text or 
                    self._check_namespace_for_pattern(agent_data, department)):
                    analysis['using_departments'].append({
                        'category': dept_category,
                        'department': department,
                        'usage_level': 'active'
                    })
        
        if analysis['using_departments']:
            analysis['primary_stakeholder'] = analysis['using_departments'][0]['category']
        
        return analysis
    
    def _check_metadata_for_pattern(self, agent_data: Dict, pattern: str) -> bool:
        """Check agent metadata for specific patterns"""
        if not agent_data or 'agent_metadata' not in agent_data:
            return False
            
        metadata = agent_data['agent_metadata']
        if isinstance(metadata, dict):
            env = metadata.get('environment', {})
            labels = metadata.get('labels', {})
            
            # Check environment variables
            if isinstance(env, dict):
                for key, value in env.items():
                    if pattern.lower() in str(value).lower() or pattern.lower() in key.lower():
                        return True
                        
            # Check labels
            if isinstance(labels, dict):
                for key, value in labels.items():
                    if pattern.lower() in str(value).lower() or pattern.lower() in key.lower():
                        return True
        
        return False
    
    def _check_endpoint_for_pattern(self, agent_data: Dict, pattern: str) -> bool:
        """Check agent endpoint for specific patterns"""
        if not agent_data or 'endpoint' not in agent_data:
            return False
        
        endpoint = str(agent_data['endpoint']).lower()
        return pattern.lower() in endpoint
    
    def _check_namespace_for_pattern(self, agent_data: Dict, pattern: str) -> bool:
        """Check namespace/region for organizational patterns"""
        if not agent_data:
            return False
            
        # Check region field
        region = str(agent_data.get('region', '')).lower()
        if pattern.lower() in region:
            return True
            
        # Check metadata namespace
        if 'agent_metadata' in agent_data:
            metadata = agent_data['agent_metadata']
            if isinstance(metadata, dict):
                namespace = metadata.get('namespace', '')
                if isinstance(namespace, str) and pattern.lower() in namespace.lower():
                    return True
        
        return False
    
    def _generate_enhanced_reasoning(self, agent_data: Dict, primary_class: str, 
                                   primary_rules: Dict, all_scores: Dict, analysis_result: Dict) -> List[str]:
        """Generate enhanced human-readable reasoning for classification"""
        reasons = []
        
        reasons.append(f"Primary classification: {primary_class.replace('_', ' ').title()}")
        reasons.append(f"Overall confidence: {all_scores[primary_class]:.2f}")
        reasons.append(f"Criticality level: {primary_rules['criticality']}")
        
        # Work engine analysis
        work_analysis = analysis_result.get('work_engine_analysis', {})
        if work_analysis.get('matched_engines'):
            engines = [e['type'] for e in work_analysis['matched_engines'][:3]]
            reasons.append(f"Work engines detected: {', '.join(engines)}")
            if work_analysis.get('primary_function'):
                reasons.append(f"Primary function: {work_analysis['primary_function'].replace('_', ' ')}")
        
        # Data source analysis
        data_analysis = analysis_result.get('data_source_analysis', {})
        if data_analysis.get('source_types'):
            reasons.append(f"Data sources: {', '.join(data_analysis['source_types'])}")
        
        # Department usage
        dept_analysis = analysis_result.get('department_usage_analysis', {})
        if dept_analysis.get('primary_stakeholder'):
            reasons.append(f"Primary stakeholder: {dept_analysis['primary_stakeholder'].replace('_', ' ')}")
        
        # Traditional keyword matches
        agent_text = self._extract_text_for_analysis(agent_data)
        matching_keywords = [kw for kw in primary_rules['keywords'] if kw.lower() in agent_text]
        if matching_keywords:
            reasons.append(f"Key indicators: {', '.join(matching_keywords[:5])}")
        
        return reasons
    
    def _determine_functional_purpose(self, classification_result: Dict, primary_class: str) -> str:
        """Determine the functional purpose of the AI system"""
        work_analysis = classification_result.get('work_engine_analysis', {})
        
        if work_analysis.get('primary_function'):
            function = work_analysis['primary_function'].replace('_', ' ').title()
            return f"AI system primarily focused on {function}"
        
        return f"{primary_class.replace('_', ' ').title()} system with general purpose functionality"
    
    def _assess_business_impact(self, classification_result: Dict, primary_class: str) -> str:
        """Assess the business impact of the AI system"""
        criticality = classification_result.get('criticality_level', 'low')
        dept_analysis = classification_result.get('department_usage_analysis', {})
        
        impact_levels = {
            'critical': 'Mission-critical system with enterprise-wide impact',
            'high': 'High-impact system affecting core business operations',
            'medium': 'Moderate impact on departmental operations',
            'low': 'Limited impact on specific workflows'
        }
        
        base_impact = impact_levels.get(criticality, 'Limited impact')
        
        if dept_analysis.get('using_departments'):
            dept_count = len(dept_analysis['using_departments'])
            if dept_count > 3:
                return base_impact + ' across multiple departments'
            elif dept_count > 1:
                return base_impact + ' affecting multiple teams'
        
        return base_impact
    
    def generate_agent_playbook(self, classification_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate automatic registration playbook based on classification"""
        frameworks = classification_result['applicable_frameworks']
        controls = classification_result['required_controls']
        criticality = classification_result['criticality_level']
        
        playbook_config = {
            'name': f"Auto-Generated {classification_result['primary_classification'].replace('_', ' ').title()} Playbook",
            'description': f"Automated registration for {classification_result['primary_classification']} agents",
            'trigger_conditions': {
                'agent_types': [classification_result['primary_classification']],
                'protocols': self._get_protocols_for_class(classification_result['primary_classification']),
                'automatic': True
            },
            'onboarding_steps': self._generate_onboarding_steps(controls, frameworks, criticality),
            'compliance_requirements': frameworks,
            'validation_rules': self._generate_validation_rules(controls),
            'notification_config': self._generate_notification_config(criticality),
            'auto_onboarding_enabled': True
        }
        
        return playbook_config
    
    def _get_protocols_for_class(self, class_type: str) -> List[str]:
        """Get protocols associated with a classification type"""
        if class_type in self.classification_rules:
            return self.classification_rules[class_type].get('protocols', [])
        return []
    
    def _generate_onboarding_steps(self, controls: List[str], frameworks: List[str], criticality: str) -> List[Dict]:
        """Generate onboarding steps based on required controls"""
        steps = [
            {
                'step': 'security_scan',
                'description': 'Perform comprehensive security assessment',
                'required': True,
                'timeout': 300
            },
            {
                'step': 'compliance_evaluation',
                'description': f'Evaluate compliance against {", ".join(frameworks)}',
                'required': True,
                'timeout': 180
            }
        ]
        
        # Add control-specific steps
        if 'encryption_at_rest' in controls:
            steps.append({
                'step': 'encryption_validation',
                'description': 'Verify encryption at rest implementation',
                'required': True,
                'timeout': 60
            })
        
        if 'access_control' in controls:
            steps.append({
                'step': 'access_control_setup',
                'description': 'Configure role-based access controls',
                'required': True,
                'timeout': 120
            })
        
        if 'phi_protection' in controls:
            steps.append({
                'step': 'phi_detection_scan',
                'description': 'Scan for PHI exposure and implement protection',
                'required': True,
                'timeout': 240
            })
        
        # High criticality agents need approval
        if criticality in ['high', 'critical']:
            steps.append({
                'step': 'manual_approval',
                'description': 'Require security team approval for high-criticality agent',
                'required': True,
                'timeout': 86400  # 24 hours
            })
        
        return steps
    
    def _generate_validation_rules(self, controls: List[str]) -> List[Dict]:
        """Generate validation rules based on required controls"""
        rules = [
            {
                'rule': 'endpoint_accessibility',
                'description': 'Verify agent endpoint is accessible',
                'type': 'connectivity'
            },
            {
                'rule': 'metadata_completeness',
                'description': 'Ensure required metadata fields are present',
                'type': 'data_quality'
            }
        ]
        
        if 'encryption_at_rest' in controls:
            rules.append({
                'rule': 'encryption_check',
                'description': 'Verify encryption is properly configured',
                'type': 'security'
            })
        
        if 'authentication' in controls:
            rules.append({
                'rule': 'auth_mechanism',
                'description': 'Validate authentication mechanism is in place',
                'type': 'security'
            })
        
        return rules
    
    def _generate_notification_config(self, criticality: str) -> Dict[str, Any]:
        """Generate notification configuration based on criticality"""
        config = {
            'channels': ['email'],
            'events': ['registration_complete', 'security_scan_complete'],
            'recipients': ['security-team@company.com']
        }
        
        if criticality in ['high', 'critical']:
            config['events'].extend(['high_risk_detected', 'compliance_violation'])
            config['recipients'].append('compliance-team@company.com')
            config['immediate_notify'] = True
        
        return config
    
    def _detect_genai_capabilities(self, agent_data: Dict[str, Any]) -> List[str]:
        """Detect specific GenAI capabilities from agent metadata"""
        capabilities = []
        agent_text = self._extract_text_for_analysis(agent_data).lower()
        
        # Text generation capabilities
        text_generation_keywords = [
            'text-generation', 'completion', 'chat', 'conversation', 'dialogue',
            'summarization', 'translation', 'paraphrasing', 'writing'
        ]
        if any(keyword in agent_text for keyword in text_generation_keywords):
            capabilities.append('text_generation')
        
        # Code generation capabilities
        code_keywords = [
            'code', 'programming', 'coding', 'github', 'copilot', 'codex',
            'development', 'software', 'script', 'function'
        ]
        if any(keyword in agent_text for keyword in code_keywords):
            capabilities.append('code_generation')
        
        # Image generation capabilities
        image_keywords = [
            'image', 'picture', 'visual', 'art', 'drawing', 'design',
            'dalle', 'midjourney', 'stable-diffusion', 'imagen'
        ]
        if any(keyword in agent_text for keyword in image_keywords):
            capabilities.append('image_generation')
        
        # Multimodal capabilities
        multimodal_keywords = [
            'multimodal', 'vision', 'audio', 'video', 'speech',
            'cross-modal', 'text-to-image', 'image-to-text'
        ]
        if any(keyword in agent_text for keyword in multimodal_keywords):
            capabilities.append('multimodal')
        
        # Fine-tuning capabilities
        if 'fine-tune' in agent_text or 'fine-tuning' in agent_text or 'custom' in agent_text:
            capabilities.append('fine_tuning')
        
        # Embedding capabilities
        if 'embedding' in agent_text or 'vector' in agent_text or 'similarity' in agent_text:
            capabilities.append('embeddings')
        
        return capabilities
    
    def _detect_agentic_features(self, agent_data: Dict[str, Any]) -> List[str]:
        """Detect specific Agentic AI features from agent metadata"""
        features = []
        agent_text = self._extract_text_for_analysis(agent_data).lower()
        
        # Planning capabilities
        planning_keywords = [
            'planning', 'plan', 'strategy', 'goal', 'objective',
            'task-planning', 'multi-step', 'workflow'
        ]
        if any(keyword in agent_text for keyword in planning_keywords):
            features.append('planning')
        
        # Reasoning capabilities
        reasoning_keywords = [
            'reasoning', 'logic', 'inference', 'deduction',
            'problem-solving', 'analysis', 'decision'
        ]
        if any(keyword in agent_text for keyword in reasoning_keywords):
            features.append('reasoning')
        
        # Tool usage capabilities
        tool_keywords = [
            'tool', 'api', 'function', 'plugin', 'extension',
            'external', 'integration', 'service', 'browser'
        ]
        if any(keyword in agent_text for keyword in tool_keywords):
            features.append('tool_usage')
        
        # Memory capabilities
        memory_keywords = [
            'memory', 'context', 'history', 'recall', 'remember',
            'persistent', 'storage', 'knowledge'
        ]
        if any(keyword in agent_text for keyword in memory_keywords):
            features.append('memory')
        
        # Autonomous execution
        autonomous_keywords = [
            'autonomous', 'automatic', 'self', 'independent',
            'unsupervised', 'auto', 'continuous'
        ]
        if any(keyword in agent_text for keyword in autonomous_keywords):
            features.append('autonomy')
        
        # Multi-agent collaboration
        multiagent_keywords = [
            'multi-agent', 'swarm', 'collaboration', 'team',
            'coordination', 'communication', 'collective'
        ]
        if any(keyword in agent_text for keyword in multiagent_keywords):
            features.append('multi_agent')
        
        # Learning and adaptation
        learning_keywords = [
            'learning', 'adaptation', 'improvement', 'evolution',
            'feedback', 'reinforcement', 'self-improvement'
        ]
        if any(keyword in agent_text for keyword in learning_keywords):
            features.append('learning')
        
        return features
    
    def assess_genai_risks(self, agent_data: Dict[str, Any], capabilities: List[str]) -> Dict[str, Any]:
        """Assess specific risks for GenAI systems"""
        risk_assessment = {
            'hallucination_risk': 'medium',
            'bias_risk': 'medium',
            'misinformation_risk': 'medium',
            'privacy_risk': 'medium',
            'safety_risk': 'low',
            'mitigation_recommendations': []
        }
        
        # Higher risks for text generation
        if 'text_generation' in capabilities:
            risk_assessment['hallucination_risk'] = 'high'
            risk_assessment['misinformation_risk'] = 'high'
            risk_assessment['mitigation_recommendations'].extend([
                'implement_hallucination_detection',
                'add_fact_checking_layer',
                'require_source_citation'
            ])
        
        # Higher risks for multimodal systems
        if 'multimodal' in capabilities or 'image_generation' in capabilities:
            risk_assessment['privacy_risk'] = 'high'
            risk_assessment['safety_risk'] = 'medium'
            risk_assessment['mitigation_recommendations'].extend([
                'content_moderation',
                'deepfake_detection',
                'privacy_filter'
            ])
        
        # Code generation specific risks
        if 'code_generation' in capabilities:
            risk_assessment['safety_risk'] = 'high'
            risk_assessment['mitigation_recommendations'].extend([
                'code_security_scanning',
                'execution_sandboxing',
                'vulnerability_detection'
            ])
        
        return risk_assessment
    
    def assess_agentic_risks(self, agent_data: Dict[str, Any], features: List[str]) -> Dict[str, Any]:
        """Assess specific risks for Agentic AI systems"""
        risk_assessment = {
            'autonomy_risk': 'medium',
            'goal_misalignment_risk': 'medium',
            'resource_consumption_risk': 'low',
            'unauthorized_action_risk': 'medium',
            'escalation_risk': 'low',
            'mitigation_recommendations': []
        }
        
        # Higher risks for autonomous systems
        if 'autonomy' in features:
            risk_assessment['autonomy_risk'] = 'critical'
            risk_assessment['goal_misalignment_risk'] = 'high'
            risk_assessment['mitigation_recommendations'].extend([
                'human_oversight_required',
                'action_approval_gates',
                'emergency_shutdown'
            ])
        
        # Tool usage risks
        if 'tool_usage' in features:
            risk_assessment['unauthorized_action_risk'] = 'high'
            risk_assessment['escalation_risk'] = 'high'
            risk_assessment['mitigation_recommendations'].extend([
                'tool_access_controls',
                'permission_validation',
                'action_logging'
            ])
        
        # Planning and reasoning risks
        if 'planning' in features and 'reasoning' in features:
            risk_assessment['goal_misalignment_risk'] = 'high'
            risk_assessment['mitigation_recommendations'].extend([
                'goal_verification',
                'plan_validation',
                'intermediate_checkpoints'
            ])
        
        # Multi-agent collaboration risks
        if 'multi_agent' in features:
            risk_assessment['resource_consumption_risk'] = 'high'
            risk_assessment['mitigation_recommendations'].extend([
                'resource_limits',
                'coordination_monitoring',
                'conflict_resolution'
            ])
        
        return risk_assessment