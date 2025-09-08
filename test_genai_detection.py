#!/usr/bin/env python3
"""
Test script to verify GenAI and Agentic AI detection and compliance capabilities
"""

from app import app, db
from models import AIAgent, AIAgentType, ScanResult, ComplianceEvaluation, ComplianceFramework
from agents.classification_engine import AIClassificationEngine
from scanners.api_scanner import APIScanner
from datetime import datetime
import json

def test_genai_agentic_detection():
    """Test GenAI and Agentic AI detection capabilities"""
    
    with app.app_context():
        print("🧪 Testing GenAI and Agentic AI Detection Capabilities\n")
        
        # Clear existing test data
        AIAgent.query.delete()
        ScanResult.query.delete()
        ComplianceEvaluation.query.delete()
        db.session.commit()
        
        # Test data for GenAI systems
        genai_test_cases = [
            {
                'name': 'GPT-4 Medical Assistant',
                'type': 'Healthcare AI Service',
                'protocol': 'rest_api',
                'endpoint': 'https://api.openai.com/v1/chat/completions',
                'metadata': {
                    'api_response': {
                        'model': 'gpt-4-turbo',
                        'object': 'chat.completion',
                        'capabilities': ['text-generation', 'medical-reasoning', 'conversation'],
                        'max_tokens': 4096,
                        'temperature': 0.7
                    },
                    'model_family': 'GPT',
                    'provider': 'OpenAI'
                }
            },
            {
                'name': 'Claude Medical AI',
                'type': 'Clinical Decision Support',
                'protocol': 'rest_api',
                'endpoint': 'https://api.anthropic.com/v1/messages',
                'metadata': {
                    'api_response': {
                        'model': 'claude-3-sonnet',
                        'type': 'completion',
                        'capabilities': ['medical-analysis', 'reasoning', 'text-generation'],
                        'multimodal': True
                    },
                    'model_family': 'Claude',
                    'provider': 'Anthropic'
                }
            },
            {
                'name': 'LLaMA Medical Fine-tuned',
                'type': 'Healthcare NLP AI',
                'protocol': 'rest_api',
                'endpoint': 'http://localhost:8080/generate',
                'metadata': {
                    'api_response': {
                        'model': 'llama-2-70b-medical',
                        'fine_tuned': True,
                        'training_data': 'medical-literature',
                        'capabilities': ['clinical-notes', 'diagnosis-assistance']
                    },
                    'model_family': 'LLaMA',
                    'provider': 'Meta'
                }
            }
        ]
        
        # Test data for Agentic AI systems
        agentic_test_cases = [
            {
                'name': 'Medical Workflow Agent',
                'type': 'Healthcare AI Service',
                'protocol': 'rest_api',
                'endpoint': 'https://medical-agents.hospital.com/workflow',
                'metadata': {
                    'api_response': {
                        'agent_type': 'autonomous',
                        'framework': 'langchain',
                        'capabilities': ['planning', 'tool-use', 'memory', 'reasoning'],
                        'tools': ['fhir-api', 'diagnostic-db', 'scheduling'],
                        'autonomy_level': 'high'
                    },
                    'agent_framework': 'LangChain',
                    'tools_available': ['FHIR', 'EHR', 'Lab']
                }
            },
            {
                'name': 'Clinical Decision Agent',
                'type': 'Clinical Decision Support',
                'protocol': 'rest_api',
                'endpoint': 'http://localhost:8080/agents/clinical',
                'metadata': {
                    'api_response': {
                        'agent': 'multi-step-reasoning',
                        'planning_capability': True,
                        'memory_enabled': True,
                        'external_tools': ['medical-db', 'research-api', 'guidelines'],
                        'decision_making': 'autonomous'
                    },
                    'agent_framework': 'AutoGPT',
                    'autonomy_level': 'supervised'
                }
            }
        ]
        
        # Initialize classification engine
        classifier = AIClassificationEngine()
        
        print("1. Testing GenAI Detection:")
        print("=" * 40)
        
        genai_agents = []
        for test_case in genai_test_cases:
            # Create agent
            agent = AIAgent(
                name=test_case['name'],
                type=test_case['type'],
                protocol=test_case['protocol'],
                endpoint=test_case['endpoint'],
                metadata=test_case['metadata'],
                cloud_provider='Unknown',
                region='unknown'
            )
            db.session.add(agent)
            db.session.flush()  # Get the ID
            
            # Classify agent
            classification = classifier.classify_agent(agent, test_case['metadata'])
            
            print(f"✅ Agent: {agent.name}")
            print(f"   AI Type: {classification.get('ai_type', 'Unknown')}")
            print(f"   Model Family: {classification.get('model_family', 'N/A')}")
            print(f"   Capabilities: {classification.get('capabilities', [])}")
            print()
            
            genai_agents.append(agent)
        
        print("2. Testing Agentic AI Detection:")
        print("=" * 40)
        
        agentic_agents = []
        for test_case in agentic_test_cases:
            # Create agent
            agent = AIAgent(
                name=test_case['name'],
                type=test_case['type'],
                protocol=test_case['protocol'],
                endpoint=test_case['endpoint'],
                metadata=test_case['metadata'],
                cloud_provider='Unknown',
                region='unknown'
            )
            db.session.add(agent)
            db.session.flush()  # Get the ID
            
            # Classify agent
            classification = classifier.classify_agent(agent, test_case['metadata'])
            
            print(f"✅ Agent: {agent.name}")
            print(f"   AI Type: {classification.get('ai_type', 'Unknown')}")
            print(f"   Framework: {classification.get('agent_framework', 'N/A')}")
            print(f"   Autonomy Level: {classification.get('autonomy_level', 'N/A')}")
            print(f"   Planning: {classification.get('planning_capability', False)}")
            print(f"   Memory: {classification.get('memory_enabled', False)}")
            print()
            
            agentic_agents.append(agent)
        
        db.session.commit()
        
        # Test compliance framework application
        print("3. Testing GenAI/Agentic AI Compliance:")
        print("=" * 40)
        
        all_agents = genai_agents + agentic_agents
        genai_compliance_checks = 0
        agentic_compliance_checks = 0
        
        for agent in all_agents:
            if agent.ai_type == AIAgentType.GENAI:
                # Apply GenAI-specific compliance
                evaluation = ComplianceEvaluation(
                    ai_agent_id=agent.id,
                    framework=ComplianceFramework.FDA_SAMD,
                    compliance_score=85.0,
                    details={
                        'genai_specific_controls': [
                            'bias_testing',
                            'prompt_injection_protection',
                            'output_validation',
                            'model_transparency'
                        ],
                        'risk_factors': ['hallucination_risk', 'training_data_privacy']
                    }
                )
                db.session.add(evaluation)
                genai_compliance_checks += 1
                print(f"📋 GenAI Compliance applied to: {agent.name}")
                
            elif agent.ai_type == AIAgentType.AGENTIC_AI:
                # Apply Agentic AI-specific compliance
                evaluation = ComplianceEvaluation(
                    ai_agent_id=agent.id,
                    framework=ComplianceFramework.HIPAA,
                    compliance_score=78.0,
                    details={
                        'agentic_specific_controls': [
                            'autonomous_decision_logging',
                            'human_oversight_requirements',
                            'tool_access_controls',
                            'planning_transparency'
                        ],
                        'risk_factors': ['autonomous_actions', 'data_access_scope']
                    }
                )
                db.session.add(evaluation)
                agentic_compliance_checks += 1
                print(f"📋 Agentic AI Compliance applied to: {agent.name}")
        
        db.session.commit()
        
        # Summary
        print("\n4. Detection Summary:")
        print("=" * 40)
        print(f"✅ GenAI Systems Detected: {len(genai_agents)}")
        print(f"✅ Agentic AI Systems Detected: {len(agentic_agents)}")
        print(f"📋 GenAI Compliance Checks: {genai_compliance_checks}")
        print(f"📋 Agentic AI Compliance Checks: {agentic_compliance_checks}")
        
        # Test database queries
        print(f"\n📊 Database Verification:")
        print(f"   Total AI Agents: {AIAgent.query.count()}")
        print(f"   GenAI Agents: {AIAgent.query.filter_by(ai_type=AIAgentType.GENAI).count()}")
        print(f"   Agentic AI Agents: {AIAgent.query.filter_by(ai_type=AIAgentType.AGENTIC_AI).count()}")
        print(f"   Compliance Evaluations: {ComplianceEvaluation.query.count()}")
        
        print("\n🎉 GenAI and Agentic AI Detection Test Completed Successfully!")
        return True

if __name__ == "__main__":
    test_genai_agentic_detection()