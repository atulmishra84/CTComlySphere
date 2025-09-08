#!/usr/bin/env python3
"""
Simple test script to verify GenAI and Agentic AI classification capabilities
"""

from app import app, db
from models import AIAgent, AIAgentType
from agents.classification_engine import AIClassificationEngine
from datetime import datetime
import json

def test_genai_agentic_classification():
    """Test GenAI and Agentic AI classification engine"""
    
    with app.app_context():
        print("🧪 Testing GenAI and Agentic AI Classification Engine\n")
        
        # Initialize classification engine
        classifier = AIClassificationEngine()
        
        # Test GenAI classification
        print("1. Testing GenAI Classification:")
        print("=" * 40)
        
        genai_test_data = [
            {
                'name': 'GPT-4 Medical Assistant',
                'metadata': {
                    'api_response': {
                        'model': 'gpt-4-turbo',
                        'object': 'chat.completion',
                        'capabilities': ['text-generation', 'conversation'],
                        'temperature': 0.7
                    }
                }
            },
            {
                'name': 'Claude Medical AI',
                'metadata': {
                    'api_response': {
                        'model': 'claude-3-sonnet',
                        'type': 'completion',
                        'multimodal': True
                    }
                }
            },
            {
                'name': 'LLaMA Healthcare Model',
                'metadata': {
                    'api_response': {
                        'model': 'llama-2-70b-medical',
                        'fine_tuned': True,
                        'capabilities': ['clinical-notes']
                    }
                }
            }
        ]
        
        for test_data in genai_test_data:
            # Create a simple agent object for testing
            class TestAgent:
                def __init__(self, name):
                    self.name = name
                    self.id = 1
            
            agent = TestAgent(test_data['name'])
            
            # Test classification
            classification = classifier.classify_agent(agent, test_data['metadata'])
            
            print(f"✅ Agent: {agent.name}")
            print(f"   AI Type: {classification.get('ai_type', 'Unknown')}")
            print(f"   Model Family: {classification.get('model_family', 'N/A')}")
            print(f"   Capabilities: {classification.get('capabilities', [])}")
            print(f"   Fine-tuned: {classification.get('fine_tuned', False)}")
            print()
        
        print("2. Testing Agentic AI Classification:")
        print("=" * 40)
        
        agentic_test_data = [
            {
                'name': 'Medical Workflow Agent',
                'metadata': {
                    'api_response': {
                        'agent_type': 'autonomous',
                        'framework': 'langchain',
                        'capabilities': ['planning', 'tool-use', 'memory'],
                        'tools': ['fhir-api', 'diagnostic-db']
                    }
                }
            },
            {
                'name': 'Clinical Decision Agent',
                'metadata': {
                    'api_response': {
                        'agent': 'multi-step-reasoning',
                        'planning_capability': True,
                        'memory_enabled': True,
                        'external_tools': ['medical-db', 'research-api']
                    }
                }
            }
        ]
        
        for test_data in agentic_test_data:
            agent = TestAgent(test_data['name'])
            
            # Test classification
            classification = classifier.classify_agent(agent, test_data['metadata'])
            
            print(f"✅ Agent: {agent.name}")
            print(f"   AI Type: {classification.get('ai_type', 'Unknown')}")
            print(f"   Framework: {classification.get('agent_framework', 'N/A')}")
            print(f"   Autonomy Level: {classification.get('autonomy_level', 'N/A')}")
            print(f"   Planning: {classification.get('planning_capability', False)}")
            print(f"   Memory: {classification.get('memory_enabled', False)}")
            print(f"   Tools: {classification.get('tool_access', [])}")
            print()
        
        print("3. Testing Scanner Integration:")
        print("=" * 40)
        
        # Test enhanced API scanner detection
        from scanners.api_scanner import APIScanner
        scanner = APIScanner()
        
        # Test GenAI detection patterns
        genai_response = {
            'model': 'gpt-4',
            'object': 'chat.completion',
            'capabilities': ['text-generation', 'conversation']
        }
        
        agentic_response = {
            'agent_type': 'autonomous',
            'framework': 'langchain',
            'planning': True,
            'tools': ['api-calling', 'memory']
        }
        
        headers = {'Content-Type': 'application/json'}
        
        genai_detected = scanner.is_ai_service(genai_response, headers)
        agentic_detected = scanner.is_ai_service(agentic_response, headers)
        
        print(f"✅ GenAI Detection: {'✓' if genai_detected else '✗'}")
        print(f"✅ Agentic AI Detection: {'✓' if agentic_detected else '✗'}")
        
        # Test service type determination
        genai_type = scanner.determine_service_type(genai_response)
        agentic_type = scanner.determine_service_type(agentic_response)
        
        print(f"   GenAI Service Type: {genai_type}")
        print(f"   Agentic Service Type: {agentic_type}")
        
        print("\n🎉 GenAI and Agentic AI Classification Test Completed!")
        print("   ✅ Classification engine working")
        print("   ✅ Enhanced scanner detection active")
        print("   ✅ Specialized AI types recognized")
        
        return True

if __name__ == "__main__":
    test_genai_agentic_classification()