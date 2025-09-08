from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import requests
import json
import os
from urllib.parse import urlparse

class APIScanner(BaseScanner):
    """Scanner for REST API-based AI agents"""
    
    def __init__(self):
        super().__init__()
        self.timeout = int(os.getenv('API_SCAN_TIMEOUT', '30'))
        self.api_endpoints = os.getenv('API_ENDPOINTS', '').split(',') if os.getenv('API_ENDPOINTS') else []
    
    def scan(self):
        """Scan for REST API-based AI agents"""
        self.start_scan()
        
        try:
            agents = self.discover_agents()
            results = []
            
            for agent_data in agents:
                agent = self.create_or_update_agent(agent_data)
                scan_result = self.perform_security_scan(agent, agent_data)
                results.append(scan_result)
            
            duration = self.end_scan()
            return {
                'status': 'completed',
                'agents_found': len(agents),
                'scan_duration': duration,
                'results': results
            }
            
        except Exception as e:
            self.logger.error(f"API scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover AI agents through API endpoints with GenAI and Agentic AI detection"""
        agents = []
        
        # Common healthcare AI API patterns
        common_endpoints = [
            'http://localhost:8080/api/v1/',
            'http://localhost:8501/v1/models/',
            'http://localhost:5000/predict',
            'https://api.healthcare-ai.local/v2/',
        ]
        
        # GenAI specific endpoints
        genai_endpoints = [
            'http://localhost:8000/v1/completions',
            'http://localhost:8000/v1/chat/completions',
            'http://localhost:8000/v1/embeddings',
            'https://api.openai.com/v1/',
            'https://api.anthropic.com/v1/',
            'http://localhost:11434/api/',  # Ollama
            'http://localhost:8080/generate',
            'http://localhost:5000/chat'
        ]
        
        # Agentic AI endpoints
        agentic_endpoints = [
            'http://localhost:8080/agents/',
            'http://localhost:8000/agent/execute',
            'http://localhost:5000/workflow/',
            'http://localhost:8080/planning/',
            'http://localhost:8000/tools/',
            'https://api.langchain.com/v1/',
            'http://localhost:8080/memory/',
            'http://localhost:5000/reasoning/'
        ]
        
        # Add configured endpoints
        all_endpoints = common_endpoints + genai_endpoints + agentic_endpoints + self.api_endpoints
        
        for endpoint in all_endpoints:
            try:
                agent_data = self.probe_endpoint(endpoint)
                if agent_data:
                    agents.append(agent_data)
            except Exception as e:
                self.logger.debug(f"Failed to probe {endpoint}: {str(e)}")
        
        return agents
    
    def probe_endpoint(self, endpoint):
        """Probe an endpoint to determine if it's an AI service"""
        try:
            # Try common API discovery endpoints
            discovery_paths = [
                '',
                'health',
                'status',
                'info',
                'metadata',
                'models',
                'api-docs',
                # GenAI specific paths
                'v1/models',
                'completions',
                'chat/completions',
                'embeddings',
                'generate',
                # Agentic AI specific paths
                'agents',
                'workflows',
                'tools',
                'memory',
                'planning',
                'reasoning'
            ]
            
            for path in discovery_paths:
                test_url = f"{endpoint.rstrip('/')}/{path}".rstrip('/')
                
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        # Look for AI/ML service indicators
                        if self.is_ai_service(data, response.headers):
                            return self.extract_agent_data(endpoint, data, response.headers)
                    except json.JSONDecodeError:
                        # Check response text for indicators
                        if self.is_ai_service_text(response.text):
                            return self.extract_agent_data_from_text(endpoint, response.text)
            
        except requests.RequestException:
            pass
        
        return None
    
    def is_ai_service(self, data, headers):
        """Determine if response indicates an AI service with GenAI and Agentic AI detection"""
        # Traditional AI indicators
        traditional_ai_indicators = [
            'model', 'models', 'prediction', 'inference', 'tensorflow', 'pytorch',
            'scikit', 'keras', 'machine_learning', 'deep_learning', 'neural',
            'healthcare', 'medical', 'clinical', 'diagnostic', 'treatment'
        ]
        
        # GenAI specific indicators
        genai_indicators = [
            'gpt', 'llm', 'large language model', 'generative', 'openai', 'claude', 'anthropic',
            'palm', 'bard', 'gemini', 'llama', 'mistral', 'completion', 'completions', 'chat',
            'conversation', 'text-generation', 'embedding', 'embeddings', 'transformer', 'bert',
            'roberta', 'bloom', 'huggingface', 'transformers', 'stable-diffusion', 'dalle',
            'midjourney', 'diffusion', 'gan', 'multimodal', 'vision-language', 'text-to-image',
            'prompt', 'fine-tune', 'fine-tuning', 'text_generation'
        ]
        
        # Agentic AI indicators
        agentic_indicators = [
            'agent', 'agents', 'autonomous', 'langchain', 'autogpt', 'crew', 'swarm',
            'multi-agent', 'planning', 'reasoning', 'tool-use', 'function-calling',
            'workflow', 'workflows', 'orchestration', 'decision-making', 'goal-oriented',
            'task-execution', 'memory', 'context', 'retrieval', 'rag', 'knowledge-base',
            'vector', 'api-calling', 'external-tools', 'tools', 'function_calling'
        ]
        
        all_indicators = traditional_ai_indicators + genai_indicators + agentic_indicators
        
        # Check response data
        data_str = json.dumps(data).lower()
        for indicator in all_indicators:
            if indicator in data_str:
                return True
        
        # Check headers for AI service indicators
        content_type = headers.get('content-type', '').lower()
        server = headers.get('server', '').lower()
        user_agent = headers.get('user-agent', '').lower()
        
        all_header_text = content_type + server + user_agent
        if any(ai_word in all_header_text for ai_word in ['ml', 'ai', 'model', 'llm', 'agent', 'gpt']):
            return True
        
        return False
    
    def is_ai_service_text(self, text):
        """Check text response for AI service indicators including GenAI and Agentic AI"""
        ai_keywords = [
            # Traditional AI
            'tensorflow', 'pytorch', 'model', 'prediction', 'inference', 'healthcare ai',
            # GenAI
            'gpt', 'llm', 'large language model', 'completion', 'chat', 'generative',
            'embedding', 'transformer', 'huggingface', 'openai', 'claude', 'anthropic',
            'text generation', 'conversational ai', 'stable diffusion', 'dalle',
            # Agentic AI
            'agent', 'autonomous', 'langchain', 'workflow', 'planning', 'reasoning',
            'tool use', 'function calling', 'orchestration', 'multi-agent'
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in ai_keywords)
    
    def extract_agent_data(self, endpoint, data, headers):
        """Extract agent information from API response"""
        parsed_url = urlparse(endpoint)
        
        # Determine service type from response data
        service_type = self.determine_service_type(data)
        
        return {
            'name': self.extract_service_name(data, parsed_url.netloc),
            'type': service_type,
            'protocol': 'rest_api',
            'endpoint': endpoint,
            'cloud_provider': self.determine_cloud_provider(parsed_url.netloc),
            'region': 'unknown',
            'metadata': {
                'api_response': data,
                'headers': dict(headers),
                'host': parsed_url.netloc,
                'path': parsed_url.path,
                'scheme': parsed_url.scheme
            }
        }
    
    def extract_agent_data_from_text(self, endpoint, text):
        """Extract agent data from text response"""
        parsed_url = urlparse(endpoint)
        
        return {
            'name': f"API Service at {parsed_url.netloc}",
            'type': 'Healthcare API Service',
            'protocol': 'rest_api',
            'endpoint': endpoint,
            'cloud_provider': self.determine_cloud_provider(parsed_url.netloc),
            'region': 'unknown',
            'metadata': {
                'response_text': text[:1000],  # Limit stored text
                'host': parsed_url.netloc,
                'path': parsed_url.path,
                'scheme': parsed_url.scheme
            }
        }
    
    def determine_service_type(self, data):
        """Determine the type of AI service from API data with GenAI and Agentic detection"""
        data_str = json.dumps(data).lower()
        
        # Check for GenAI indicators first (more specific)
        genai_patterns = {
            'gpt': 'GenAI - GPT Model',
            'claude': 'GenAI - Claude Model',
            'llama': 'GenAI - LLaMA Model',
            'gemini': 'GenAI - Gemini Model',
            'mistral': 'GenAI - Mistral Model',
            'completion': 'GenAI - Text Generation',
            'chat': 'GenAI - Conversational AI',
            'embedding': 'GenAI - Embedding Model',
            'text-generation': 'GenAI - Text Generation',
            'text-to-image': 'GenAI - Multimodal',
            'stable-diffusion': 'GenAI - Image Generation',
            'dalle': 'GenAI - Image Generation'
        }
        
        for pattern, ai_type in genai_patterns.items():
            if pattern in data_str:
                return ai_type
        
        # Check for Agentic AI indicators
        agentic_patterns = {
            'agent': 'Agentic AI - Autonomous Agent',
            'workflow': 'Agentic AI - Workflow Agent',
            'planning': 'Agentic AI - Planning Agent',
            'reasoning': 'Agentic AI - Reasoning Agent',
            'tool-use': 'Agentic AI - Tool-Using Agent',
            'langchain': 'Agentic AI - LangChain Agent',
            'autogpt': 'Agentic AI - AutoGPT Agent',
            'multi-agent': 'Agentic AI - Multi-Agent System',
            'orchestration': 'Agentic AI - Orchestration System'
        }
        
        for pattern, ai_type in agentic_patterns.items():
            if pattern in data_str:
                return ai_type
        
        # Traditional healthcare AI patterns
        if 'imaging' in data_str or 'radiology' in data_str:
            return 'Medical Imaging AI'
        elif 'clinical' in data_str or 'diagnosis' in data_str:
            return 'Clinical Decision Support'
        elif 'nlp' in data_str or 'text' in data_str:
            return 'Healthcare NLP AI'
        elif 'drug' in data_str or 'pharmaceutical' in data_str:
            return 'Drug Discovery AI'
        else:
            return 'Healthcare AI Service'
    
    def extract_service_name(self, data, default_host):
        """Extract service name from API data"""
        # Try various common name fields
        name_fields = ['name', 'service_name', 'model_name', 'title', 'application']
        
        for field in name_fields:
            if field in data and data[field]:
                return data[field]
        
        return f"API Service at {default_host}"
    
    def determine_cloud_provider(self, hostname):
        """Determine cloud provider from hostname"""
        if 'amazonaws.com' in hostname:
            return 'AWS'
        elif 'azure.com' in hostname or 'azurewebsites.net' in hostname:
            return 'Azure'
        elif 'googleapis.com' in hostname or 'googlecloud.com' in hostname:
            return 'GCP'
        elif 'localhost' in hostname or '127.0.0.1' in hostname:
            return 'Local'
        else:
            return 'Unknown'
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        agent = AIAgent.query.filter_by(
            endpoint=agent_data['endpoint']
        ).first()
        
        if not agent:
            agent = AIAgent(
                name=agent_data['name'],
                type=agent_data['type'],
                protocol=agent_data['protocol'],
                endpoint=agent_data['endpoint'],
                cloud_provider=agent_data['cloud_provider'],
                region=agent_data['region'],
                metadata=agent_data['metadata']
            )
            db.session.add(agent)
        else:
            agent.metadata = agent_data['metadata']
        
        db.session.commit()
        return agent
    
    def perform_security_scan(self, agent, agent_data):
        """Perform security scan on API endpoint"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'none'
        
        endpoint = agent_data['endpoint']
        metadata = agent_data['metadata']
        
        # Check HTTPS usage
        if endpoint.startswith('https://'):
            encryption_status = 'tls'
        elif endpoint.startswith('http://'):
            vulnerabilities += 1
            
        # Check for authentication requirements
        try:
            response = requests.get(endpoint, timeout=self.timeout)
            if response.status_code == 200:
                vulnerabilities += 1  # No authentication required
        except:
            pass
        
        # Check for PHI exposure indicators
        api_response = metadata.get('api_response', {})
        if self.check_phi_exposure(api_response):
            phi_exposure = True
            
        # Check security headers
        headers = metadata.get('headers', {})
        security_headers = ['x-frame-options', 'x-content-type-options', 'strict-transport-security']
        missing_headers = sum(1 for header in security_headers if header not in headers)
        vulnerabilities += missing_headers
        
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='api_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'security_headers': headers,
                'authentication_required': vulnerabilities == 0
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure, encryption_status)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def check_phi_exposure(self, api_response):
        """Check if API response contains PHI indicators"""
        phi_indicators = [
            'patient', 'medical_record', 'ssn', 'diagnosis', 'treatment',
            'phi', 'pii', 'health_record', 'medical_data'
        ]
        
        response_str = json.dumps(api_response).lower()
        return any(indicator in response_str for indicator in phi_indicators)
    
    def generate_recommendations(self, vulnerabilities, phi_exposure, encryption_status):
        """Generate API-specific security recommendations"""
        recommendations = []
        
        if encryption_status == 'none':
            recommendations.append({
                'priority': 'critical',
                'category': 'encryption',
                'description': 'API endpoint not using HTTPS',
                'action': 'Enable HTTPS/TLS encryption for all API communications'
            })
            
        if phi_exposure:
            recommendations.append({
                'priority': 'high',
                'category': 'data_protection',
                'description': 'Potential PHI exposure detected in API responses',
                'action': 'Implement data masking and access controls for PHI'
            })
            
        if vulnerabilities > 2:
            recommendations.append({
                'priority': 'medium',
                'category': 'api_security',
                'description': 'Multiple API security issues detected',
                'action': 'Implement API authentication, rate limiting, and security headers'
            })
        
        return recommendations
