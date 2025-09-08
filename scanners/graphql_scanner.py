from .base_scanner import BaseScanner
from app import db
from models import AIAgent, ScanResult, RiskLevel
import requests
import json
import os
from urllib.parse import urlparse

class GraphQLScanner(BaseScanner):
    """Scanner for GraphQL-based AI agents and healthcare APIs"""
    
    def __init__(self):
        super().__init__()
        self.timeout = int(os.getenv('GRAPHQL_SCAN_TIMEOUT', '30'))
        self.graphql_endpoints = os.getenv('GRAPHQL_ENDPOINTS', '').split(',') if os.getenv('GRAPHQL_ENDPOINTS') else []
    
    def scan(self):
        """Scan for GraphQL-based AI agents"""
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
            self.logger.error(f"GraphQL scan failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'scan_duration': self.end_scan()
            }
    
    def discover_agents(self):
        """Discover GraphQL AI agents through endpoint probing"""
        agents = []
        
        # Common GraphQL endpoint patterns for healthcare
        common_endpoints = [
            'http://localhost:4000/graphql',
            'http://localhost:8080/graphql',
            'http://localhost:3000/graphql',
            'https://api.healthcare-ai.local/graphql',
            'https://medical-ai.local/api/graphql'
        ]
        
        # Add configured endpoints
        all_endpoints = common_endpoints + [ep.strip() for ep in self.graphql_endpoints if ep.strip()]
        
        for endpoint in all_endpoints:
            try:
                agent_data = self.probe_graphql_endpoint(endpoint)
                if agent_data:
                    agents.append(agent_data)
            except Exception as e:
                self.logger.debug(f"Failed to probe GraphQL endpoint {endpoint}: {str(e)}")
        
        return agents
    
    def probe_graphql_endpoint(self, endpoint):
        """Probe a GraphQL endpoint to determine if it's an AI service"""
        try:
            # First, try introspection query to get schema
            introspection_query = """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        kind
                        name
                        description
                        fields {
                            name
                            description
                            type { name }
                        }
                    }
                }
            }
            """
            
            response = requests.post(
                endpoint,
                json={'query': introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if 'data' in data and '__schema' in data['data']:
                        # Valid GraphQL endpoint with schema
                        if self.is_healthcare_ai_schema(data['data']['__schema']):
                            return self.extract_agent_data_from_schema(endpoint, data['data']['__schema'])
                except json.JSONDecodeError:
                    pass
            
            # If introspection fails, try simple query
            simple_query = """
            query {
                __typename
            }
            """
            
            response = requests.post(
                endpoint,
                json={'query': simple_query},
                headers={'Content-Type': 'application/json'},
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if 'data' in data:
                        # Valid GraphQL endpoint
                        return self.extract_basic_agent_data(endpoint, data)
                except json.JSONDecodeError:
                    pass
            
        except requests.RequestException:
            pass
        
        return None
    
    def is_healthcare_ai_schema(self, schema):
        """Determine if GraphQL schema indicates a healthcare AI service"""
        healthcare_indicators = [
            'patient', 'medical', 'clinical', 'diagnosis', 'treatment',
            'health', 'physician', 'doctor', 'nurse', 'hospital',
            'medication', 'prescription', 'symptom', 'disease'
        ]
        
        ai_indicators = [
            'prediction', 'model', 'inference', 'analysis', 'recommendation',
            'ai', 'ml', 'machine_learning', 'neural', 'algorithm'
        ]
        
        # Check types and fields for healthcare and AI indicators
        types = schema.get('types', [])
        schema_text = json.dumps(types).lower()
        
        has_healthcare = any(indicator in schema_text for indicator in healthcare_indicators)
        has_ai = any(indicator in schema_text for indicator in ai_indicators)
        
        return has_healthcare and has_ai
    
    def extract_agent_data_from_schema(self, endpoint, schema):
        """Extract agent information from GraphQL schema"""
        parsed_url = urlparse(endpoint)
        
        # Analyze schema to determine service type
        service_type = self.determine_service_type_from_schema(schema)
        service_name = self.extract_service_name_from_schema(schema, parsed_url.netloc)
        
        # Extract field information for analysis
        types = schema.get('types', [])
        custom_types = [t for t in types if t.get('kind') == 'OBJECT' and not t.get('name', '').startswith('__')]
        
        return {
            'name': service_name,
            'type': service_type,
            'protocol': 'graphql',
            'endpoint': endpoint,
            'cloud_provider': self.determine_cloud_provider(parsed_url.netloc),
            'region': 'unknown',
            'metadata': {
                'schema_types': len(custom_types),
                'has_mutations': schema.get('mutationType') is not None,
                'has_subscriptions': schema.get('subscriptionType') is not None,
                'custom_types': [t.get('name') for t in custom_types[:10]],  # Limit stored types
                'host': parsed_url.netloc,
                'path': parsed_url.path,
                'scheme': parsed_url.scheme,
                'introspection_enabled': True
            }
        }
    
    def extract_basic_agent_data(self, endpoint, response_data):
        """Extract basic agent data when full schema is not available"""
        parsed_url = urlparse(endpoint)
        
        return {
            'name': f"GraphQL Service at {parsed_url.netloc}",
            'type': 'Healthcare GraphQL API',
            'protocol': 'graphql',
            'endpoint': endpoint,
            'cloud_provider': self.determine_cloud_provider(parsed_url.netloc),
            'region': 'unknown',
            'metadata': {
                'host': parsed_url.netloc,
                'path': parsed_url.path,
                'scheme': parsed_url.scheme,
                'introspection_enabled': False,
                'basic_response': response_data
            }
        }
    
    def determine_service_type_from_schema(self, schema):
        """Determine AI service type from GraphQL schema"""
        types = schema.get('types', [])
        type_names = [t.get('name', '').lower() for t in types]
        
        # Check for specific healthcare AI patterns
        if any('imaging' in name or 'radiology' in name for name in type_names):
            return 'Medical Imaging AI'
        elif any('clinical' in name or 'diagnosis' in name for name in type_names):
            return 'Clinical Decision Support'
        elif any('drug' in name or 'pharmaceutical' in name for name in type_names):
            return 'Drug Discovery AI'
        elif any('patient' in name and 'monitor' in name for name in type_names):
            return 'Patient Monitoring AI'
        else:
            return 'Healthcare AI GraphQL Service'
    
    def extract_service_name_from_schema(self, schema, default_host):
        """Extract service name from GraphQL schema"""
        # Look for service identification in type descriptions
        types = schema.get('types', [])
        
        for type_obj in types:
            description = type_obj.get('description', '')
            if description and ('service' in description.lower() or 'api' in description.lower()):
                # Extract name from description
                words = description.split()
                if len(words) > 0:
                    return f"{words[0]} GraphQL Service"
        
        return f"GraphQL Service at {default_host}"
    
    def determine_cloud_provider(self, hostname):
        """Determine cloud provider from hostname"""
        if 'localhost' in hostname or '127.0.0.1' in hostname:
            return 'Local'
        elif 'amazonaws.com' in hostname:
            return 'AWS'
        elif 'azure.com' in hostname or 'azurewebsites.net' in hostname:
            return 'Azure'
        elif 'googleapis.com' in hostname or 'googlecloud.com' in hostname:
            return 'GCP'
        else:
            return 'Unknown'
    
    def create_or_update_agent(self, agent_data):
        """Create or update AI agent in database"""
        agent = AIAgent.query.filter_by(
            endpoint=agent_data['endpoint'],
            protocol='graphql'
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
        """Perform security scan on GraphQL endpoint"""
        vulnerabilities = 0
        phi_exposure = False
        encryption_status = 'none'
        
        endpoint = agent_data['endpoint']
        metadata = agent_data['metadata']
        
        # Check HTTPS usage
        if endpoint.startswith('https://'):
            encryption_status = 'tls'
        else:
            vulnerabilities += 1
            
        # Check introspection (security risk if enabled in production)
        if metadata.get('introspection_enabled'):
            vulnerabilities += 1
            
        # Check for depth limiting and query complexity analysis
        if not self.check_query_depth_limiting(endpoint):
            vulnerabilities += 1
            
        # Check for rate limiting
        if not self.check_rate_limiting(endpoint):
            vulnerabilities += 1
            
        # Check for PHI exposure in schema
        if self.check_phi_exposure_in_schema(metadata):
            phi_exposure = True
            
        # Check authentication requirements
        if not self.check_authentication_required(endpoint):
            vulnerabilities += 1
            
        # Calculate risk
        risk_score = self.calculate_risk_score(vulnerabilities, phi_exposure, encryption_status)
        risk_level = self.determine_risk_level(risk_score)
        
        # Create scan result
        scan_result = ScanResult(
            ai_agent_id=agent.id,
            scan_type='graphql_security',
            status='COMPLETED',
            risk_score=risk_score,
            risk_level=getattr(RiskLevel, risk_level),
            vulnerabilities_found=vulnerabilities,
            phi_exposure_detected=phi_exposure,
            scan_data={
                'encryption_status': encryption_status,
                'introspection_enabled': metadata.get('introspection_enabled', False),
                'schema_types_count': metadata.get('schema_types', 0),
                'has_mutations': metadata.get('has_mutations', False)
            },
            recommendations=self.generate_recommendations(vulnerabilities, phi_exposure, encryption_status, metadata)
        )
        
        db.session.add(scan_result)
        agent.last_scanned = scan_result.created_at
        db.session.commit()
        
        return scan_result
    
    def check_query_depth_limiting(self, endpoint):
        """Check if GraphQL endpoint implements query depth limiting"""
        try:
            # Try a deeply nested query to test depth limiting
            deep_query = """
            query DeepQuery {
                level1 {
                    level2 {
                        level3 {
                            level4 {
                                level5 {
                                    level6 {
                                        level7 {
                                            level8 {
                                                level9 {
                                                    level10 { id }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
            
            response = requests.post(
                endpoint,
                json={'query': deep_query},
                timeout=self.timeout,
                verify=False
            )
            
            # If the query is rejected, depth limiting is likely in place
            return response.status_code == 400 or 'depth' in response.text.lower()
            
        except Exception:
            # Assume depth limiting is in place if we can't test
            return True
    
    def check_rate_limiting(self, endpoint):
        """Check if GraphQL endpoint implements rate limiting"""
        try:
            # Send multiple rapid requests
            simple_query = "query { __typename }"
            
            for _ in range(5):
                response = requests.post(
                    endpoint,
                    json={'query': simple_query},
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code == 429:  # Too Many Requests
                    return True
            
            # No rate limiting detected
            return False
            
        except Exception:
            # Assume rate limiting is in place if we can't test
            return True
    
    def check_phi_exposure_in_schema(self, metadata):
        """Check if GraphQL schema exposes PHI fields"""
        custom_types = metadata.get('custom_types', [])
        
        phi_indicators = [
            'ssn', 'socialsecurity', 'patient', 'medicalrecord', 'diagnosis',
            'prescription', 'treatment', 'phi', 'personalhealth'
        ]
        
        types_str = ' '.join(custom_types).lower()
        return any(indicator in types_str for indicator in phi_indicators)
    
    def check_authentication_required(self, endpoint):
        """Check if GraphQL endpoint requires authentication"""
        try:
            # Try to access without authentication
            response = requests.post(
                endpoint,
                json={'query': 'query { __typename }'},
                timeout=self.timeout,
                verify=False
            )
            
            # If successful without auth, it's a vulnerability
            return response.status_code == 401 or response.status_code == 403
            
        except Exception:
            # Assume authentication is required if we can't test
            return True
    
    def generate_recommendations(self, vulnerabilities, phi_exposure, encryption_status, metadata):
        """Generate GraphQL-specific security recommendations"""
        recommendations = []
        
        if encryption_status == 'none':
            recommendations.append({
                'priority': 'critical',
                'category': 'encryption',
                'description': 'GraphQL endpoint not using HTTPS',
                'action': 'Enable HTTPS/TLS encryption for all GraphQL communications'
            })
            
        if metadata.get('introspection_enabled'):
            recommendations.append({
                'priority': 'high',
                'category': 'information_disclosure',
                'description': 'GraphQL introspection enabled in production',
                'action': 'Disable GraphQL introspection in production environments'
            })
            
        if phi_exposure:
            recommendations.append({
                'priority': 'high',
                'category': 'data_protection',
                'description': 'PHI fields detected in GraphQL schema',
                'action': 'Implement field-level access controls and data masking for PHI'
            })
            
        if vulnerabilities > 2:
            recommendations.append({
                'priority': 'medium',
                'category': 'graphql_security',
                'description': 'Multiple GraphQL security issues detected',
                'action': 'Implement query depth limiting, rate limiting, and authentication'
            })
            
        recommendations.append({
            'priority': 'low',
            'category': 'monitoring',
            'description': 'Enhance GraphQL query monitoring and logging',
            'action': 'Implement query performance monitoring and audit logging'
        })
        
        return recommendations
