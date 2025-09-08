"""
Real-time Kubernetes cluster integration for live monitoring and agent discovery
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
import threading
import time

from app import db
from models import AIAgent, ScanResult, RiskLevel

logger = logging.getLogger(__name__)


class KubernetesIntegration:
    """Real-time Kubernetes cluster integration"""
    
    def __init__(self):
        self.v1 = None
        self.apps_v1 = None
        self.is_connected = False
        self.watch_threads = {}
        self.event_handlers = []
        self.last_heartbeat = None
        
        try:
            # Try in-cluster config first, then local config
            try:
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes configuration")
            except config.ConfigException:
                config.load_kube_config()
                logger.info("Loaded local Kubernetes configuration")
            
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.is_connected = self._test_connection()
            
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            self.is_connected = False
    
    def _test_connection(self) -> bool:
        """Test Kubernetes API connectivity"""
        try:
            self.v1.list_namespace(limit=1)
            self.last_heartbeat = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Kubernetes connection test failed: {e}")
            return False
    
    def get_cluster_info(self) -> Dict[str, Any]:
        """Get cluster information and health status"""
        if not self.is_connected:
            return {
                'status': 'disconnected',
                'error': 'Not connected to Kubernetes cluster'
            }
        
        try:
            # Get cluster version
            version_info = self.v1.get_code()
            
            # Get namespaces
            namespaces = self.v1.list_namespace()
            
            # Get nodes
            nodes = self.v1.list_node()
            
            return {
                'status': 'connected',
                'cluster_version': {
                    'major': version_info.major,
                    'minor': version_info.minor,
                    'git_version': version_info.git_version
                },
                'namespaces_count': len(namespaces.items),
                'nodes_count': len(nodes.items),
                'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
                'nodes': [
                    {
                        'name': node.metadata.name,
                        'status': self._get_node_status(node),
                        'version': node.status.node_info.kubelet_version,
                        'architecture': node.status.node_info.architecture,
                        'os': node.status.node_info.operating_system
                    }
                    for node in nodes.items
                ]
            }
        except Exception as e:
            logger.error(f"Failed to get cluster info: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def _get_node_status(self, node) -> str:
        """Get node status from conditions"""
        if not node.status or not node.status.conditions:
            return 'Unknown'
        
        for condition in node.status.conditions:
            if condition.type == 'Ready':
                return 'Ready' if condition.status == 'True' else 'NotReady'
        return 'Unknown'
    
    def discover_ai_workloads(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Discover AI workloads across the cluster in real-time"""
        if not self.is_connected:
            return []
        
        ai_workloads = []
        
        try:
            # Discover AI Pods
            pods = self._discover_ai_pods(namespace)
            ai_workloads.extend(pods)
            
            # Discover AI Deployments
            deployments = self._discover_ai_deployments(namespace)
            ai_workloads.extend(deployments)
            
            # Discover AI Services
            services = self._discover_ai_services(namespace)
            ai_workloads.extend(services)
            
            logger.info(f"Discovered {len(ai_workloads)} AI workloads")
            return ai_workloads
            
        except Exception as e:
            logger.error(f"Failed to discover AI workloads: {e}")
            return []
    
    def _discover_ai_pods(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Discover AI-related pods"""
        ai_pods = []
        
        try:
            if namespace:
                pods = self.v1.list_namespaced_pod(namespace=namespace)
            else:
                pods = self.v1.list_pod_for_all_namespaces()
            
            for pod in pods.items:
                if self._is_ai_workload(pod.metadata.labels, pod.metadata.annotations):
                    ai_pod = {
                        'name': pod.metadata.name,
                        'namespace': pod.metadata.namespace,
                        'type': 'Pod',
                        'ai_type': self._determine_ai_type(pod.metadata.labels, pod.metadata.annotations),
                        'status': pod.status.phase,
                        'created': pod.metadata.creation_timestamp.isoformat(),
                        'labels': pod.metadata.labels or {},
                        'annotations': pod.metadata.annotations or {},
                        'containers': [
                            {
                                'name': container.name,
                                'image': container.image,
                                'ports': [
                                    {
                                        'containerPort': port.container_port,
                                        'protocol': port.protocol,
                                        'name': port.name
                                    }
                                    for port in (container.ports or [])
                                ],
                                'resources': self._extract_resources(container.resources)
                            }
                            for container in pod.spec.containers
                        ],
                        'node_name': pod.spec.node_name,
                        'restart_policy': pod.spec.restart_policy,
                        'service_account': pod.spec.service_account_name
                    }
                    ai_pods.append(ai_pod)
        
        except Exception as e:
            logger.error(f"Failed to discover AI pods: {e}")
        
        return ai_pods
    
    def _discover_ai_deployments(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Discover AI-related deployments"""
        ai_deployments = []
        
        try:
            if namespace:
                deployments = self.apps_v1.list_namespaced_deployment(namespace=namespace)
            else:
                deployments = self.apps_v1.list_deployment_for_all_namespaces()
            
            for deployment in deployments.items:
                if self._is_ai_workload(deployment.metadata.labels, deployment.metadata.annotations):
                    ai_deployment = {
                        'name': deployment.metadata.name,
                        'namespace': deployment.metadata.namespace,
                        'type': 'Deployment',
                        'ai_type': self._determine_ai_type(deployment.metadata.labels, deployment.metadata.annotations),
                        'replicas': {
                            'desired': deployment.spec.replicas,
                            'ready': deployment.status.ready_replicas or 0,
                            'available': deployment.status.available_replicas or 0
                        },
                        'created': deployment.metadata.creation_timestamp.isoformat(),
                        'labels': deployment.metadata.labels or {},
                        'annotations': deployment.metadata.annotations or {},
                        'strategy': deployment.spec.strategy.type if deployment.spec.strategy else 'Unknown',
                        'containers': [
                            {
                                'name': container.name,
                                'image': container.image,
                                'ports': [
                                    {
                                        'containerPort': port.container_port,
                                        'protocol': port.protocol,
                                        'name': port.name
                                    }
                                    for port in (container.ports or [])
                                ],
                                'resources': self._extract_resources(container.resources)
                            }
                            for container in deployment.spec.template.spec.containers
                        ]
                    }
                    ai_deployments.append(ai_deployment)
        
        except Exception as e:
            logger.error(f"Failed to discover AI deployments: {e}")
        
        return ai_deployments
    
    def _discover_ai_services(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Discover AI-related services"""
        ai_services = []
        
        try:
            if namespace:
                services = self.v1.list_namespaced_service(namespace=namespace)
            else:
                services = self.v1.list_service_for_all_namespaces()
            
            for service in services.items:
                if self._is_ai_workload(service.metadata.labels, service.metadata.annotations):
                    ai_service = {
                        'name': service.metadata.name,
                        'namespace': service.metadata.namespace,
                        'type': 'Service',
                        'ai_type': self._determine_ai_type(service.metadata.labels, service.metadata.annotations),
                        'cluster_ip': service.spec.cluster_ip,
                        'service_type': service.spec.type,
                        'created': service.metadata.creation_timestamp.isoformat(),
                        'labels': service.metadata.labels or {},
                        'annotations': service.metadata.annotations or {},
                        'ports': [
                            {
                                'port': port.port,
                                'target_port': str(port.target_port) if port.target_port else None,
                                'protocol': port.protocol,
                                'name': port.name,
                                'node_port': port.node_port
                            }
                            for port in (service.spec.ports or [])
                        ],
                        'selector': service.spec.selector or {}
                    }
                    ai_services.append(ai_service)
        
        except Exception as e:
            logger.error(f"Failed to discover AI services: {e}")
        
        return ai_services
    
    def _is_ai_workload(self, labels: Dict[str, str], annotations: Dict[str, str]) -> bool:
        """Determine if a workload is AI-related"""
        if not labels and not annotations:
            return False
        
        ai_indicators = [
            'ai', 'ml', 'model', 'tensorflow', 'pytorch', 'sklearn', 'huggingface',
            'inference', 'training', 'serving', 'mlflow', 'kubeflow', 'seldon',
            'kfserving', 'torchserve', 'triton', 'onnx', 'opencv', 'transformers'
        ]
        
        # Check labels
        if labels:
            for key, value in labels.items():
                for indicator in ai_indicators:
                    if indicator in key.lower() or indicator in str(value).lower():
                        return True
        
        # Check annotations
        if annotations:
            for key, value in annotations.items():
                for indicator in ai_indicators:
                    if indicator in key.lower() or indicator in str(value).lower():
                        return True
        
        return False
    
    def _determine_ai_type(self, labels: Dict[str, str], annotations: Dict[str, str]) -> str:
        """Determine the specific AI workload type"""
        combined_metadata = {}
        if labels:
            combined_metadata.update(labels)
        if annotations:
            combined_metadata.update(annotations)
        
        for key, value in combined_metadata.items():
            key_lower = key.lower()
            value_lower = str(value).lower()
            
            # Healthcare AI types
            if any(term in key_lower or term in value_lower for term in ['medical', 'clinical', 'healthcare', 'dicom', 'phi']):
                return 'Healthcare AI'
            
            # Framework-specific types
            if 'tensorflow' in key_lower or 'tensorflow' in value_lower:
                return 'TensorFlow AI'
            elif 'pytorch' in key_lower or 'pytorch' in value_lower:
                return 'PyTorch AI'
            elif 'huggingface' in key_lower or 'huggingface' in value_lower:
                return 'Transformer AI'
            
            # Function-specific types
            elif any(term in key_lower or term in value_lower for term in ['inference', 'serving']):
                return 'AI Inference Service'
            elif any(term in key_lower or term in value_lower for term in ['training']):
                return 'AI Training Service'
            elif any(term in key_lower or term in value_lower for term in ['nlp', 'text']):
                return 'NLP AI'
            elif any(term in key_lower or term in value_lower for term in ['vision', 'image', 'cv']):
                return 'Computer Vision AI'
        
        return 'AI Agent'
    
    def _extract_resources(self, resources) -> Dict[str, Any]:
        """Extract resource requirements and limits"""
        if not resources:
            return {}
        
        result = {}
        
        if resources.requests:
            result['requests'] = dict(resources.requests)
        
        if resources.limits:
            result['limits'] = dict(resources.limits)
        
        return result
    
    def start_real_time_monitoring(self):
        """Start real-time monitoring of Kubernetes resources"""
        if not self.is_connected:
            logger.error("Cannot start monitoring: not connected to Kubernetes")
            return False
        
        try:
            # Start watching pods
            self._start_resource_watch('pods', self.v1.list_pod_for_all_namespaces)
            
            # Start watching deployments
            self._start_resource_watch('deployments', self.apps_v1.list_deployment_for_all_namespaces)
            
            # Start watching services
            self._start_resource_watch('services', self.v1.list_service_for_all_namespaces)
            
            logger.info("Started real-time Kubernetes monitoring")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start real-time monitoring: {e}")
            return False
    
    def _start_resource_watch(self, resource_type: str, list_func):
        """Start watching a specific resource type"""
        def watch_resource():
            w = watch.Watch()
            while True:
                try:
                    for event in w.stream(list_func, timeout_seconds=300):
                        self._handle_resource_event(resource_type, event)
                except Exception as e:
                    logger.error(f"Error watching {resource_type}: {e}")
                    time.sleep(10)  # Wait before reconnecting
        
        thread = threading.Thread(target=watch_resource, daemon=True)
        thread.start()
        self.watch_threads[resource_type] = thread
    
    def _handle_resource_event(self, resource_type: str, event: Dict[str, Any]):
        """Handle resource change events"""
        event_type = event['type']  # ADDED, MODIFIED, DELETED
        resource = event['object']
        
        # Only process AI workloads
        labels = getattr(resource.metadata, 'labels', None) or {}
        annotations = getattr(resource.metadata, 'annotations', None) or {}
        
        if not self._is_ai_workload(labels, annotations):
            return
        
        logger.info(f"AI workload {event_type}: {resource.metadata.name} ({resource_type})")
        
        # Trigger event handlers
        for handler in self.event_handlers:
            try:
                handler(resource_type, event_type, resource)
            except Exception as e:
                logger.error(f"Error in event handler: {e}")
    
    def add_event_handler(self, handler):
        """Add an event handler for resource changes"""
        self.event_handlers.append(handler)
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        # Stop watch threads
        for resource_type, thread in self.watch_threads.items():
            logger.info(f"Stopping {resource_type} watch")
        
        self.watch_threads.clear()
        self.event_handlers.clear()
    
    def get_ai_workload_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics for AI workloads"""
        if not self.is_connected:
            return {}
        
        try:
            ai_workloads = self.discover_ai_workloads()
            
            # Aggregate metrics
            metrics = {
                'total_workloads': len(ai_workloads),
                'by_type': {},
                'by_namespace': {},
                'by_ai_type': {},
                'status_summary': {
                    'running': 0,
                    'pending': 0,
                    'failed': 0,
                    'succeeded': 0
                },
                'resource_usage': {
                    'total_cpu_requests': 0,
                    'total_memory_requests': 0,
                    'total_gpu_requests': 0
                }
            }
            
            for workload in ai_workloads:
                # Count by resource type
                resource_type = workload['type']
                metrics['by_type'][resource_type] = metrics['by_type'].get(resource_type, 0) + 1
                
                # Count by namespace
                namespace = workload['namespace']
                metrics['by_namespace'][namespace] = metrics['by_namespace'].get(namespace, 0) + 1
                
                # Count by AI type
                ai_type = workload['ai_type']
                metrics['by_ai_type'][ai_type] = metrics['by_ai_type'].get(ai_type, 0) + 1
                
                # Status summary (for pods mainly)
                if 'status' in workload:
                    status = workload['status'].lower()
                    if status in metrics['status_summary']:
                        metrics['status_summary'][status] += 1
                
                # Resource usage
                containers = workload.get('containers', [])
                for container in containers:
                    resources = container.get('resources', {})
                    requests = resources.get('requests', {})
                    
                    # Parse CPU requests
                    if 'cpu' in requests:
                        cpu_value = self._parse_cpu_value(requests['cpu'])
                        metrics['resource_usage']['total_cpu_requests'] += cpu_value
                    
                    # Parse memory requests
                    if 'memory' in requests:
                        memory_value = self._parse_memory_value(requests['memory'])
                        metrics['resource_usage']['total_memory_requests'] += memory_value
                    
                    # Count GPU requests
                    if 'nvidia.com/gpu' in requests:
                        gpu_value = int(requests['nvidia.com/gpu'])
                        metrics['resource_usage']['total_gpu_requests'] += gpu_value
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get AI workload metrics: {e}")
            return {}
    
    def _parse_cpu_value(self, cpu_str: str) -> float:
        """Parse CPU value from Kubernetes format"""
        try:
            if cpu_str.endswith('m'):
                return float(cpu_str[:-1]) / 1000
            else:
                return float(cpu_str)
        except:
            return 0.0
    
    def _parse_memory_value(self, memory_str: str) -> int:
        """Parse memory value from Kubernetes format to bytes"""
        try:
            memory_str = memory_str.strip()
            
            # Handle different units
            if memory_str.endswith('Ki'):
                return int(memory_str[:-2]) * 1024
            elif memory_str.endswith('Mi'):
                return int(memory_str[:-2]) * 1024 * 1024
            elif memory_str.endswith('Gi'):
                return int(memory_str[:-2]) * 1024 * 1024 * 1024
            elif memory_str.endswith('Ti'):
                return int(memory_str[:-2]) * 1024 * 1024 * 1024 * 1024
            else:
                return int(memory_str)  # Assume bytes
        except:
            return 0
    
    def get_namespace_ai_summary(self) -> List[Dict[str, Any]]:
        """Get AI workload summary by namespace"""
        if not self.is_connected:
            return []
        
        ai_workloads = self.discover_ai_workloads()
        namespace_summary = {}
        
        for workload in ai_workloads:
            namespace = workload['namespace']
            
            if namespace not in namespace_summary:
                namespace_summary[namespace] = {
                    'namespace': namespace,
                    'total_workloads': 0,
                    'pods': 0,
                    'deployments': 0,
                    'services': 0,
                    'ai_types': set(),
                    'status': {
                        'running': 0,
                        'pending': 0,
                        'failed': 0
                    }
                }
            
            summary = namespace_summary[namespace]
            summary['total_workloads'] += 1
            summary[workload['type'].lower() + 's'] += 1
            summary['ai_types'].add(workload['ai_type'])
            
            if 'status' in workload:
                status = workload['status'].lower()
                if status in summary['status']:
                    summary['status'][status] += 1
        
        # Convert sets to lists for JSON serialization
        for namespace, summary in namespace_summary.items():
            summary['ai_types'] = list(summary['ai_types'])
        
        return list(namespace_summary.values())


# Global instance
kubernetes_integration = KubernetesIntegration()