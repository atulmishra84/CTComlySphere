"""
Real-time Docker environment integration for live monitoring and agent discovery
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import docker
from docker.errors import DockerException, APIError
import threading
import time

from app import db
from models import AIAgent, ScanResult, RiskLevel

logger = logging.getLogger(__name__)


class DockerIntegration:
    """Real-time Docker environment integration"""
    
    def __init__(self):
        self.client = None
        self.is_connected = False
        self.last_heartbeat = None
        
        try:
            self.client = docker.from_env()
            self.is_connected = self._test_connection()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.is_connected = False
    
    def _test_connection(self) -> bool:
        """Test Docker daemon connectivity"""
        try:
            self.client.ping()
            self.last_heartbeat = datetime.utcnow()
            return True
        except Exception as e:
            logger.error(f"Docker connection test failed: {e}")
            return False
    
    def get_docker_info(self) -> Dict[str, Any]:
        """Get Docker daemon information and health status"""
        if not self.is_connected:
            return {
                'status': 'disconnected',
                'error': 'Not connected to Docker daemon'
            }
        
        try:
            info = self.client.info()
            version = self.client.version()
            
            return {
                'status': 'connected',
                'daemon_version': version.get('Version'),
                'api_version': version.get('ApiVersion'),
                'platform': version.get('Platform', {}).get('Name'),
                'architecture': version.get('Arch'),
                'containers': {
                    'total': info.get('Containers', 0),
                    'running': info.get('ContainersRunning', 0),
                    'paused': info.get('ContainersPaused', 0),
                    'stopped': info.get('ContainersStopped', 0)
                },
                'images': info.get('Images', 0),
                'memory': {
                    'total': info.get('MemTotal', 0),
                    'limit': info.get('MemoryLimit', False)
                },
                'cpu': {
                    'cpus': info.get('NCPU', 0),
                    'cpu_set': info.get('CpuCfsPeriod', False)
                },
                'storage': {
                    'driver': info.get('Driver'),
                    'backing_filesystem': info.get('DriverStatus', [])
                },
                'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None
            }
        except Exception as e:
            logger.error(f"Failed to get Docker info: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def discover_ai_containers(self) -> List[Dict[str, Any]]:
        """Discover AI-related containers in real-time"""
        if not self.is_connected:
            return []
        
        ai_containers = []
        
        try:
            containers = self.client.containers.list(all=True)
            
            for container in containers:
                if self._is_ai_container(container):
                    ai_container = {
                        'id': container.id,
                        'short_id': container.short_id,
                        'name': container.name,
                        'image': container.image.tags[0] if container.image.tags else container.image.short_id,
                        'image_id': container.image.short_id,
                        'status': container.status,
                        'state': container.attrs['State'],
                        'created': container.attrs['Created'],
                        'ai_type': self._determine_ai_type(container),
                        'labels': container.labels or {},
                        'environment': self._extract_environment_vars(container),
                        'ports': self._extract_port_mappings(container),
                        'mounts': self._extract_mounts(container),
                        'network_settings': self._extract_network_settings(container),
                        'resource_usage': self._get_container_stats(container),
                        'health': self._get_container_health(container),
                        'restart_policy': container.attrs.get('RestartPolicy', {}),
                        'log_config': container.attrs.get('LogConfig', {})
                    }
                    ai_containers.append(ai_container)
            
            logger.info(f"Discovered {len(ai_containers)} AI containers")
            return ai_containers
            
        except Exception as e:
            logger.error(f"Failed to discover AI containers: {e}")
            return []
    
    def _is_ai_container(self, container) -> bool:
        """Determine if a container is AI-related"""
        # Check image name
        image_name = ''
        if container.image.tags:
            image_name = container.image.tags[0].lower()
        
        # Check labels
        labels = container.labels or {}
        
        # Check environment variables
        env_vars = self._extract_environment_vars(container)
        
        ai_indicators = [
            'tensorflow', 'pytorch', 'sklearn', 'pandas', 'numpy', 'jupyter',
            'ai', 'ml', 'model', 'inference', 'training', 'serving',
            'huggingface', 'transformers', 'opencv', 'keras', 'mlflow',
            'kubeflow', 'seldon', 'triton', 'onnx', 'torchserve'
        ]
        
        # Check image name
        for indicator in ai_indicators:
            if indicator in image_name:
                return True
        
        # Check labels
        for key, value in labels.items():
            for indicator in ai_indicators:
                if indicator in key.lower() or indicator in str(value).lower():
                    return True
        
        # Check environment variables
        for key, value in env_vars.items():
            for indicator in ai_indicators:
                if indicator in key.lower() or indicator in str(value).lower():
                    return True
        
        # Check for common AI ports
        ports = self._extract_port_mappings(container)
        ai_ports = [8888, 8080, 8501, 5000, 6006]  # Jupyter, TensorBoard, TF Serving, etc.
        
        for port_mapping in ports:
            if port_mapping.get('container_port') in ai_ports:
                return True
        
        return False
    
    def _determine_ai_type(self, container) -> str:
        """Determine the specific AI container type"""
        image_name = ''
        if container.image.tags:
            image_name = container.image.tags[0].lower()
        
        labels = container.labels or {}
        env_vars = self._extract_environment_vars(container)
        
        # Combine all metadata for analysis
        all_text = f"{image_name} {json.dumps(labels).lower()} {json.dumps(env_vars).lower()}"
        
        # Healthcare AI
        if any(term in all_text for term in ['medical', 'clinical', 'healthcare', 'dicom', 'phi', 'hipaa']):
            return 'Healthcare AI'
        
        # Framework-specific
        if 'tensorflow' in all_text:
            if 'serving' in all_text:
                return 'TensorFlow Serving'
            return 'TensorFlow AI'
        elif 'pytorch' in all_text:
            return 'PyTorch AI'
        elif 'jupyter' in all_text:
            return 'Jupyter AI Notebook'
        elif 'huggingface' in all_text or 'transformers' in all_text:
            return 'Transformer AI'
        
        # Function-specific
        elif 'inference' in all_text or 'serving' in all_text:
            return 'AI Inference Service'
        elif 'training' in all_text:
            return 'AI Training Service'
        elif 'nlp' in all_text or 'text' in all_text:
            return 'NLP AI'
        elif 'vision' in all_text or 'image' in all_text or 'opencv' in all_text:
            return 'Computer Vision AI'
        elif 'mlflow' in all_text:
            return 'ML Experiment Tracking'
        
        return 'Containerized AI Agent'
    
    def _extract_environment_vars(self, container) -> Dict[str, str]:
        """Extract environment variables from container"""
        try:
            env_list = container.attrs.get('Config', {}).get('Env', [])
            env_dict = {}
            
            for env_var in env_list:
                if '=' in env_var:
                    key, value = env_var.split('=', 1)
                    env_dict[key] = value
            
            return env_dict
        except Exception as e:
            logger.error(f"Failed to extract environment variables: {e}")
            return {}
    
    def _extract_port_mappings(self, container) -> List[Dict[str, Any]]:
        """Extract port mappings from container"""
        try:
            port_mappings = []
            network_settings = container.attrs.get('NetworkSettings', {})
            ports = network_settings.get('Ports', {})
            
            for container_port, host_bindings in ports.items():
                mapping = {
                    'container_port': int(container_port.split('/')[0]),
                    'protocol': container_port.split('/')[1] if '/' in container_port else 'tcp',
                    'host_bindings': []
                }
                
                if host_bindings:
                    for binding in host_bindings:
                        mapping['host_bindings'].append({
                            'host_ip': binding.get('HostIp', '0.0.0.0'),
                            'host_port': int(binding.get('HostPort', 0))
                        })
                
                port_mappings.append(mapping)
            
            return port_mappings
        except Exception as e:
            logger.error(f"Failed to extract port mappings: {e}")
            return []
    
    def _extract_mounts(self, container) -> List[Dict[str, Any]]:
        """Extract mount information from container"""
        try:
            mounts = []
            for mount in container.attrs.get('Mounts', []):
                mounts.append({
                    'type': mount.get('Type'),
                    'source': mount.get('Source'),
                    'destination': mount.get('Destination'),
                    'mode': mount.get('Mode'),
                    'rw': mount.get('RW', True),
                    'propagation': mount.get('Propagation', '')
                })
            return mounts
        except Exception as e:
            logger.error(f"Failed to extract mounts: {e}")
            return []
    
    def _extract_network_settings(self, container) -> Dict[str, Any]:
        """Extract network settings from container"""
        try:
            network_settings = container.attrs.get('NetworkSettings', {})
            return {
                'ip_address': network_settings.get('IPAddress', ''),
                'gateway': network_settings.get('Gateway', ''),
                'bridge': network_settings.get('Bridge', ''),
                'networks': {
                    name: {
                        'ip_address': network.get('IPAddress', ''),
                        'gateway': network.get('Gateway', ''),
                        'mac_address': network.get('MacAddress', ''),
                        'network_id': network.get('NetworkID', '')
                    }
                    for name, network in network_settings.get('Networks', {}).items()
                }
            }
        except Exception as e:
            logger.error(f"Failed to extract network settings: {e}")
            return {}
    
    def _get_container_stats(self, container) -> Dict[str, Any]:
        """Get real-time container resource usage stats"""
        try:
            if container.status != 'running':
                return {'status': 'not_running'}
            
            stats = container.stats(stream=False)
            
            # CPU usage
            cpu_usage = 0
            if 'cpu_stats' in stats and 'precpu_stats' in stats:
                cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
                system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
                if system_delta > 0:
                    cpu_usage = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage'].get('percpu_usage', [1])) * 100
            
            # Memory usage
            memory_usage = 0
            memory_limit = 0
            if 'memory_stats' in stats:
                memory_usage = stats['memory_stats'].get('usage', 0)
                memory_limit = stats['memory_stats'].get('limit', 0)
            
            # Network I/O
            network_rx = 0
            network_tx = 0
            if 'networks' in stats:
                for interface, data in stats['networks'].items():
                    network_rx += data.get('rx_bytes', 0)
                    network_tx += data.get('tx_bytes', 0)
            
            # Block I/O
            block_read = 0
            block_write = 0
            if 'blkio_stats' in stats and 'io_service_bytes_recursive' in stats['blkio_stats']:
                for item in stats['blkio_stats']['io_service_bytes_recursive']:
                    if item['op'] == 'Read':
                        block_read += item['value']
                    elif item['op'] == 'Write':
                        block_write += item['value']
            
            return {
                'status': 'running',
                'cpu_percent': round(cpu_usage, 2),
                'memory_usage_bytes': memory_usage,
                'memory_limit_bytes': memory_limit,
                'memory_percent': round((memory_usage / memory_limit * 100), 2) if memory_limit > 0 else 0,
                'network_rx_bytes': network_rx,
                'network_tx_bytes': network_tx,
                'block_read_bytes': block_read,
                'block_write_bytes': block_write,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get container stats: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def _get_container_health(self, container) -> Dict[str, Any]:
        """Get container health status"""
        try:
            state = container.attrs['State']
            health = state.get('Health', {})
            
            return {
                'status': health.get('Status', 'none'),
                'failing_streak': health.get('FailingStreak', 0),
                'log': health.get('Log', [])[-3:] if health.get('Log') else []  # Last 3 health checks
            }
        except Exception as e:
            logger.error(f"Failed to get container health: {e}")
            return {'status': 'unknown'}
    
    
    
    
    
    
    def get_container_logs(self, container_id: str, lines: int = 100) -> str:
        """Get container logs"""
        if not self.is_connected:
            return "Not connected to Docker daemon"
        
        try:
            container = self.client.containers.get(container_id)
            logs = container.logs(tail=lines, timestamps=True).decode('utf-8')
            return logs
        except Exception as e:
            logger.error(f"Failed to get container logs: {e}")
            return f"Error retrieving logs: {str(e)}"
    
    def execute_container_command(self, container_id: str, command: str) -> Dict[str, Any]:
        """Execute command in container"""
        if not self.is_connected:
            return {'error': 'Not connected to Docker daemon'}
        
        try:
            container = self.client.containers.get(container_id)
            
            if container.status != 'running':
                return {'error': 'Container is not running'}
            
            exec_result = container.exec_run(command)
            
            return {
                'exit_code': exec_result.exit_code,
                'output': exec_result.output.decode('utf-8') if exec_result.output else ''
            }
        except Exception as e:
            logger.error(f"Failed to execute command in container: {e}")
            return {'error': str(e)}


# Global instance
docker_integration = DockerIntegration()