#!/usr/bin/env python3
"""
VYN v1.2 - Docker Helper Module
Natural language to Docker command translation.
Specialized for homelab management.
"""

import re
import subprocess
import shutil
from typing import Dict, Optional, List, Tuple

class DockerHelper:
    """
    Translates natural language requests into Docker commands.
    Designed for homelab users who want to manage containers conversationally.
    """
    
    # Valid Docker container/service identifier (prevents invalid names and shell injection)
    VALID_TARGET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
    
    # Reserved command words that should not be treated as a container/service name
    RESERVED_TARGETS = frozenset({
        'de', 'del', 'el', 'la', 'los', 'las', 'un', 'una', 'en', 'puerto', 'port',
        'contenedor', 'contenedores', 'container', 'containers', 'servicio', 'servicios',
        'docker', 'status', 'estado', 'estados', 'stats', 'recursos', 'imagenes', 'images',
        'logs', 'registros',
    })
    
    # Common service templates for quick deployment
    SERVICE_TEMPLATES = {
        'nextcloud': {
            'image': 'nextcloud',
            'ports': ['8080:80'],
            'volumes': ['nextcloud_data:/var/www/html'],
            'description': 'Self-hosted cloud storage'
        },
        'jellyfin': {
            'image': 'jellyfin/jellyfin',
            'ports': ['8096:8096'],
            'volumes': ['/media:/media:ro', 'jellyfin_config:/config'],
            'description': 'Media server'
        },
        'plex': {
            'image': 'plexinc/pms-docker',
            'ports': ['32400:32400'],
            'volumes': ['/media:/media:ro', 'plex_config:/config'],
            'description': 'Media server'
        },
        'nginx': {
            'image': 'nginx:alpine',
            'ports': ['80:80', '443:443'],
            'volumes': ['nginx_conf:/etc/nginx'],
            'description': 'Web server / Reverse proxy'
        },
        'traefik': {
            'image': 'traefik:v2.10',
            'ports': ['80:80', '443:443', '8080:8080'],
            'volumes': ['/var/run/docker.sock:/var/run/docker.sock:ro'],
            'description': 'Reverse proxy with auto-discovery'
        },
        'portainer': {
            'image': 'portainer/portainer-ce',
            'ports': ['9000:9000'],
            'volumes': ['/var/run/docker.sock:/var/run/docker.sock', 'portainer_data:/data'],
            'description': 'Docker management UI'
        },
        'watchtower': {
            'image': 'containrrr/watchtower',
            'volumes': ['/var/run/docker.sock:/var/run/docker.sock'],
            'description': 'Auto-update containers'
        },
        'postgres': {
            'image': 'postgres:15',
            'ports': ['5432:5432'],
            'env': {'POSTGRES_PASSWORD': 'changeme'},
            'volumes': ['postgres_data:/var/lib/postgresql/data'],
            'description': 'PostgreSQL database'
        },
        'mariadb': {
            'image': 'mariadb:10',
            'ports': ['3306:3306'],
            'env': {'MARIADB_ROOT_PASSWORD': 'changeme'},
            'volumes': ['mariadb_data:/var/lib/mysql'],
            'description': 'MariaDB database'
        },
        'redis': {
            'image': 'redis:alpine',
            'ports': ['6379:6379'],
            'description': 'In-memory cache/database'
        },
        'pihole': {
            'image': 'pihole/pihole',
            'ports': ['53:53/tcp', '53:53/udp', '80:80'],
            'env': {'WEBPASSWORD': 'changeme'},
            'description': 'Network-wide ad blocker'
        },
        'homeassistant': {
            'image': 'homeassistant/home-assistant',
            'ports': ['8123:8123'],
            'volumes': ['homeassistant_config:/config'],
            'description': 'Home automation'
        }
    }
    
    # Natural language patterns for Docker operations
    NL_PATTERNS = {
        'run': [
            r'\b(?:levanta|inicia|crea|lanza|ejecuta|run|start|create)\s+(?:un\s+|el\s+)?(?:contenedor\s+(?:de\s+)?|servicio\s+(?:de\s+)?)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
            r'\b(?:deploy|despliega)\s+(?:el\s+)?(?:servicio\s+|contenedor\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
        ],
        'stop': [
            r'\b(?:para|detén|deten|stop)\s+(?:el\s+)?(?:contenedor\s+|servicio\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
        ],
        'restart': [
            r'\b(?:reinicia|restart)\s+(?:el\s+)?(?:contenedor\s+|servicio\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
        ],
        'remove': [
            r'\b(?:elimina|borra|remove|rm)\s+(?:el\s+)?(?:contenedor\s+|servicio\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
        ],
        'logs': [
            r'\b(?:logs?|registros?)\s+(?:de\s+|del\s+)?(?:contenedor\s+|servicio\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
            r'\b(?:muestra|ver)\s+(?:los\s+)?logs?\s+(?:de\s+|del\s+)?(?:contenedor\s+|servicio\s+)?([a-zA-Z0-9][a-zA-Z0-9_.-]*)',
        ],
        'status': [
            r'\b(?:status|estado|estados)\b\s*(?:de\s+)?(?:los\s+)?(?:contenedores?)?',
            r'\b(?:muestra|lista|ver)\s+(?:los\s+)?contenedores?\b',
            r'\bdocker\s+ps\b',
        ],
        'images': [
            r'\b(?:imagenes|imágenes|images)\b\s*(?:de\s+docker)?',
            r'\b(?:lista|muestra)\s+(?:las\s+)?(?:imagenes|imágenes)\b',
        ],
        'stats': [
            r'\b(?:recursos|resources|stats)\b\s*(?:de\s+)?(?:los\s+)?(?:contenedores?)?',
            r'\b(?:consumo|uso)\s+(?:de\s+)?(?:recursos|memoria|cpu)\b',
        ],
    }
    
    def __init__(self, console=None):
        self.console = console
        self._check_docker()
    
    def _check_docker(self) -> bool:
        """Check if Docker is available."""
        self.docker_available = shutil.which('docker') is not None
        return self.docker_available
    
    def log(self, message: str, style: str = ""):
        """Print message using rich console if available."""
        if self.console:
            if style:
                self.console.print(f"[{style}]{message}[/{style}]")
            else:
                self.console.print(message)
        else:
            print(message)
    
    @classmethod
    def is_valid_target(cls, target: Optional[str]) -> bool:
        """Return True if target is a safe, non-reserved container/service identifier."""
        if not target:
            return False
        lowered = target.lower()
        if lowered in cls.RESERVED_TARGETS:
            return False
        return bool(cls.VALID_TARGET_RE.match(target))

    @staticmethod
    def is_valid_port(port: Optional[str]) -> bool:
        """Return True if port is a valid TCP/UDP port in range 1..65535."""
        if port is None or not str(port).isdigit():
            return False
        port_num = int(port)
        return 1 <= port_num <= 65535

    def parse_natural_language(self, query: str) -> Tuple[Optional[str], Optional[str], Dict]:
        """
        Parse natural language query into Docker operation.
        
        Args:
            query: Natural language query
            
        Returns:
            Tuple of (operation, target, options)
        """
        query_lower = (query or "").lower().strip()
        if not query_lower:
            return (None, None, {})
        
        # Reject queries containing shell metacharacters or control characters
        if any(ch in query_lower for ch in (";", "|", "&", "$", "`", ">", "<", "\n", "\r")):
            return (None, None, {})
        
        # Try to match each operation pattern
        for operation, patterns in self.NL_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, query_lower)
                if match:
                    target = match.group(1) if match.groups() else None
                    if target is not None and not self.is_valid_target(target):
                        continue
                    
                    # Extract port if mentioned
                    options = {}
                    port_match = re.search(r'\b(?:puerto|port)\s+(\d+)\b', query_lower)
                    if port_match:
                        port_str = port_match.group(1)
                        if not self.is_valid_port(port_str):
                            return (None, None, {})
                        options['port'] = port_str
                    
                    return (operation, target, options)
        
        return (None, None, {})
    
    def get_docker_command(self, query: str) -> Optional[str]:
        """
        Convert natural language query to Docker command.
        
        Args:
            query: Natural language query
            
        Returns:
            Docker command string or None
        """
        operation, target, options = self.parse_natural_language(query)
        
        if not operation:
            return None
        
        if operation == 'status':
            return 'docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
        
        if operation == 'images':
            return 'docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"'
        
        if operation == 'stats':
            return 'docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"'
        
        if not target or not self.is_valid_target(target):
            return None
        if 'port' in options and not self.is_valid_port(options['port']):
            return None
        
        if operation == 'run':
            return self._build_run_command(target, options)
        elif operation == 'stop':
            return f'docker stop {target}'
        elif operation == 'restart':
            return f'docker restart {target}'
        elif operation == 'remove':
            return f'docker rm -f {target}'
        elif operation == 'logs':
            return f'docker logs --tail 50 {target}'
        
        return None
    
    def _build_run_command(self, service: str, options: Dict) -> str:
        """Build docker run command for a service."""
        service_lower = service.lower()
        
        # Check if it's a known service
        if service_lower in self.SERVICE_TEMPLATES:
            template = self.SERVICE_TEMPLATES[service_lower]
            
            cmd_parts = ['docker run -d']
            cmd_parts.append(f'--name {service_lower}')
            
            # Handle ports
            ports = template.get('ports', [])
            if options.get('port') and ports:
                # Replace first port with custom port
                custom_port = options['port']
                first_port = ports[0].split(':')[1] if ':' in ports[0] else ports[0]
                cmd_parts.append(f'-p {custom_port}:{first_port}')
                for port in ports[1:]:
                    cmd_parts.append(f'-p {port}')
            else:
                for port in ports:
                    cmd_parts.append(f'-p {port}')
            
            # Handle volumes
            for volume in template.get('volumes', []):
                cmd_parts.append(f'-v {volume}')
            
            # Handle environment variables
            for key, value in template.get('env', {}).items():
                cmd_parts.append(f'-e {key}={value}')
            
            cmd_parts.append(template['image'])
            
            return ' '.join(cmd_parts)
        else:
            # Unknown service - try to pull and run
            port = options.get('port', '8080')
            return f'docker run -d --name {service} -p {port}:80 {service}'
    
    def list_available_services(self) -> List[Dict]:
        """Get list of available service templates."""
        return [
            {'name': name, **template}
            for name, template in self.SERVICE_TEMPLATES.items()
        ]
    
    def get_container_status(self, local: bool = True) -> Dict:
        """
        Get status of all Docker containers.
        
        Args:
            local: If True, run locally. Otherwise return command for remote execution.
            
        Returns:
            Dict with container statuses
        """
        if not local:
            return {'command': 'docker ps -a --format "{{.Names}}|{{.Status}}|{{.Ports}}"'}
        
        if not self.docker_available:
            return {'error': 'Docker not installed', 'containers': []}
        
        try:
            result = subprocess.run(
                ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Status}}|{{.Ports}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        containers.append({
                            'name': parts[0],
                            'status': parts[1],
                            'ports': parts[2] if len(parts) > 2 else ''
                        })
            
            return {'containers': containers}
            
        except Exception as e:
            return {'error': str(e), 'containers': []}
    
    def get_resource_usage(self, local: bool = True) -> Dict:
        """
        Get resource usage of running containers.
        
        Args:
            local: If True, run locally.
            
        Returns:
            Dict with resource usage
        """
        if not local:
            return {'command': 'docker stats --no-stream --format "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}"'}
        
        if not self.docker_available:
            return {'error': 'Docker not installed', 'stats': []}
        
        try:
            result = subprocess.run(
                ['docker', 'stats', '--no-stream', '--format', '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            stats = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 3:
                        stats.append({
                            'name': parts[0],
                            'cpu': parts[1],
                            'memory': parts[2]
                        })
            
            return {'stats': stats}
            
        except Exception as e:
            return {'error': str(e), 'stats': []}
    
    def explain_command(self, command: str) -> str:
        """
        Explain what a Docker command does.
        
        Args:
            command: Docker command
            
        Returns:
            Explanation string
        """
        parts = command.split()
        if len(parts) < 2:
            return "Comando Docker"
        
        subcommand = parts[1]
        
        explanations = {
            'run': 'Crear y ejecutar un nuevo contenedor',
            'start': 'Iniciar un contenedor detenido',
            'stop': 'Detener un contenedor en ejecución',
            'restart': 'Reiniciar un contenedor',
            'rm': 'Eliminar un contenedor',
            'rmi': 'Eliminar una imagen',
            'pull': 'Descargar una imagen',
            'push': 'Subir una imagen',
            'build': 'Construir una imagen desde Dockerfile',
            'ps': 'Listar contenedores',
            'images': 'Listar imágenes',
            'logs': 'Ver logs de un contenedor',
            'exec': 'Ejecutar un comando dentro de un contenedor',
            'stats': 'Ver uso de recursos en tiempo real',
            'network': 'Gestionar redes Docker',
            'volume': 'Gestionar volúmenes Docker',
            'compose': 'Gestionar multi-contenedor con Compose',
        }
        
        return explanations.get(subcommand, f'Docker {subcommand}')


def create_docker_helper(console=None) -> DockerHelper:
    """Factory function to create DockerHelper instance."""
    return DockerHelper(console)
