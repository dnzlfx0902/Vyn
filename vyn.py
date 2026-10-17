#!/usr/bin/env python3

import sys
import json
import ollama
import signal
from pathlib import Path
from datetime import datetime, timedelta
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
import psutil

console = Console()

def check_first_run():
    config_file = Path.home() / ".config" / "vyn" / "config.json"
    return not config_file.exists()

def load_config():
    config_file = Path.home() / ".config" / "vyn" / "config.json"
    
    if not config_file.exists():
        console.print("[red]❌ No se encontró configuración.[/red]")
        console.print("[yellow]Ejecuta el setup wizard:[/yellow]")
        console.print("  [cyan]python setup_wizard.py[/cyan]\n")
        sys.exit(1)
    
    with open(config_file, 'r') as f:
        config = json.load(f)
    
    if config.get('homelab', {}).get('ssh_key'):
        config['homelab']['ssh_key'] = str(Path(config['homelab']['ssh_key']).expanduser())
    
    if config.get('memory', {}).get('database'):
        config['memory']['database'] = str(Path(config['memory']['database']).expanduser())
        
    return config

GLOBAL_CLEANUP_STATE = {
    'search_engine': None,
    'homelab': None,
    'memory': None,
    'messages': [],
    'current_model': None
}

def graceful_shutdown():
    console.print("\n[yellow]═══ GRACEFUL SHUTDOWN ═══[/yellow]")
    
    if GLOBAL_CLEANUP_STATE.get('search_engine'):
        GLOBAL_CLEANUP_STATE['search_engine'].close()
        console.print("[green]✓[/green] Search engine cerrado")
    
    if GLOBAL_CLEANUP_STATE.get('homelab'):
        GLOBAL_CLEANUP_STATE['homelab'].close()
        console.print("[green]✓[/green] HomeLab cerrado")
    
    if GLOBAL_CLEANUP_STATE.get('memory'):
        GLOBAL_CLEANUP_STATE['memory'].close()
        console.print("[green]✓[/green] Memoria cerrada")
    
    console.print("[yellow]═══ SHUTDOWN COMPLETE ═══[/yellow]\n")
    sys.exit(0)

def signal_handler(sig, frame):
    graceful_shutdown()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if check_first_run():
        console.print("""
[bold cyan]╔══════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║           VYN v1.2 - AI Assistant System                 ║[/bold cyan]
[bold cyan]╚══════════════════════════════════════════════════════════╝[/bold cyan]

[yellow]¡Primera ejecución detectada![/yellow]

Necesitas configurar VYN antes de usarlo.
Esto solo toma 2 minutos.

[dim]Presiona Enter para iniciar el setup wizard...[/dim]
""")
        input()
        
        import setup_wizard
        wizard = setup_wizard.SetupWizard()
        success = wizard.run()
        
        if not success:
            console.print("[red]Setup incompleto. Por favor, intenta de nuevo.[/red]")
            sys.exit(1)
        
        console.print("\n[green]✨ Setup completado. Iniciando VYN...[/green]\n")
    
    config = load_config()
    
    console.print(f"""
[bold cyan]╔══════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║           VYN v1.2 - AI Assistant System                 ║[/bold cyan]
[bold cyan]║           Configuración: {config['ui']['theme']:^30}║[/bold cyan]
[bold cyan]╚══════════════════════════════════════════════════════════╝[/bold cyan]
""")
    
    from core.search_engine import SearchEngine
    from core.memory import MemoryManager
    from core.sandbox import SandboxExecutor
    
    homelab = None
    if config['homelab']['enabled']:
        from modules.homelab import HomeLab
        homelab = HomeLab(
            config['homelab']['host'],
            config['homelab']['user'],
            config['homelab']['ssh_key']
        )
        GLOBAL_CLEANUP_STATE['homelab'] = homelab
        console.print(f"[green]✓[/green] Home Lab: {config['homelab']['host']}")
    
    search_engine = None
    if config['web_search']['enabled']:
        search_engine = SearchEngine()
        GLOBAL_CLEANUP_STATE['search_engine'] = search_engine
        console.print("[green]✓[/green] Búsqueda web activada")
    
    memory = MemoryManager(config['memory']['database'])
    GLOBAL_CLEANUP_STATE['memory'] = memory
    
    # Initialize sandbox for command execution
    import os
    sandbox = SandboxExecutor(None)
    current_cwd = os.path.expanduser("~")
    
    # Initialize security layer
    from modules.security_layer import SecurityLayer
    security = SecurityLayer(console, config.get('language', 'es'))
    
    console.print("[green]✓[/green] VYN iniciado correctamente\n")
    
    model_roles = {
        'CODING': config['models']['coding'],
        'RESEARCH': config['models']['research'],
        'SYSADMIN': config['models']['sysadmin'],
        'VISION': config['models']['vision']
    }
    
    current_model = config['models']['research']
    GLOBAL_CLEANUP_STATE['current_model'] = current_model
    
    ahora = datetime.now()
    lang = config.get('language', 'es')
    
    if lang == 'es':
        system_prompt = f"""Eres VYN - Asistente IA experto en programación y tecnología.
Fuiste creado por Chriss-devv (GitHub: github.com/Chriss-devv)

HOY: {ahora.strftime("%A %d %B %Y")}

Tu principal fortaleza es generar código de alta calidad. Cuando el usuario pida código:
- Genera código completo y funcional
- Usa buenas prácticas de programación
- Incluye comentarios explicativos si es necesario
- No te niegues a generar código - ES TU TRABAJO

También puedes:
- Resolver problemas técnicos
- Explicar conceptos de programación
- Ayudar con configuración de sistemas
- Buscar información cuando sea necesario

Responde de forma directa y útil. Sin emojis."""
    else:
        system_prompt = f"""You are VYN - AI Assistant expert in programming and technology.
You were created by Chriss-devv (GitHub: github.com/Chriss-devv)

TODAY: {ahora.strftime("%A %B %d, %Y")}

Your main strength is generating high-quality code. When the user asks for code:
- Generate complete and functional code
- Use good programming practices
- Include explanatory comments if necessary
- Do not refuse to generate code - IT'S YOUR JOB

You can also:
- Solve technical problems
- Explain programming concepts
- Help with system configuration
- Search for information when necessary

Respond directly and helpfully. No emojis."""

    messages = [{"role": "system", "content": system_prompt}]
    GLOBAL_CLEANUP_STATE['messages'] = messages
    
    mensaje_count = 0
    
    def detect_intent(text):
        text_lower = text.lower()
        
        coding_keywords = ['código', 'codigo', 'programa', 'script', 'función', 'funcion',
                          'class', 'def ', 'python', 'javascript', 'java', 'c++', 'rust',
                          'html', 'css', 'react', 'vue', 'angular', 'django', 'flask',
                          'api', 'database', 'sql', 'code', 'programming', 'develop',
                          'app', 'aplicación', 'aplicacion', 'web', 'frontend', 'backend',
                          'bug', 'error', 'fix', 'arregla', 'corrige', 'implementa',
                          'crea un', 'hazme un', 'genera', 'escribe', 'write', 'create',
                          'game', 'juego', 'gta', 'pygame', 'unity']
        
        research_keywords = ['busca', 'investiga', 'información', 'informacion', 'noticias',
                            'qué es', 'que es', 'quién es', 'quien es', 'search', 'find',
                            'explain', 'explica', 'define', 'letra', 'lyrics', 'song']
        
        sysadmin_keywords = ['servidor', 'server', 'docker', 'linux', 'ssh', 'homelab',
                            'terminal', 'bash', 'shell', 'systemctl', 'nginx', 'apache',
                            'firewall', 'network', 'red', 'ip', 'dns', 'temperatura',
                            'cpu', 'ram', 'disco', 'disk']
        
        vision_keywords = ['imagen', 'image', 'foto', 'photo', 'screenshot', 'captura',
                          'analiza', 'analyze', 'qué ves', 'que ves', 'what do you see',
                          '.png', '.jpg', '.jpeg', '.webp', '.gif']
        
        if any(kw in text_lower for kw in coding_keywords):
            return 'CODING'
        elif any(kw in text_lower for kw in vision_keywords):
            return 'VISION'
        elif any(kw in text_lower for kw in sysadmin_keywords):
            return 'SYSADMIN'
        elif any(kw in text_lower for kw in research_keywords):
            return 'RESEARCH'
        
        return 'GENERAL'
    
    from i18n import TRANSLATIONS
    def tr(key):
        return TRANSLATIONS.get(lang, TRANSLATIONS['es']).get(key, key)
    
    commands_table = Table(show_header=True, header_style="bold magenta", box=None)
    cmd_header = "Command" if lang == 'en' else "Comando"
    desc_header = "Description" if lang == 'en' else "Descripción"
    commands_table.add_column(cmd_header, style="cyan")
    commands_table.add_column(desc_header, style="dim")
    
    commands_table.add_row("salir/exit/quit", tr('cmd_exit'))
    commands_table.add_row("limpiar/clear", tr('cmd_clear'))
    commands_table.add_row("guardar/save", tr('cmd_save'))
    commands_table.add_row("modelos/models", tr('cmd_models'))
    commands_table.add_row("cambiar/switch", tr('cmd_change'))
    commands_table.add_row("roles", "Reconfigurar roles de auto-switch")
    commands_table.add_row("estado", "Ver estadísticas de la sesión")
    commands_table.add_row("audit", "Ver historial de comandos")
    commands_table.add_row("config", tr('cmd_config'))
    commands_table.add_row("reconfig", tr('cmd_reconfig'))
    commands_table.add_row("sandbox", "Abrir sandbox interactivo")
    commands_table.add_row("shell", "Shell interactivo con IA")
    commands_table.add_row("docker", "Gestión de contenedores (lenguaje natural)")
    commands_table.add_row("run <cmd>", "Ejecutar comando del sistema")
    commands_table.add_row("```", "Modo multi-línea (pegar código)")
    commands_table.add_row("help", tr('cmd_help'))
    
    console.print(f"[bold cyan]{tr('commands_available')}[/bold cyan]")
    console.print(commands_table)
    console.print()
    
    def get_installed_models():
        import subprocess
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return []
            lines = result.stdout.strip().split('\n')
            models = []
            for line in lines[1:]:
                if line.strip():
                    parts = line.split()
                    if parts:
                        models.append(parts[0])
            return models
        except Exception:
            return []
    
    while True:
        try:
            user_input = console.input("\n[bold green]>[/bold green] ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ["salir", "exit", "quit"]:
                graceful_shutdown()
            
            if user_input.lower() in ["limpiar", "clear"]:
                messages = [messages[0]]
                mensaje_count = 0
                console.print("[green]Historial limpiado[/green]")
                continue
            
            if user_input.lower() == "help":
                console.print("\n[bold cyan]Comandos de VYN:[/bold cyan]")
                console.print(commands_table)
                continue
            
            if user_input.lower() == "config":
                console.print(json.dumps(config, indent=2))
                continue
            
            if user_input.lower() == "reconfig":
                import setup_wizard
                wizard = setup_wizard.SetupWizard()
                wizard.run()
                config = load_config()
                console.print("[green]✓[/green] Configuración actualizada")
                continue
            
            # Roles command - reconfigure model roles
            if user_input.lower() == "roles":
                console.print("\n[bold cyan]Configurar roles de modelos[/bold cyan]")
                installed = get_installed_models()
                for i, m in enumerate(installed, 1):
                    console.print(f"  {i}. {m}")
                
                for role in ['CODING', 'RESEARCH', 'SYSADMIN', 'VISION']:
                    console.print(f"\n[cyan]{role}[/cyan] (actual: {model_roles.get(role, 'ninguno')})")
                    console.print("Número del modelo (Enter para mantener): ", end="")
                    try:
                        choice = input().strip()
                        if choice and choice.isdigit():
                            idx = int(choice) - 1
                            if 0 <= idx < len(installed):
                                model_roles[role] = installed[idx]
                                console.print(f"[green]✓ {role} = {installed[idx]}[/green]")
                    except:
                        pass
                continue
            
            # Estado command - show statistics
            if user_input.lower() == "estado":
                try:
                    ram = psutil.virtual_memory()
                    cpu = psutil.cpu_percent(interval=0)  # Non-blocking
                    ram_pct = f"{ram.percent:.1f}%"
                    cpu_pct = f"{cpu:.1f}%"
                except:
                    ram_pct = "N/A"
                    cpu_pct = "N/A"
                console.print(f"""
[bold cyan]Estado de VYN v1.2[/bold cyan]
├─ Modelo: {current_model}
├─ Mensajes: {mensaje_count}
├─ RAM: {ram_pct}
├─ CPU: {cpu_pct}
└─ Roles: CODING={model_roles.get('CODING', '-')}, RESEARCH={model_roles.get('RESEARCH', '-')}
""")
                continue
            
            # Audit command - view security audit history
            if user_input.lower() == "audit":
                history = security.get_audit_history(limit=20)
                if not history:
                    console.print("[dim]No hay historial de auditoría.[/dim]")
                else:
                    audit_table = Table(title="Historial de Seguridad", show_header=True, header_style="bold magenta")
                    audit_table.add_column("Fecha", style="dim", width=16)
                    audit_table.add_column("Comando", style="cyan", max_width=40)
                    audit_table.add_column("Riesgo", width=10)
                    audit_table.add_column("Ejecutado", width=10)
                    
                    for entry in history[-10:]:  # Show last 10
                        timestamp = entry.get('timestamp', '')[:16].replace('T', ' ')
                        cmd = entry.get('command', '')[:40]
                        risk = entry.get('risk', 'N/A')
                        executed = "[green]✓[/green]" if entry.get('executed') else "[red]✗[/red]"
                        
                        risk_style = {
                            'LOW': '[green]LOW[/green]',
                            'MEDIUM': '[yellow]MEDIUM[/yellow]',
                            'HIGH': '[orange1]HIGH[/orange1]',
                            'CRITICAL': '[red]CRITICAL[/red]'
                        }.get(risk, risk)
                        
                        audit_table.add_row(timestamp, cmd, risk_style, executed)
                    
                    console.print(audit_table)
                    console.print(f"[dim]Archivo: {security.AUDIT_FILE}[/dim]")
                continue
            
            # Docker command - natural language Docker management
            if user_input.lower().startswith("docker"):
                from modules.docker_helper import DockerHelper
                docker = DockerHelper(console)
                
                if not docker.docker_available:
                    console.print("[red]Docker no está instalado en este sistema.[/red]")
                    console.print("[dim]Instala Docker: curl -fsSL https://get.docker.com | sh[/dim]")
                    continue
                
                query = user_input[6:].strip() if len(user_input) > 6 else ""
                
                if not query or query.lower() in ['help', 'ayuda']:
                    # Show docker help
                    console.print("\n[bold cyan]═══ Docker Helper (Lenguaje Natural) ═══[/bold cyan]\n")
                    console.print("[yellow]Ejemplos:[/yellow]")
                    console.print("  • docker status           - Ver contenedores")
                    console.print("  • docker stats            - Ver uso de recursos")
                    console.print("  • docker levanta nextcloud en puerto 8080")
                    console.print("  • docker para nginx")
                    console.print("  • docker logs portainer")
                    console.print("  • docker reinicia jellyfin")
                    console.print("  • docker servicios        - Ver templates disponibles")
                    console.print()
                    continue
                
                if query.lower() in ['servicios', 'services', 'templates']:
                    # Show available service templates
                    console.print("\n[bold cyan]Servicios disponibles:[/bold cyan]\n")
                    services_table = Table(show_header=True, header_style="bold magenta")
                    services_table.add_column("Servicio", style="cyan")
                    services_table.add_column("Imagen", style="green")
                    services_table.add_column("Puertos")
                    services_table.add_column("Descripción", style="dim")
                    
                    for svc in docker.list_available_services():
                        ports = ', '.join(svc.get('ports', [])[:2])
                        services_table.add_row(
                            svc['name'],
                            svc['image'],
                            ports,
                            svc['description']
                        )
                    
                    console.print(services_table)
                    console.print("\n[dim]Uso: docker levanta <servicio> en puerto <num>[/dim]")
                    continue
                
                # Try to parse natural language
                docker_cmd = docker.get_docker_command(query)
                
                if docker_cmd:
                    console.print(f"\n[cyan]Comando generado:[/cyan] {docker_cmd}")
                    
                    # Check security (gate any non-LOW risk: MEDIUM, HIGH, CRITICAL)
                    risk, reason = security.classify_risk(docker_cmd)
            
                    if risk != security.RISK_LOW:
                        explanation = security.explain_command(docker_cmd)
                        console.print(f"\n[bold yellow]⚠ Comando {risk}:[/bold yellow] {explanation}")
                        if reason:
                            console.print(f"[yellow]Riesgo:[/yellow] {reason}")
                        if risk == security.RISK_CRITICAL:
                            console.print("\n[bold red]Escribir 'CONFIRMO' para ejecutar:[/bold red] ", end="")
                            confirmed = input().strip() == "CONFIRMO"
                        else:
                            console.print("\n[cyan]¿Ejecutar? (s/n):[/cyan] ", end="")
                            confirmed = input().strip().lower() in ['s', 'si', 'y', 'yes']
                        if not confirmed:
                            console.print("[green]Cancelado.[/green]")
                            security.audit_log(docker_cmd, risk, False, False)
                            continue
                    
                    # Execute
                    result = sandbox.execute_command_realtime(docker_cmd, shell=True, cwd=current_cwd)
                    security.audit_log(docker_cmd, risk, True, True, result)
                else:
                    # Show status as fallback
                    console.print("\n[cyan]Estado de contenedores:[/cyan]")
                    result = sandbox.execute_command_realtime(
                        'docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"',
                        shell=True, cwd=current_cwd
                    )
                continue
            
            # Sandbox command
            if user_input.lower() == "sandbox":
                console.print("\n[cyan]═══════════════ SANDBOX ═══════════════[/cyan]")
                console.print("[dim]Ejecuta código Python. 'exit' para salir.[/dim]\n")
                
                while True:
                    console.print("[green]>>> [/green]", end="")
                    try:
                        code = input().strip()
                        if code.lower() == 'exit':
                            break
                        if code:
                            result = sandbox.execute_code(code)
                            if result.get('output'):
                                console.print(result['output'])
                            if result.get('error'):
                                console.print(f"[red]{result['error']}[/red]")
                    except KeyboardInterrupt:
                        console.print("\n[yellow]Ctrl+C - 'exit' para salir[/yellow]")
                    except EOFError:
                        break
                
                console.print("[cyan]═══════════════ FIN SANDBOX ═══════════════[/cyan]\n")
                continue
            
            # Multi-line mode
            if user_input.strip() == "```":
                console.print("[dim]Modo multi-línea. Termina con ``` en línea sola.[/dim]")
                lines = []
                while True:
                    try:
                        line = input()
                        if line.strip() == "```":
                            break
                        lines.append(line)
                    except EOFError:
                        break
                user_input = "\n".join(lines)
                if not user_input.strip():
                    continue
            if user_input.lower() == "guardar":
                save_dir = Path.home() / ".config" / "vyn" / "sessions"
                save_dir.mkdir(parents=True, exist_ok=True)
                filename = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                filepath = save_dir / filename
                with open(filepath, 'w') as f:
                    json.dump({
                        'messages': messages,
                        'model': current_model,
                        'timestamp': datetime.now().isoformat()
                    }, f, indent=2)
                console.print(f"[green]✓[/green] Sesión guardada: {filepath}")
                continue
            
            if user_input.lower() == "modelos":
                available = get_installed_models()
                if available:
                    table = Table(title="Modelos Instalados", show_header=True, header_style="bold magenta")
                    table.add_column("#", style="cyan", width=4)
                    table.add_column("Modelo", style="green")
                    for idx, m in enumerate(available, 1):
                        marker = " [cyan](activo)[/cyan]" if m == current_model else ""
                        table.add_row(str(idx), f"{m}{marker}")
                    console.print(table)
                else:
                    console.print("[red]No se encontraron modelos instalados[/red]")
                continue
            
            if user_input.lower() == "cambiar":
                available = get_installed_models()
                if not available:
                    console.print("[red]No hay modelos instalados[/red]")
                    continue
                
                table = Table(title="Modelos", show_header=True, header_style="bold magenta")
                table.add_column("#", style="cyan", width=4)
                table.add_column("Modelo", style="green")
                for idx, m in enumerate(available, 1):
                    table.add_row(str(idx), m)
                console.print(table)
                
                try:
                    choice = console.input("[cyan]Selecciona modelo (número):[/cyan] ").strip()
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(available):
                        current_model = available[choice_num - 1]
                        GLOBAL_CLEANUP_STATE['current_model'] = current_model
                        console.print(f"[green]✓[/green] Modelo cambiado a: {current_model}")
                    else:
                        console.print("[red]Número inválido[/red]")
                except ValueError:
                    console.print("[red]Entrada inválida[/red]")
                except KeyboardInterrupt:
                    console.print("\n[yellow]Cancelado[/yellow]")
                continue
            
            # ============================================================
            # SHELL MODE - Interactive command execution with AI feedback
            # ============================================================
            if user_input.lower() == "shell":
                shell_cwd = current_cwd
                shell_history = []
                
                # Auto-switch to CODING model
                previous_model = current_model
                if model_roles.get('CODING'):
                    current_model = model_roles['CODING']
                    GLOBAL_CLEANUP_STATE['current_model'] = current_model
                    console.print(f"[blue]Auto-switch: {current_model} (CODING)[/blue]")
                
                console.print("\n[cyan]═══════════════ MODO SHELL ═══════════════[/cyan]")
                console.print("[dim]Ejecuta comandos. Después de cada uno, puedes pedir ayuda de IA.[/dim]")
                console.print("[dim]Comandos: edit <archivo>, cd <dir>, exit[/dim]\n")
                
                while True:
                    try:
                        console.print(f"[green]{shell_cwd}$[/green] ", end="")
                        cmd = input().strip()
                        
                        if cmd.lower() == 'exit':
                            break
                        if not cmd:
                            continue
                        
                        # Handle cd
                        if cmd.startswith("cd "):
                            new_path = cmd[3:].strip()
                            if new_path.startswith("~"):
                                new_path = os.path.expanduser(new_path)
                            elif not new_path.startswith("/"):
                                new_path = os.path.join(shell_cwd, new_path)
                            new_path = os.path.normpath(new_path)
                            if os.path.isdir(new_path):
                                shell_cwd = new_path
                                current_cwd = new_path
                            else:
                                console.print(f"[red]No existe: {new_path}[/red]")
                            continue
                        
                        # Handle edit
                        if cmd.startswith("edit "):
                            filepath = cmd[5:].strip()
                            if not filepath.startswith("/"):
                                filepath = os.path.join(shell_cwd, filepath)
                            filepath = os.path.normpath(filepath)
                            
                            if not os.path.isfile(filepath):
                                console.print(f"[red]Archivo no existe: {filepath}[/red]")
                                continue
                            
                            try:
                                with open(filepath, 'r') as f:
                                    content = f.read()
                                
                                console.print(f"\n[cyan]═══ {os.path.basename(filepath)} ({len(content)} chars) ═══[/cyan]")
                                console.print(content[:2000] if len(content) > 2000 else content)
                                console.print(f"[cyan]═══ FIN ═══[/cyan]\n")
                                
                                console.print("[cyan]Opciones: 1) Review IA  2) Modificar  3) Cancelar[/cyan]")
                                console.print("[cyan]Opción:[/cyan] ", end="")
                                option = input().strip()
                                
                                if option == "1":
                                    console.print("[cyan]¿Qué quieres que haga la IA?[/cyan] ", end="")
                                    ai_request = input().strip()
                                    if ai_request:
                                        review_kw = ['opina', 'opinion', 'que tal', 'como ves', 'analiza', 'review']
                                        is_review = any(kw in ai_request.lower() for kw in review_kw)
                                        
                                        if is_review:
                                            ai_query = f"[CODE REVIEW]\n```\n{content[:3000]}\n```\n{ai_request}"
                                            messages.append({"role": "user", "content": ai_query})
                                            console.print(f"[green]═══ ANÁLISIS ═══[/green]")
                                            for chunk in ollama.chat(model=current_model, messages=messages, stream=True):
                                                print(chunk['message']['content'], end="", flush=True)
                                            print()
                                            console.print(f"[green]═══ FIN ═══[/green]")
                                        else:
                                            ai_query = f"[EDIT]\n```\n{content[:3000]}\n```\n{ai_request}\nSolo código, sin explicaciones."
                                            response = ollama.chat(model=current_model, messages=[{"role": "user", "content": ai_query}])
                                            new_content = response['message']['content']
                                            import re as code_re
                                            code_match = code_re.search(r'```[\w]*\n(.*?)```', new_content, code_re.DOTALL)
                                            if code_match:
                                                new_content = code_match.group(1).strip()
                                            console.print(f"[green]═══ CÓDIGO ═══[/green]")
                                            console.print(new_content)
                                            console.print(f"[green]═══ FIN ═══[/green]")
                                            console.print("[cyan]¿Guardar? (s/n):[/cyan] ", end="")
                                            if input().strip().lower() in ['s', 'si', 'y']:
                                                with open(filepath, 'w') as f:
                                                    f.write(new_content)
                                                console.print(f"[green]✅ Guardado[/green]")
                            except Exception as e:
                                console.print(f"[red]Error: {e}[/red]")
                            continue
                        
                        # Security Check (gate any non-LOW risk: MEDIUM, HIGH, CRITICAL)
                        risk, reason = security.classify_risk(cmd)
                        
                        if risk != security.RISK_LOW:
                            # Show command explanation
                            explanation = security.explain_command(cmd)
                            console.print(f"\n[bold yellow]⚠ Comando {risk}[/bold yellow]")
                            console.print(f"[cyan]Acción:[/cyan] {explanation}")
                            if reason:
                                console.print(f"[yellow]Riesgo:[/yellow] {reason}")
                            
                            if risk == security.RISK_CRITICAL:
                                console.print(f"\n[bold red]Escribir 'CONFIRMO' para ejecutar:[/bold red] ", end="")
                                if input().strip() != "CONFIRMO":
                                    console.print("[green]Comando cancelado.[/green]")
                                    security.audit_log(cmd, risk, False, False)
                                    continue
                            else:
                                console.print(f"\n[cyan]¿Ejecutar? (s/n):[/cyan] ", end="")
                                if input().strip().lower() not in ['s', 'si', 'y', 'yes']:
                                    console.print("[green]Comando cancelado.[/green]")
                                    security.audit_log(cmd, risk, False, False)
                                    continue
                        
                        # Execute command
                        result = sandbox.execute_command_realtime(cmd, shell=True, cwd=shell_cwd)
                        shell_history.append({'cmd': cmd, 'success': result['success']})
                        
                        # Audit log the execution
                        security.audit_log(cmd, risk, True, True, result)
                        
                        # Ask for AI feedback
                        console.print("\n[cyan]¿Retroalimentación IA? (s/n):[/cyan] ", end="")
                        try:
                            if input().strip().lower() in ['s', 'si', 'y']:
                                console.print("[cyan]Tu pregunta:[/cyan] ", end="")
                                question = input().strip()
                                if question:
                                    history_ctx = "\n".join([f"$ {h['cmd']}" for h in shell_history[-5:]])
                                    ai_q = f"[SHELL]\n{history_ctx}\nPregunta: {question}"
                                    messages.append({"role": "user", "content": ai_q})
                                    console.print(f"\n[bold cyan]VYN[/bold cyan]: ", end="")
                                    for chunk in ollama.chat(model=current_model, messages=messages, stream=True):
                                        print(chunk['message']['content'], end="", flush=True)
                                    print()
                        except:
                            pass
                        print()
                    except KeyboardInterrupt:
                        console.print("\n[yellow]Ctrl+C - 'exit' para salir[/yellow]")
                    except EOFError:
                        break
                
                if previous_model != current_model:
                    current_model = previous_model
                    GLOBAL_CLEANUP_STATE['current_model'] = current_model
                    console.print(f"[blue]Modelo restaurado: {current_model}[/blue]")
                console.print("\n[cyan]═══════════════ FIN SHELL ═══════════════[/cyan]\n")
                continue
            
            # ============================================================
            # RUN COMMAND - Execute system commands
            # ============================================================
            if user_input.lower().startswith("run "):
                command = user_input[4:].strip()
                if command:
                    if command.startswith("cd "):
                        new_path = command[3:].strip()
                        if new_path.startswith("~"):
                            new_path = os.path.expanduser(new_path)
                        elif not new_path.startswith("/"):
                            new_path = os.path.join(current_cwd, new_path)
                        new_path = os.path.normpath(new_path)
                        if os.path.isdir(new_path):
                            current_cwd = new_path
                            console.print(f"[green]📁 Directorio: {current_cwd}[/green]")
                        else:
                            console.print(f"[red]No existe: {new_path}[/red]")
                        continue
                    
                    console.print(f"[dim]📁 {current_cwd}[/dim]")
                    
                    # Security Check (gate any non-LOW risk: MEDIUM, HIGH, CRITICAL)
                    risk, reason = security.classify_risk(command)
                    
                    if risk != security.RISK_LOW:
                        explanation = security.explain_command(command)
                        console.print(f"\n[bold yellow]⚠ Comando {risk}[/bold yellow]")
                        console.print(f"[cyan]Acción:[/cyan] {explanation}")
                        if reason:
                            console.print(f"[yellow]Riesgo:[/yellow] {reason}")
                        
                        if risk == security.RISK_CRITICAL:
                            console.print(f"\n[bold red]Escribir 'CONFIRMO' para ejecutar:[/bold red] ", end="")
                            if input().strip() != "CONFIRMO":
                                console.print("[green]Comando cancelado.[/green]")
                                security.audit_log(command, risk, False, False)
                                continue
                        else:
                            console.print(f"\n[cyan]¿Ejecutar? (s/n):[/cyan] ", end="")
                            if input().strip().lower() not in ['s', 'si', 'y', 'yes']:
                                console.print("[green]Comando cancelado.[/green]")
                                security.audit_log(command, risk, False, False)
                                continue
                    
                    result = sandbox.execute_command_realtime(command, shell=True, cwd=current_cwd)
                    
                    # Audit log
                    security.audit_log(command, risk, True, True, result)
                    
                    if result['error']:
                        console.print(f"[red]{result['error']}[/red]")
                else:
                    console.print("[yellow]Uso: run <comando>[/yellow]")
                continue
            if config['ui']['show_telemetry'] and (mensaje_count == 0 or mensaje_count % 5 == 0):
                try:
                    ram = psutil.virtual_memory()
                    cpu = psutil.cpu_percent(interval=0)  # Non-blocking
                    
                    telemetry_panel = Panel(
                        f"[green]RAM:[/green] {'█' * int(ram.percent/10)}{'░' * (10-int(ram.percent/10))} {ram.percent:.0f}%\n"
                        f"[blue]CPU:[/blue] {'█' * int(cpu/10)}{'░' * (10-int(cpu/10))} {cpu:.0f}%\n"
                        f"[cyan]Modelo:[/cyan] {current_model}\n"
                        f"[cyan]Mensajes:[/cyan] {mensaje_count}",
                        title="System",
                        border_style="cyan"
                    )
                    console.print(telemetry_panel)
                except:
                    pass  # Skip telemetry if psutil fails
            
            intent = detect_intent(user_input)
            
            if intent == 'CODING' and model_roles.get('CODING'):
                if current_model != model_roles['CODING']:
                    current_model = model_roles['CODING']
                    GLOBAL_CLEANUP_STATE['current_model'] = current_model
                    console.print(f"[blue]Auto-switch: {current_model} (CODING)[/blue]")
            elif intent == 'VISION' and model_roles.get('VISION'):
                if current_model != model_roles['VISION']:
                    current_model = model_roles['VISION']
                    GLOBAL_CLEANUP_STATE['current_model'] = current_model
                    console.print(f"[blue]Auto-switch: {current_model} (VISION)[/blue]")
            elif intent == 'SYSADMIN' and model_roles.get('SYSADMIN'):
                if current_model != model_roles['SYSADMIN']:
                    current_model = model_roles['SYSADMIN']
                    GLOBAL_CLEANUP_STATE['current_model'] = current_model
                    console.print(f"[blue]Auto-switch: {current_model} (SYSADMIN)[/blue]")
            elif intent == 'RESEARCH' and model_roles.get('RESEARCH'):
                if current_model != model_roles['RESEARCH']:
                    current_model = model_roles['RESEARCH']
                    GLOBAL_CLEANUP_STATE['current_model'] = current_model
                    console.print(f"[blue]Auto-switch: {current_model} (RESEARCH)[/blue]")
            
            # Auto-search with SMART DETECTION (v1.1)
            import re
            search_trigger_patterns = [
                r'\bbusca\b', r'\bbúsca\b', r'\binvestiga\b', r'\bnoticias\b',
                r'\bqué pasó\b', r'\bque paso\b', r'\bletra de\b', r'\blyrics\b',
                r'\bcanción\b', r'\binformación\b', r'\binformacion\b',
                r'\bsearch\b', r'\bfind\b', r'\bwhat is\b', r'\bwho is\b'
            ]
            
            user_lower = user_input.lower()
            needs_search = search_engine and any(re.search(pattern, user_lower) for pattern in search_trigger_patterns)
            
            # Context-aware correction detection
            correction_patterns = [r'\bbuscala\b', r'\bbuscalo\b', r'\bbúscala\b', r'\bbúscalo\b']
            is_correction = any(re.search(pattern, user_lower) for pattern in correction_patterns)
            
            user_input_for_search = user_input
            if is_correction and len(messages) > 2:
                for msg in reversed(messages[-6:]):
                    if msg['role'] == 'user' and '===' not in msg['content']:
                        prev_content = msg['content']
                        if 'letra' in prev_content.lower() or 'canción' in prev_content.lower():
                            user_input_for_search = prev_content
                            needs_search = True
                            console.print("[dim]Detectado: corrección, buscando tema anterior[/dim]")
                            break
            
            web_content = None
            
            if needs_search:
                console.print("[blue]Buscando en la web...[/blue]")
                
                try:
                    search_result = search_engine.search(user_input_for_search, max_results=5, messages=messages)
                    
                    if search_result.get('error'):
                        console.print(f"[yellow]Error de búsqueda: {search_result['error']}[/yellow]")
                    elif search_result.get('extracted_content') or search_result.get('results'):
                        console.print(f"[dim]Query: '{search_result.get('optimized_query', user_input)}'[/dim]")
                        
                        synthesized = search_engine.synthesize_results(search_result)
                        
                        console.print("\n[cyan]== RESULTADOS WEB ==[/cyan]")
                        console.print(synthesized[:3000] if len(synthesized) > 3000 else synthesized)
                        console.print("[cyan]== FIN ==[/cyan]\n")
                        
                        web_content = synthesized
                    else:
                        console.print("[yellow]No se encontraron resultados[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]Error en búsqueda: {e}[/yellow]")
                    import traceback
                    traceback.print_exc()
            
            context_parts = [user_input]
            
            if web_content:
                context_parts.append(f"\nRESULTADOS WEB (información real, NO inventes):\n{web_content}")
            
            final_input = "\n\n".join(context_parts)
            
            console.print(f"\n[blue]VYN ({current_model})...[/blue]\n")
            
            messages.append({"role": "user", "content": final_input})
            
            try:
                response = ollama.chat(
                    model=current_model,
                    messages=messages,
                    stream=True,
                    options={'temperature': 0.7, 'num_predict': 4000}
                )
                
                console.print("[bold cyan]VYN[/bold cyan]: ", end="")
                assistant_message = ""
                
                for chunk in response:
                    if 'message' in chunk and 'content' in chunk['message']:
                        content = chunk['message']['content']
                        console.print(content, end="")
                        assistant_message += content
                
                console.print("\n")
                
                if assistant_message.strip():
                    # AI-DRIVEN SEARCH DETECTION
                    if assistant_message.strip().startswith("🔍BUSCAR:") and search_engine:
                        search_query = assistant_message.replace("🔍BUSCAR:", "").strip()
                        console.print(f"[blue][Auto-Search] VYN solicitó: '{search_query}'[/blue]")
                        
                        search_result = search_engine.search(search_query, max_results=10, messages=messages)
                        
                        if search_result and search_result.get('results'):
                            synthesized = search_engine.synthesize_results(search_result)
                            console.print("\n[cyan]== RESULTADOS WEB ==[/cyan]")
                            console.print(synthesized[:2000])
                            console.print("[cyan]== FIN ==[/cyan]\n")
                            
                            search_context = f"""DATOS DE BÚSQUEDA:
{synthesized}

AHORA responde usando estos datos."""
                            messages.append({"role": "user", "content": search_context})
                            
                            console.print("[blue]Reprocesando...[/blue]")
                            retry_response = ollama.chat(
                                model=current_model,
                                messages=messages,
                                stream=True,
                                options={'temperature': 0.7, 'num_predict': 2000}
                            )
                            
                            console.print("[bold cyan]VYN[/bold cyan]: ", end="")
                            final_message = ""
                            for chunk in retry_response:
                                if 'message' in chunk and 'content' in chunk['message']:
                                    content = chunk['message']['content']
                                    console.print(content, end="")
                                    final_message += content
                            console.print("\n")
                            
                            messages.pop()
                            messages.append({"role": "assistant", "content": final_message})
                            mensaje_count += 1
                        else:
                            messages.append({"role": "assistant", "content": assistant_message})
                            mensaje_count += 1
                    else:
                        messages.append({"role": "assistant", "content": assistant_message})
                        mensaje_count += 1
                    
                    if memory:
                        memory.log_conversation(user_input, assistant_message, current_model, "general", "general")
            
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                if messages[-1]['role'] == 'user':
                    messages.pop()
        
        except EOFError:
            graceful_shutdown()
        
        except KeyboardInterrupt:
            graceful_shutdown()
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    main()
