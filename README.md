# VYN — Voice Your Needs

[![CI](https://github.com/dnzlfx0902/Vyn/actions/workflows/ci.yml/badge.svg)](https://github.com/dnzlfx0902/Vyn/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Local-first](https://img.shields.io/badge/inference-local%20(Ollama)-green)

**VYN** es una capa de orquestación *local-first* que convierte LLMs estáticos en
agentes autónomos: les da las "manos del sistema" (herramientas, sandbox y
protocolos) para interactuar de forma segura con tu entorno local y tu
infraestructura remota — sin enviar datos a proveedores en la nube.

> Inferencia local con **Ollama**. Sin telemetría. Ejecución contenida en un sandbox.

---

## Tabla de contenido
- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación desde fuente](#instalación-desde-fuente)
- [Configuración](#configuración)
- [Uso](#uso)
- [Arquitectura](#arquitectura)
- [Desarrollo](#desarrollo)
- [Seguridad](#seguridad)
- [Licencia](#licencia)

## Características

| Módulo | Qué hace |
|--------|----------|
| **Orquestación de modelos** | Cambia de ruta de razonamiento según la complejidad de la tarea |
| **Búsqueda web inteligente** | Optimización de queries + extracción recursiva de contenido |
| **Sandbox de código** | Ejecución aislada con análisis de traceback y autocorrección |
| **Gestión de homelab** | Administración remota por SSH con permisos de dos niveles |
| **Visión** | Análisis local de imágenes y diagnóstico visual de errores de terminal |
| **Memoria de largo plazo** | Estado persistente en SQLite |
| **Setup wizard** | Configuración interactiva según tu hardware |

## Requisitos

- **Python 3.11+**
- **Ollama** corriendo en `localhost:11434`
- Modelos recomendados: `llama3.1:8b` o `mistral:7b-instruct`

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl start ollama
ollama pull llama3.1:8b
```

## Instalación desde fuente

```bash
git clone https://github.com/dnzlfx0902/Vyn.git
cd Vyn
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config_template.json config.json    # ajusta a tu entorno (ignorado por git)
python vyn.py
```

El *setup wizard* se ejecuta en el primer arranque para configurar rutas y modelos.

## Configuración

Toda la configuración real vive en `config.json` (a partir de
`config_template.json`). **Nunca** se versiona: contiene rutas, host del homelab
y preferencias. Las claves/secretos van en `.env`. Ambos están en `.gitignore`.

## Uso

```text
help            Muestra comandos y módulos disponibles
search <query>  Búsqueda web optimizada + síntesis
code <prompt>   Genera y prueba código en el sandbox
config          Ver o modificar la configuración local
exit            Termina la sesión
```

## Arquitectura

```
vyn.py            # punto de entrada / loop del agente
├── core/         # llm_manager, memory, sandbox, search_engine, system_installer
├── modules/      # homelab (SSH), command_policy, docker_helper, rag, vision, security
├── ui/           # dashboard y prompts (rich)
├── i18n.py       # internacionalización
└── setup_wizard.py
```

## Clasificación de comandos (seguridad)

`modules/command_policy.py` es la **fuente única de verdad** para decidir qué
comandos de shell pueden ejecutarse sin confirmación. Es *fail-closed*: solo un
comando **simple y de solo lectura** se clasifica como `LOW` (auto-ejecutable).
Cualquier composición o expansión de shell (`;`, `|`, `&&`, `$(...)`, backticks,
redirecciones, saltos de línea) degrada la clasificación y **exige confirmación
explícita**, igual que los envoltorios (`sudo`, `xargs`, `env`, ...) y los
subcomandos peligrosos de binarios "seguros" (`docker rm`, `systemctl restart`).

Ejemplo:

```python
from modules.command_policy import CommandPolicy

CommandPolicy.is_command_safe("df -h")          # True  -> sin confirmación
CommandPolicy.is_command_safe("ls; rm -rf /")   # False -> requiere confirmación
CommandPolicy.classify("docker rm -f app")      # ("MEDIUM", "...")
```

Tanto `modules/homelab.HomeLab._is_safe_command` como
`modules/security_layer.SecurityLayer.classify_risk` delegan en esta política,
de modo que no pueden divergir.

## Desarrollo

```bash
make dev      # instala deps + herramientas de dev
make lint     # ruff
make test     # pytest (smoke: compila todo y valida config)
make compile  # chequeo de sintaxis
```

Para probar **solo** la política de comandos (no requiere dependencias pesadas):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q tests/test_command_policy.py
# esperado: 154 passed
```

Ver [CONTRIBUTING.md](CONTRIBUTING.md).

## Seguridad

- Inferencia 100% local: ningún dato sale a proveedores de IA externos.
- Sin telemetría.
- Sandbox aislado para la ejecución de scripts.
- Sin secretos en el repo (ver [SECURITY.md](SECURITY.md)).

## Licencia

Ver [`LICENSE`](LICENSE). El código es **source-available**: está publicado para
consulta, pero los derechos están reservados por el autor. Para uso comercial o
relicenciamiento, contacta al autor.

---

**Desarrollado por Chris-devv**
