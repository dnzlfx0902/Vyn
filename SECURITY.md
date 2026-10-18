# Política de Seguridad

## Reporte de vulnerabilidades

Si encuentras una vulnerabilidad, **no abras un issue público**. Escribe en
privado al mantenedor (Chris-devv) vía los canales del perfil de GitHub.
Intentaremos responder en un plazo razonable.

## Manejo de secretos

VYN **no contiene** credenciales en el repositorio:

- La API/keys y la config real viven en `config.json` y `.env`, **ignorados por git**.
- Usa `config_template.json` como base.
- Nunca subas `config.json`, `.env`, `*.db` ni claves SSH.

## Alcance

VYN ejecuta código en un sandbox y administra servidores por SSH. Ejecuta solo
en entornos donde confíes en la configuración y los modelos locales.

## Modelo de confianza de comandos

Toda ejecución de comandos de shell pasa por una **política fail-closed única**
(`modules/command_policy.py`):

- Solo un comando **simple y de solo lectura** (`ls`, `df -h`, `docker ps`, ...)
  se ejecuta sin confirmación.
- Comandos compuestos o con expansión de shell (`;`, `|`, `&&`, `$(...)`,
  backticks, redirecciones, saltos de línea) **siempre** piden confirmación,
  incluso si empiezan por un binario de la allowlist.
- Envoltorios (`sudo`, `doas`, `xargs`, `env`, `command`, `eval`, `nohup`, ...)
  y subcomandos peligrosos de binarios "seguros" (`docker rm`,
  `systemctl restart`, `find -exec`) requieren confirmación.
- **Escape por argumentos**: la allowlist es por *binario*, así que un binario de
  lectura cuyos *argumentos* ejecutan o mutan también se degrada. Se exige
  confirmación para `awk 'BEGIN{system(...)}'` / `print | "cmd"`, el comando `e`
  y el flag `e` de `sed`, `sort --compress-program=`, `man -P`, `awk -f`/`sed -f`,
  y para mutadores como `sort -o`, `date -s`, `hostname <nombre>`,
  `ifconfig <if> up|down|<ip>`, `fuser -k`, `ss -K`, `dmesg -c`,
  `git -c core.pager=...` y `find -fprintf`.
- Un binario invocado **por ruta** (`./ls`, `/tmp/ls`, `~/ls`) solo hereda la
  allowlist si vive en un directorio de sistema confiable (`/bin`, `/usr/bin`,
  `/usr/local/bin`, ...); en cualquier otro caso pide confirmación.

> Corrección de seguridad: hasta la revisión previa, la clasificación usaba
> `str.startswith` contra una allowlist, por lo que `ls; rm -rf /` se consideraba
> "seguro" y se ejecutaba en el servidor remoto **sin confirmación**. Ver
> `tests/test_command_policy.py` (pruebas de regresión parametrizadas).

> Segunda corrección (2026-10-18): la allowlist por binario era insuficiente.
> `command`, `eval` y `exec` estaban *dentro* de la allowlist (ejecutan la línea
> que sigue), y binarios de lectura como `awk`, `sed`, `sort` y `man` se
> clasificaban `LOW` aunque sus argumentos lanzaran un subproceso o escribieran
> en disco: se auto-ejecutaban en el servidor remoto sin confirmación. Ambas
> familias están ahora cubiertas y verificadas en la misma suite.
