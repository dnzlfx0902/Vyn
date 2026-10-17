"""VYN - Politica central de clasificacion de comandos de shell.

Modulo **stdlib-only**. Es la fuente unica de verdad para decidir si un
comando de shell puede ejecutarse SIN confirmacion explicita.

Motivacion (fix de seguridad)
-----------------------------
La version previa de ``modules/homelab.HomeLab`` clasificaba con
``command.lower().startswith(safe_cmd)``. Como el prefijo unicamente se
comparaba contra el inicio de la cadena, comandos compuestos se colaban como
"seguros" y se ejecutaban en el servidor remoto sin pedir confirmacion:

    ls; rm -rf /        -> clasificado SEGURO (!!)
    ls && reboot        -> clasificado SEGURO (!!)
    uptime; shutdown -h -> clasificado SEGURO (!!)

Aqui se tokeniza el comando y, ante **cualquier** composicion o expansion de
shell (``;``, ``|``, ``&``, ``$(...)``, backticks, redirecciones, saltos de
linea), se degrada deliberadamente la clasificacion: el comando jamas sera
LOW y por lo tanto siempre exigira confirmacion. El modo de fallo es
*fail-closed*: lo desconocido no se auto-ejecuta.
"""

from __future__ import annotations

import shlex
from typing import List, Optional, Set, Tuple

__all__ = ["CommandPolicy"]

# Niveles de riesgo (mismos literales que modules.security_layer.SecurityLayer)
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

# Operadores y expansiones de shell. Si aparecen FUERA de comillas simples, o
# los que aun expanden dentro de comillas dobles ($ y `), el comando no puede
# considerarse LOW: cualquiera de ellos permite encadenar o inyectar ejecucion.
_SHELL_METACHARS = frozenset(";|&$><`\n\r()")

# Binarios de solo lectura que nunca modifican el sistema por si mismos.
SAFE_BINARIES = frozenset({
    "ls", "cat", "head", "tail", "pwd", "whoami", "hostname", "uname", "id",
    "date", "uptime", "free", "df", "du", "ps", "top", "htop", "w", "who",
    "echo", "printf", "wc", "sort", "uniq", "cut", "tr", "stat", "file",
    "which", "whereis", "type", "command", "man", "help",
    "netstat", "ip", "ifconfig", "ping", "ss", "lsof", "fuser",
    "journalctl", "dmesg",
    "git", "docker", "docker-compose", "podman", "systemctl", "tmux",
    "find", "grep", "sed", "awk",
})

# Envoltorios que ejecutan OTRO comando: la allowlist no aplica al envoltorio.
_PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas", "su", "pkexec"})
_EXEC_WRAPPERS = frozenset({"xargs", "env", "nice", "ionice", "timeout", "watch", "strace"})

# Subcomandos de solo lectura por binario (cualquier otro subcomando -> MEDIUM).
_READONLY_SUBCOMMANDS = {
    "docker": frozenset({
        "ps", "images", "logs", "inspect", "version", "info", "stats",
        "top", "port", "diff", "history", "events",
    }),
    "docker-compose": frozenset({"ps", "logs", "config", "version", "images"}),
    "podman": frozenset({"ps", "images", "logs", "inspect", "version", "info"}),
    "systemctl": frozenset({
        "status", "show", "is-active", "is-enabled", "is-failed", "cat",
        "list-units", "list-unit-files", "list-sockets", "list-timers",
        "list-dependencies", "get-default",
    }),
    "git": frozenset({
        "status", "log", "diff", "show", "branch", "remote", "describe",
        "rev-parse", "ls-files", "blame", "shortlog", "tag", "--version",
    }),
    "tmux": frozenset({"ls", "list-sessions", "list-windows", "list-panes"}),
    "ip": frozenset({"addr", "a", "link", "route", "r", "neigh"}),
}

# Acciones mutantes en binarios cuyos subcomandos base admiten lecturas y escrituras.
_MUTATING_SUBCOMMAND_ARGS = {
    ("git", "branch"): frozenset({
        "-d", "-D", "--delete", "-m", "-M", "--move", "-c", "-C", "--copy",
        "--set-upstream-to", "-u", "--unset-upstream", "--edit-description",
    }),
    ("git", "tag"): frozenset({"-a", "-s", "-u", "-d", "-f", "--delete", "--force"}),
    ("git", "remote"): frozenset({
        "add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune",
    }),
    ("ip", "addr"): frozenset({"add", "del", "delete", "change", "replace", "flush"}),
    ("ip", "a"): frozenset({"add", "del", "delete", "change", "replace", "flush"}),
    ("ip", "link"): frozenset({"add", "del", "delete", "set", "change", "replace"}),
    ("ip", "route"): frozenset({"add", "del", "delete", "change", "replace", "flush", "append"}),
    ("ip", "r"): frozenset({"add", "del", "delete", "change", "replace", "flush", "append"}),
    ("ip", "neigh"): frozenset({"add", "del", "delete", "change", "replace", "flush"}),
}

# Flags de `find` que ejecutan comandos o escriben archivos.
_FIND_EXEC_FLAGS = frozenset({
    "-exec", "-execdir", "-ok", "-okdir", "-delete",
    "-fprint", "-fprint0", "-fls",
})

# Flags de `sed` que escriben en disco.
_SED_WRITE_FLAGS = ("-i", "--in-place")


class CommandPolicy:
    """Clasificacion fail-closed de comandos de shell (stdlib-only)."""

    RISK_LOW = RISK_LOW
    RISK_MEDIUM = RISK_MEDIUM
    RISK_HIGH = RISK_HIGH
    RISK_CRITICAL = RISK_CRITICAL

    #: Binarios considerados de solo lectura (expuestos para introspeccion).
    SAFE_BINARIES = SAFE_BINARIES

    @staticmethod
    def _unquoted_metachars(command: str) -> Set[str]:
        """Devuelve los metacaracteres de shell activos (comillas-aware).

        Dentro de comillas simples nada expande. Dentro de comillas dobles
        siguen expandiendo ``$`` (sustitucion) y las comillas invertidas.
        """
        found: Set[str] = set()
        quote: Optional[str] = None
        i = 0
        n = len(command)
        while i < n:
            ch = command[i]
            if quote == "'":
                if ch == "'":
                    quote = None
                i += 1
                continue
            if quote == '"':
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    quote = None
                elif ch in "$`":
                    found.add(ch)
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                i += 1
                continue
            if ch == "\\":
                found.add("\\")
                i += 2
                continue
            if ch in _SHELL_METACHARS:
                found.add(ch)
            i += 1
        return found

    @classmethod
    def classify(cls, command: str) -> Tuple[str, Optional[str]]:
        """Clasifica ``command`` devolviendo ``(riesgo, motivo)``.

        Un comando solo es ``LOW`` (auto-ejecutable) si es un unico comando
        simple, sin composicion ni expansion, cuyo binario es de solo lectura
        y cuyo subcomando (si aplica) tambien lo es.
        """
        cmd = (command or "").strip()
        if not cmd:
            return (cls.RISK_LOW, None)

        metachars = cls._unquoted_metachars(cmd)
        if metachars:
            return (
                cls.RISK_HIGH,
                "Composicion/expansion de shell ({}): requiere confirmacion".format(
                    " ".join(sorted(metachars))
                ),
            )

        try:
            tokens: List[str] = shlex.split(cmd, posix=True)
        except ValueError:
            return (cls.RISK_HIGH, "Comando no parseable (comillas sin cerrar)")

        if not tokens:
            return (cls.RISK_LOW, None)

        base = tokens[0]
        args = tokens[1:]

        if base in _PRIVILEGE_WRAPPERS:
            return (cls.RISK_HIGH, "Elevacion de privilegios ({}): requiere confirmacion".format(base))
        if base in _EXEC_WRAPPERS:
            return (cls.RISK_HIGH, "Envoltorio de ejecucion ({}): requiere confirmacion".format(base))

        if base not in SAFE_BINARIES:
            return (cls.RISK_MEDIUM, "Comando no reconocido: requiere confirmacion")

        if base == "find" and any(a in _FIND_EXEC_FLAGS for a in args):
            return (cls.RISK_HIGH, "find con -exec/-delete: requiere confirmacion")
        if base == "sed" and any(a.startswith(_SED_WRITE_FLAGS) for a in args):
            return (cls.RISK_MEDIUM, "sed en modo edicion in-place: requiere confirmacion")

        readonly = _READONLY_SUBCOMMANDS.get(base)
        if readonly is not None:
            sub = args[0] if args else ""
            if sub not in readonly:
                return (cls.RISK_MEDIUM, "Subcomando '{} {}' no es de solo lectura".format(base, sub))
            sub_args = args[1:]
            mutating_flags = _MUTATING_SUBCOMMAND_ARGS.get((base, sub))
            if mutating_flags and any(a in mutating_flags for a in sub_args):
                return (
                    cls.RISK_MEDIUM,
                    "Argumentos mutantes en '{} {}': requiere confirmacion".format(base, sub),
                )
            if (base, sub) == ("git", "branch") and any(not a.startswith("-") for a in sub_args):
                # `git branch <nombre>` sin flags de listado crea una rama.
                if not any(a in ("-l", "--list", "-a", "--all", "-r", "--remotes", "--contains", "--no-contains", "--merged", "--no-merged") for a in sub_args):
                    return (
                        cls.RISK_MEDIUM,
                        "Creacion de rama en 'git branch': requiere confirmacion",
                    )
            if (base, sub) == ("git", "tag") and any(not a.startswith("-") for a in sub_args):
                # `git tag <nombre>` sin flags crea un tag ligero; solo `-l`/`--list` es lectura.
                if not any(a in ("-l", "--list", "-v", "--verify") for a in sub_args):
                    return (
                        cls.RISK_MEDIUM,
                        "Creacion de tag en 'git tag': requiere confirmacion",
                    )

        return (cls.RISK_LOW, None)

    @classmethod
    def is_command_safe(cls, command: str) -> bool:
        """``True`` solo si ``command`` puede auto-ejecutarse sin confirmacion."""
        risk, _ = cls.classify(command)
        return risk == cls.RISK_LOW
