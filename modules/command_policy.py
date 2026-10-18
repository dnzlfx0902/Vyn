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

Segunda capa (2026-10-18): **vectores de ejecucion y mutacion a nivel de
argumento**. Una allowlist por binario no basta: hay binarios de lectura cuyos
*argumentos* lanzan subprocesos o mutan el sistema aunque la linea de comandos
sea un unico comando simple. Todos estos casos se clasificaban LOW (es decir,
se auto-ejecutaban en el servidor remoto **sin confirmacion**):

    command rm -rf /                      -> ejecuta rm                 (bypass total)
    command shutdown -h now               -> apaga la maquina
    awk 'BEGIN{system("id")}'             -> ejecucion arbitraria
    sed -n '1e whoami' f                  -> comando 'e' de GNU sed
    sed 's/a/b/e' f                       -> flag 'e' de s///
    sort --compress-program=/bin/sh f     -> ejecuta el programa indicado
    man -P "sh -c id" ls                  -> pager arbitrario
    sed -f script.sed f / awk -f p.awk f  -> programa no inspeccionable
    fuser -k f / ss -K                   -> mata procesos/sockets
    date -s / hostname NAME / ifconfig eth0 down / dmesg -c -> mutan el sistema

Ademas, los binarios invocados por ruta solo se aceptan desde directorios de
sistema confiables (``/bin``, ``/usr/bin``, ...); ``./ls`` o ``/tmp/ls``
quedan fuera para que un binario homonimo del atacante no herede la allowlist.
"""

from __future__ import annotations

import re
import shlex
from typing import List, Optional, Sequence, Set, Tuple

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
    # OJO: 'command' NO esta aqui. Es un builtin de shell que ejecuta el
    # comando que le sigue ('command rm -rf /'), por lo que pertenece a
    # _EXEC_WRAPPERS: sin este detalle la allowlist se saltaba por completo.
    "which", "whereis", "type", "man", "help",
    "netstat", "ip", "ifconfig", "ping", "ss", "lsof", "fuser",
    "journalctl", "dmesg",
    "git", "docker", "docker-compose", "podman", "systemctl", "tmux",
    "find", "grep", "sed", "awk",
})

# Envoltorios que ejecutan OTRO comando: la allowlist no aplica al envoltorio.
_PRIVILEGE_WRAPPERS = frozenset({"sudo", "doas", "su", "pkexec"})
_EXEC_WRAPPERS = frozenset({
    "xargs", "env", "nice", "ionice", "timeout", "watch", "strace",
    # Builtins de shell y lanzadores que ejecutan el resto de la linea.
    "command", "eval", "exec", "builtin", "time", "nohup", "setsid",
    "stdbuf", "script", "chroot", "unshare", "nsenter", "systemd-run",
    "parallel", "runuser", "sg", "firejail", "busybox", "toybox",
})

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
    "-fprint", "-fprintf", "-fprint0", "-fls",
})

# Flags de `sed` que escriben en disco.
_SED_WRITE_FLAGS = ("-i", "--in-place")

# --- Vectores de ejecucion / mutacion a nivel de ARGUMENTO ------------------- #

# Directorios de sistema confiables para invocaciones con ruta explicita. Un
# binario homonimo fuera de ellos (./ls, /tmp/ls) no hereda la allowlist.
TRUSTED_BIN_DIRS = frozenset({
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
})

# awk y familia: el *programa* puede lanzar subprocesos con system() o tuberias.
_AWK_BINARIES = frozenset({"awk", "gawk", "mawk", "nawk"})
_AWK_EXEC_RE = re.compile(r"system\s*\(")
# Tuberia de salida de awk hacia un comando: print ... | "cmd"  /  |& getline.
_AWK_PIPE_RE = re.compile(r"\|&|\|")

# GNU sed ejecuta comandos con el comando `e` y con el flag `e` de `s///`.
_SED_EXEC_CMD_RE = re.compile(r"(?:^|[;\s}])(?:\d+(?:,\d+)?)?e(?:\s|$)")
_SED_EXEC_FLAG_RE = re.compile(r"s(.).*?\1.*?\1[0-9gpImM]*e")

# Flags cuyo VALOR es un programa/comando a ejecutar -> ejecucion arbitraria.
_EXEC_ARG_FLAGS = {
    "sort": ("--compress-program",),
    "man": ("-P", "--pager"),
    "awk": ("-f", "--file"),
    "gawk": ("-f", "--file"),
    "mawk": ("-f", "--file"),
    "nawk": ("-f", "--file"),
    "sed": ("-f", "--file"),
}

# Flags que mutan el sistema (matan procesos, escriben, cambian configuracion).
_MUTATING_ARG_FLAGS = {
    "date": ("-s", "--set"),
    "dmesg": ("-c", "-C", "--clear", "-D", "--console-off", "-E", "--console-on"),
    "fuser": ("-k", "-K", "--kill"),
    "ss": ("-K", "--kill"),
    "sort": ("-o", "--output"),
    "git": ("-c", "--config-env", "--pager"),
    "journalctl": ("--rotate", "--vacuum-time", "--vacuum-size", "--vacuum-files"),
}

# Palabras de mutacion que `ifconfig` acepta como argumentos posicionales.
_IFCONFIG_MUTATING_WORDS = frozenset({
    "up", "down", "netmask", "broadcast", "mtu", "arp", "-arp", "promisc",
    "-promisc", "allmulti", "-allmulti", "txqueuelen", "add", "del", "hw",
    "metric", "pointopoint", "tunnel",
})

# Flags de `hostname` que solo consultan (el resto de invocaciones con
# argumento posicional renombran el equipo).
_HOSTNAME_QUERY_FLAGS = frozenset({"-f", "--fqdn", "-d", "--domain", "-i", "--ip-address",
                                   "-I", "--all-ip-addresses", "-s", "--short", "-a", "--alias"})


def _matches_flag(args: Sequence[str], flags: Sequence[str]) -> Optional[str]:
    """Devuelve el primer flag de ``flags`` presente en ``args``, o ``None``.

    Acepta la forma exacta (``-c``) y la forma con valor adjunto
    (``--output=x``, ``--compress-program=/bin/sh``).
    """
    for arg in args:
        for flag in flags:
            if arg == flag or (flag.startswith("--") and arg.startswith(flag + "=")):
                return flag
    return None


def _awk_program_text(args: Sequence[str]) -> str:
    """Extrae el texto de programa de una invocacion de awk.

    Se omiten los flags y los valores de los que consumen argumento
    (``-F``/``--field-separator``, ``-v``/``--assign``) para no confundir una
    asignacion o un separador de campos con el programa.
    """
    program: List[str] = []
    skip_next = False
    value_flags = ("-F", "--field-separator", "-v", "--assign")
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in value_flags:
            skip_next = True
            continue
        if (arg.startswith("-F") or arg.startswith("-v")
                or arg.startswith("--field-separator=") or arg.startswith("--assign=")
                or arg.startswith("-")):
            continue
        program.append(arg)
    return " ".join(program)


def _awk_executes(args: Sequence[str]) -> bool:
    """``True`` si el programa awk puede lanzar un subproceso."""
    text = _awk_program_text(args)
    return bool(_AWK_EXEC_RE.search(text) or _AWK_PIPE_RE.search(text))


def _sed_executes(args: Sequence[str]) -> bool:
    """``True`` si el script sed usa el comando `e` o el flag `e` de `s///`."""
    scripts = [a for a in args if not a.startswith("-")]
    return any(
        _SED_EXEC_CMD_RE.search(s) or _SED_EXEC_FLAG_RE.search(s) for s in scripts
    )


def _ifconfig_mutates(args: Sequence[str]) -> bool:
    """``True`` si la invocacion de ifconfig cambia la configuracion de red."""
    if any(a in _IFCONFIG_MUTATING_WORDS for a in args):
        return True
    positionals = [a for a in args if not a.startswith("-")]
    return len(positionals) >= 2


def _hostname_mutates(args: Sequence[str]) -> bool:
    """``True`` si la invocacion de hostname renombra el equipo."""
    positionals = [a for a in args if not a.startswith("-")]
    if positionals:
        return True
    return any(a not in _HOSTNAME_QUERY_FLAGS for a in args)


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

        # Invocacion por ruta (/usr/bin/ls, ./ls, /tmp/ls). Solo se acepta si
        # el binario vive en un directorio de sistema confiable: un homonimo
        # bajo control del usuario no debe heredar la allowlist.
        if "/" in base:
            directory, _, name = base.rpartition("/")
            if directory not in TRUSTED_BIN_DIRS:
                return (
                    cls.RISK_MEDIUM,
                    "Binario invocado por ruta no confiable ('{}'): requiere confirmacion".format(base),
                )
            base = name

        if base in _PRIVILEGE_WRAPPERS:
            return (cls.RISK_HIGH, "Elevacion de privilegios ({}): requiere confirmacion".format(base))
        if base in _EXEC_WRAPPERS:
            return (cls.RISK_HIGH, "Envoltorio de ejecucion ({}): requiere confirmacion".format(base))

        if base not in SAFE_BINARIES:
            return (cls.RISK_MEDIUM, "Comando no reconocido: requiere confirmacion")

        if base == "find" and any(a in _FIND_EXEC_FLAGS for a in args):
            return (cls.RISK_HIGH, "find con -exec/-delete/-fprintf: requiere confirmacion")
        if base == "sed" and any(a.startswith(_SED_WRITE_FLAGS) for a in args):
            return (cls.RISK_MEDIUM, "sed en modo edicion in-place: requiere confirmacion")

        # --- Argumentos que lanzan subprocesos (ejecucion arbitraria) --------- #
        exec_flag = _matches_flag(args, _EXEC_ARG_FLAGS.get(base, ()))
        if exec_flag:
            return (
                cls.RISK_HIGH,
                "Flag '{} {}' ejecuta un programa externo: requiere confirmacion".format(base, exec_flag),
            )
        if base in _AWK_BINARIES and _awk_executes(args):
            return (
                cls.RISK_HIGH,
                "Programa awk con system()/tuberia a comando: requiere confirmacion",
            )
        if base == "sed" and _sed_executes(args):
            return (
                cls.RISK_HIGH,
                "Script sed con comando 'e' (ejecuta comandos de shell): requiere confirmacion",
            )

        # --- Argumentos que mutan el estado del sistema ----------------------- #
        mutating_flag = _matches_flag(args, _MUTATING_ARG_FLAGS.get(base, ()))
        if mutating_flag:
            return (
                cls.RISK_MEDIUM,
                "Flag mutante '{} {}' modifica el sistema: requiere confirmacion".format(base, mutating_flag),
            )
        if base == "ifconfig" and _ifconfig_mutates(args):
            return (cls.RISK_MEDIUM, "ifconfig con parametros de escritura: requiere confirmacion")
        if base == "hostname" and _hostname_mutates(args):
            return (cls.RISK_MEDIUM, "hostname con nombre nuevo (renombra el equipo): requiere confirmacion")

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
