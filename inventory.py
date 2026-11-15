"""Server connections and Supervisor settings from a plain INI inventory."""
from dataclasses import dataclass
import math
from pathlib import Path
import shlex

DEFAULT_COLLECTOR = "sudo -n /usr/local/libexec/ops-dashboard-collect"
SERVER_KEYS = {"host", "user", "port", "identity_file", "sudo", "collector_command"}
SUPERVISOR_KEYS = {"server", "command", "interval", "enabled"}


@dataclass
class Server:
    name: str
    host: str
    user: str = ""
    port: int = 0
    identity: str = ""
    sudo: bool = False
    collector_command: str = DEFAULT_COLLECTOR


@dataclass
class Supervisor:
    server: Server
    command: str = "sudo -n supervisorctl status"
    interval: float = 240


def boolean(value, label):
    value = str(value).lower()
    if value not in ("true", "false", "yes", "no", "1", "0"):
        raise ValueError(label + " must be true or false")
    return value in ("true", "yes", "1")


def ini_value(value):
    lexer = shlex.shlex(value, posix=False)
    lexer.whitespace_split, lexer.commenters = True, "#"
    tokens = list(lexer)
    if len(tokens) == 1 and tokens[0].startswith(('"', "'")):
        return shlex.split(tokens[0])[0]
    return " ".join(tokens)


def read_settings(path):
    groups, variables, supervisor, section = {}, {}, {}, None
    for number, raw in enumerate(Path(path).expanduser().read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section or (":" in section and not section.endswith(":vars")):
                raise ValueError(f"Inventory line {number}: use [group], [group:vars] or [supervisor]")
            continue
        if section is None:
            raise ValueError(f"Inventory line {number}: add a [servers] section")
        if section == "supervisor" or section.endswith(":vars"):
            key, separator, value = line.partition("=")
            key = key.strip()
            allowed = SUPERVISOR_KEYS if section == "supervisor" else SERVER_KEYS
            if not separator or key not in allowed:
                raise ValueError(f"Inventory line {number}: unsupported setting {key!r} in [{section}]")
            destination = supervisor if section == "supervisor" else variables.setdefault(section[:-5], {})
            destination[key] = ini_value(value.strip())
        else:
            tokens = shlex.split(line, comments=True)
            if not tokens:
                continue
            options = {}
            for token in tokens[1:]:
                key, separator, value = token.partition("=")
                if not separator or key not in SERVER_KEYS:
                    raise ValueError(f"Inventory line {number}: use host, user, port, identity_file, sudo or collector_command")
                options[key] = value
            groups.setdefault(section, []).append((tokens[0], options))
    hosts = {}
    for group, entries in groups.items():
        for name, options in entries:
            if name.startswith("-") or any(char.isspace() for char in name):
                raise ValueError("Invalid inventory alias: " + name)
            item = hosts.setdefault(name, {"groups": [], "options": {}})
            item["groups"].append(group)
            item["options"].update(options)
    servers = []
    for name, item in hosts.items():
        settings = dict(variables.get("all", {}))
        for group in item["groups"]:
            settings.update(variables.get(group, {}))
        settings.update(item["options"])
        host, user = settings.get("host", name), settings.get("user", "")
        if not host or host.startswith("-") or user.startswith("-") or any(c.isspace() for c in host + user):
            raise ValueError("Invalid host/user for " + name)
        port = int(settings["port"]) if "port" in settings else 0
        if "port" in settings and not 1 <= port <= 65535:
            raise ValueError("Invalid SSH port for " + name)
        servers.append(Server(name, host, user, port, settings.get("identity_file", ""),
                              boolean(settings.get("sudo", "false"), "sudo for " + name),
                              settings.get("collector_command", DEFAULT_COLLECTOR)))
    return servers, supervisor


def load_inventory(path):
    return read_settings(path)[0]


def load_supervisor(path):
    servers, options = read_settings(path)
    if not options or not boolean(options.get("enabled", "true"), "Supervisor enabled"):
        return None
    name = options.get("server", "")
    server = next((server for server in servers if server.name == name), None)
    if server is None:
        raise ValueError("[supervisor] server must name an entry defined in the inventory")
    interval = float(options.get("interval", 240))
    if not math.isfinite(interval) or interval < 1:
        raise ValueError("Supervisor interval must be at least 1 second")
    command = options.get("command", "sudo -n supervisorctl status")
    if not command.strip():
        raise ValueError("Supervisor command cannot be empty")
    return Supervisor(server, command, interval)
