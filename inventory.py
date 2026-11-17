"""Use Ansible's inventory parser for the dashboard and provisioning."""
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

DEFAULT_COLLECTOR = "sudo -n /usr/local/libexec/ops-dashboard-collect"


@dataclass
class Server:
    name: str
    host: str
    user: str = ""
    port: int = 0
    identity: str = ""
    sudo: bool = False
    collector_command: str = DEFAULT_COLLECTOR
    ssh_args: tuple = ()
    variables: dict = field(default_factory=dict, repr=False)


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


def read_inventory(path):
    path = Path(path).expanduser().resolve()
    contents = path.read_text()
    if not any(line.strip() and not line.lstrip().startswith(("#", ";")) for line in contents.splitlines()):
        return {"_meta": {"hostvars": {}}}
    executable = shutil.which("ansible-inventory")
    if not executable:
        raise ValueError("Install Ansible on this machine; ansible-inventory is not in PATH")
    with tempfile.TemporaryDirectory(prefix="ops-inventory-") as directory:
        env = dict(os.environ, ANSIBLE_LOCAL_TEMP=directory,
                   ANSIBLE_INVENTORY_UNPARSED_FAILED="true", ANSIBLE_NOCOLOR="1")
        try:
            playbook_dir = Path(__file__).resolve().parent / "ansible"
            result = subprocess.run([executable, "-i", str(path), "--playbook-dir", str(playbook_dir), "--list"], stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=30, env=env)
        except subprocess.TimeoutExpired as exc:
            raise ValueError("Ansible inventory parsing timed out") from exc
    if result.returncode:
        raise ValueError("Ansible could not read the inventory: " + (result.stderr.strip() or "invalid inventory"))
    try:
        data = json.loads(result.stdout)
    except ValueError as exc:
        raise ValueError("ansible-inventory did not return valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("_meta", {}).get("hostvars", {}), dict):
        raise ValueError("Invalid Ansible inventory response")
    return data


def group_hosts(data, group, seen=None):
    seen = set() if seen is None else seen
    if group in seen:
        return set()
    seen.add(group)
    entry = data.get(group, {})
    hosts = set(entry.get("hosts", []))
    for child in entry.get("children", []):
        hosts.update(group_hosts(data, child, seen))
    return hosts


def inventory_servers(data):
    variables = data.get("_meta", {}).get("hostvars", {})
    names = set(variables)
    names.update(group_hosts(data, "all"))
    servers = []
    for name in sorted(names):
        settings = variables.get(name, {})
        host = str(settings.get("ansible_host", name))
        user = str(settings.get("ansible_user", settings.get("ansible_ssh_user", "")))
        if (not host or host.startswith("-") or user.startswith("-") or name.startswith("-")
                or any(char.isspace() for char in host + user + name)):
            raise ValueError("Invalid host/user for " + name)
        port_value = settings.get("ansible_port", settings.get("ansible_ssh_port"))
        port = int(port_value) if port_value is not None else 0
        if port_value is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid SSH port for " + name)
        extra = shlex.split(str(settings.get("ansible_ssh_common_args", "")))
        extra += shlex.split(str(settings.get("ansible_ssh_extra_args", "")))
        servers.append(Server(name, host, user, port, str(settings.get("ansible_ssh_private_key_file", settings.get("ansible_private_key_file", ""))),
                              boolean(settings.get("ansible_become", False), "ansible_become for " + name),
                              str(settings.get("collector_command", DEFAULT_COLLECTOR)), tuple(extra), settings))
    return servers


def load_inventory(path):
    data = read_inventory(path)
    monitoring_only = group_hosts(data, "supervisor_hosts")
    return [server for server in inventory_servers(data) if server.name not in monitoring_only]


def load_supervisor(path):
    data = read_inventory(path)
    members = group_hosts(data, "supervisor_hosts")
    servers = [server for server in inventory_servers(data) if server.name in members and
               boolean(server.variables.get("supervisor_enabled", True), "supervisor_enabled")]
    if not servers:
        return None
    if len(servers) != 1:
        raise ValueError("Put exactly one enabled server in [supervisor_hosts]")
    server = servers[0]
    interval = float(server.variables.get("supervisor_interval", 240))
    if not math.isfinite(interval) or interval < 1:
        raise ValueError("supervisor_interval must be at least 1 second")
    command = str(server.variables.get("supervisor_command", "sudo -n supervisorctl status"))
    if not command.strip():
        raise ValueError("supervisor_command cannot be empty")
    return Supervisor(server, command, interval)
