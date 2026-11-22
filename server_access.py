"""SSH collection, audit decoding, and persisted user/cron snapshot comparisons."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from audit_report import describe_audit


@dataclass
class Event:
    kind: str
    time: str
    actor: str
    ip: str
    detail: str
    warning: bool = False


def ssh_command(server):
    command = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2"]
    if server.port:
        command.extend(["-p", str(server.port)])
    if server.user:
        command.extend(["-l", server.user])
    if server.identity:
        command.extend(["-i", str(Path(server.identity).expanduser())])
    command.extend(server.ssh_args)
    command.append(server.host)
    return command


def run_collector(server, argument, timeout=155):
    remote = shlex.split(server.collector_command)
    if not remote:
        raise ValueError("Empty collector_command")
    source = Path(__file__).with_name("collect_server.py").read_text() if remote == ["python3", "-"] else None
    if server.sudo and remote[0] != "sudo":
        remote = ["sudo", "-n"] + remote
    command = ssh_command(server) + [" ".join(shlex.quote(part) for part in remote + [str(argument)])]
    result = subprocess.run(command, input=source, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or f"SSH collector exited {result.returncode}"
        if argument in ("resources", "history") and "invalid literal" in message:
            message = "The server collector is outdated; run ansible/setup.yml to update it"
        raise RuntimeError(message)
    try:
        payload = json.loads(result.stdout)
    except ValueError as exc:
        raise RuntimeError("Collector did not return JSON. Check remote Python and shell startup output.") from exc
    if payload.get("error") or payload.get("schema") != 1:
        raise RuntimeError(payload.get("error", "Unsupported collector response"))
    return payload


def collect(server, hours):
    return run_collector(server, hours)


def collect_resources(server):
    payload = run_collector(server, "resources", timeout=25)
    if payload.get("mode") != "resources":
        raise RuntimeError("The server collector needs an update; run the Ansible setup playbook")
    return payload


def collect_history(server):
    payload = run_collector(server, "history", timeout=25)
    if payload.get("mode") != "history" or not isinstance(payload.get("samples"), list):
        raise RuntimeError("The server collector needs an update; run the Ansible setup playbook")
    return payload


def fields(line):
    pattern = r'''\b([A-Za-z_][\w]*)=(?:"([^"]*)"|'([^']*)'|([^\s]+))'''
    values = {}
    for match in re.finditer(pattern, line):
        key = match.group(1)
        values[key] = next((value for value in match.groups()[1:] if value is not None), "")
        if match.group(2) is not None or match.group(3) is not None:
            values["_quoted_" + key] = True
    # USER_LOGIN and USER_MGMT carry nested fields inside msg='...'.
    if "msg" in values and "=" in values["msg"]:
        values.update(fields(values.pop("msg")))
    return values


def audit_string(value, quoted=False):
    # Audit quotes normal paths but hex-encodes paths containing unsafe bytes.
    if not quoted and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", value or "-"):
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        except ValueError:
            pass
    return value


def audit_events(text, users, kind):
    grouped, raw_events = {}, {}
    for line in text.splitlines():
        marker = re.search(r"audit\((\d+(?:\.\d+)?):(\d+)\)", line)
        if marker:
            grouped.setdefault(marker.groups(), []).append(fields(line))
            raw_events.setdefault(marker.groups(), []).append(line)
    events = []
    for (epoch, serial), records in grouped.items():
        primary = next((r for r in records if r.get("type") == "SYSCALL"), None) or next(
            (r for r in records if r.get("type") in ("ADD_USER", "DEL_USER", "USER_MGMT", "USER_LOGIN", "CONFIG_CHANGE")), {})
        if not primary:
            continue
        success = primary.get("success", primary.get("res", "unknown"))
        if kind == "LOGIN" and success not in ("yes", "success", "1"):
            continue
        date = datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()
        paths = [audit_string(r["name"], r.get("_quoted_name", False)) for r in records if r.get("type") == "PATH" and r.get("name") not in (None, "(null)")]
        cwd = next((audit_string(r["cwd"], r.get("_quoted_cwd", False)) for r in records if r.get("type") == "CWD" and "cwd" in r), "")
        paths = [str(Path(cwd) / path) if cwd and not path.startswith("/") else path for path in paths]
        path_records = [record for record in records if record.get("type") == "PATH" and record.get("name") not in (None, "(null)")]
        path_roles = [(path, record.get("nametype", "UNKNOWN")) for path, record in zip(paths, path_records)]
        decoded = dict(primary)
        for field in ("exe", "comm"):
            if field in decoded:
                decoded[field] = audit_string(decoded[field], decoded.get("_quoted_" + field, False))
        event_kind, actor, ip, details, warning = describe_audit(
            decoded, records, path_roles, users, kind, serial, "\n".join(raw_events[(epoch, serial)]))
        events.append(Event(event_kind, date, actor, ip, details, warning))
    return events


def payload_events(payload):
    events = []
    sources, users = payload["sources"], payload["users"]
    now = payload["time"]
    if payload.get("euid") != 0:
        events.append(Event("COVERAGE", now, "collector", "", "The collector ran without root permissions. Some login logs, audit records or other users' cron files may be inaccessible.", True))
    source_names = {"journal": "SSH login history", "last": "supplemental login-session history",
                    "audit_status": "audit service status", "audit_rules": "loaded audit rules",
                    "audit_files": "watched-file audit events", "audit_reads": "file-read audit events",
                    "audit_writes": "file-write audit events", "audit_users": "account-management audit events",
                    "audit_logins": "successful audit login events"}
    for name, source in sources.items():
        if not source["ok"]:
            description = source_names.get(name, name)
            message = f"The collector could not retrieve {description}. Other data sources may still work."
            if "No such file or directory" in source["text"]:
                message += " A required command is missing from the server or its command search path."
            elif "timed out" in source["text"].lower():
                message += " The query exceeded its collection time limit."
            events.append(Event("COVERAGE", now, "collector", "", message + f"\n\nSource: {name}\nReported error: {source['text']}", True))
        if source.get("truncated"):
            events.append(Event("COVERAGE", now, "collector", "", f"The {source_names.get(name, name)} result is incomplete. Its output was capped or the query ended early. Older records may be missing.\nSource: {name}", True))
    journal = sources.get("journal", {})
    for line in journal.get("text", "").splitlines() if journal.get("ok") else []:
        try:
            entry = json.loads(line)
            message = entry.get("MESSAGE", "")
            accepted = re.search(r"Accepted (\S+) for (\S+) from (\S+) port (\d+)", message)
            if accepted:
                method, user, ip, port = accepted.groups()
                stamp = datetime.fromtimestamp(int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000, timezone.utc).isoformat()
                method_text = {"publickey": "an SSH key", "password": "a password"}.get(method, method)
                events.append(Event("LOGIN", stamp, user, ip, f"{user} authenticated over SSH from {ip} using {method_text}.\n\nClient port: {port}\nThis records successful authentication, not necessarily an interactive shell."))
        except (ValueError, KeyError, TypeError):
            continue
    if journal.get("ok"):
        events.append(Event("INFO", now, "collector", "", "The collector checked the SSH journal for successful authentication.\n\nLookback starts: " + payload["since"] + "\nLimit: newest 800 retained SSH log entries. Older or rotated-out history may be unavailable."))
    last = sources.get("last", {})
    if last.get("ok"):
        for line in last["text"].splitlines():
            if line.strip() and not line.startswith(("wtmp begins", "reboot", "shutdown", "runlevel")):
                tokens = line.split()
                if len(tokens) >= 4:
                    events.append(Event("SESSION", "wtmp (server time)", tokens[0], tokens[2], line))
    for key, kind in (("audit_files", "FILE ACCESS"), ("audit_reads", "FILE READ"),
                      ("audit_writes", "FILE WRITE"), ("audit_users", "USER CHANGE"), ("audit_logins", "LOGIN")):
        source = sources.get(key, {})
        if source.get("ok"):
            events.extend(audit_events(source["text"], users, kind))
    status = sources.get("audit_status", {})
    rules = sources.get("audit_rules", {})
    if status.get("ok"):
        state = dict(re.findall(r"^(\w+)\s+(\d+)", status["text"], re.M))
        enabled_text = {"0": "disabled", "1": "enabled", "2": "enabled with rules locked until reboot"}.get(state.get("enabled"), "in an unknown state")
        events.append(Event("INFO", now, "collector", "", f"Linux auditing is {enabled_text}. The kernel reports {state.get('lost', 'an unknown number of')} lost audit events.\n\nAudit daemon PID: {state.get('pid', 'unknown')}\nQueued events: {state.get('backlog', 'unknown')}\n\nTechnical status\n" + status["text"].strip()))
        if state.get("enabled") == "0" or state.get("pid") == "0" or int(state.get("lost", "0")) > 0:
            events.append(Event("COVERAGE", now, "", "", "Audit is disabled, has no daemon, or reports lost events; history is incomplete", True))
    if rules.get("ok"):
        configured = rules["text"]
        events.append(Event("INFO", now, "collector", "", "These are the currently loaded audit rules. They determine which activity can be recorded; a rule being listed is not a file-change event.\n\nLoaded rules\n" + configured))
        for key in ("ops_dashboard_read", "ops_dashboard_write", "ops_dashboard"):
            if key not in configured:
                events.append(Event("COVERAGE", now, "", "", f"No loaded {key} rule; configure paths before expecting matching file events", True))
    events.append(Event("INFO", now, "collector", "", f"The collector found {len(users)} available user accounts and checked {len(payload['crons'])} cron files during this scan.\n\nThis is an inventory summary, not a record of someone accessing those accounts or files. Account information comes from Linux NSS and may include directory-service accounts. Cron snapshots store metadata and content fingerprints, not file contents."))
    for name, user in sorted(users.items()):
        login_note = "Interactive shell login is disabled for this account." if user.get("shell", "").endswith(("/nologin", "/false")) else "The configured shell is shown below; this scan does not establish whether the account has logged in."
        events.append(Event("USER ACCOUNT", now, name, "", f"Account {name} exists in the server's account database. {login_note}\n\nUser ID: {user['uid']}\nPrimary group ID: {user.get('gid', '?')}\nHome directory: {user.get('home', '?')}\nLogin shell: {user.get('shell', '?')}\n\nSource: current collector snapshot. The account's creation time is unknown."))
    for path, info in sorted(payload["crons"].items()):
        mtime = datetime.fromtimestamp(info.get("mtime", 0), timezone.utc).isoformat()
        owner_uid = str(info.get("uid", "?"))
        owner = next((name for name, data in users.items() if str(data["uid"]) == owner_uid), owner_uid)
        events.append(Event("CRON FILE", now, owner, "", f"The collector inspected cron file {path}, owned by {owner}. This entry is file inventory, not evidence that {owner} edited it.\n\nLast modified: {mtime}\nPermission bits: {info.get('mode', '?')}\nContent fingerprint (SHA-256): {info['sha256']}\n\nLater snapshots use this fingerprint to detect changes."))
    events.append(Event("COVERAGE", now, "", "", "Only retained logs and configured audit paths are covered. File READ means an audited access/open, not proof a person viewed the contents."))
    for error in payload.get("cron_errors", []):
        events.append(Event("COVERAGE", now, "", "", "Cron: " + error, True))
    return events


def compare_snapshots(previous, payload):
    events = []
    now = payload["time"]
    if previous is None:
        return [Event("BASELINE", now, "collector", "", "The collector saved the first account and cron snapshot for this server. Future scans can compare against it. This does not establish when existing accounts were created or existing files were changed.")]
    interval = f"Observed between {previous['time']} and {now}; actor/IP unknown without an audit event"
    for category, kind in (("users", "USER CHANGE"), ("crons", "CRON CHANGE")):
        # Partial cron snapshots must not imply files were removed.
        if category == "crons" and (payload.get("cron_errors") or previous.get("cron_errors")):
            continue
        before, after = previous[category], payload[category]
        for name in sorted(before.keys() | after.keys()):
            action = "added" if name not in before else "removed" if name not in after else "changed"
            if before.get(name) != after.get(name):
                item = f"Account {name}" if category == "users" else f"Cron file {name}"
                verb = {"added": "appeared", "removed": "disappeared", "changed": "changed"}[action]
                changed_fields = []
                if action == "changed":
                    for key in sorted(before[name].keys() | after[name].keys()):
                        if before[name].get(key) != after[name].get(key):
                            label = {"sha256": "content fingerprint", "mtime": "modification time", "mode": "permissions", "uid": "user/owner ID", "gid": "primary group ID", "shell": "login shell", "home": "home directory"}.get(key, key)
                            changed_fields.append(label)
                extra = "\nChanged fields: " + ", ".join(changed_fields) if changed_fields else ""
                events.append(Event(kind, now, "unknown", "", f"{item} {verb} between collector scans.{extra}\n\n{interval}. A matching audit event is needed to identify who did it and the exact operation."))
    return events


class AccessStore:
    def __init__(self, state_dir):
        self.state_dir = Path(state_dir).expanduser()

    def scan(self, server, hours=24):
        payload = collect(server, hours)
        identity = json.dumps([server.name, server.host, server.port, server.user, server.collector_command, server.sudo])
        key = hashlib.sha256(identity.encode()).hexdigest()[:24]
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.state_dir / (key + ".json")
        previous = json.loads(path.read_text()) if path.exists() else None
        history = previous.get("history", []) if previous else []
        changes = compare_snapshots(previous, payload)
        history = (history + [asdict(event) for event in changes])[-500:]
        snapshot = {key: payload[key] for key in ("time", "users", "crons", "cron_errors")}
        snapshot["history"] = history
        fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w") as stream:
                json.dump(snapshot, stream)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return payload_events(payload) + [Event(**event) for event in reversed(history)]
