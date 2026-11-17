#!/usr/bin/env python3
"""Read Linux security metadata; output JSON. No server configuration changes."""
import collections
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import subprocess
import sys
import time


def run(command, timeout=12, limit=1_000_000):
    """Keep only a bounded tail and stop a slow command without a pipe deadlock."""
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env=dict(os.environ, LC_ALL="C"))
    except OSError as exc:
        return {"ok": False, "text": str(exc), "truncated": False}
    output, truncated, deadline = bytearray(), False, time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                return {"ok": False, "text": "Collection timed out", "truncated": True}
            for key, _ in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    del output[:-limit]
                    truncated = True
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        text = output.decode("utf-8", errors="replace")
        return {"ok": code == 0, "text": text, "truncated": truncated}
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def file_snapshot():
    result, errors = {}, []
    roots = [Path("/etc/crontab"), Path("/etc/anacrontab"), Path("/etc/cron.d"),
             Path("/etc/cron.hourly"), Path("/etc/cron.daily"), Path("/etc/cron.weekly"),
             Path("/etc/cron.monthly"), Path("/var/spool/cron")]
    count = 0
    for root in roots:
        try:
            root.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{root}: {exc}")
            continue
        pending = [root]
        while pending:
            path = pending.pop()
            count += 1
            if count > 3000:
                errors.append("Cron snapshot capped at 3000 entries")
                return result, errors
            try:
                info = path.lstat()
                if path.is_symlink():
                    result[str(path)] = {"sha256": hashlib.sha256(os.readlink(path).encode()).hexdigest(),
                                         "uid": info.st_uid, "mode": oct(info.st_mode & 0o7777), "mtime": info.st_mtime}
                elif path.is_dir():
                    pending.extend(path.iterdir())
                elif path.is_file():
                    if info.st_size > 2_000_000:
                        raise ValueError("Cron file exceeds 2 MB collection limit")
                    result[str(path)] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                         "uid": info.st_uid, "mode": oct(info.st_mode & 0o7777), "mtime": info.st_mtime}
            except (OSError, ValueError) as exc:
                errors.append(f"{path}: {exc}")
    return result, errors


def cpu_counters(text):
    values = [int(value) for value in text.splitlines()[0].split()[1:9]]
    if len(values) < 4:
        raise ValueError("Incomplete /proc/stat CPU counters")
    # guest/guest_nice are already included in user/nice; don't count twice.
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def cpu_percent(before, after):
    total = after[0] - before[0]
    idle = after[1] - before[1]
    if total <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (total - idle) * 100 / total)), 1)


def memory_usage(text):
    values = {}
    for line in text.splitlines():
        name, _, value = line.partition(":")
        tokens = value.split()
        if tokens:
            values[name] = int(tokens[0]) * 1024
    total = values["MemTotal"]
    available = values.get("MemAvailable")
    if available is None:
        available = sum(values.get(key, 0) for key in ("MemFree", "Buffers", "Cached", "SReclaimable")) - values.get("Shmem", 0)
    available = max(0, min(total, available))
    used = total - available
    swap_total = values.get("SwapTotal", 0)
    swap_used = max(0, swap_total - values.get("SwapFree", 0))
    return {"total": total, "available": available, "used": used,
            "percent": round(100 * used / total, 1) if total else 0,
            "swap_total": swap_total, "swap_used": swap_used}


def mount_paths(text):
    paths = {"/"}
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if not separator or len(fields) < 5 or len(filesystem) < 2:
            continue
        kind, source = filesystem[:2]
        # Avoid pseudo filesystems, snap images, and network mounts that may hang.
        if kind == "squashfs" or not (source.startswith("/dev/") or kind == "zfs"):
            continue
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
        paths.add(path)
    return sorted(paths, key=lambda path: (path != "/", path))


def disk_usage(path):
    info = os.statvfs(path)
    size = info.f_frsize or info.f_bsize
    total, used, available = info.f_blocks * size, (info.f_blocks - info.f_bfree) * size, info.f_bavail * size
    # Like df: use space available to ordinary users; reserved blocks aren't free.
    denominator = used + available
    return {"path": path, "total": total, "used": used, "available": available,
            "percent": round(100 * used / denominator, 1) if denominator else 0,
            "inodes_total": info.f_files, "inodes_free": info.f_favail}


def resource_snapshot(interval=1.0):
    before = cpu_counters(Path("/proc/stat").read_text())
    time.sleep(interval)
    after = cpu_counters(Path("/proc/stat").read_text())
    memory = memory_usage(Path("/proc/meminfo").read_text())
    disks, errors = [], []
    for path in mount_paths(Path("/proc/self/mountinfo").read_text()):
        try:
            disks.append(disk_usage(path))
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    return {"schema": 1, "mode": "resources", "time": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename, "cpu_percent": cpu_percent(before, after),
            "cpu_count": os.cpu_count(), "sample_seconds": interval,
            "load_average": list(os.getloadavg()), "memory": memory, "disks": disks, "errors": errors}


def collect(hours):
    since = datetime.now().astimezone() - timedelta(hours=hours)
    users = {user.pw_name: {"uid": user.pw_uid, "gid": user.pw_gid, "home": user.pw_dir, "shell": user.pw_shell}
             for user in pwd.getpwall()}
    # NSS users can include directory accounts; report the scope rather than
    # claiming an observed account creation is necessarily local useradd.
    crons, errors = file_snapshot()
    # run() forces the C locale. ausearch expects that locale's short date
    # (MM/DD/YY); newer versions reject a four-digit year here.
    start = ["-ts", since.strftime("%m/%d/%y"), since.strftime("%H:%M:%S")]
    sources = {
        "journal": run(["journalctl", "--since", since.isoformat(), "--no-pager", "-o", "json", "-n", "800",
                        "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"]),
        "last": run((["last"] if shutil.which("last") else ["wtmpdb", "last"]) + ["-i", "-F", "-n", "100"]),
        "audit_status": run(["auditctl", "-s"]),
        "audit_rules": run(["auditctl", "-l"]),
        # SSH supplies a pipe as stdin. Force ausearch to use auditd's logs
        # rather than interpreting that pipe as a stream of audit records.
        "audit_files": run(["ausearch", "--input-logs", "-k", "ops_dashboard"] + start + ["--raw"]),
        "audit_reads": run(["ausearch", "--input-logs", "-k", "ops_dashboard_read"] + start + ["--raw"]),
        "audit_writes": run(["ausearch", "--input-logs", "-k", "ops_dashboard_write"] + start + ["--raw"]),
        "audit_users": run(["ausearch", "--input-logs", "-m", "ADD_USER,DEL_USER,USER_MGMT"] + start + ["--raw"]),
        "audit_logins": run(["ausearch", "--input-logs", "-m", "USER_LOGIN"] + start + ["--raw"]),
    }
    # ausearch exit 1 means no matching events as well as some failures. Only
    # accept its explicit no-matches message; leave other errors visible.
    for name, source in sources.items():
        if name.startswith("audit_") and "<no matches>" in source["text"].lower():
            source["ok"], source["text"] = True, ""
    return {"schema": 1, "time": datetime.now(timezone.utc).isoformat(), "since": since.isoformat(),
            "euid": os.geteuid(), "users": users, "crons": crons, "cron_errors": errors, "sources": sources}


def main():
    try:
        if len(sys.argv) > 2:
            raise ValueError("Usage: ops-dashboard-collect [hours | resources]")
        if len(sys.argv) == 2 and sys.argv[1] == "resources":
            print(json.dumps(resource_snapshot()))
            return 0
        hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
        if not 1 <= hours <= 168:
            raise ValueError("Lookback must be 1–168 hours")
        print(json.dumps(collect(hours)))
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
