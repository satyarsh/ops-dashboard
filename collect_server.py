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
        "last": run(["last", "-i", "-F", "-n", "100"]),
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
