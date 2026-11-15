"""Plain-language summaries of audit evidence, with conservative attribution."""
from pathlib import PurePosixPath

# Selected Linux ABI numbers, keyed by the audit record's architecture. Never
# use the Mac's architecture to decode a remote server's syscall number.
# Reference tables: linux-audit/audit-userspace/lib/{aarch64,x86_64}_table.h.
SYSCALLS = {
    "c00000b7": {34: "mkdirat", 35: "unlinkat", 36: "symlinkat", 37: "linkat", 38: "renameat",
                  45: "truncate", 46: "ftruncate", 48: "faccessat", 52: "fchmod", 53: "fchmodat",
                  54: "fchownat", 55: "fchown", 56: "openat", 57: "close", 63: "read", 64: "write",
                  65: "readv", 66: "writev", 67: "pread", 68: "pwrite", 69: "preadv", 70: "pwritev",
                  78: "readlinkat", 79: "newfstatat", 80: "newfstat", 88: "utimensat", 206: "sendto",
                  211: "sendmsg", 221: "execve", 276: "renameat2", 281: "execveat", 291: "statx"},
    "c000003e": {0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat",
                  17: "pread", 18: "pwrite", 19: "readv", 20: "writev", 21: "access", 44: "sendto",
                  46: "sendmsg", 59: "execve", 76: "truncate", 77: "ftruncate", 82: "rename",
                  83: "mkdir", 84: "rmdir", 85: "creat", 87: "unlink", 90: "chmod", 91: "fchmod",
                  92: "chown", 93: "fchown", 94: "lchown", 257: "openat", 258: "mkdirat",
                  260: "fchownat", 262: "newfstatat", 263: "unlinkat", 264: "renameat",
                  268: "fchmodat", 269: "faccessat", 280: "utimensat"},
}
# These newer syscall assignments are shared by the two 64-bit ABIs above.
for table in SYSCALLS.values():
    table.update({437: "openat2", 439: "faccessat2", 452: "fchmodat2"})


def syscall_name(record):
    value = record.get("syscall", "")
    if value and not value.isdigit():
        return value
    return SYSCALLS.get(record.get("arch", "").lower(), {}).get(int(value) if value.isdigit() else -1, "")


def uid_name(uid, users):
    return next((name for name, data in users.items() if str(data["uid"]) == str(uid)),
                "root" if str(uid) == "0" else f"UID {uid}")


def cron_path(path):
    return (path in ("/etc/crontab", "/etc/anacrontab") or
            path.startswith(("/etc/cron.", "/var/spool/cron/")) or path == "/var/spool/cron")


def describe_audit(primary, records, paths, users, kind, serial, raw):
    """Return category, login actor, IP, report text and warning flag."""
    uid = primary.get("auid", "unset")
    known_actor = uid not in ("unset", "-1", "4294967295")
    actor = uid_name(uid, users) if known_actor else "unknown"
    subject = actor if known_actor else "A process without a recorded login user"
    effective = primary.get("euid", primary.get("uid", "unknown"))
    executable = primary.get("exe", primary.get("comm", "unknown program"))
    program = PurePosixPath(executable).name
    call = syscall_name(primary)
    config = next((record for record in records if record.get("type") == "CONFIG_CHANGE"), None)
    result = (config or {}).get("res", primary.get("success", primary.get("res", "unknown")))
    succeeded = result in ("yes", "success", "1")
    failed = result in ("no", "failed", "failure", "0")
    outcome = "Succeeded" if succeeded else "Failed" if failed else "Not recorded"
    ip = primary.get("addr", "")
    if ip in ("?", "(null)", "unknown"):
        ip = ""

    targets = [path for path, role in paths if role != "PARENT"]
    parents = [path for path, role in paths if role == "PARENT"]
    target = ", ".join(dict.fromkeys(targets)) or "an unspecified file or directory"
    all_paths = ", ".join(dict.fromkeys(path for path, _ in paths))
    note = ""
    event_kind = kind

    def sentence(action, past):
        authority = " with root privileges" if str(effective) == "0" else ""
        if succeeded:
            return f"{subject} {past} using {program}{authority}."
        if failed:
            return f"{subject} tried to {action} using {program}{authority}, but the operation failed."
        return f"{subject} was associated with an attempt to {action} using {program}{authority}. The outcome was not recorded."

    if config is not None:
        event_kind = "AUDIT RULE"
        operation = config.get("op", "")
        operation_text = {"add_rule": ("add an audit rule", "added an audit rule"),
                          "remove_rule": ("remove an audit rule", "removed an audit rule"),
                          "delete_rule": ("remove an audit rule", "removed an audit rule")}.get(
                              operation, ("change audit configuration", "changed audit configuration"))
        summary = sentence(*operation_text)
        if all_paths:
            summary += " Related path: " + all_paths + "."
        note = "This record concerns auditing configuration. It does not establish that the watched file was edited."
    elif program == "auditctl":
        event_kind = "AUDIT ACTIVITY"
        summary = sentence("perform an audit-management operation", "performed an audit-management operation")
        if all_paths:
            summary += " Related path: " + all_paths + "."
        note = "The exact rule operation was not included. Running auditctl is not evidence of a cron file edit."
    elif primary.get("type") == "USER_LOGIN":
        event_kind = "LOGIN"
        actor = primary.get("acct", uid_name(primary.get("id", uid), users))
        summary = f"Account {actor} authenticated successfully" + (f" from {ip}." if ip else ".")
        note = "Authentication alone does not confirm that an interactive shell was opened."
    elif primary.get("type") in ("ADD_USER", "DEL_USER", "USER_MGMT"):
        event_kind = "USER CHANGE"
        account = primary.get("acct") or (uid_name(primary["id"], users) if "id" in primary else "not specified")
        action, past = {"ADD_USER": (f"create account {account}", f"created account {account}"),
                        "DEL_USER": (f"delete account {account}", f"deleted account {account}")}.get(
                            primary["type"], (f"update account {account}", f"updated account {account}"))
        summary = sentence(action, past)
    else:
        change = False
        if call in ("chmod", "fchmod", "fchmodat", "fchmodat2"):
            action, past = f"change permissions on {target}", f"changed permissions on {target}"
            change = True
        elif call in ("chown", "lchown", "fchown", "fchownat"):
            action, past = f"change ownership of {target}", f"changed ownership of {target}"
            change = True
        elif call in ("unlink", "unlinkat", "rmdir"):
            action, past = f"remove {target}", f"removed {target}"
            change = True
        elif call in ("rename", "renameat", "renameat2"):
            old = ", ".join(path for path, role in paths if role == "DELETE")
            new = ", ".join(path for path, role in paths if role == "CREATE")
            label = f"{old} to {new}" if old and new else target
            action, past = f"rename or move {label}", f"renamed or moved {label}"
            change = True
        elif call in ("mkdir", "mkdirat"):
            action, past = f"create directory {target}", f"created directory {target}"
            change = True
        elif call in ("truncate", "ftruncate"):
            action, past = f"change the size of {target}", f"changed the size of {target}"
            change = True
        elif call in ("write", "writev", "pwrite", "pwrite64", "pwritev", "pwritev2"):
            action, past = f"write to {target}", f"wrote to {target}"
            change = True
        elif call in ("read", "readv", "pread", "pread64", "preadv", "preadv2"):
            action, past = f"read from {target}", f"read from {target}"
            event_kind = "FILE READ"
            note = "This is a process read. It does not prove a person viewed the contents on screen."
        elif call in ("open", "openat", "openat2", "creat"):
            flag_name = "a1" if call == "open" else "a2"
            try:
                flags = int(primary[flag_name], 16) if call in ("open", "openat") else None
            except (KeyError, ValueError):
                flags = None
            mode = " for writing" if call == "creat" else ""
            if flags is not None and flags & 0x200000:
                mode = " to obtain a path reference"
                event_kind = "FILE ACCESS"
            elif flags is not None:
                access_mode = flags & 3
                mode = {0: " for reading", 1: " for writing", 2: " for reading and writing"}.get(access_mode, "")
                change = access_mode in (1, 2)
                event_kind = "FILE WRITE" if change else "FILE READ"
            elif call == "creat":
                change, event_kind = True, "FILE WRITE"
            action, past = f"open {target}{mode}", f"opened {target}{mode}"
            note = "An open operation alone does not establish that bytes were read or that file contents changed."
        elif call in ("stat", "fstat", "lstat", "newfstat", "newfstatat", "statx", "access", "faccessat", "faccessat2"):
            action, past = f"check metadata or access permissions for {target}", f"checked metadata or access permissions for {target}"
            event_kind = "FILE ACCESS"
        elif call in ("execve", "execveat"):
            action, past = f"execute {target}", f"executed {target}"
            event_kind = "FILE ACCESS"
        else:
            action, past = f"perform an audited operation involving {target}", f"performed an audited operation involving {target}"
            event_kind = "FILE ACCESS"
            note = "The operation could not be described more specifically from the available evidence. No content change is inferred."
        summary = sentence(action, past)
        if change:
            event_kind = "FILE WRITE"
            if any(cron_path(path) for path in targets):
                event_kind = "CRON CHANGE"
            elif any(path in ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow") for path in targets):
                event_kind = "USER CHANGE"
                note += " An account-database operation does not by itself prove an account was created or deleted."

    login = f"{actor} (login UID {uid})" if known_actor else "Not recorded; this may be service activity"
    identity = uid_name(effective, users) + f" (effective UID {effective})"
    call_text = (call + " ") if call else "Unknown operation "
    if primary.get("syscall"):
        call_text += f"[number {primary['syscall']}, architecture {primary.get('arch', 'not recorded')}]"
    else:
        call_text = "Not included in this record"
    lines = [summary, "", f"Outcome: {outcome}", f"Login identity: {login}", f"Run as: {identity}",
             f"Program: {executable}", "Affected path(s): " + (", ".join(dict.fromkeys(targets)) or "No specific file recorded")]
    if parents:
        lines.append("Parent directory context: " + ", ".join(dict.fromkeys(parents)))
    lines += [f"Source IP: {ip or 'Not included in this audit record'}",
              f"Audit session: {primary.get('ses', 'not recorded')} (an identifier for correlating audit records)"]
    if note:
        lines += ["", "Interpretation: " + note.strip()]
    lines += ["", "Technical details", f"Audit event: {serial}", f"Record type: {primary.get('type', 'unknown')}",
              "System call: " + call_text]
    if config is not None:
        lines.append("Audit rule operation: " + config.get("op", "not recorded"))
    if raw:
        lines += ["", "Original audit records", raw]
    return event_kind, actor, ip, "\n".join(lines), failed
