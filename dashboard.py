#!/usr/bin/env python3
"""A terminal dashboard for SSL, HTTP probes, Supervisor, server access and resources."""
import argparse
import curses
import math
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import textwrap
import time
from access_page import AccessPage
from inventory import load_supervisor
from server_access import ssh_command
from resource_page import ResourcePage, size_text
from history_page import HistoryPage, draw_history


@dataclass
class Row:
    name: str
    state: str
    detail: str
    metrics: dict = field(default_factory=dict)


CERT = re.compile(r"^(\S+)\s+expiry:\s+(EXPIRING SOON|EXPIRED|OK)\s+(-?\d+(?:\.\d+)?) days left; chain/hostname: (.+)$")
PROCESS = re.compile(r"^(\S+)\s+(RUNNING|STARTING|STOPPED|STOPPING|BACKOFF|EXITED|FATAL|UNKNOWN)(?:\s+(.*))?$")
PROBE = re.compile(r"^(\S+)\s+probe:\s+(UP|WARNING|DOWN)\s+status:\s+(\d+|-)\s+duration:\s+(\d+(?:\.\d+)?)s"
                   r"\s+redirects:\s+(\d+)\s+http:\s+(\S+)\s+tls:\s+(.+?)\s+bytes:\s+(\d+)$")
HEALTHY_STATES = ("OK", "RUNNING", "UP", "READY", "INFO", "DISABLED")


def parse_certs(output):
    rows = []
    for line in output.splitlines():
        match = CERT.match(line.strip())
        if match:
            host, expiry, days, verification = match.groups()
            state = expiry if verification == "OK" else "VERIFY FAILED"
            rows.append(Row(host, state, f"{days} days left | expiry: {expiry} | chain/hostname: {verification}"))
        elif "CHECK FAILED:" in line:
            host, detail = line.split("CHECK FAILED:", 1)
            rows.append(Row(host.strip(), "CHECK FAILED", detail.strip()))
        elif line.strip() and rows and rows[-1].state == "CHECK FAILED":
            rows[-1].detail += " | " + line.strip()
        elif line.strip():
            raise RuntimeError("Unexpected certificate output: " + line.strip())
    if not rows:
        raise RuntimeError("No domains returned. Check domains.txt.")
    return rows


def parse_probes(output):
    rows = []
    for line in output.splitlines():
        match = PROBE.match(line.strip())
        if match:
            target, state, status, duration, redirects, version, tls, byte_count = match.groups()
            detail = (f"{status} in {duration}s | redirects: {redirects} | "
                      f"http/{version} | tls: {tls} | {byte_count} bytes")
            rows.append(Row(target, state, detail))
        elif "PROBE FAILED:" in line:
            target, detail = line.split("PROBE FAILED:", 1)
            rows.append(Row(target.strip(), "DOWN", detail.strip()))
        elif line.strip() and rows and rows[-1].state == "DOWN":
            rows[-1].detail += " | " + line.strip()
        elif line.strip():
            raise RuntimeError("Unexpected probe output: " + line.strip())
    if not rows:
        raise RuntimeError("No domains returned. Check domains.txt.")
    return rows


def parse_supervisor(output):
    rows, other = [], []
    for line in output.splitlines():
        match = PROCESS.match(line.strip())
        if match:
            name, state, detail = match.groups()
            rows.append(Row(name, state, detail or ""))
        elif line.strip():
            other.append(line.strip())
    if other:
        raise RuntimeError(" | ".join(other))
    return rows


def default_domains():
    return Path(__file__).resolve().with_name("domains.txt")


def run_domains_script(script, domains, per_domain_timeout, label):
    contents = domains.read_text()
    count = sum(bool(line.split("#", 1)[0].strip()) for line in contents.splitlines())
    if not count:
        raise RuntimeError("No domains configured in " + str(domains))
    # The supplied scripts read a relative domains.txt. Give them an isolated
    # working directory so they run unchanged, including when launched from
    # another folder.
    with tempfile.TemporaryDirectory(prefix="ops-dashboard-") as directory:
        Path(directory, "domains.txt").write_text(contents)
        result = subprocess.run([sys.executable, "-u", str(script)], cwd=directory,
                                capture_output=True, text=True, timeout=max(60, count * per_domain_timeout))
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"{label} failed")
    return result.stdout


def certificate_rows(args):
    script = args.cert_script.expanduser().resolve()
    domains = args.domains.expanduser().resolve() if args.domains else default_domains()
    return parse_certs(run_domains_script(script, domains, 40, "Certificate script"))


def probe_rows(args):
    script = args.http_script.expanduser().resolve()
    domains = args.domains.expanduser().resolve() if args.domains else default_domains()
    return parse_probes(run_domains_script(script, domains, 20, "HTTP probe script"))


def supervisor_rows(inventory, panel):
    config = load_supervisor(inventory)
    panel.interval = config.interval if config else 0
    if config is None:
        return [Row("Supervisor not configured", "DISABLED", "Add one inventory host to [supervisor_hosts], then press r on page 1.")]
    command = ssh_command(config.server) + [config.command]
    result = subprocess.run(command, capture_output=True, text=True, timeout=25)
    if result.returncode == 255:
        raise RuntimeError(result.stderr.strip() or "SSH connection failed")
    rows = parse_supervisor(result.stdout)
    # supervisorctl can return nonzero when processes are stopped or failed.
    if result.returncode and not rows:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or
                           f"supervisorctl exited {result.returncode}")
    return rows


def supervisor_panel(inventory):
    panel = Panel("SUPERVISOR", 0, lambda: [])
    panel.fetch = lambda: supervisor_rows(inventory, panel)
    try:
        config = load_supervisor(inventory)
        panel.interval = config.interval if config else 0
        if config is None:
            panel.rows = [Row("Supervisor not configured", "DISABLED", "Add one inventory host to [supervisor_hosts], then press r on page 1.")]
    except (OSError, ValueError) as exc:
        panel.error = str(exc)
    return panel


@dataclass
class Panel:
    title: str
    interval: float
    fetch: object
    rows: list = field(default_factory=list)
    error: str = ""
    busy: bool = False
    updated: str = "never"
    due: float = 0
    selected: int = 0
    top: int = 0
    page_size: int = 1
    lock: object = field(default_factory=threading.Lock)

    def refresh(self):
        with self.lock:
            if self.busy:
                return
            self.busy = True
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            rows = self.fetch()
            with self.lock:
                self.rows, self.error = rows, ""
                self.updated = datetime.now().strftime("%H:%M:%S")
        except Exception as exc:
            with self.lock:
                self.error = str(exc)
        finally:
            with self.lock:
                self.busy = False
                self.due = time.monotonic() + self.interval


def refresh_automatic(panels):
    for panel in panels:
        if panel.interval > 0 and time.monotonic() >= panel.due:
            panel.refresh()


def page_selection(panel, direction):
    with panel.lock:
        step = max(1, panel.page_size)
        panel.selected = min(max(0, len(panel.rows) - 1), max(0, panel.selected + direction * step))
        panel.top = min(max(0, len(panel.rows) - step), max(0, panel.top + direction * step))


def safe_text(value):
    # Format timestamps for display without changing collected or saved data.
    value = re.sub(
        r"\b(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})",
        lambda match: f"{match[1]} T{match[2]} {('+00:00' if match[3] == 'Z' else match[3])}",
        str(value),
    )
    return "".join(char if char.isprintable() else " " for char in value)


def put(window, y, x, value, width, attr=0):
    if width <= 0:
        return
    value = safe_text(value)
    if len(value) > width:
        value = value[:max(0, width - 1)] + "…"
    try:
        window.addnstr(y, x, value, width, attr)
    except curses.error:
        pass  # A resize or the bottom-right terminal cell can reject a write.


def state_color(state):
    if state in ("OK", "RUNNING", "UP"):
        return curses.color_pair(2)
    if state in ("EXPIRING SOON", "STARTING", "STOPPING", "WARNING"):
        return curses.color_pair(3)
    if state in ("READY", "INFO", "DISABLED"):
        return curses.color_pair(1)
    return curses.color_pair(4)


AMBER = 214  # Amber (#FFAF00) from the standard 256-color palette.


def accent_color():
    """Amber on any 256-color terminal, else the nearest basic hue."""
    return AMBER if curses.COLORS > AMBER else curses.COLOR_YELLOW


def detail_lines(text, width):
    """Wrap every character without losing explicit line breaks or long paths."""
    lines = []
    for line in text.split("\n"):
        lines.extend(textwrap.wrap(safe_text(line), width=max(1, width),
                                   replace_whitespace=False, drop_whitespace=False,
                                   break_long_words=True, break_on_hyphens=False) or [""])
    return lines


def details_view(screen, panel, on_tick=lambda: None):
    # Keep the opened record stable even if the panel refreshes in the background.
    with panel.lock:
        title, error, updated = panel.title, panel.error, panel.updated
        index = min(max(0, panel.selected), max(0, len(panel.rows) - 1))
        row = panel.rows[index] if panel.rows else None
        document = f"Panel: {title}\nLast successful refresh: {updated}\n"
        if row:
            document += f"\nName: {row.name}\nStatus: {row.state}\n\nDetails\n\n"
            document += row.detail.replace(" | ", "\n").replace("; ", "\n")
        if error:
            document += "\n\nRefresh error\n\n" + error
        if not row and not error:
            document += "\nNo results yet. Return to the list and run a check."
    offset, wrapped_width, lines = 0, None, []
    while True:
        on_tick()
        height, width = screen.getmaxyx()
        body_width = max(1, width - 4)
        if body_width != wrapped_width:
            lines = detail_lines(document, body_width)
            wrapped_width = body_width
        visible = max(1, height - 5)
        limit = max(0, len(lines) - visible)
        offset = min(max(0, offset), limit)
        screen.erase()
        put(screen, 0, 2, "FULL DETAILS / " + title, width - 4, curses.A_BOLD | curses.color_pair(1))
        put(screen, 1, 2, f"Lines {offset + 1}–{min(offset + visible, len(lines))} of {len(lines)}", width - 4, curses.A_DIM)
        for number, line in enumerate(lines[offset:offset + visible], 3):
            put(screen, number, 2, line, body_width)
        put(screen, height - 1, 1, "Esc / Enter / q back  ↑/↓ scroll  u/d or PgUp/PgDn page  Home/End", width - 2, curses.A_DIM)
        screen.refresh()
        key = screen.getch()
        if key in (27, 10, 13, curses.KEY_ENTER, ord("q"), ord("Q")):
            return
        if key == 3:
            raise KeyboardInterrupt
        if key in (curses.KEY_DOWN, ord("j")):
            offset += 1
        elif key in (curses.KEY_UP, ord("k")):
            offset -= 1
        elif key in (curses.KEY_NPAGE, ord(" "), ord("d")):
            offset += visible
        elif key in (curses.KEY_PPAGE, ord("u")):
            offset -= visible
        elif key in (curses.KEY_HOME, ord("g")):
            offset = 0
        elif key in (curses.KEY_END, ord("G")):
            offset = limit


def draw_panel(screen, panel, y, x, height, width, active):
    win = screen.derwin(height, width, y, x)
    win.erase()
    win.attrset(curses.color_pair(1) if active else curses.A_DIM)
    win.box()
    win.attrset(0)
    with panel.lock:
        rows, error, busy, updated = list(panel.rows), panel.error, panel.busy, panel.updated
    put(win, 0, 2, f" {panel.title} ", width - 4, curses.A_BOLD | curses.color_pair(1))
    bad = sum(row.state not in HEALTHY_STATES for row in rows)
    status = "Refreshing…" if busy else "Manual · r to run" if panel.interval == 0 else f"Next refresh in {max(0, int(panel.due - time.monotonic()))}s"
    if not busy and rows and all(row.state == "DISABLED" for row in rows):
        status = "Disabled · configure servers.ini"
    put(win, 1, 2, f"{len(rows)} items · {bad} need attention · {status}", width - 4)
    put(win, 2, 2, f"Last success {updated}" + (" · STALE / refresh failed" if error and rows else ""), width - 4, curses.A_DIM)
    if error:
        put(win, 3, 2, error, width - 4, curses.color_pair(4))
    else:
        put(win, 3, 2, "Tab panel · ↑/↓ select · u/d page · Enter full details", width - 4, curses.A_DIM)
    name_width = max(12, width - 24)
    heading = {"CERTIFICATES": "DOMAIN", "HTTP PROBE": "TARGET", "SUPERVISOR": "PROCESS"}.get(panel.title, "NAME")
    put(win, 5, 2, heading, name_width, curses.A_DIM)
    put(win, 5, 3 + name_width, "STATUS", 17, curses.A_DIM)
    visible = max(1, (height - 10) // 2)
    panel.page_size = visible
    panel.selected = min(max(0, panel.selected), max(0, len(rows) - 1))
    panel.top = min(max(0, panel.top), max(0, len(rows) - visible))
    if panel.selected < panel.top:
        panel.top = panel.selected
    elif panel.selected >= panel.top + visible:
        panel.top = panel.selected - visible + 1
    start = panel.top
    for index, row in enumerate(rows[start:start + visible], start):
        line_y = 6 + (index - start) * 2
        highlight = curses.A_REVERSE if active and index == panel.selected else 0
        put(win, line_y, 2, row.name.ljust(name_width), name_width, highlight)
        put(win, line_y, 3 + name_width, row.state, 17, state_color(row.state) | curses.A_BOLD)
        put(win, line_y + 1, 4, row.detail, width - 6, curses.A_DIM)
    if not rows:
        put(win, 7, 2, "Waiting for results…" if busy else "No items", width - 4, curses.A_DIM)
    if rows:
        put(win, height - 2, 2, f"Selected {panel.selected + 1}/{len(rows)} · Enter: full details", width - 4, curses.A_DIM)


def usage_bar(percent, width):
    percent = max(0.0, min(100.0, percent))
    cells = max(1, width - 9)
    filled = min(cells, int(cells * percent / 100 + 0.5))
    return "[" + "█" * filled + "░" * (cells - filled) + f"] {percent:.1f}%"


def draw_resources(screen, resources, height, width):
    panel = resources.panel
    win = screen.derwin(height - 5, width - 2, 3, 1)
    win.erase()
    win.attrset(curses.color_pair(1))
    win.box()
    win.attrset(0)
    with panel.lock:
        rows, error, busy = list(panel.rows), panel.error, panel.busy
    put(win, 0, 2, " SERVER RESOURCES ", width - 6, curses.A_BOLD | curses.color_pair(1))
    note = "Refreshing…" if busy else f"Next refresh in {max(0, int(panel.due - time.monotonic()))}s"
    put(win, 1, 2, f"{len(rows)} servers · {note}", width - 6)
    put(win, 2, 2, error or "r refresh · i reload inventory · u/d page · Enter full details", width - 6,
        curses.color_pair(4) if error else curses.A_DIM)
    server_width = max(12, min(28, width - 86))
    usage_width = max(15, min(28, (width - server_width - 29) // 3))
    usage_x = server_width + 3
    status_x = usage_x + 3 * (usage_width + 1)
    columns = [(2, "SERVER", server_width), (usage_x, "CPU", usage_width),
               (usage_x + usage_width + 1, "RAM", usage_width),
               (usage_x + 2 * (usage_width + 1), "DISK MAX", usage_width),
               (status_x, "STATUS", 10), (status_x + 11, "SAMPLE", 8)]
    for x, title, span in columns:
        put(win, 4, x, title, span, curses.A_DIM)
    visible = max(1, (height - 13) // 2)
    panel.page_size = visible
    panel.selected = min(max(0, panel.selected), max(0, len(rows) - 1))
    panel.top = min(max(0, panel.top), max(0, len(rows) - visible))
    if panel.selected < panel.top:
        panel.top = panel.selected
    elif panel.selected >= panel.top + visible:
        panel.top = panel.selected - visible + 1
    for index, row in enumerate(rows[panel.top:panel.top + visible], panel.top):
        y = 5 + (index - panel.top) * 2
        data = row.metrics
        worst = max(data.get("disks", []), key=lambda disk: disk["percent"], default={})
        values = [row.name, usage_bar(data["cpu_percent"], usage_width) if data else "—",
                  usage_bar(data["memory"]["percent"], usage_width) if data else "—",
                  usage_bar(worst["percent"], usage_width) if worst else "—", row.state,
                  data.get("time", "").split("T")[-1][:8] or "never"]
        for position, ((x, _, span), value) in enumerate(zip(columns, values)):
            attr = curses.A_REVERSE if index == panel.selected and position == 0 else 0
            if 1 <= position <= 3 and data:
                attr |= curses.color_pair(1)
            elif position == 4:
                attr |= state_color(row.state)
            put(win, y, x, value, span, attr)
        description = row.detail.splitlines()[0]
        if data and row.state not in ("STALE", "ERROR"):
            memory = data["memory"]
            description = f"RAM {size_text(memory['used'])}/{size_text(memory['total'])} · fullest disk {worst.get('path', 'unavailable')} · sample time UTC"
        put(win, y + 1, 3, description, width - 7, curses.A_DIM)
    if not rows:
        put(win, 6, 2, "Waiting for results…" if busy else "No servers. Add hosts to servers.ini.", width - 6)
    else:
        put(win, height - 7, 2, f"Selected {panel.selected + 1}/{len(rows)} · Enter: full details", width - 6, curses.A_DIM)
def tui(screen, status_panels, access, resources, history, initial_page="status"):
    curses.set_escdelay(25)  # Keep Escape responsive while decoding terminal key sequences.
    curses.curs_set(0)
    if curses.has_colors():
        curses.start_color()
        curses.use_default_colors()
        for number, color in enumerate((accent_color(), curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_RED), 1):
            curses.init_pair(number, color, -1)
    screen.timeout(150)
    active = 0
    page = initial_page
    while True:
        panels = status_panels if page == "status" else [access.hosts, access.activity] if page == "access" else [resources.panel] if page == "resources" else [history.panel]
        refresh_automatic(status_panels)
        if page == "resources":
            refresh_automatic([resources.panel])
        if page == "history":
            refresh_automatic([history.panel])
        screen.erase()
        height, width = screen.getmaxyx()
        put(screen, 0, 2, "OPS / LIVE   [1] Status   [2] Server access   [3] Resources   [4] Metrics", width - 4, curses.A_BOLD | curses.color_pair(1))
        subtitle = "SSL and probes: manual" if page == "status" else f"{access.kind} · l logins / f files / U users / c cron / a all · i reload inventory" if page == "access" else "↑/↓ or n/p server · u/d charts · r refresh · Enter details · times UTC" if page == "history" else "Resource-only polling · disk max = fullest local filesystem · no audit-log scan"
        put(screen, 1, 2, datetime.now().strftime("%a %d %b %Y %H:%M:%S") + " · " + subtitle, width - 4, curses.A_DIM)
        if width < 60 or height < 16:
            put(screen, 4, 2, "Enlarge terminal to at least 60 columns × 16 rows.", width - 4)
        elif page == "history":
            draw_history(screen, history, height, width, put, state_color)
        elif page == "resources" and width >= 90:
            draw_resources(screen, resources, height, width)
        elif page == "resources":
            draw_panel(screen, resources.panel, 3, 1, height - 5, width - 2, True)
        elif page == "access" and width >= 110:
            split = max(30, width // 3)
            draw_panel(screen, panels[0], 3, 1, height - 5, split - 1, active == 0)
            draw_panel(screen, panels[1], 3, split + 1, height - 5, width - split - 2, active == 1)
        elif page == "access":
            draw_panel(screen, panels[active], 3, 1, height - 5, width - 2, True)
        elif width >= 110 and height >= 29:
            # Certificates top-left with HTTP probes beneath them; Supervisor full-height right.
            split = width // 2
            half = (height - 5) // 2
            draw_panel(screen, panels[0], 3, 1, half, split - 1, active == 0)
            draw_panel(screen, panels[1], 3 + half, 1, height - 5 - half, split - 1, active == 1)
            draw_panel(screen, panels[2], 3, split + 1, height - 5, width - split - 2, active == 2)
        elif height >= 44:
            third = (height - 5) // 3
            draw_panel(screen, panels[0], 3, 1, third, width - 2, active == 0)
            draw_panel(screen, panels[1], 3 + third, 1, third, width - 2, active == 1)
            draw_panel(screen, panels[2], 3 + 2 * third, 1, height - 5 - 2 * third, width - 2, active == 2)
        else:
            draw_panel(screen, panels[active], 3, 1, height - 5, width - 2, True)
        panel = panels[active]
        footer = "q quit  1/2/3/4 screen  r run all  c SSL  p probe  Tab panel  u/d page  Enter details" if page == "status" else "q quit  1/2/3/4 screen  r scan server  Tab panel  u/d page  U users  Enter scan/details" if page == "access" else "q quit  1/2/3/4 screen  r refresh  i inventory  u/d page  Enter details"
        if page == "history":
            footer = "q quit  1/2/3/4 screen  ↑/↓ n/p server  u/d charts  r refresh  i inventory  Enter details"
        put(screen, height - 1, 1, footer, width - 2, curses.A_DIM)
        screen.refresh()
        key = screen.getch()
        if key in (ord("q"), ord("Q"), 3):
            return
        if key in (ord("1"), ord("2"), ord("3"), ord("4")):
            page = {ord("1"): "status", ord("2"): "access", ord("3"): "resources", ord("4"): "history"}[key]
            active = 0
        elif key == ord("r"):
            if page == "access":
                access.scan()
            elif page in ("resources", "history"):
                panels[0].refresh()
            else:
                for item in panels:
                    item.refresh()
        elif page == "status" and key in (ord("c"), ord("p")):
            status_panels[0 if key == ord("c") else 1].refresh()
        elif page == "access" and key in map(ord, "lfUca"):
            access.filter({"l": "LOGINS", "f": "FILES", "U": "USERS", "c": "CRON", "a": "ALL"}[chr(key)])
        elif page == "access" and key == ord("i"):
            if not access.activity.busy:
                access.reload()
        elif page in ("resources", "history") and key == ord("i"):
            panels[0].refresh()
        elif page == "history" and key in (ord("d"), curses.KEY_NPAGE, ord("u"), curses.KEY_PPAGE):
            history.chart_top += history.chart_page_size * (1 if key in (ord("d"), curses.KEY_NPAGE) else -1)
        elif page == "history" and key in (ord("n"), ord("p"), curses.KEY_LEFT, curses.KEY_RIGHT):
            with panel.lock:
                direction = 1 if key in (ord("n"), curses.KEY_RIGHT) else -1
                panel.selected = (panel.selected + direction) % max(1, len(panel.rows))
        elif key == 9:
            active = (active + 1) % len(panels)
        elif key in (ord("d"), curses.KEY_NPAGE):
            page_selection(panel, 1)
        elif key in (ord("u"), curses.KEY_PPAGE):
            page_selection(panel, -1)
        elif key in (curses.KEY_UP, ord("k")):
            panel.selected = max(0, panel.selected - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            with panel.lock:
                panel.selected = min(max(0, len(panel.rows) - 1), panel.selected + 1)
        elif key in (10, 13, curses.KEY_ENTER):
            if page == "access" and active == 0:
                access.scan()
                active = 1
            else:
                details_view(screen, panel, lambda: refresh_automatic(status_panels + ([resources.panel] if page == "resources" else [history.panel] if page == "history" else [])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert-script", type=Path, default=Path(__file__).resolve().with_name("check_certs.py"))
    parser.add_argument("--http-script", type=Path, default=Path(__file__).resolve().with_name("check_http.py"))
    parser.add_argument("--domains", type=Path, help="Defaults to domains.txt beside this dashboard")
    parser.add_argument("--inventory", type=Path, default=Path(__file__).with_name("servers.ini"))
    parser.add_argument("--audit-hours", type=int, default=24, help="Audit/journal lookback, 1–168 hours (default: 24)")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/ops-dashboard")
    parser.add_argument("--page", choices=("status", "access", "resources", "history"), default="status")
    parser.add_argument("--resource-interval", type=float, default=30, help="Resource refresh delay in seconds (default: 30)")
    parser.add_argument("--server", help="Only load this server alias from the inventory")
    parser.add_argument("--once", action="store_true", help="Run the selected page's checks once and print results")
    args = parser.parse_args()
    if not 1 <= args.audit_hours <= 168:
        parser.error("Audit hours must be 1–168")
    if not math.isfinite(args.resource_interval) or args.resource_interval < 1:
        parser.error("Resource interval must be at least 1 second")
    panels = [Panel("CERTIFICATES", 0, lambda: certificate_rows(args)),
              Panel("HTTP PROBE", 0, lambda: probe_rows(args)),
              supervisor_panel(args.inventory)]
    access = AccessPage(args, Panel, Row)
    resources = ResourcePage(args, Panel, Row)
    history = HistoryPage(args, Panel, Row)
    if args.once:
        if args.page in ("resources", "history"):
            chosen = resources.panel if args.page == "resources" else history.panel
            chosen._run()
            if chosen.error:
                print("ERROR:", safe_text(chosen.error))
                return 1
            for row in chosen.rows:
                print(safe_text(f"{row.name} | {row.state} | {row.detail}"))
            return int(any(row.state not in HEALTHY_STATES for row in chosen.rows))
        if args.page == "access":
            if access.hosts.error:
                print("ERROR:", access.hosts.error)
                return 1
            failed = False
            for server in access.servers:
                print(server.name)
                try:
                    for event in access.store.scan(server, args.audit_hours):
                        print(safe_text(f"  {event.kind} | {event.time} | {event.actor} | {event.ip} | {event.detail}"))
                        failed = failed or event.warning
                except Exception as exc:
                    print("  ERROR:", safe_text(exc))
                    failed = True
            return int(failed)
        for panel in panels:
            panel.refresh()
        while any(panel.busy for panel in panels):
            time.sleep(0.05)
        for panel in panels:
            print(panel.title)
            if panel.error:
                print("  ERROR:", panel.error)
            for row in panel.rows:
                print(f"  {row.name:35} {row.state:15} {row.detail}")
        return int(any(panel.error or any(row.state not in HEALTHY_STATES for row in panel.rows) for panel in panels))
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("Use a terminal for the TUI, or pass --once for plain output")
    try:
        curses.wrapper(tui, panels, access, resources, history, args.page)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
