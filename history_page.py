"""Three-day resource charts, read from each server over SSH."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import curses
import math
import time
from inventory import load_inventory
from resource_page import ResourcePage, size_text
from server_access import collect_history

RANGES = (4, 8, 24, 48, 72)
RANGE_LABELS = {4: "4h", 8: "8h", 24: "1d", 48: "2d", 72: "3d"}
CHARTS = [("CPU", ("cpu",), True), ("RAM", ("ram",), True),
          ("DISK USAGE · fullest filesystem", ("disk",), True),
          ("NETWORK I/O · R receive / T transmit", ("rx", "tx"), False),
          ("DISK I/O · R read / T write", ("read", "write"), False)]


def utc_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%d %b %H:%M")


def number(value):
    return isinstance(value, (int, float)) and math.isfinite(value)


def buckets(samples, key, start, end, width):
    """Fixed time buckets: missing intervals remain gaps, never invented zeroes."""
    groups = [[] for _ in range(width)]
    if end <= start:
        return [None] * width
    for sample in samples:
        value, timestamp = sample.get(key), sample.get("ts")
        if number(value) and number(timestamp) and start <= timestamp <= end:
            index = min(width - 1, int((timestamp - start) * width / (end - start)))
            groups[index].append(value)
    return [(sum(group) / len(group), min(group), max(group)) if group else None for group in groups]


def window_samples(data, hours=72):
    end = data.get("end", time.time())
    start = end - hours * 3600
    samples = [sample for sample in data.get("samples", [])
               if number(sample.get("ts")) and start <= sample["ts"] <= end]
    return samples, start, end


def history_details(name, data, hours=72):
    samples, start, end = window_samples(data, hours)
    lines = [f"Metrics for {name} · past {RANGE_LABELS[hours]}",
             f"Window: {utc_time(start)} – {utc_time(end)} UTC", "Times are UTC. Collection: once per minute.",
             f"Stored samples in this window: {len(samples)}"]
    if not data.get("configured"):
        lines += ["History is not installed. Run ansible/setup.yml on this host."]
    elif not samples:
        lines += ["No samples in the selected time range."]
    else:
        lines += [f"First sample: {utc_time(samples[0]['ts'])}", f"Last sample: {utc_time(samples[-1]['ts'])}"]
        for title, keys, percent in CHARTS:
            for key in keys:
                values = [s[key] for s in samples if number(s.get(key))]
                if values:
                    fmt = lambda v: f"{v:.1f}%" if percent else size_text(v) + "/s"
                    lines += [f"{title} ({key}): latest {fmt(values[-1])}, average {fmt(sum(values)/len(values))}, peak {fmt(max(values))}"]
        lines += ["", "Latest fullest disk: " + str(samples[-1].get("disk_path") or "unavailable")]
        errors = samples[-1].get("errors") or []
        if errors:
            lines += ["Latest disk collection errors:", *errors]
    lines += ["", "CPU: one-second samples each minute. RAM: total minus available memory.",
              "Disk usage: maximum percentage across local filesystems; the fullest mount may change.",
              "Network: total non-loopback interfaces; virtual bridges/VPNs can count traffic more than once.",
              "Disk I/O: whole block devices; backing devices with holders and loop/ram devices excluded.",
              "I/O rates cover intervals between samples. Reboots, resets and gaps over 3 minutes have no rate.",
              "Chart columns show averages; shaded ranges show minimum to maximum within each column.",
              "Missing history is blank. Data before installation or during downtime cannot be recovered."]
    return "\n".join(lines)


class HistoryPage:
    def __init__(self, args, panel_class, row_class):
        self.args, self.Row = args, row_class
        self.previous = {}
        self.hours = getattr(args, "history_hours", 72)
        self.chart_top = 0
        self.chart_page_size = 1
        self.panel = panel_class("METRICS / HISTORY", 60, self.fetch)

    def change_range(self, direction=1):
        self.hours = RANGES[(RANGES.index(self.hours) + direction) % len(RANGES)]
        self.update_details()

    def update_details(self):
        with self.panel.lock:
            for row in self.panel.rows:
                if row.metrics:
                    prefix = row.detail.split("\n\n", 1)[0] + "\n\n" if row.detail.startswith("Could not read history") else ""
                    row.detail = prefix + history_details(row.name, row.metrics, self.hours)

    def fetch(self):
        servers = load_inventory(self.args.inventory)
        if self.args.server:
            servers = [s for s in servers if s.name == self.args.server]
            if not servers:
                raise ValueError("Server not found: " + self.args.server)
        result, previous = {}, {}
        if servers:
            with ThreadPoolExecutor(max_workers=min(4, len(servers))) as pool:
                futures = {pool.submit(collect_history, s): s for s in servers}
                for future in as_completed(futures):
                    server = futures[future]
                    key = ResourcePage.identity(server)
                    try:
                        data = future.result()
                        samples = data.get("samples", [])
                        state = "OK" if samples else "WAITING" if data.get("configured") else "SETUP NEEDED"
                        if samples and data["end"] - samples[-1]["ts"] > 180:
                            state = "STALE"
                        previous[key] = data
                        detail = history_details(server.name, data, self.hours)
                    except Exception as exc:
                        data = self.previous.get(key, {})
                        state = "STALE" if data else "ERROR"
                        detail = f"Could not read history for {server.name}: {exc}"
                        if data:
                            previous[key] = data
                            detail += "\n\n" + history_details(server.name, data, self.hours)
                    result[server.name] = self.Row(server.name, state, detail, metrics=data)
        self.previous = previous
        return [result[s.name] for s in servers]


def draw_chart(screen, y, x, height, width, title, keys, percent, samples, start, end, put):
    win = screen.derwin(height, width, y, x)
    win.erase()
    amber = curses.color_pair(1)
    win.attrset(amber)
    win.box()
    win.attrset(0)
    put(win, 0, 2, " " + title + " ", width - 4, amber | curses.A_BOLD)
    plot_width, plot_height = max(1, width - 12), max(1, height - 5)
    series = [buckets(samples, key, start, end, plot_width) for key in keys]
    values = [point[2] for points in series for point in points if point is not None]
    maximum = 100 if percent else max(values, default=1) or 1
    fmt = lambda value: f"{value:.1f}%" if percent else size_text(value) + "/s"
    # Report measured values, independent of terminal-sized aggregation.
    summary = []
    for key in keys:
        actual = [s[key] for s in samples if number(s.get(key))]
        prefix = "" if len(keys) == 1 else ("R " if key in ("rx", "read") else "T ")
        summary.append(prefix + ((f"last {fmt(actual[-1])} · peak {fmt(max(actual))}" if len(keys) == 1 else fmt(actual[-1])) if actual else "no samples"))
    put(win, 1, 2, " | ".join(summary), width - 4, amber)
    def level(value):
        return min(plot_height - 1, max(0, round((1 - value / maximum) * (plot_height - 1))))
    scale = "100%" if percent else size_text(maximum).replace(" ", "")
    put(win, 2, 1, scale, 8, curses.A_DIM)
    put(win, height - 4, 1, "0%" if percent else "0 B/s", 8, curses.A_DIM)
    for points in series:
        for column, point in enumerate(points):
            if point is not None:
                for row in range(level(point[2]), level(point[1]) + 1):
                    put(win, 2 + row, 9 + column, "░", 1, amber | curses.A_DIM)
    for index, points in enumerate(series):
        for column, point in enumerate(points):
            if point is not None:
                overlap = len(series) > 1 and series[1-index][column] is not None and level(series[1-index][column][0]) == level(point[0])
                glyph = "◆" if overlap else "●" if len(keys) == 1 else "R" if index == 0 else "T"
                put(win, 2 + level(point[0]), 9 + column, glyph, 1, amber | curses.A_BOLD)
    put(win, height - 2, 2, utc_time(start), 13, curses.A_DIM)
    label = utc_time(end) + " UTC"
    put(win, height - 2, max(16, width - len(label) - 2), label, len(label), curses.A_DIM)
    if not values:
        put(win, 2 + plot_height // 2, 10, "No samples in this window", plot_width - 1, curses.A_DIM)


def draw_history(screen, history, height, width, put, state_color):
    panel = history.panel
    with panel.lock:
        rows, error, busy = list(panel.rows), panel.error, panel.busy
    panel.selected = min(max(0, panel.selected), max(0, len(rows) - 1))
    row = rows[panel.selected] if rows else None
    remaining = max(0, int(panel.due - time.monotonic()))
    note = "Refreshing…" if busy else f"Refresh in {remaining}s"
    title = f"METRICS / {row.name} · {panel.selected+1}/{len(rows)} · {row.state}" if row else f"METRICS / PAST {RANGE_LABELS[history.hours]}"
    put(screen, 3, 2, title + " · " + note, width - 4, curses.color_pair(1) | curses.A_BOLD)
    data = row.metrics if row else {}
    samples, start, end = window_samples(data, history.hours)
    message = error or (row.detail.splitlines()[0] if row and row.state in ("ERROR", "STALE") else
                       "Run ansible/setup.yml to install history collection." if row and not data.get("configured") else
                       "No samples in this time range; collection runs once per minute." if row and not samples else
                       f"{len(samples)} samples · {RANGE_LABELS[history.hours]} window · amber = usage · blank = missing history")
    if not rows and not busy and not error:
        message = "No servers. Add hosts to servers.ini; Supervisor hosts are excluded."
    put(screen, 4, 2, message, width - 4, state_color(row.state) if row and row.state in ("ERROR", "STALE") else curses.A_DIM)
    columns = 2 if width >= 100 else 1
    available = height - 7
    count_rows = min(3 if columns == 2 else 5, max(1, available // 9))
    history.chart_page_size = columns * count_rows
    last_page = (len(CHARTS)-1) // history.chart_page_size * history.chart_page_size
    history.chart_top = min(max(0, history.chart_top), last_page)
    selector = "Range: " + "  ".join(f"[{RANGE_LABELS[h]}]" if h == history.hours else RANGE_LABELS[h] for h in RANGES) + " · t cycle"
    if history.chart_page_size < len(CHARTS):
        selector += f" · charts {history.chart_top + 1}–{min(len(CHARTS), history.chart_top + history.chart_page_size)}/{len(CHARTS)}"
    put(screen, 5, 2, selector, width - 4, curses.color_pair(1))
    card_width = (width - 3) // columns
    card_height = available // count_rows
    for offset, chart in enumerate(CHARTS[history.chart_top:history.chart_top+history.chart_page_size]):
        title, keys, percent = chart
        draw_chart(screen, 6 + offset // columns * card_height, 1 + offset % columns * (card_width + 1),
                   card_height, card_width, title, keys, percent, samples, start, end, put)
