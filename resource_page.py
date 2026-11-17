"""Concurrent, resource-only polling for inventory hosts."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from inventory import load_inventory
from server_access import collect_resources


def size_text(value):
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(size) < 1024 or unit == "PiB":
            return f"{size:.1f} {unit}"
        size /= 1024


def usage_state(data):
    percentages = [data["cpu_percent"], data["memory"]["percent"]]
    percentages.extend(disk["percent"] for disk in data["disks"])
    maximum = max(percentages)
    return "CRITICAL" if maximum >= 95 else "WARNING" if maximum >= 80 or data.get("errors") or not data["disks"] else "OK"


def resource_details(server, data):
    memory = data["memory"]
    worst = max(data["disks"], key=lambda disk: disk["percent"], default={})
    disk_text = f"{worst['percent']:.1f}% ({worst['path']})" if worst else "unavailable"
    lines = [f"CPU: {data['cpu_percent']:.1f}% · RAM: {memory['percent']:.1f}% · disk: {disk_text}", "",
             f"Resource sample for {server.name} ({data.get('hostname', server.host)}).",
             f"Collected at: {data['time']}", "",
             f"CPU: {data['cpu_percent']:.1f}% busy across {data.get('cpu_count', '?')} logical CPUs",
             f"Sampling window: {data.get('sample_seconds', 1)} second(s)",
             "Load averages (1 / 5 / 15 minutes): " + " / ".join(str(number) for number in data.get("load_average", [])),
             "", f"RAM: {memory['percent']:.1f}% used",
             f"Used: {size_text(memory['used'])}", f"Available: {size_text(memory['available'])}",
             f"Total: {size_text(memory['total'])}",
             f"Swap: {size_text(memory.get('swap_used', 0))} used / {size_text(memory.get('swap_total', 0))} total", "", "Disks"]
    for disk in data["disks"]:
        lines += [f"{disk['path']}: {disk['percent']:.1f}% used",
                  f"  Used {size_text(disk['used'])} / total {size_text(disk['total'])}; available {size_text(disk['available'])}"]
    lines += ["", "RAM usage is total minus available memory. Disk percentages include reserved-space effects like df.",
              "Disk coverage: root and local device/ZFS mounts. Network mounts, tmpfs and squashfs images are excluded."]
    if data.get("errors"):
        lines += ["", "Disk collection errors", *data["errors"]]
    return "\n".join(lines)


class ResourcePage:
    def __init__(self, args, panel_class, row_class):
        self.args, self.Row = args, row_class
        self.previous = {}
        self.panel = panel_class("SERVER RESOURCES", args.resource_interval, self.fetch)

    @staticmethod
    def identity(server):
        return (server.name, server.host, server.user, server.port, server.identity, server.collector_command, server.sudo, server.ssh_args)

    def fetch(self):
        servers = load_inventory(self.args.inventory)
        if self.args.server:
            servers = [server for server in servers if server.name == self.args.server]
            if not servers:
                raise ValueError("Server not found: " + self.args.server)
        if not servers:
            self.previous = {}
            return []
        result, next_previous = {}, {}
        with ThreadPoolExecutor(max_workers=min(4, len(servers))) as pool:
            futures = {pool.submit(collect_resources, server): server for server in servers}
            for future in as_completed(futures):
                server = futures[future]
                key = self.identity(server)
                data = None
                try:
                    data = future.result()
                    state = usage_state(data)
                    detail = resource_details(server, data)
                    next_previous[key] = data
                except Exception as exc:
                    data = self.previous.get(key)
                    state = "STALE" if data else "ERROR"
                    detail = f"Could not collect current resources for {server.name}: {exc}"
                    if data:
                        next_previous[key] = data
                        detail += "\n\nLast successful sample (stale)\n" + resource_details(server, data)
                result[server.name] = self.Row(server.name, state, detail, metrics=data or {})
        self.previous = next_previous
        return [result[server.name] for server in servers]
