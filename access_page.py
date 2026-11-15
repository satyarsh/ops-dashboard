"""State for the manually refreshed server-access page."""
from inventory import load_inventory
from server_access import AccessStore


class AccessPage:
    def __init__(self, args, panel_class, row_class):
        self.args, self.Row = args, row_class
        self.store = AccessStore(args.state_dir)
        self.servers, self.cache = [], {}
        self.kind = "ALL"
        self.target = None
        self.hosts = panel_class("SERVERS", 0, lambda: [])
        self.activity = panel_class("SERVER ACTIVITY", 0, lambda: [])
        self.reload()

    def reload(self):
        try:
            self.servers = load_inventory(self.args.inventory)
            if self.args.server:
                self.servers = [server for server in self.servers if server.name == self.args.server]
                if not self.servers:
                    raise ValueError("Server not found: " + self.args.server)
            self.hosts.rows = [self.Row(server.name, "READY", f"{server.user + '@' if server.user else ''}{server.host}; SSH port {server.port or 'from SSH config'}; Enter to scan") for server in self.servers]
            self.hosts.error = "" if self.servers else "Add servers to " + str(self.args.inventory)
        except Exception as exc:
            self.servers, self.hosts.rows = [], []
            self.hosts.error = str(exc)

    def rows(self):
        events = self.cache.get(self.target, [])
        categories = {
            "LOGINS": {"LOGIN", "SESSION"}, "FILES": {"FILE READ", "FILE WRITE", "FILE ACCESS"},
            "USERS": {"USER CHANGE", "USER ACCOUNT", "BASELINE"}, "CRON": {"CRON CHANGE", "CRON FILE", "BASELINE"},
        }
        allowed = categories.get(self.kind)
        rows = []
        inventory_kinds = {"COVERAGE", "INFO", "BASELINE", "USER ACCOUNT", "CRON FILE"}
        for event in events:
            if allowed is not None and event.kind not in allowed and event.kind not in ("COVERAGE", "INFO"):
                continue
            label = "Observed at" if event.kind in inventory_kinds else "Event time"
            detail = event.detail + f"\n\n{label}: {event.time}"
            if event.ip and "Source IP:" not in event.detail:
                detail += "\nSource IP: " + event.ip
            rows.append(self.Row(f"{event.kind} / {event.actor or '-'}", "WARNING" if event.warning else "INFO", detail))
        return rows

    def filter(self, kind):
        self.kind = kind
        with self.activity.lock:
            self.activity.rows = self.rows()
            self.activity.selected = 0

    def scan(self):
        if self.activity.busy or not self.servers:
            return
        server = self.servers[min(self.hosts.selected, len(self.servers) - 1)]
        self.target = server.name
        self.activity.title = f"ACTIVITY / {server.name}"
        self.activity.rows, self.activity.error = self.rows(), ""
        self.activity.updated = "never" if server.name not in self.cache else "cached"
        self.activity.selected = 0

        def fetch():
            self.cache[server.name] = self.store.scan(server, self.args.audit_hours)
            return self.rows()

        self.activity.fetch = fetch
        self.activity.refresh()
