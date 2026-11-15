"""HTTP(S) blackbox prober, similar to the Prometheus blackbox exporter.

Reads targets from domains.txt and prints one dashboard line per target, or
Prometheus text exposition with --metrics. Uses only the standard library:
each probe performs a GET, follows redirects, verifies TLS, and reports the
status code, duration, redirect count, HTTP version, and content length.
"""
import argparse
import http.client
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

TIMEOUT = 15
MAX_REDIRECTS = 10
MAX_BODY = 5_000_000
USER_AGENT = "ops-dashboard-blackbox/1.0"
REDIRECT_STATUSES = (301, 302, 303, 307, 308)
HTTP_VERSIONS = {9: "0.9", 10: "1.0", 11: "1.1", 20: "2"}


@dataclass
class ProbeResult:
    target: str
    success: bool = False
    status: int = 0
    duration: float = 0.0
    redirects: int = 0
    version: str = "-"
    tls: str = "no"
    content_length: int = 0
    error: str = ""


def normalize_target(value):
    value = value.strip()
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid target URL: {exc}") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Use an http or https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs must not contain credentials")
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii")
    if not host or any(char.isspace() for char in host) or ":" in host or host.startswith("-"):
        raise ValueError("Enter a valid DNS hostname or http/https URL")
    authority = f"{host}:{port}" if port is not None else host
    normalized = f"{parsed.scheme.lower()}://{authority}{(parsed.path or '/').replace(' ', '%20')}"
    if parsed.query:
        normalized += "?" + parsed.query.replace(" ", "%20")
    return normalized


def probe(target, timeout=TIMEOUT, max_redirects=MAX_REDIRECTS):
    result = ProbeResult(target=target, success=False)
    start = time.monotonic()
    deadline = start + timeout
    url = target
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"probe exceeded the {timeout:.0f}s overall timeout")
            parsed = urlsplit(url)
            secure = parsed.scheme.lower() == "https"
            port = parsed.port or (443 if secure else 80)
            if secure:
                connection = http.client.HTTPSConnection(
                    parsed.hostname, port, timeout=remaining,
                    context=ssl.create_default_context())
            else:
                connection = http.client.HTTPConnection(parsed.hostname, port, timeout=remaining)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            try:
                connection.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
                response = connection.getresponse()
                body = response.read(MAX_BODY)
            finally:
                connection.close()
            result.version = HTTP_VERSIONS.get(response.version, str(response.version))
            if secure:
                result.tls = "OK"
            location = response.getheader("Location")
            if response.status in REDIRECT_STATUSES and location and result.redirects < max_redirects:
                url = urljoin(url, location)
                if urlsplit(url).scheme.lower() not in ("http", "https"):
                    raise ValueError(f"redirect to unsupported scheme: {location}")
                result.redirects += 1
                continue
            result.status = response.status
            result.content_length = len(body)
            result.success = True
            break
    except ssl.SSLCertVerificationError as exc:
        result.tls = f"FAILED ({exc.verify_message})"
        result.error = f"TLS verification failed: {exc.verify_message}"
    except socket.gaierror as exc:
        result.error = f"DNS lookup failed: {exc.strerror or exc}"
    except (TimeoutError, socket.timeout) as exc:
        result.error = str(exc) or "timed out"
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result.error = str(exc) or exc.__class__.__name__
    result.duration = time.monotonic() - start
    return result


def format_result(result):
    if result.error:
        return f"{result.target} PROBE FAILED: {result.error} (after {result.duration:.3f}s)"
    state = "UP" if result.status < 400 else "WARNING"
    status = result.status if result.status else "-"
    return (f"{result.target} probe: {state} status: {status} "
            f"duration: {result.duration:.3f}s redirects: {result.redirects} "
            f"http: {result.version} tls: {result.tls} bytes: {result.content_length}")


def escape_label(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_metrics(result):
    labels = f'target="{escape_label(result.target)}"'
    return "\n".join((
        f"probe_success{{{labels}}} {int(result.success)}",
        f"probe_duration_seconds{{{labels}}} {result.duration:.3f}",
        f"probe_http_status_code{{{labels}}} {result.status}",
        f"probe_http_redirects{{{labels}}} {result.redirects}",
        f"probe_http_ssl{{{labels}}} {int(result.tls != 'no')}",
        f"probe_http_content_length{{{labels}}} {result.content_length}",
    ))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", action="store_true",
                        help="Print Prometheus text exposition instead of dashboard lines")
    args = parser.parse_args()
    for line in Path("domains.txt").read_text().splitlines():
        target = line.split("#", 1)[0].strip()
        if not target:
            continue
        try:
            result = probe(normalize_target(target))
        except Exception as exc:  # An invalid target must not stop the remaining probes.
            if args.metrics:
                print(f'probe_success{{target="{escape_label(target)}"}} 0')
            else:
                print(f"{target} PROBE FAILED: {exc}")
            continue
        print(format_metrics(result) if args.metrics else format_result(result))


if __name__ == "__main__":
    main()