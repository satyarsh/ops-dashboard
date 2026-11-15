"""Certificate checker adapted from the supplied script for macOS LibreSSL."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import socket
import ssl
import subprocess
from urllib.parse import urlsplit


def normalize_host(value):
    value = value.strip()
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Use a hostname or an http/https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs must not contain credentials")
    if parsed.port not in (None, 443):
        raise ValueError("Certificate checks use port 443; remove the explicit port")
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii")
    if not host or any(char.isspace() for char in host) or ":" in host or host.startswith("-"):
        raise ValueError("Enter a valid DNS hostname or http/https URL")
    return host.lower()


def verify_host(host):
    # Python handles hostname verification and certificate-chain validation.
    # This avoids LibreSSL's unsupported s_client -verify_hostname option.
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=15) as connection:
            with context.wrap_socket(connection, server_hostname=host):
                pass
        return "OK"
    except ssl.SSLCertVerificationError as exc:
        return f"FAILED ({exc.verify_message})"
    except (OSError, ssl.SSLError) as exc:
        return f"FAILED ({exc})"


def check_host(host):
    # Keep retrieving expiry independently: it remains useful when validation
    # fails. The unverified certificate is never used to claim trust.
    connection = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host, "-showcerts"],
        input="", capture_output=True, text=True, timeout=15,
    )
    cert = subprocess.run(
        ["openssl", "x509", "-noout", "-enddate"], input=connection.stdout,
        capture_output=True, text=True, timeout=5,
    )
    if cert.returncode:
        raise RuntimeError(cert.stderr.strip() or connection.stderr.strip() or "Could not retrieve certificate")
    expiry = datetime.strptime(cert.stdout.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days = (expiry - now).total_seconds() / 86400
    status = "EXPIRED" if days <= 0 else "EXPIRING SOON" if expiry <= now + timedelta(days=30) else "OK"
    verification = verify_host(host)
    return f"{host:35} expiry: {status:13} {days:6.1f} days left; chain/hostname: {verification}"


def main():
    for line in Path("domains.txt").read_text().splitlines():
        host = line.split("#", 1)[0].strip()
        if not host:
            continue
        try:
            host = normalize_host(host)
            print(check_host(host))
        except Exception as exc:
            print(f"{host:35} CHECK FAILED: {exc}")


if __name__ == "__main__":
    main()
