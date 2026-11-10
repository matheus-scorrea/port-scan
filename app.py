#!/usr/bin/env python3
"""Mapeia as portas TCP de um único IP e aponta a interface web.

Feito para rodar no Windows com dois cliques em iniciar.bat.
"""

from __future__ import annotations

import html
import json
import os
import queue
import re
import socket
import ssl
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}

DEFAULT_PORTS = (
    80, 81, 82, 83, 88, 443, 800, 808, 1080, 1443, 4433, 4443, 5000, 5001,
    5443, 7443, 7547, 8000, 8008, 8080, 8081, 8082, 8083, 8088, 8090, 8181,
    8443, 8444, 8800, 8880, 8888, 9000, 9080, 9090, 9443, 10000, 10443,
)
TLS_FIRST = {443, 4433, 4443, 5443, 7443, 8443, 8444, 9443, 10443}
MAX_BODY = 48_000
WORKERS = 128
HOST_RE = re.compile(r"^(?:[a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$")
TITLE_RE = re.compile(br"<title[^>]*>(.*?)</title>", re.I | re.S)
PASSWORD_RE = re.compile(br"type\s*=\s*['\"]password['\"]", re.I)
STATUS_RE = re.compile(br"HTTP/\d(?:\.\d)?\s+(\d{3})")
SCAN_RE = re.compile(r"^/api/scan/([a-f0-9]{12})$")
CANCEL_RE = re.compile(r"^/api/scan/([a-f0-9]{12})/cancel$")
REFUSED = {111, 61, 10061}
RESET = {104, 54, 10054, 32}
TIMED_OUT = {110, 60, 10060, 10065}

jobs: dict[str, "ScanJob"] = {}
jobs_lock = threading.Lock()


class ScanError(ValueError):
    pass


class BusyError(ScanError):
    pass


class ScanJob:
    def __init__(self, host: str, address: str, ports: list[int], timeout: float) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.host = host
        self.address = address
        self.ports = ports
        self.timeout = timeout
        self.total = len(ports)
        self.tested = 0
        self.closed = 0
        self.silent = 0
        self.phase = "tcp"
        self.status = "running"
        self.error = None
        self.open_ports: list[dict] = []
        self.started = time.perf_counter()
        self.cancel = threading.Event()
        self.lock = threading.Lock()

    def snapshot(self) -> dict:
        with self.lock:
            opened = sorted(self.open_ports, key=lambda item: item["port"])
            elapsed_ms = int((time.perf_counter() - self.started) * 1000)
            remaining = None
            if self.status == "running" and self.phase == "tcp" and self.tested:
                remaining = int(elapsed_ms / self.tested * (self.total - self.tested))
            return {
                "id": self.id,
                "host": self.host,
                "address": self.address,
                "status": self.status,
                "phase": self.phase,
                "total": self.total,
                "tested": self.tested,
                "closed": self.closed,
                "silent": self.silent,
                "elapsed_ms": elapsed_ms,
                "remaining_ms": remaining,
                "interfaces": [item for item in opened if item.get("web")],
                "open_ports": opened,
                "error": self.error,
            }


def normalize_target(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        raise ScanError("Informe o IP do roteador.")
    if any(char in text for char in " \t\r\n,;"):
        raise ScanError("Informe um único IP ou nome, sem lista e sem faixa de rede.")
    if "://" not in text and re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", text):
        raise ScanError("Informe um único IP. Faixas de rede, como /24, não são aceitas.")

    if "://" in text or "/" in text:
        parsed = urlparse(text if "://" in text else f"http://{text}")
        text = parsed.hostname or ""
        if not text:
            raise ScanError("Não consegui ler o IP nesse endereço.")

    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "/" in text or text.endswith("."):
        raise ScanError("Informe um único IP. Faixas de rede, como /24, não são aceitas.")

    try:
        return str(ipaddress_of(text))
    except ValueError:
        pass
    if not HOST_RE.fullmatch(text):
        raise ScanError("IP ou nome inválido.")
    return text


def ipaddress_of(text: str):
    import ipaddress

    return ipaddress.ip_address(text)


def resolve_address(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ScanError("Não encontrei esse endereço.") from error
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0]
    if not infos:
        raise ScanError("Não encontrei esse endereço.")
    return infos[0][4][0]


def validate_port(port: int) -> int:
    if port < 1 or port > 65535:
        raise ScanError(f"Porta fora do intervalo: {port}")
    return port


def parse_ports(raw: str, include_common: bool) -> list[int]:
    ports: set[int] = set(DEFAULT_PORTS if include_common else ())
    text = (raw or "").strip()
    if text:
        for chunk in re.split(r"[\s,;]+", text):
            if not chunk:
                continue
            if re.fullmatch(r"\d{1,5}", chunk):
                ports.add(validate_port(int(chunk)))
                continue
            span = re.fullmatch(r"(\d{1,5})-(\d{1,5})", chunk)
            if not span:
                raise ScanError(f"Porta inválida: {chunk}")
            start = validate_port(int(span.group(1)))
            end = validate_port(int(span.group(2)))
            if end < start:
                raise ScanError(f"Faixa inválida: {chunk}")
            ports.update(range(start, end + 1))
    if not ports:
        raise ScanError("Informe ao menos uma porta, por exemplo 80, 443, 8000-9000.")
    return sorted(ports)


def ports_for_mode(mode: str, extra: str) -> list[int]:
    if mode == "all":
        return list(range(1, 65536))
    if mode == "common":
        return parse_ports(extra, include_common=True)
    if mode == "custom":
        return parse_ports(extra, include_common=False)
    raise ScanError("Escolha o que mapear.")


def clamp_timeout(value) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        timeout = 0.8
    return min(4.0, max(0.25, timeout))


def failure_kind(error: BaseException) -> str:
    if isinstance(error, ConnectionRefusedError):
        return "refused"
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(error, ssl.SSLError):
        return "tls"
    code = getattr(error, "winerror", None) or getattr(error, "errno", None)
    if code in REFUSED:
        return "refused"
    if code in RESET:
        return "reset"
    if code in TIMED_OUT:
        return "timeout"
    return "other"


def tcp_state(host: str, port: int, timeout: float) -> str:
    try:
        sock = socket.create_connection((host, port), timeout)
    except OSError as error:
        kind = failure_kind(error)
        if kind in {"refused", "reset"}:
            return "closed"
        return "silent"
    else:
        sock.close()
        return "open"


def tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return context


def read_response(sock: socket.socket, host: str, port: int, tls: bool) -> bytes:
    host_header = f"[{host}]" if ":" in host else host
    if not ((port == 80 and not tls) or (port == 443 and tls)):
        host_header = f"{host_header}:{port}"
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "User-Agent: MapeamentoPortas/1.0\r\n"
        "Accept: text/html,*/*\r\n"
        "Connection: close\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    chunks: list[bytes] = []
    total = 0
    while total < MAX_BODY:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def http_exchange(host: str, port: int, tls: bool, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout) as raw:
        raw.settimeout(timeout)
        if not tls:
            return read_response(raw, host, port, tls)
        server_name = None if is_ip(host) else host
        with tls_context().wrap_socket(raw, server_hostname=server_name) as secure:
            secure.settimeout(timeout)
            return read_response(secure, host, port, tls)


def is_ip(host: str) -> bool:
    try:
        ipaddress_of(host)
    except ValueError:
        return False
    return True


def parse_http(data: bytes) -> dict | None:
    head = data.lstrip(b"\r\n\t ")
    if not head.startswith(b"HTTP/"):
        return None
    header_blob, _, body = head.partition(b"\r\n\r\n")
    lines = header_blob.split(b"\r\n")
    status_match = STATUS_RE.match(lines[0])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin1").lower()] = value.decode("latin1", "replace").strip()

    title = None
    title_match = TITLE_RE.search(body)
    if title_match:
        raw_title = re.sub(br"\s+", b" ", title_match.group(1)).strip()
        title = html.unescape(raw_title.decode("utf-8", "replace"))[:180] or None

    status = int(status_match.group(1)) if status_match else None
    login = status == 401 or "www-authenticate" in headers
    if not login:
        login = PASSWORD_RE.search(body) is not None
    return {
        "status": status,
        "server": (headers.get("server") or "")[:120] or None,
        "location": (headers.get("location") or "")[:300] or None,
        "title": title,
        "login": login,
    }


def blank_port(port: int) -> dict:
    return {
        "port": port,
        "open": True,
        "web": False,
        "scheme": None,
        "status": None,
        "server": None,
        "title": None,
        "location": None,
        "login": False,
        "url": None,
        "detail": "aberta",
    }


def probe_port(host: str, port: int, timeout: float) -> dict:
    result = blank_port(port)
    order = ("https", "http") if port in TLS_FIRST else ("http", "https")
    saw_tcp = False
    refused = False
    timed_out = False

    for scheme in order:
        try:
            payload = http_exchange(host, port, scheme == "https", timeout)
            saw_tcp = True
        except OSError as error:
            kind = failure_kind(error)
            if kind == "refused":
                refused = True
                break
            if kind == "tls":
                saw_tcp = True
                continue
            if kind == "reset":
                saw_tcp = True
                continue
            timed_out = timed_out or kind == "timeout"
            continue

        parsed = parse_http(payload)
        if not parsed:
            continue
        result.update(parsed)
        result["open"] = True
        result["web"] = True
        result["scheme"] = scheme
        host_for_url = f"[{host}]" if ":" in host else host
        result["url"] = f"{scheme}://{host_for_url}:{port}/"
        result["detail"] = "página web"
        return result

    if saw_tcp:
        result["detail"] = "aberta, sem página web"
    elif refused:
        result["open"] = False
        result["detail"] = "recusada"
    elif timed_out:
        result["open"] = False
        result["detail"] = "sem resposta"
    else:
        result["open"] = False
        result["detail"] = "sem conexão"
    return result


def peek_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout) as sock:
            sock.settimeout(min(0.5, timeout))
            data = sock.recv(180)
    except OSError:
        return None
    if not data:
        return None
    if data[0] == 0x16:
        return "conexão criptografada, sem página web"
    text = "".join(char if char.isprintable() else " " for char in data.decode("latin1", "replace"))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:120] or None


def run_job(job: ScanJob) -> None:
    try:
        _run_job(job)
    except Exception:
        import traceback

        traceback.print_exc()
        with job.lock:
            job.status = "error"
            job.error = "O mapeamento parou por um erro interno."


def _run_job(job: ScanJob) -> None:
    pending: queue.Queue[int] = queue.Queue()
    for port in job.ports:
        pending.put(port)
    worker_count = min(WORKERS, max(1, job.total))

    def worker() -> None:
        while not job.cancel.is_set():
            try:
                port = pending.get_nowait()
            except queue.Empty:
                return
            state = tcp_state(job.address, port, job.timeout)
            with job.lock:
                job.tested += 1
                if state == "open":
                    job.open_ports.append(blank_port(port))
                elif state == "closed":
                    job.closed += 1
                else:
                    job.silent += 1

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if job.cancel.is_set():
        with job.lock:
            job.status = "cancelled"
        return

    with job.lock:
        job.phase = "web"
        open_ports = [item["port"] for item in job.open_ports]

    http_timeout = min(3.0, max(job.timeout, 1.2))
    for port in open_ports:
        if job.cancel.is_set():
            break
        result = probe_port(job.address, port, http_timeout)
        if not result["open"]:
            result = blank_port(port)
            result["detail"] = "aberta, sem página web"
        elif not result["web"]:
            result["detail"] = peek_banner(job.address, port, job.timeout) or result["detail"]
        with job.lock:
            job.open_ports = [
                result if item["port"] == port else item for item in job.open_ports
            ]

    with job.lock:
        job.status = "cancelled" if job.cancel.is_set() else "done"


def start_scan(host: str, mode: str, extra: str, timeout: float) -> dict:
    ports = ports_for_mode(mode, extra)
    address = resolve_address(host)
    with jobs_lock:
        if any(item.status == "running" for item in jobs.values()):
            raise BusyError("Já existe um mapeamento em andamento. Pare ele antes de iniciar outro.")
        job = ScanJob(host, address, ports, timeout)
        jobs[job.id] = job
        finished = [key for key, item in jobs.items() if item.status != "running"]
        for key in finished[:-4]:
            jobs.pop(key, None)
    threading.Thread(target=run_job, args=(job,), daemon=True).start()
    return job.snapshot()


def get_job(scan_id: str) -> ScanJob:
    with jobs_lock:
        job = jobs.get(scan_id)
    if job is None:
        raise ScanError("Esse mapeamento não existe mais.")
    return job


class Handler(BaseHTTPRequestHandler):
    server_version = "MapeamentoPortas/1.0"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        match = SCAN_RE.fullmatch(path)
        if match:
            try:
                job = get_job(match.group(1))
            except ScanError as error:
                self.send_json(404, {"error": str(error)})
                return
            self.send_json(200, job.snapshot())
            return
        spec = STATIC.get(path)
        if not spec:
            self.send_error(404)
            return
        name, content_type = spec
        body = (ROOT / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        cancel = CANCEL_RE.fullmatch(path)
        if cancel:
            try:
                job = get_job(cancel.group(1))
            except ScanError as error:
                self.send_json(404, {"error": str(error)})
                return
            job.cancel.set()
            self.send_json(200, job.snapshot())
            return
        if path != "/api/scan":
            self.send_error(404)
            return
        try:
            payload = self.read_json()
            host = normalize_target(str(payload.get("host", "")))
            mode = str(payload.get("mode", "all"))
            extra = str(payload.get("extra_ports", ""))
            timeout = clamp_timeout(payload.get("timeout", 0.8))
            snapshot = start_scan(host, mode, extra, timeout)
        except BusyError as error:
            running = next((item for item in jobs.values() if item.status == "running"), None)
            body = {"error": str(error)}
            if running is not None:
                body["id"] = running.id
            self.send_json(409, body)
            return
        except ScanError as error:
            self.send_json(400, {"error": str(error)})
            return
        self.send_json(200, snapshot)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        if length < 0 or length > 16_000:
            raise ScanError("Pedido inválido.")
        if length == 0:
            return {}
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ScanError("Pedido inválido.") from error
        if not isinstance(payload, dict):
            raise ScanError("Pedido inválido.")
        return payload

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")


def main() -> None:
    if os.name == "nt":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
    host = "127.0.0.1"
    port = 8765
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError:
        print("A porta 8765 já está em uso. Feche a outra janela deste app e abra de novo.")
        sys.exit(1)
    url = f"http://{host}:{port}"
    print(f"Mapeamento de portas em {url}")
    print("Deixe esta janela aberta. Feche a janela para encerrar o app.")
    if os.name == "nt":
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
