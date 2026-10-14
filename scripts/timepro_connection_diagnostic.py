"""One bounded, anonymous connection diagnosis. Never imports the clock-in script.

Only fixed stage names, outcomes, durations, HTTP codes and failure categories
are emitted. Responses are inspected in memory; no files/artifacts are written.
"""

import asyncio
from contextlib import contextmanager, suppress
import html
import http.client
import json
import os
import re
import signal
import socket
import ssl
import time
from urllib.parse import urlsplit


HOST = "employ.nittai.ac.jp"
PATH = "/TimePro-VG/page/Ovg00010t.aspx"
URL = "https://" + HOST + PATH
BODY_LIMIT = 512 * 1024
DENIED_STATUSES = {401, 403, 407, 429, 451}
RESOURCE_TYPES = {"document", "stylesheet", "image", "media", "font", "script",
                  "texttrack", "xhr", "fetch", "eventsource", "manifest"}
DENIAL_PHRASES = ("access denied", "request blocked", "access forbidden",
                  "403 forbidden", "アクセスが拒否", "アクセスを拒否",
                  "アクセス制限", "アクセスできるipアドレス", "アクセスは禁止")


class StopDiagnostic(Exception):
    def __init__(self, kind, status=None):
        self.kind, self.status = kind, status


def record(stage, outcome, started=None, status=None, failure=None):
    item = {"stage": stage, "result": outcome}
    if started is not None:
        item["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    if status is not None:
        item["response_code"] = int(status)
    if failure:
        item["failure"] = failure
    print(json.dumps(item, sort_keys=True), flush=True)


def failure_kind(error):
    if isinstance(error, StopDiagnostic):
        return error.kind
    if isinstance(error, (TimeoutError, socket.timeout)) or type(error).__name__ == "TimeoutError":
        return "timeout"
    if isinstance(error, socket.gaierror):
        return "dns_resolution_error"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "certificate_verification_error"
    if isinstance(error, ssl.SSLError):
        return "tls_error"
    if isinstance(error, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(error, ConnectionResetError):
        return "connection_reset"
    if isinstance(error, OSError):
        return "os_network_error"
    return "internal_error"


@contextmanager
def deadline(seconds):
    def expired(_signum, _frame):
        raise TimeoutError()
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def measure(stage, operation, seconds, response=False):
    start = time.monotonic()
    try:
        with deadline(seconds):
            result = operation()
        record(stage, "ok", start, result.status if response else None)
        return result
    except Exception as error:
        record(stage, "failed", start, getattr(error, "status", None), failure_kind(error))
        raise StopDiagnostic(failure_kind(error)) from None


def has_denial(body):
    # Only classify text in memory. Do not return or log any of the text.
    text = html.unescape(body.decode("utf-8", errors="replace")).casefold()
    text = re.sub(r"<[^>]+>", " ", text)
    text = " ".join(text.split())
    return any(phrase in text for phrase in DENIAL_PHRASES)


def probe_https():
    addresses = measure("dns", lambda: socket.getaddrinfo(
        HOST, 443, type=socket.SOCK_STREAM), 10)
    if not addresses:
        raise StopDiagnostic("dns_no_address")
    # Use the first ordinary resolver result once; never try alternative IPs.
    family, kind, protocol, _, address = addresses[0]
    connection = None
    sock = socket.socket(family, kind, protocol)
    try:
        sock.settimeout(10)
        measure("tcp_443", lambda: sock.connect(address), 10)
        sock = measure("tls", lambda: ssl.create_default_context().wrap_socket(
            sock, server_hostname=HOST), 10)
        sock.settimeout(15)
        connection = http.client.HTTPSConnection(HOST, timeout=15)
        connection.sock = sock

        def get_headers():
            # Standard http.client behavior, without cookies, auth or redirects.
            connection.request("GET", PATH, headers={"Connection": "close"})
            response = connection.getresponse()
            if response.status in DENIED_STATUSES:
                raise StopDiagnostic("access_denied", response.status)
            if not 200 <= response.status < 300:
                raise StopDiagnostic("http_status_stop", response.status)
            return response

        response = measure("https_get_headers", get_headers, 15, response=True)

        def get_body():
            body = response.read(BODY_LIMIT + 1)
            if len(body) > BODY_LIMIT:
                raise StopDiagnostic("body_limit")
            if has_denial(body):
                raise StopDiagnostic("access_denied", response.status)

        measure("https_get_body", get_body, 15)
    finally:
        if connection:
            connection.close()
        sock.close()


def allowed_request(url, method, count):
    parts = urlsplit(url)
    if method != "GET":
        return "non_read_only_request"
    if count > 64:
        return "request_limit"
    if (parts.scheme != "https" or parts.hostname != HOST or
            parts.port not in (None, 443) or parts.username or parts.password):
        return "out_of_scope_request"
    return None


async def probe_browser():
    from playwright.async_api import async_playwright, TimeoutError as BrowserTimeout

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True, timeout=15000)
        # Fresh non-persistent context: no imported cookies, credentials, storage,
        # custom user agent, proxy, certificate bypass, downloads or recordings.
        context = await browser.new_context(accept_downloads=False, service_workers="block")
        page = await context.new_page()
        stopped = asyncio.Event()
        pending = {}
        statuses = {}
        request_count = 0

        def stop(stage, kind, status=None):
            if not stopped.is_set():
                record(stage, "failed", status=status, failure=kind)
                stopped.set()

        def request_stage(request):
            if request.is_navigation_request():
                return "browser_main_document" if request.frame == page.main_frame else "browser_frame_document"
            kind = request.resource_type
            return "browser_resource_" + (kind if kind in RESOURCE_TYPES else "other")

        async def guard(route):
            nonlocal request_count
            request_count += 1
            reason = allowed_request(route.request.url, route.request.method, request_count)
            if stopped.is_set() or reason:
                if reason:
                    stop("browser_request_guard", reason)
                await route.abort()
            else:
                await route.continue_()

        def on_request(request):
            pending[request] = (request_stage(request), time.monotonic())

        def on_response(response):
            statuses[response.request] = response.status
            if response.status in DENIED_STATUSES:
                stop(request_stage(response.request), "access_denied", response.status)

        async def on_finished(request):
            stage, start = pending.pop(request, (request_stage(request), time.monotonic()))
            status = statuses.pop(request, None)
            try:
                if request.is_navigation_request() and not stopped.is_set():
                    response = await request.response()
                    body = await asyncio.wait_for(response.body(), timeout=2)
                    if len(body) > BODY_LIMIT:
                        stop(stage, "body_limit", status)
                        return
                    if has_denial(body):
                        stop(stage, "access_denied", status)
                        return
                record(stage, "ok" if status and status < 400 else "failed", start,
                       status, None if status and status < 400 else "http_resource_error")
            except Exception:
                if not stopped.is_set():
                    stop(stage, "document_inspection_error", status)

        def on_failed(request):
            stage, start = pending.pop(request, (request_stage(request), time.monotonic()))
            statuses.pop(request, None)
            # Never print Playwright exception/request strings (they contain URLs).
            record(stage, "failed", start, failure="resource_request_failed")

        async def reject_websocket(route):
            stop("browser_request_guard", "websocket_not_requested")
            await route.close()

        await context.route("**/*", guard)
        await context.route_web_socket("**/*", reject_websocket)
        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfinished", on_finished)
        page.on("requestfailed", on_failed)

        async def observe():
            for state, milliseconds in [("commit", 15000), ("domcontentloaded", 15000),
                                        ("load", 15000), ("networkidle", 5000)]:
                start = time.monotonic()
                try:
                    if state == "commit":
                        response = await page.goto(URL, wait_until="commit", timeout=milliseconds)
                        status = response.status if response else None
                    else:
                        await page.wait_for_load_state(state, timeout=milliseconds)
                        status = None
                    record("browser_" + state, "ok", start, status)
                except BrowserTimeout:
                    record("browser_" + state, "failed", start, failure="timeout")
                    return False
                if stopped.is_set():
                    return False
            return True

        observation = asyncio.create_task(observe())
        denial = asyncio.create_task(stopped.wait())
        success = False
        try:
            done, _ = await asyncio.wait({observation, denial}, timeout=45,
                                         return_when=asyncio.FIRST_COMPLETED)
            if stopped.is_set():
                return False
            if observation in done:
                success = observation.result()
            else:
                record("browser_budget", "failed", failure="timeout")
            # Read only readiness, never frame URLs, names, form values or text.
            for frame in page.frames[:8]:
                try:
                    state = await asyncio.wait_for(frame.evaluate("document.readyState"), 1)
                    if state not in {"loading", "interactive", "complete"}:
                        state = "unknown"
                    record("browser_frame_" + state, "ok" if state == "complete" else "incomplete")
                except Exception:
                    record("browser_frame_state", "failed", failure="unavailable")
            return success and not stopped.is_set()
        finally:
            for task in (observation, denial):
                task.cancel()
            await asyncio.gather(observation, denial, return_exceptions=True)
            for stage, start in list(pending.values()):
                record(stage, "incomplete", start, failure="pending_at_stop")
            with suppress(Exception):
                await asyncio.wait_for(context.close(), 5)
            with suppress(Exception):
                await asyncio.wait_for(browser.close(), 5)


def main():
    if any(os.environ.get(key) for key in
           ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")):
        record("preflight", "failed", failure="proxy_environment_present")
        return 1
    try:
        probe_https()
        async def bounded_browser():
            return await asyncio.wait_for(probe_browser(), timeout=75)

        if not asyncio.run(bounded_browser()):
            return 1
        record("diagnostic", "ok")
        return 0
    except StopDiagnostic:
        return 1
    except Exception as error:
        record("diagnostic", "failed", failure=failure_kind(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
