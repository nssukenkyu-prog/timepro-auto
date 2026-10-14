"""Offline tests: no university traffic and no browser login or clock-in."""
from contextlib import redirect_stdout
import io
import json
import socket
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from scripts import timepro_connection_diagnostic as diagnostic


class DiagnosticSafetyTests(unittest.TestCase):
    def test_only_exact_origin_get_is_permitted(self):
        self.assertIsNone(diagnostic.allowed_request(diagnostic.URL, "GET", 1))
        for url, method, count in [
            (diagnostic.URL, "POST", 1),
            ("https://elsewhere.example/", "GET", 1),
            (diagnostic.URL.replace("https:", "http:"), "GET", 1),
            (diagnostic.URL.replace(".jp/", ".jp:8443/"), "GET", 1),
            (diagnostic.URL.replace("https://", "https://user:secret@"), "GET", 1),
            (diagnostic.URL, "GET", 65),
        ]:
            with self.subTest(method=method, count=count):
                self.assertIsNotNone(diagnostic.allowed_request(url, method, count))

    def test_denial_text_is_detected_without_returning_body(self):
        self.assertTrue(diagnostic.has_denial(b"<h1>Access <b>Denied</b></h1>"))
        self.assertTrue(diagnostic.has_denial("アクセスが拒否されました".encode()))
        self.assertFalse(diagnostic.has_denial(b'<html><iframe src="login.aspx"></iframe></html>'))

    def test_raw_exception_and_query_are_never_logged(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(diagnostic.StopDiagnostic):
            diagnostic.measure("tcp_443", lambda: (_ for _ in ()).throw(
                TimeoutError("https://example/?token=PRIVATE; Cookie: SECRET")), 1)
        item = json.loads(output.getvalue())
        self.assertEqual(item["failure"], "timeout")
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertNotIn("SECRET", output.getvalue())

    def test_dns_failure_stops_before_socket_and_browser(self):
        with patch.dict("os.environ", {}, clear=True), \
                patch.object(diagnostic.socket, "getaddrinfo", side_effect=socket.gaierror()), \
                patch.object(diagnostic.socket, "socket") as tcp, \
                patch.object(diagnostic, "probe_browser") as browser, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(diagnostic.main(), 1)
            tcp.assert_not_called()
            browser.assert_not_called()

    def run_http_probe(self, status=200, body=b"<html></html>", tcp_error=None):
        response = MagicMock(status=status)
        response.read.return_value = body
        connection = MagicMock()
        connection.getresponse.return_value = response
        raw = MagicMock()
        if tcp_error:
            raw.connect.side_effect = tcp_error
        tls = MagicMock()
        output = io.StringIO()
        result = None
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 443))]
        with patch.object(diagnostic.socket, "getaddrinfo", return_value=addresses), \
                patch.object(diagnostic.socket, "socket", return_value=raw), \
                patch.object(diagnostic.ssl, "create_default_context") as ssl_context, \
                patch.object(diagnostic.http.client, "HTTPSConnection", return_value=connection), \
                redirect_stdout(output):
            ssl_context.return_value.wrap_socket.return_value = tls
            try:
                diagnostic.probe_https()
            except diagnostic.StopDiagnostic as error:
                result = error.kind
        return result, raw, connection, [json.loads(line) for line in output.getvalue().splitlines()]

    def test_single_get_has_no_auth_or_cookie_and_no_alternative_ip(self):
        result, raw, connection, records = self.run_http_probe()
        self.assertIsNone(result)
        raw.connect.assert_called_once_with(("192.0.2.1", 443))
        connection.request.assert_called_once_with("GET", diagnostic.PATH,
                                                   headers={"Connection": "close"})
        self.assertEqual([r["stage"] for r in records],
                         ["dns", "tcp_443", "tls", "https_get_headers", "https_get_body"])

    def test_tcp_timeout_has_no_retry_or_http_request(self):
        result, raw, connection, records = self.run_http_probe(tcp_error=TimeoutError())
        self.assertEqual(result, "timeout")
        self.assertEqual(raw.connect.call_count, 1)
        connection.request.assert_not_called()
        self.assertEqual(records[-1]["stage"], "tcp_443")

    def test_redirect_and_denial_stop_without_follow_up_request(self):
        for status, kind in [(302, "http_status_stop"), (401, "access_denied"),
                             (403, "access_denied"), (429, "access_denied")]:
            with self.subTest(status=status):
                result, _, connection, records = self.run_http_probe(status=status)
                self.assertEqual(result, kind)
                self.assertEqual(connection.request.call_count, 1)
                connection.getresponse.return_value.read.assert_not_called()
                self.assertEqual(records[-1]["response_code"], status)

    def test_http_200_block_page_stops_before_browser(self):
        result, _, _, records = self.run_http_probe(body=b"<h1>Access Denied</h1>")
        self.assertEqual(result, "access_denied")
        self.assertEqual(records[-1]["stage"], "https_get_body")
        with patch.dict("os.environ", {}, clear=True), \
                patch.object(diagnostic, "probe_https", side_effect=diagnostic.StopDiagnostic(result)), \
                patch.object(diagnostic, "probe_browser") as browser:
            self.assertEqual(diagnostic.main(), 1)
            browser.assert_not_called()

    def test_proxy_configuration_stops_without_changing_it(self):
        with patch.dict("os.environ", {"HTTPS_PROXY": "http://PRIVATE"}, clear=True), \
                patch.object(diagnostic, "probe_https") as probe, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostic.main(), 1)
            probe.assert_not_called()
            self.assertNotIn("PRIVATE", output.getvalue())


class BrowserSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, status=200, body=b"<html></html>", load_timeout=False):
        class BrowserTimeout(Exception):
            pass

        frame = MagicMock()
        frame.evaluate = AsyncMock(return_value="complete")
        page = MagicMock(main_frame=frame, frames=[frame])
        handlers = {}
        page.on.side_effect = lambda name, handler: handlers.setdefault(name, handler)
        request = MagicMock(frame=frame, resource_type="document")
        request.is_navigation_request.return_value = True
        response = MagicMock(status=status, request=request)
        response.body = AsyncMock(return_value=body)
        request.response = AsyncMock(return_value=response)

        async def navigate(*args, **kwargs):
            handlers["request"](request)
            handlers["response"](response)
            await handlers["requestfinished"](request)
            return response

        page.goto = AsyncMock(side_effect=navigate)
        page.wait_for_load_state = AsyncMock()
        if load_timeout:
            page.wait_for_load_state.side_effect = BrowserTimeout("PRIVATE_QUERY_AND_COOKIE")
        context = MagicMock()
        context.new_page = AsyncMock(return_value=page)
        context.route = AsyncMock()
        context.route_web_socket = AsyncMock()
        context.close = AsyncMock()
        browser = MagicMock()
        browser.new_context = AsyncMock(return_value=context)
        browser.close = AsyncMock()
        playwright = MagicMock()
        playwright.chromium.launch = AsyncMock(return_value=browser)
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=playwright)
        manager.__aexit__ = AsyncMock(return_value=False)
        module = types.ModuleType("playwright.async_api")
        module.async_playwright = lambda: manager
        module.TimeoutError = BrowserTimeout
        output = io.StringIO()
        with patch.dict("sys.modules", {"playwright": types.ModuleType("playwright"),
                                        "playwright.async_api": module}), redirect_stdout(output):
            result = await diagnostic.probe_browser()
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertNotIn("https://", output.getvalue())
        context.close.assert_awaited_once()
        browser.close.assert_awaited_once()
        return result, browser, page, [json.loads(line) for line in output.getvalue().splitlines()]

    async def test_browser_starts_fresh_and_navigates_only_once(self):
        result, browser, page, records = await self.exercise()
        self.assertTrue(result)
        browser.new_context.assert_awaited_once_with(accept_downloads=False, service_workers="block")
        page.goto.assert_awaited_once_with(diagnostic.URL, wait_until="commit", timeout=15000)
        self.assertEqual([call.args[0] for call in page.wait_for_load_state.await_args_list],
                         ["domcontentloaded", "load", "networkidle"])
        self.assertTrue(any(item["stage"] == "browser_frame_complete" for item in records))

    async def test_browser_stops_on_denial_status_and_200_block_page(self):
        for status, body in [(403, b""), (200, b"<h1>Access Denied</h1>")]:
            result, _, page, records = await self.exercise(status=status, body=body)
            self.assertFalse(result)
            page.wait_for_load_state.assert_not_awaited()
            self.assertEqual(page.goto.await_count, 1)
            self.assertTrue(any(item.get("failure") == "access_denied" for item in records))

    async def test_browser_timeout_never_retries_or_logs_exception_text(self):
        result, _, page, records = await self.exercise(load_timeout=True)
        self.assertFalse(result)
        self.assertEqual(page.goto.await_count, 1)
        self.assertTrue(any(item.get("failure") == "timeout" for item in records))


if __name__ == "__main__":
    unittest.main()
