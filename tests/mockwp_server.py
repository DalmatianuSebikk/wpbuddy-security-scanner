"""A local mock WordPress site for testing WpBuddy end-to-end.

Serves static files from tests/fixtures/mockwp/ and implements just enough
WordPress behaviour to exercise the scanner:
- /wp-json/ index and /wp-json/wp/v2/users (JSON)
- ?rest_route= and ?author= user enumeration
- wp-login.php POST with valid credentials admin / dadadada
- xmlrpc.php: GET 405, POST system.listMethods / system.multicall brute shape

The placeholder __PORT__ in fixture files is replaced with the real port, so
fixtures can cross-reference themselves with absolute URLs.
"""

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mockwp"

VALID_USER, VALID_PASSWORD = "admin", "dadadada"

# The mock plays a WAF in front of version-probe files: plain
# /wp-content/<kind>/<slug>/{readme.txt,style.css,changelog.txt} requests get a
# Cloudflare-style 403; obfuscated paths (//, /./, %2f, ;, case) slip through,
# which is exactly what the scanner's evasion ladder exploits.
WAF_BLOCKED_RE = re.compile(
    r"^/wp-content/(plugins|themes)/[^/]+/(readme\.(txt|md)|changelog\.txt|style\.css)$", re.I)

WAF_BLOCK_BODY = (b"<html><head><title>Attention Required! | Cloudflare</title></head>"
                  b"<body>cf blocked</body></html>")

LIST_METHODS_XML = """<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
{strings}
</data></array></value></param></params></methodResponse>"""

METHODS = ["system.multicall", "system.listMethods", "wp.getUsersBlogs", "pingback.ping"]

# REST routes the mock knows about (drives /wp-json/<route> OPTIONS answers)
_ROUTES = {
    "": ["GET"],
    "wp/v2/posts": ["GET", "POST"],
    "wp/v2/pages": ["GET"],
    "wp/v2/users": ["GET"],
    "wp/v2/settings": ["GET", "POST", "DELETE"],
    "contact-form-7/v1/contact-forms": ["GET", "POST"],
    "wpdiscuz/v1/ping": ["GET", "POST"],
}


class MockWPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # keep test output clean

    # ---------------- helpers ----------------
    def _port(self):
        return self.server.server_address[1]

    def _fixture(self, relpath):
        path = (FIXTURES / relpath).resolve()
        if not str(path).startswith(str(FIXTURES.resolve())) or not path.is_file():
            return None
        return path.read_bytes().replace(b"__PORT__", str(self._port()).encode())

    def _send(self, status, body, content_type="text/html; charset=utf-8", headers=()):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/8.2.0")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location):
        body = b""
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.write(body)

    # ---------------- OPTIONS ----------------
    def do_OPTIONS(self):
        """Route inventory support (deep profile): known REST routes answer
        with Allow; everything else 404s like real WordPress."""
        path = unquote(urlsplit(self.path).path)
        if path.startswith("/wp-json/"):
            route = path[len("/wp-json/"):]
            if route in _ROUTES:
                methods = ",".join(sorted(_ROUTES[route]))
                self.send_response(204)
                self.send_header("Allow", methods)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        self._send(404, "no route", "text/plain")

    # ---------------- GET ----------------
    def do_GET(self):
        split = urlsplit(self.path)
        raw_path = split.path
        path = unquote(split.path)
        query = parse_qs(split.query)

        # WAF simulation: plain-form version probes are blocked
        if self._waf_blocks(raw_path):
            self._send(403, WAF_BLOCK_BODY,
                       headers=[("Server", "cloudflare"), ("Cf-Ray", "8f3a1b2c9d10")])
            return

        # "executed" PHP endpoint: simulates a directly-accessible file that
        # echoes a request parameter back (vulnerable reflected output).
        if path == "/wp-content/plugins/vulnplugin/reflect.php":
            msg = query.get("msg", [""])[0]
            body = f"<html><body>Message: {msg}</body></html>"
            self._send(200, body)
            return

        # test endpoint: reports what the server actually received (header check)
        if path == "/wpbuddy-echo":
            import json
            payload = {
                "ua": self.headers.get("User-Agent"),
                "referer": self.headers.get("Referer"),
                "sec_ch_ua": self.headers.get("sec-ch-ua"),
                "accept_language": self.headers.get("Accept-Language"),
                "origin": self.headers.get("Origin"),
            }
            self._send(200, json.dumps(payload), "application/json; charset=UTF-8")
            return

        if path in ("/wp-json", "/wp-json/"):
            self._send(200, self._fixture("wp-json/index.json") or b"{}",
                       "application/json; charset=UTF-8")
            return
        if path == "/wp-json/wp/v2/users" or query.get("rest_route", [""])[0] == "/wp/v2/users":
            self._send(200, self._fixture("wp-json/users.json") or b"[]",
                       "application/json; charset=UTF-8")
            return
        # Authenticated identity endpoint (F-3): answers only for the valid
        # app-password credentials, REST-forbidden otherwise.
        if path == "/wp-json/wp/v2/users/me":
            import base64
            import json as _json
            auth = self.headers.get("Authorization", "")
            ok = False
            if auth.startswith("Basic "):
                try:
                    user, _, secret = base64.b64decode(auth[6:]).decode().partition(":")
                    ok = user == VALID_USER and secret == VALID_PASSWORD
                except Exception:
                    ok = False
            if ok:
                self._send(200, _json.dumps({
                    "id": 1, "name": "Admin Site", "slug": VALID_USER,
                    "roles": ["administrator"],
                    "capabilities": {"manage_options": True, "install_plugins": True,
                                     "upload_files": True}}),
                    "application/json; charset=UTF-8")
            else:
                self._send(403, '{"code":"rest_forbidden","message":"Sorry, you are not '
                                'allowed to access this."}',
                           "application/json; charset=UTF-8")
            return
        if "rest_route" in query:  # other REST routes -> WP-style 404 error object
            self._send(404, '{"code":"rest_no_route","message":"No route was found"}',
                       "application/json; charset=UTF-8")
            return
        if "author" in query:
            author = query["author"][0]
            if author == "1":
                self._redirect(f"http://127.0.0.1:{self._port()}/author/adminsite/")
            else:
                self._send(404, "<html><body>404</body></html>")
            return
        if path == "/wp-login.php" and query.get("action", [""])[0] == "register":
            # self-registration ENABLED (a deliberate finding on the mock)
            self._send(200,
                       '<html><body><form name="registerform" method="post">'
                       '<input type="text" name="user_login" />'
                       '<input type="email" name="user_email" />'
                       '<input type="submit" value="Register" />'
                       '</form><a href="wp-login.php?action=lostpassword">Lost your password?</a>'
                       '</body></html>')
            return
        if path == "/xmlrpc.php":
            self._send(405, "XML-RPC server accepts POST requests only.")
            return
        if path == "/feed":
            self._send(200, self._fixture("feed.xml") or b"", "application/rss+xml")
            return

        self._serve_file(path)

    def _waf_blocks(self, raw_path):
        """Block only the canonical plain form; obfuscated variants pass."""
        if not WAF_BLOCKED_RE.match(raw_path):
            return False
        if raw_path.startswith("//") or "/./" in raw_path or "%" in raw_path or ";" in raw_path:
            return False
        return raw_path == raw_path.lower()

    def _serve_file(self, path):
        import posixpath
        # normalize what the WAF let through (//, /./, ;, case) back to fixtures,
        # remembering whether the request was for a directory (trailing slash)
        is_dir = path.rstrip(";").endswith("/")
        relpath = posixpath.normpath(unquote(path)).lstrip("/").replace(";", "") or "index.html"
        if is_dir and not posixpath.splitext(relpath)[1]:
            relpath += "/index.html"
        data = self._fixture(relpath)
        if data is None and relpath != relpath.lower():
            data = self._fixture(relpath.lower())  # case-insensitive origin
        if data is None:
            self._send(404, "<html><body><h1>404</h1></body></html>")
            return
        content_type = "text/html; charset=utf-8"
        if relpath.endswith((".json",)):
            content_type = "application/json; charset=UTF-8"
        elif relpath.endswith((".css",)):
            content_type = "text/css"
        elif relpath.endswith((".txt", ".md")):
            content_type = "text/plain"
        self._send(200, data, content_type)

    # ---------------- POST ----------------
    def do_POST(self):
        split = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")

        if split.path == "/wp-login.php":
            form = parse_qs(body.replace("&amp;", "&"))
            user = form.get("log", [""])[0]
            password = form.get("pwd", [""])[0]
            known_users = {VALID_USER, "adminsite", "editoruser"}
            if user == VALID_USER and password == VALID_PASSWORD:
                self._redirect(f"http://127.0.0.1:{self._port()}/wp-admin/")
            elif user in known_users:
                # real WP wording: confirms the account exists
                self._send(200, f'<html><body><div id="login_error">ERROR: The password you '
                                f'entered for the user {user} is incorrect. '
                                f'<a href="#">Lost your password?</a></div></body></html>')
            else:
                self._send(200, '<html><body><div id="login_error">ERROR: Invalid username.</div>'
                                '</body></html>')
            return

        if split.path == "/xmlrpc.php":
            if "system.listMethods" in body:
                strings = "".join(f"<value><string>{m}</string></value>" for m in METHODS)
                self._send(200, LIST_METHODS_XML.format(strings=strings),
                           "text/xml; charset=UTF-8")
                return
            if "system.multicall" in body and "wp.getUsersBlogs" in body:
                self._send(200, self._multicall_response(body), "text/xml; charset=UTF-8")
                return
            self._send(200, '<?xml version="1.0"?><methodResponse><fault><value><struct>'
                            '<member><name>faultCode</name><value><int>405</int></value></member>'
                            '</struct></value></fault></methodResponse>', "text/xml; charset=UTF-8")
            return

        self._send(404, "not found")

    def _multicall_response(self, body):
        """One response item per wp.getUsersBlogs call, in order - in the REAL
        WordPress shape: successes wrapped in their own <array>, failures as
        bare <struct> faults (a uniform wrapper once hid a parser bug)."""
        import re
        calls = re.findall(r"<string>([^<]*)</string>", body)
        # calls come in methodName/params strings; keep username/password pairs
        params = [c for c in calls if c not in ("wp.getUsersBlogs",)]
        pairs = [(params[i], params[i + 1]) for i in range(0, len(params) - 1, 2)]
        items = []
        for user, password in pairs:
            if user == VALID_USER and password == VALID_PASSWORD:
                items.append("<value><array><data><value><struct>"
                             '<member><name>url</name><value><string>http://mock/</string></value></member>'
                             '<member><name>blogName</name><value><string>Mock</string></value></member>'
                             "</struct></value></data></array></value>")
            else:
                items.append("<value><struct>"
                             '<member><name>faultCode</name><value><int>403</int></value></member>'
                             '<member><name>faultString</name><value><string>Incorrect username or password</string></value></member>'
                             "</struct></value>")
        return ('<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
                + "".join(items) + "</data></array></value></param></params></methodResponse>")


def start_mock_wp(port=0):
    """Start the mock site on a background thread. Returns (server, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), MockWPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    return server, base


if __name__ == "__main__":
    import time
    srv, url = start_mock_wp(8765)
    print(f"mock WordPress running at {url}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        srv.shutdown()
