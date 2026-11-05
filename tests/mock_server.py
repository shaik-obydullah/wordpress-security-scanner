"""Local mock WordPress server for testing the scanner end-to-end.

Serves fake-but-realistic responses so we can verify the scanner pipeline
without touching any external site.
"""

import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

HOMEPAGE = """<!DOCTYPE html>
<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2"></script>
<link rel="https://api.w.org/" href="/wp-json/">
</head><body>
<a href="/wp-admin/">Admin</a>
<a href="/author/admin/">admin's posts</a>
<a href="/feed/">RSS</a>
</body></html>"""

REST_USERS = '{"code":"rest_no_route","message":"No route"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = self.path
        # WordPress detection
        if path in ("/", ""):
            return self._send(200, HOMEPAGE)
        if path == "/feed/":
            return self._send(
                200, "<rss><generator>https://wordpress.org/?v=6.4.2</generator></rss>"
            )
        if path == "/readme.html":
            return self._send(200, "<h1>WordPress</h1><p>Version 6.4.2</p>")
        if path.startswith("/wp-content/plugins/"):
            if "contact-form-7" in path:
                return self._send(
                    200, "=== Contact Form 7 ===\nStable tag: 5.9.2", "text/plain"
                )
            return self._send(404, "Not Found")
        if path.startswith("/wp-content/themes/"):
            if "storefront" in path:
                return self._send(
                    200, "/*\nTheme Name: Storefront\nVersion: 4.6.0\n*/", "text/css"
                )
            return self._send(404, "Not Found")
        if path.startswith("/wp-json/wp/v2/users"):
            return self._send(200, '[{"slug":"admin"},{"slug":"editor1"}]', "application/json")
        if path == "/wp-json/":
            return self._send(
                200,
                '{"name":"mock","routes":{"/wp/v2/users":{},"/wp/v2/posts":{}}}',
                "application/json",
            )
        if path == "/xmlrpc.php":
            return self._send(404, "Not Found")
        if path == "/readme" or "/readme.html" in path:
            return self._send(200, "<h1>WordPress</h1>")
        if re.match(r"/\?author=\d+", path):
            # Redirect to author archive revealing username
            m = re.search(r"author=(\d+)", path)
            uid = int(m.group(1))
            return self._send(302, "")
        # Config exposure
        if path in ("/wp-config.php", "/wp-config.php.bak", "/.env", "/backup.sql"):
            return self._send(403, "Forbidden")
        if path.startswith("/wp-content/") or path == "/wp-includes/":
            body = "<html><body><h1>Index of</h1><a href='file.txt'>file.txt</a></body></html>"
            return self._send(200, body)
        if path == "/debug.log":
            return self._send(404, "Not Found")
        # Security headers are already sent above; body any
        return self._send(404, "Not Found")

    def do_POST(self):
        if self.path == "/wp-login.php":
            return self._send(
                200,
                "<html><body><div id='login_error'>Invalid username. Unknown username.</div></body></html>",
            )
        if self.path == "/xmlrpc.php":
            return self._send(
                200,
                '<?xml version="1.0"?><methodResponse>'
                "<params><param><value><array><data>"
                "<value><string>system.multicall</string></value>"
                "</data></array></value></param></params></methodResponse>",
                "text/xml",
            )
        return self._send(404, "Not Found")

    def do_HEAD(self):
        self.do_GET()


def start_mock_server(port=8807):
    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    server = start_mock_server()
    print(f"Mock WordPress server running on http://127.0.0.1:8807")
    try:
        raw_input = input
        raw_input("Press Enter to stop...")
    except KeyboardInterrupt:
        pass
    server.shutdown()