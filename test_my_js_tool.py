from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from my_js_tool import scan


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        routes = {
            '/': ('text/html', '''<base href="/assets/"><script>fetch('/api/inline')</script>
                  <script src="app.js?v=1"></script><script src="app.js?v=1"></script>
                  <script src="http://localhost:1/external.js"></script>'''),
            '/assets/app.js?v=1': ('application/javascript', '''import './child.js';
                const api="/api/users"; const key="AIza''' + 'A' * 35 + '''";'''),
            '/assets/child.js': ('application/javascript', '''import './app.js?v=1'; fetch('/api/child');'''),
            '/broken': ('text/html', '<script src="/missing.js"></script>'),
            '/large.js': ('application/javascript', 'x' * 1000),
            '/redirect': ('redirect', '/assets/app.js?v=1'),
            '/external': ('redirect', 'http://localhost:1/no.js'),
        }
        item = routes.get(self.path)
        if item is None:
            self.send_error(404)
            return
        mime, body = item
        if mime == 'redirect':
            self.send_response(302)
            self.send_header('Location', body)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_html_inline_base_imports_duplicates_and_secrets(self):
        result = scan(self.base + '/')
        self.assertFalse(result['errors'])
        self.assertEqual(len(result['results']), 3)
        self.assertEqual(result['requests_attempted'], 3)
        self.assertEqual(len(result['skipped']), 1)
        endpoints = [v['value'] for r in result['results'] for v in r['endpoints']]
        self.assertIn('/api/inline', endpoints)
        self.assertIn('/api/users', endpoints)
        self.assertIn('/api/child', endpoints)
        secrets = [s for r in result['results'] for s in r['potential_secrets']]
        self.assertTrue(any(s['type'] == 'google_api' for s in secrets))

    def test_direct_js(self):
        self.assertEqual(len(scan(self.base + '/assets/child.js')['results']), 2)

    def test_errors_and_limits(self):
        self.assertEqual(len(scan(self.base + '/broken')['errors']), 1)
        self.assertTrue(scan(self.base + '/', max_files=1)['truncated'])
        self.assertEqual(len(scan(self.base + '/large.js', max_bytes=20)['errors']), 1)

    def test_redirect_policy(self):
        self.assertFalse(scan(self.base + '/redirect')['errors'])
        self.assertIn('external origin blocked', scan(self.base + '/external')['errors'][0]['error'])

    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            scan('file:///etc/passwd')


if __name__ == '__main__':
    unittest.main()
