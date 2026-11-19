"""Run the actual served JavaScript against offline formatter fixtures."""
import os
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from test_console import auth, enroll_owner_passkey, login, make_env


def test_served_review_formatter(tmp_path):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node.js is required for the console JavaScript checks')
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    js = client.get('/console.js', headers=auth(raw))
    assert js.status_code == 200
    source = tmp_path / 'console.js'
    source.write_bytes(js.content)
    harness = Path(__file__).with_name('review_console.cjs')
    result = subprocess.run([node, str(harness), str(source)], capture_output=True,
                            text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_authenticated_page_has_fullscreen_command_review(tmp_path):
    client, _, passkeys, _, _ = make_env(tmp_path)
    assert 'command-review' not in client.get('/').text
    raw = login(client, enroll_owner_passkey(client, passkeys))
    page = client.get('/', headers=auth(raw)).text
    assert '<dialog id="command-review"' in page
    assert 'Exact arguments (argv)' in page
    assert 'Approve with passkey' in page


@pytest.mark.parametrize('viewport', ['390,844', '1280,900'])
def test_review_in_chromium(tmp_path, viewport):
    chrome = os.environ.get('NEKO_QA_CHROME')
    if not chrome:
        pytest.skip('Set NEKO_QA_CHROME to a Chromium executable for browser QA')
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    assert raw
    html = client.get('/', headers=auth(raw)).content
    js = client.get('/console.js', headers=auth(raw)).content
    tag = b'<script src="/console.js"></script>'
    assert html.count(tag) == 1
    html = html.replace(tag, b'<script src="/qa.js"></script>' + tag)
    fixture = Path(__file__).with_name('review_browser.js').read_bytes()
    routes = {'/': ('text/html; charset=utf-8', html),
              '/console.js': ('application/javascript', js),
              '/qa.js': ('application/javascript', fixture)}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in routes:
                self.send_error(404)
                return
            kind, data = routes[self.path]
            self.send_response(200)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/#review=pending-1'
            result = subprocess.run([
                chrome, '--headless', '--no-first-run', '--no-default-browser-check',
                '--disable-background-networking', '--disable-component-update',
                f'--user-data-dir={tmp_path / "chromium"}', f'--window-size={viewport}',
                '--virtual-time-budget=3500', '--dump-dom', url,
            ], capture_output=True, text=True, encoding='utf-8', errors='replace',
                check=False, timeout=35)
        finally:
            server.shutdown()
            thread.join(timeout=3)
    assert result.returncode == 0, result.stderr
    assert 'data-browser-review="passed"' in result.stdout, next(
        (line for line in result.stdout.splitlines() if 'data-browser-review=' in line),
        'Browser never signaled a result; ' + result.stderr[-1200:],
    )
