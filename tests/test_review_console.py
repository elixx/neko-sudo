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
                '--virtual-time-budget=8000', '--dump-dom', url,
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


STALE_QA = """
sessionStorage.setItem('loads', String(Number(sessionStorage.getItem('loads') || 0) + 1));
window.fetch = async (path) => { const j = b => new Response(JSON.stringify(b));
  if (path === '/whoami') return j({label: 'qa'});
  if (path === '/approvals') return j({pending: [], build: '%s'});
  if (path.startsWith('/history')) return j({items: [], total: 0, page: 0, page_size: 5});
  return j({}); };
addEventListener('load', () => setTimeout(() => { const u = document.getElementById('update-status');
  document.body.dataset.stale = sessionStorage.getItem('loads') + '|' + (u.hidden ? '' : u.textContent); }, 1500));
"""


@pytest.mark.parametrize('served_build, expected', [
    ('0123456789abcdef', '2|The gate was updated. Reload this page to get the new console.'),
    (None, '1|'),
])
def test_stale_console_reloads_once_in_chromium(tmp_path, served_build, expected):
    """A tab still running an old console reloads itself once when
    /approvals reports another build; if that didn't help it says so
    instead of looping. A current tab never reloads."""
    import re
    import time
    chrome = os.environ.get('NEKO_QA_CHROME')
    if not chrome:
        pytest.skip('Set NEKO_QA_CHROME to a Chromium executable for browser QA')
    from gate.console import BUILD_ID
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    tag = b'<script src="/console.js"></script>'
    html = client.get('/', headers=auth(raw)).content.replace(tag, b'<script src="/qa.js"></script>' + tag)
    routes = {'/': ('text/html; charset=utf-8', html),
              '/console.js': ('application/javascript', client.get('/console.js', headers=auth(raw)).content),
              '/qa.js': ('application/javascript', (STALE_QA % (served_build or BUILD_ID)).encode())}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            kind, data = routes.get(self.path.split('#')[0], ('text/plain', b''))
            self.send_response(200 if self.path.split('#')[0] in routes else 404)
            self.send_header('Content-Type', kind)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = subprocess.run([
                chrome, '--headless', '--no-first-run', '--no-default-browser-check',
                '--disable-background-networking', '--disable-component-update',
                f'--user-data-dir={tmp_path / "chromium"}', '--window-size=504,844',
                '--virtual-time-budget=12000', '--dump-dom', f'http://127.0.0.1:{server.server_port}/',
            ], capture_output=True, text=True, encoding='utf-8', errors='replace', check=False, timeout=60)
        finally:
            server.shutdown()
            thread.join(timeout=3)
    found = re.search(r'data-stale="([^"]*)"', result.stdout)
    assert found, 'browser never reported; ' + result.stderr[-800:]
    assert found.group(1) == expected



def run_console_page(tmp_path, qa_js, url_hash='', budget=12000):
    """Serve the real signed-in page + console.js with a QA script loaded
    first, run headless Chromium, return the body's data-qa value."""
    import re
    chrome = os.environ.get('NEKO_QA_CHROME')
    if not chrome:
        pytest.skip('Set NEKO_QA_CHROME to a Chromium executable for browser QA')
    client, _, passkeys, _, _ = make_env(tmp_path)
    raw = login(client, enroll_owner_passkey(client, passkeys))
    tag = b'<script src="/console.js"></script>'
    html = client.get('/', headers=auth(raw)).content.replace(tag, b'<script src="/qa.js"></script>' + tag)
    routes = {'/': ('text/html; charset=utf-8', html),
              '/console.js': ('application/javascript', client.get('/console.js', headers=auth(raw)).content),
              '/qa.js': ('application/javascript', qa_js.encode())}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split('#')[0]
            kind, data = routes.get(path, ('text/plain', b''))
            self.send_response(200 if path in routes else 404)
            self.send_header('Content-Type', kind)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = subprocess.run([
                chrome, '--headless', '--no-first-run', '--no-default-browser-check',
                '--disable-background-networking', '--disable-component-update',
                f'--user-data-dir={tmp_path / "chromium"}', '--window-size=504,844',
                f'--virtual-time-budget={budget}', '--dump-dom',
                f'http://127.0.0.1:{server.server_port}/{url_hash}',
            ], capture_output=True, text=True, encoding='utf-8', errors='replace', check=False, timeout=60)
        finally:
            server.shutdown()
            thread.join(timeout=3)
    found = re.search(r'data-qa="([^"]*)"', result.stdout)
    assert found, 'browser never reported; ' + result.stderr[-800:]
    return found.group(1).replace('&amp;', '&')


SERIES_QA = """
const first = {id: 'earlier-1', host: 'web01', user: 'neko', cwd: '/tmp', argv: ['systemctl', 'stop', 'x'],
  seconds_left: 200, digest: 'b'.repeat(64), queue: {position: 1, total: 2}, earlier: []};
const second = {id: 'pending-1', host: 'web01', user: 'neko', cwd: '/tmp', argv: ['systemctl', 'start', 'x'],
  seconds_left: 200, digest: 'a'.repeat(64), queue: {position: 2, total: 2}, earlier: [{id: 'earlier-1', argv: first.argv}]};
const unlocked = {...second, queue: {position: 1, total: 1}, earlier: []};
let pending = [first, second];
let slow = 0;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
window.fetch = async (path) => { const j = b => new Response(JSON.stringify(b));
  if (path === '/whoami') return j({label: 'qa'});
  if (path === '/approvals') { if (slow) await sleep(slow); return j({pending}); }
  if (path.startsWith('/history')) return j({items: [], total: 0, page: 0, page_size: 5});
  if (path === '/approvals/earlier-1/approve/options') return j({challenge_id: 'c', options: {challenge: 'YQ', rpId: 'localhost', allowCredentials: []}});
  if (path === '/approvals/earlier-1/approve') { pending = [unlocked]; slow = 700; return j({ok: true}); }
  return j({}); };
Object.defineProperty(navigator.credentials, 'get', {value: async () => ({id: 'cred', response: {
  clientDataJSON: Uint8Array.of(1), authenticatorData: Uint8Array.of(2), signature: Uint8Array.of(3)}})});
const report = value => { document.body.dataset.qa = value; };
async function opened(id) { for (let i = 0; i < 100; i++) {
  const d = document.getElementById('command-review');
  if (d.open && location.hash === '#review=' + id) return; await sleep(20); } throw new Error('never opened ' + id); }
"""


def test_auto_advance_respects_a_close_during_the_poll(tmp_path):
    """Closing the review while the post-decision poll is in flight must
    not reopen it on the next card. A close must stick."""
    qa = SERIES_QA + """
addEventListener('load', async () => { try {
  await opened('earlier-1');
  document.getElementById('review-approve').click();
  await sleep(400);  // decision done, advance poll in flight (700 ms)
  document.getElementById('review-close').click();
  await sleep(2000);
  report((document.getElementById('command-review').open ? 'open' : 'closed') + '|' + location.hash);
} catch (error) { report('error: ' + error.message); } });
"""
    assert run_console_page(tmp_path, qa, '#review=earlier-1') == 'closed|'


def test_open_review_unlocks_when_earlier_is_decided_elsewhere(tmp_path):
    """The 5 s poll unlocks an open later
    card once its earlier request is decided elsewhere, without reopening."""
    qa = SERIES_QA + """
addEventListener('load', async () => { try {
  await opened('pending-1');
  const get = id => document.getElementById(id);
  const before = get('review-approve').disabled && get('review-deny').disabled;
  get('review-result').textContent = 'marker';
  pending = [unlocked];  // the earlier request was decided on another device
  await sleep(6000);
  report([before, get('review-approve').disabled, get('review-deny').disabled,
    get('review-result').textContent, location.hash].join('|'));
} catch (error) { report('error: ' + error.message); } });
"""
    assert run_console_page(tmp_path, qa, '#review=pending-1') == 'true|false|false|marker|#review=pending-1'


@pytest.mark.parametrize('ceremony', ['signin', 'enroll'])
def test_no_reload_during_signin_or_enroll_ceremony(tmp_path, ceremony):
    """A redeploy must not reload the page under an open sign-in or
    enroll passkey prompt, not only under a review decision. Any open
    WebAuthn ceremony defers it."""
    from gate.console import BUILD_ID
    qa = """
sessionStorage.setItem('loads', String(Number(sessionStorage.getItem('loads') || 0) + 1));
let build = '%s';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
window.fetch = async (path) => { const j = b => new Response(JSON.stringify(b));
  if (path === '/whoami') return j({label: 'qa'});
  if (path === '/approvals') return j({pending: [], build});
  if (path.startsWith('/history')) return j({items: [], total: 0, page: 0, page_size: 5});
  if (path === '/login/options') return j({challenge_id: 'c', options: {challenge: 'YQ', rpId: 'localhost', allowCredentials: []}});
  if (path === '/enroll/options') return j({challenge_id: 'c', user_id: 'dQ', options: {challenge: 'YQ',
    rp: {id: 'localhost', name: 'qa'}, user: {name: 'n', displayName: 'n'}, pubKeyCredParams: [{type: 'public-key', alg: -7}]}});
  return j({}); };
const hang = () => { sessionStorage.setItem('opened', '1'); return new Promise(() => {}); };
Object.defineProperty(navigator.credentials, 'get', {value: hang});
Object.defineProperty(navigator.credentials, 'create', {value: hang});
addEventListener('load', async () => {
  if (sessionStorage.getItem('loads') === '1') {
    await sleep(300);
    if ('%s' === 'signin') document.getElementById('signin-btn').click();
    else document.getElementById('enroll-form').requestSubmit();
    await sleep(200);
    build = 'ffffffffffffffff';  // the gate is redeployed mid-ceremony
  }
  await sleep(7000);
  document.body.dataset.qa = sessionStorage.getItem('loads') + '|' + (sessionStorage.getItem('opened') || '');
});
""" % (BUILD_ID, ceremony)
    assert run_console_page(tmp_path, qa, budget=15000) == '1|1'
