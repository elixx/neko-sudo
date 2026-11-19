'use strict';

// The preview is not a shell parser or a replacement for argv. Never expand,
// execute, rewrite or hide any of the supplied input.
const invisibles = /[\x00-\x09\x0b-\x1f\x7f-\x9f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g;
function visibleText(text) {
  return text.replace(invisibles, ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
}

function shellSlices(script) {
  // Only recognize simple quoted words and command separators. Redirects,
  // expansions, escapes, multiline input, and shell grammar fall back intact.
  if (script.length > 65536 || /[^\x20-\x7e\t]/.test(script)) return null;
  const unsupported = /^(?:if|then|else|elif|fi|for|while|until|case|esac|do|done|in|select|function|time|coproc|!)$/;
  const lines = [];
  let start = 0, quote = '', word = '', haveWord = false;
  for (let i = 0; i < script.length; i++) {
    const ch = script[i];
    if (quote) {
      if (ch === quote) quote = '';
      else if (quote === '"' && '$`\\'.includes(ch)) return null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      haveWord = true;
      quote = ch;
    } else if (/[A-Za-z0-9_.,/:@%+=~-]/.test(ch)) {
      haveWord = true;
      word += ch;
    } else if (ch === ' ' || ch === '\t') {
      if (unsupported.test(word)) return null;
      word = '';
    } else if (';&|'.includes(ch)) {
      if (!haveWord || unsupported.test(word) || lines.length >= 256) return null;
      if (ch !== ';' && script[i + 1] === ch) i++;
      else if (ch === '&') return null;
      lines.push(script.slice(start, i + 1));
      start = i + 1;
      haveWord = false;
      word = '';
    } else {
      return null;
    }
  }
  if (quote || unsupported.test(word)) return null;
  if (!haveWord) {
    if (!lines.length || !lines[lines.length - 1].endsWith(';')) return null;
    lines[lines.length - 1] += script.slice(start);
  } else {
    lines.push(script.slice(start));
  }
  return lines;
}

function decodeLiteral(script) {
  // Optional inspection of one unambiguous, canonical literal pattern only.
  const match = /^printf +'%s' +'([A-Za-z0-9+/]{1,8192}={0,2})' +\| +base64 +(?:-d|--decode)$/.exec(script);
  if (!match || match[0] !== script) return null;
  try {
    const binary = atob(match[1]);
    if (btoa(binary) !== match[1]) return null;
    return new TextDecoder('utf-8', {fatal: true, ignoreBOM: true})
      .decode(Uint8Array.from(binary, ch => ch.charCodeAt(0)));
  } catch (_) {
    return null;
  }
}

function commandSummary(argv) {
  // The list is only an entry point. The dialog shows the whole command.
  let preview = '';
  for (const arg of argv) {
    const part = visibleText(arg.slice(0, 160 - preview.length));
    preview += (preview ? ' ' : '') + part.replaceAll('\n', '\\n');
    if (preview.length >= 160) return preview.slice(0, 160) + '…';
  }
  return preview;
}

function formatCommand(argv) {
  const exact = visibleText(JSON.stringify(argv, null, 2));
  const name = argv[0]?.split('/').pop();
  if (!['sh', 'bash', 'dash', 'ash'].includes(name) ||
      !['-c', '-lc', '-cl'].includes(argv[1]) || argv.length < 3) {
    return {exact, shell: null};
  }
  const script = argv[2];
  const lines = shellSlices(script);
  return {exact, shell: {index: 2, lines: lines || [script],
    formatted: Boolean(lines && lines.length > 1), decoded: decodeLiteral(script)}};
}

let activeReview = null;
let pendingReviews = [];
let pendingReadAt = 0;

function linkedReviewId() {
  return /^#review=([A-Za-z0-9_-]{1,64})$/.exec(location.hash)?.[1] || '';
}

function syncLinkedReview() {
  const id = linkedReviewId();
  if (!id || activeReview) {
    $('review-link-status').textContent = '';
    return;
  }
  const match = pendingReviews.find(request => request.id === id);
  const notice = match ? '' : 'This request is no longer pending. Check Recent requests.';
  if ($('review-link-status').textContent !== notice) $('review-link-status').textContent = notice;
  if (match) openReview(match, true);
}

function openReview(request, pending) {
  const dialog = $('command-review');
  if (dialog.open || activeReview) return;
  const view = formatCommand(request.argv);
  activeReview = {request, pending, busy: false, ended: false,
    deadline: pendingReadAt + (request.seconds_left || 0) * 1000};
  $('review-title').textContent = pending ? 'Review privileged command' : 'Command history';
  $('review-host').textContent = visibleText(request.host);
  $('review-user').textContent = visibleText(request.user);
  $('review-cwd').textContent = visibleText(request.cwd);
  $('review-digest').textContent = request.digest || '—';
  $('review-digest-label').hidden = $('review-digest').hidden = !request.digest;
  $('review-timing').textContent = pending ? '' :
    `${request.status} · ${new Date((request.decided_at ?? request.created_at) * 1000).toLocaleString()}`;
  $('review-result').textContent = '';
  $('review-exact').textContent = view.exact;
  $('review-exact-toggle').open = !view.shell || request.argv.length > 3;
  $('review-script').hidden = !view.shell;
  $('review-decoded').hidden = view.shell?.decoded == null;
  $('review-decoded').open = false;
  $('review-decoded-text').textContent = view.shell?.decoded == null ? '' : visibleText(view.shell.decoded);
  const script = $('review-script-text');
  script.replaceChildren();
  if (view.shell) {
    $('review-script-title').textContent = 'Shell argument preview · ' +
      visibleText(JSON.stringify(request.argv.slice(0, view.shell.index)));
    $('review-script-note').textContent = view.shell.formatted
      ? 'Visual line breaks only. The exact argv below is what gets approved.'
      : 'Shown as supplied, without interpreting shell syntax. See exact argv for all arguments.';
    for (const line of view.shell.lines) {
      const part = document.createElement('span');
      part.textContent = visibleText(line);
      script.append(part);
    }
  }
  $('review-actions').hidden = !pending;
  updateReviewButtons();
  dialog.showModal();
  $('review-body').scrollTop = 0;
  $('review-close').focus();
}

function updateReviewButtons() {
  const item = activeReview;
  if (!item || !item.pending) return;
  const left = Math.max(0, Math.ceil((item.deadline - performance.now()) / 1000));
  $('review-timing').textContent = item.ended ? 'No longer pending' :
    left ? `${left}s remaining` : 'Approval window expired';
  $('review-approve').disabled = $('review-deny').disabled = item.busy || item.ended || !left;
  $('review-close').disabled = item.busy;
}

async function decideReview(approved) {
  const item = activeReview;
  if (!item || !item.pending || item.busy || item.ended || performance.now() >= item.deadline) return;
  item.busy = true;
  $('review-result').textContent = approved ? 'Waiting for passkey…' : 'Denying…';
  updateReviewButtons();
  const id = encodeURIComponent(item.request.id);
  try {
    if (approved) await approve(id);
    else await api(`/approvals/${id}/deny`, {method: 'POST'});
    item.ended = true;
    $('review-result').textContent = approved ? 'Approved.' : 'Denied.';
  } catch (error) {
    $('review-result').textContent = `${approved ? 'Approval' : 'Denial'} failed: ${error.code || error.message}`;
    if (error.code === 'not_pending' || error.code === 'unknown_request') item.ended = true;
  } finally {
    item.busy = false;
    updateReviewButtons();
    refresh();
  }
}

function initReview() {
  const dialog = $('command-review');
  const closeReview = () => {
    if (activeReview?.busy) return;
    const id = activeReview?.request.id;
    dialog.close();
    activeReview = null;
    if (id && linkedReviewId() === id) history.replaceState(null, '', location.pathname + location.search);
    syncLinkedReview();
  };
  $('review-close').onclick = closeReview;
  $('review-approve').onclick = () => decideReview(true);
  $('review-deny').onclick = () => decideReview(false);
  dialog.oncancel = event => {
    event.preventDefault();
    closeReview();
  };
  addEventListener('hashchange', () => refresh());
  setInterval(updateReviewButtons, 1000);
}
