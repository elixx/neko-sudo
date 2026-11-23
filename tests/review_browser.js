'use strict';

// Only loaded by the offline Chromium fixture, not by the production app.
const fixtureScript = "printf '%s' '<img src=x onerror=alert(1)>; safe' && id; sort";
const openCard = {id: 'pending-1', host: 'fixture-host', user: 'neko', cwd: '<style>body{display:none}</style>',
  argv: ['/bin/sh', '-c', fixtureScript, 'arg0', ''], seconds_left: 90, digest: 'a'.repeat(64)};
const oldCard = {...openCard, id: 'finished-1', argv: ['sh', '-c', 'id; uptime'], cwd: '/tmp',
  digest: undefined, status: 'approved', decided_at: 1794000000, created_at: 1793000000};
// The deep-linked card starts blocked behind an earlier same-host
// request; the fixture decides that one elsewhere mid-test.
const earlierCard = {id: 'earlier-1', host: 'fixture-host', user: 'neko', cwd: '/tmp',
  argv: ['systemctl', 'stop', 'x'], seconds_left: 90, digest: 'b'.repeat(64),
  queue: {position: 1, total: 2}, earlier: []};
const blockedCard = {...openCard, queue: {position: 2, total: 2},
  earlier: [{id: 'earlier-1', argv: earlierCard.argv}]};
let pending = [earlierCard, blockedCard];
const writes = [];
const tick = (ms = 25) => new Promise(resolve => setTimeout(resolve, ms));
const check = (value, label) => { if (!value) throw new Error(label); };
async function until(predicate, label) {
  for (let i = 0; i < 40; i++) { if (predicate()) return; await tick(); }
  throw new Error(label);
}
window.fetch = async (path, options) => {
  if (options?.method === 'POST') writes.push([path, options.body]);
  const json = (body, status = 200) => new Response(JSON.stringify(body), {status});
  if (path === '/whoami') return json({label: 'offline-test'});
  if (path === '/approvals') return json({pending});
  if (path === '/history?page=0') return json({items: [oldCard], total: 1, page: 0, page_size: 5});
  if (path === '/approvals/pending-1/approve/options') {
    return json({challenge_id: 'fixture', options: {challenge: 'YQ', rpId: 'localhost', allowCredentials: []}});
  }
  if (path === '/approvals/pending-1/approve') { pending = []; return json({ok: true}); }
  throw new Error('Unexpected request to ' + path);
};
Object.defineProperty(navigator.credentials, 'get', {value: async () => ({id: 'fixture-cred', response: {
  clientDataJSON: Uint8Array.of(1), authenticatorData: Uint8Array.of(2), signature: Uint8Array.of(3)}})});

window.addEventListener('load', async () => {
  const get = (id) => document.getElementById(id);
  const d = get('command-review');
  try {
    await until(() => d.open, 'deep link did not open the exact pending card');
    check(!get('review-order').hidden, 'blocked card did not explain the earlier request');
    check(get('review-order-list').textContent.includes('systemctl stop x'), 'earlier argv missing');
    check(get('review-queue').textContent === '2 of 2 pending on fixture-host', 'queue position missing');
    check(get('review-approve').disabled && !get('review-deny').disabled, 'approve must be blocked, deny allowed');
    check(Number(getComputedStyle(get('review-approve')).opacity) < 0.6, 'blocked approve does not look disabled');
    check(document.querySelector('#approvals .queue'), 'pending card shows no queue badge');
    get('review-order-list').querySelector('button').click();
    await until(() => d.open && location.hash === '#review=earlier-1', 'earlier request did not open');
    check(get('review-exact').textContent.includes('"stop"'), 'switched to the wrong request');
    check(!get('review-approve').disabled && get('review-order').hidden, 'earlier request must be approvable');
    check(writes.length === 0, 'switching requests wrote a decision');
    get('review-close').click();
    await until(() => !d.open, 'earlier review would not close');
    pending = [openCard];  // the earlier request was decided elsewhere
    history.replaceState(null, '', '#review=pending-1');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await until(() => d.open && !get('review-approve').disabled, 'approve did not unlock once the earlier request was decided');
    check(get('review-order').hidden && get('review-queue').hidden, 'stale order notice after the earlier request was decided');
    const box = d.getBoundingClientRect();
    check(box.width === innerWidth && box.height === innerHeight, 'dialog did not fill viewport');
    check(document.activeElement === get('review-close'), 'initial focus must be on the safe close button');
    check(writes.length === 0, 'opening a deep link wrote an approval');
    check(get('review-cwd').textContent === openCard.cwd && !get('review-cwd').querySelector('style'), 'cwd was not literal text');
    check(!get('review-script-text').querySelector('img'), 'script inserted HTML');
    check(get('review-script-text').textContent === fixtureScript, 'source changed in preview');
    check(get('review-script-text').children.length === 3, 'formatted shell segments missing');
    check(JSON.stringify(JSON.parse(get('review-exact').textContent)) === JSON.stringify(openCard.argv), 'argv changed');
    check(get('review-exact-toggle').open, 'arguments after -c must be visible by default');
    get('review-approve').click();
    get('review-approve').click();
    await until(() => get('review-result').textContent === 'Approved.', 'passkey approve did not complete');
    check(writes.length === 2 && writes[0][0] === '/approvals/pending-1/approve/options' && writes[1][0] === '/approvals/pending-1/approve', 'duplicate or wrong approval');
    check(JSON.parse(writes[1][1]).challenge_id === 'fixture', 'passkey ceremony binding lost');
    get('review-close').click();
    await until(() => !d.open && !location.hash, 'close did not clear the consumed deep link');
    document.querySelector('#history-rows button').click();
    check(d.open && get('review-title').textContent === 'Command history', 'history entry did not reopen the viewer');
    check(get('review-actions').hidden && getComputedStyle(get('review-actions')).display === 'none', 'history exposed decision actions');
    check(get('review-script-text').children.length === 2, 'history did not use same formatter');
    check(writes.length === 2, 'history performed a write');
    get('review-close').click();
    await until(() => !d.open, 'history viewer would not close');
    history.replaceState(null, '', '#review=expired-1');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await until(() => get('review-link-status').textContent.includes('no longer pending'), 'expired link did not explain unavailability');
    check(!d.open && writes.length === 2, 'expired link selected or acted on another card');
    document.body.dataset.browserReview = 'passed';
  } catch (error) {
    document.body.dataset.browserReview = error.message;
  }
});
