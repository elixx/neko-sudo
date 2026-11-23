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
  for (let i = 0; i < 80; i++) { if (predicate()) return; await tick(); }
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
  if (path === '/approvals/earlier-1/approve/options') {
    return json({challenge_id: 'fixture-earlier', options: {challenge: 'YQ', rpId: 'localhost', allowCredentials: []}});
  }
  if (path === '/approvals/earlier-1/approve') {
    pending = [{...openCard, queue: {position: 1, total: 1}, earlier: []}];
    return json({ok: true});
  }
  throw new Error('Unexpected request to ' + path);
};
Object.defineProperty(navigator.credentials, 'get', {value: async () => ({id: 'fixture-cred', response: {
  clientDataJSON: Uint8Array.of(1), authenticatorData: Uint8Array.of(2), signature: Uint8Array.of(3)}})});

window.addEventListener('load', async () => {
  const get = (id) => document.getElementById(id);
  const d = get('command-review');
  try {
    await until(() => d.open, 'deep link did not open the exact pending card');
    // A later card of a series can't be decided at all.
    check(!get('review-order').hidden, 'blocked card did not explain the earlier request');
    check(get('review-order-list').textContent.includes('systemctl stop x'), 'earlier argv missing');
    check(get('review-queue').textContent === '2 of 2 pending on fixture-host', 'queue position missing');
    check(get('review-approve').disabled && get('review-deny').disabled, 'approve and deny must both be blocked');
    for (const id of ['review-approve', 'review-deny']) {
      check(Number(getComputedStyle(get(id)).opacity) < 0.6, id + ' does not look disabled');
    }
    check(document.querySelector('#approvals .queue'), 'pending card shows no queue badge');
    check(!get('review-series').hidden, 'series navigation missing');
    check(get('review-series-label').textContent === '2 of 2 on fixture-host', 'series label wrong');
    // Every card of a series names its position on its
    // first line, above the "decide first" notice.
    const firstLine = (label) => {
      const pos = get('review-position'), title = get('review-title').closest('h2');
      check(!pos.hidden && pos.textContent === label, 'position missing from the first line: ' + label);
      const p = pos.getBoundingClientRect(), t = title.getBoundingClientRect();
      check(Math.abs(p.top - t.top) < 4 && title.contains(pos), label + ' is not on the title line');
      check(get('review-order').hidden || p.bottom <= get('review-order').getBoundingClientRect().top, label + ' sits below the notice');
    };
    firstLine('(2 of 2)');
    check(get('review-next').disabled && !get('review-prev').disabled, 'series ends not respected');
    const at = (id, label) => until(() => d.open && location.hash === '#review=' + id, label);
    get('review-prev').click();
    await at('earlier-1', 'previous button did not open the earlier card');
    check(get('review-exact').textContent.includes('"stop"'), 'switched to the wrong request');
    check(!get('review-approve').disabled && !get('review-deny').disabled && get('review-order').hidden, 'first card must be decidable');
    check(get('review-series-label').textContent === '1 of 2 on fixture-host' && get('review-prev').disabled, 'first card series state wrong');
    firstLine('(1 of 2)');
    d.dispatchEvent(new KeyboardEvent('keydown', {key: 'ArrowRight', bubbles: true}));
    await at('pending-1', 'arrow key did not move to the next card');
    const body = get('review-body');
    const swipe = (fromX, toX) => {
      const start = new Touch({identifier: 1, target: body, clientX: fromX, clientY: 300});
      const end = new Touch({identifier: 1, target: body, clientX: toX, clientY: 310});
      body.dispatchEvent(new TouchEvent('touchstart', {touches: [start], changedTouches: [start], bubbles: true}));
      body.dispatchEvent(new TouchEvent('touchend', {touches: [], changedTouches: [end], bubbles: true}));
    };
    swipe(60, 220);
    await at('earlier-1', 'swipe right did not move to the previous card');
    swipe(220, 60);
    await at('pending-1', 'swipe left did not move to the next card');
    get('review-first').click();
    await at('earlier-1', 'go-to-first did not open the first card');
    check(writes.length === 0, 'navigating the series wrote a decision');
    // Deciding the first card advances to the next one, now decidable.
    get('review-approve').click();
    await at('pending-1', 'review did not advance after the first card was decided');
    await until(() => !get('review-approve').disabled, 'next card did not unlock after the first was decided');
    check(get('review-result').textContent.includes('Previous request approved'), 'auto-advance did not say why');
    check(get('review-order').hidden && get('review-queue').hidden && get('review-series').hidden, 'stale order notice after the earlier request was decided');
    check(get('review-position').hidden, 'a lone card must not show a position');
    check(writes.length === 2 && writes[1][0] === '/approvals/earlier-1/approve', 'first card approval missing');
    const box = d.getBoundingClientRect();
    check(box.width === innerWidth && box.height === innerHeight, 'dialog did not fill viewport');
    check(document.activeElement === get('review-close'), 'initial focus must be on the safe close button');
    check(writes.length === 2, 'opening the next card wrote a decision');
    check(get('review-cwd').textContent === openCard.cwd && !get('review-cwd').querySelector('style'), 'cwd was not literal text');
    check(!get('review-script-text').querySelector('img'), 'script inserted HTML');
    check(get('review-script-text').textContent === fixtureScript, 'source changed in preview');
    check(get('review-script-text').children.length === 3, 'formatted shell segments missing');
    check(JSON.stringify(JSON.parse(get('review-exact').textContent)) === JSON.stringify(openCard.argv), 'argv changed');
    check(get('review-exact-toggle').open, 'arguments after -c must be visible by default');
    get('review-approve').click();
    get('review-approve').click();
    await until(() => get('review-result').textContent === 'Approved.', 'passkey approve did not complete');
    check(writes.length === 4 && writes[2][0] === '/approvals/pending-1/approve/options' && writes[3][0] === '/approvals/pending-1/approve', 'duplicate or wrong approval');
    check(JSON.parse(writes[3][1]).challenge_id === 'fixture', 'passkey ceremony binding lost');
    get('review-close').click();
    await until(() => !d.open && !location.hash, 'close did not clear the consumed deep link');
    document.querySelector('#history-rows button').click();
    check(d.open && get('review-title').textContent === 'Command history', 'history entry did not reopen the viewer');
    check(get('review-actions').hidden && getComputedStyle(get('review-actions')).display === 'none', 'history exposed decision actions');
    check(get('review-position').hidden, 'history viewer shows a series position');
    check(get('review-script-text').children.length === 2, 'history did not use same formatter');
    check(writes.length === 4, 'history performed a write');
    get('review-close').click();
    await until(() => !d.open, 'history viewer would not close');
    history.replaceState(null, '', '#review=expired-1');
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    await until(() => get('review-link-status').textContent.includes('no longer pending'), 'expired link did not explain unavailability');
    check(!d.open && writes.length === 4, 'expired link selected or acted on another card');
    document.body.dataset.browserReview = 'passed';
  } catch (error) {
    document.body.dataset.browserReview = error.message;
  }
});
