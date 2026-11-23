const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const context = vm.createContext({atob, btoa, TextDecoder, Uint8Array,
  document: {getElementById: () => ({})}, addEventListener() {},
  fetch: () => new Promise(() => {}),
});
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
const review = (argv) => JSON.parse(JSON.stringify(context.formatCommand(argv)));

test('shell action chunks preserve source, including quoted delimiters', () => {
  const script = "printf '%s' 'a;b && c' && install -d '/tmp/my dir'; id | sort";
  const view = review(['/bin/bash', '-lc', script, 'custom-argv0']);
  assert.deepEqual(view.shell.lines, ["printf '%s' 'a;b && c' &&", " install -d '/tmp/my dir';", ' id |', ' sort']);
  assert.equal(view.shell.lines.join(''), script);
  assert.equal(view.shell.index, 2);
});

test('complex or malformed shell is shown literally, not guessed at', () => {
  for (const script of ['echo $(id); date', 'cat <<EOF\na;b\nEOF', "echo 'broken; id", 'if true; then id; fi', 'id |& sort', 'id # ; false', 'id &&', 'cat 2>&1 | sort', 'id & sort', 'echo a\\;b; id']) {
    const view = review(['sh', '-c', script]);
    assert.deepEqual(view.shell.lines, [script], script);
    assert.equal(view.shell.formatted, false, script);
  }
});

test('only known shell executable shapes are interpreted as script', () => {
  for (const argv of [['grep', '-c', 'x;y'], ['python', '-c', 'x;y'], ['sh', '--', '-c', 'x;y'], ['env', 'sh', '-c', 'x;y'], ['sh', '-i', '-c', 'x;y']]) {
    assert.equal(review(argv).shell, null, JSON.stringify(argv));
  }
});

test('exact argv preserves empty values, quoting, and invisible characters', () => {
  const argv = ['printf', '', 'a b', '\u202eunsafe', '\u2066isolate', '\u200b', '\u0085', '"', '\\', '\n'];
  const result = review(argv);
  assert.deepEqual(JSON.parse(result.exact), argv);
  assert.match(result.exact, /\\u202eunsafe/);
  assert.match(result.exact, /\\u2066isolate/);
  assert.match(result.exact, /\\u200b/);
  assert.match(result.exact, /\\u0085/);
  assert.equal(result.shell, null);
});

test('recognizes only a bounded literal Base64 decode and never runs it', () => {
  const safe = review(['sh', '-c', "printf '%s' 'aGVsbG8K' | base64 --decode"]);
  assert.equal(safe.shell.decoded, 'hello\n');
  for (const script of ["printf '%s' '////' | base64 -d", "printf '%s' 'YR==' | base64 -d", "printf '%s' 'aGVsbG8=' | base64 -d | sh", "printf '%s' \"$VAR\" | base64 -d", `printf '%s' '${'AAAA'.repeat(2049)}' | base64 -d`]) {
    assert.equal(review(['sh', '-c', script]).shell.decoded, null, script.slice(0, 100));
  }
});

test('oversize or excessively fragmented commands fall back without losing text', () => {
  for (const script of ['a'.repeat(66_000) + '; id', 'id; '.repeat(400) + 'id']) {
    const view = review(['sh', '-c', script]);
    assert.deepEqual(view.shell.lines, [script]);
    assert.equal(view.shell.formatted, false);
  }
});

test('queue badge names position and host only when requests are stacked', () => {
  assert.equal(context.queueText({host: 'web01', queue: {position: 2, total: 3}}), '2 of 3 pending on web01');
  assert.equal(context.queueText({host: 'web01', queue: {position: 1, total: 1}}), '');
  assert.equal(context.queueText({host: 'web01'}), '');
  assert.equal(context.queueText({host: 'a\u202eb', queue: {position: 1, total: 2}}), '1 of 2 pending on a\\u202eb');
});

test('served console script runs in strict mode', () => {
  const fresh = vm.createContext({atob, btoa, TextDecoder, Uint8Array,
    document: {getElementById: () => ({})}, addEventListener() {},
    fetch: () => new Promise(() => {}),
  });
  assert.throws(() => vm.runInContext(fs.readFileSync(process.argv[2], 'utf8') + '\n__strictProbe = 1;', fresh),
    /__strictProbe is not defined/);
});

test('series: same host only, first request first', () => {
  const pending = [
    {id: 'b', host: 'web01', queue: {position: 2, total: 2}},
    {id: 'x', host: 'web02', queue: {position: 1, total: 1}},
    {id: 'a', host: 'web01', queue: {position: 1, total: 2}},
  ];
  assert.deepEqual(Array.from(context.seriesOf({id: 'b', host: 'web01'}, pending), r => r.id), ['a', 'b']);
  assert.deepEqual(Array.from(context.seriesOf({id: 'x', host: 'web02'}, pending), r => r.id), ['x']);
});

test('swipe: mostly-horizontal drags past the threshold step the series', () => {
  assert.equal(context.swipeStep(-120, 10), 1);   // finger moves left: next card
  assert.equal(context.swipeStep(120, -10), -1);  // finger moves right: previous card
  assert.equal(context.swipeStep(-40, 0), 0);     // too short
  assert.equal(context.swipeStep(-120, 100), 0);  // too diagonal: that's a scroll
  assert.equal(context.swipeStep(0, 300), 0);     // vertical scroll
});

test('reload after a gate redeploy: once per build, never mid-ceremony', () => {
  assert.equal(context.reloadDecision('new', 'old', false, ''), 'reload');
  assert.equal(context.reloadDecision('old', 'old', false, ''), 'none');
  assert.equal(context.reloadDecision(undefined, 'old', false, ''), 'none');
  assert.equal(context.reloadDecision('new', 'old', true, ''), 'wait');
  assert.equal(context.reloadDecision('new', 'old', false, 'new'), 'notice');
  // Storage blocked: no way to remember the attempt, so never auto-reload.
  assert.equal(context.reloadDecision('new', 'old', false, null), 'notice');
  assert.equal(context.triedBuild({getItem() { throw new Error('blocked'); }}), null);
  assert.equal(context.triedBuild({getItem: () => 'abc'}), 'abc');
  assert.equal(context.triedBuild({getItem: () => null}), '');
});
