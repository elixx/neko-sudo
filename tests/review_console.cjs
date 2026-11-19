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
