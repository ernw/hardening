// Summarizes hardener JSON reports. JXA, ships with macOS.
// Usage: osascript -l JavaScript summarize.js <report.json>...

ObjC.import('Foundation');

function readJSON(path) {
  const data = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null);
  if (data.isNil()) throw new Error('cannot read ' + path);
  return JSON.parse(ObjC.unwrap(data));
}

function state(c) {
  if (c.skipped) return 'skipped_level';
  if (c.skipped_distro) return 'skipped_platform';
  if (c.skipped_missing) return 'missing_command';
  if (c.manual) return 'manual';
  if (c.error && !c.fix_applied) return 'error';
  if (c.fix_applied) return c.fix_verified ? 'fixed' : 'fix_not_effective';
  return c.passed ? 'passed' : 'failed';
}

function oneLine(s, n) {
  s = String(s || '').replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function run(argv) {
  const out = [];
  const listed = ['error', 'fix_not_effective', 'missing_command', 'failed'];
  argv.forEach(function (path) {
    const r = readJSON(path);
    const counts = {};
    const lines = {};
    listed.forEach(function (k) { lines[k] = []; });
    (r.suite_results || []).forEach(function (s) {
      (s.checks || []).forEach(function (c) {
        const st = state(c);
        counts[st] = (counts[st] || 0) + 1;
        if (lines[st]) lines[st].push('  - ' + c.id + ' [' + s.title + ']: ' + oneLine(c.error || c.output, 220));
      });
    });
    out.push('== ' + path);
    out.push('type=' + r.report_type + ' incomplete=' + !!r.incomplete);
    out.push('counts: ' + Object.keys(counts).sort().map(function (k) { return k + '=' + counts[k]; }).join(' '));
    listed.forEach(function (k) {
      if (lines[k].length) {
        out.push(k.toUpperCase() + ' (' + lines[k].length + '):');
        out.push.apply(out, lines[k]);
      }
    });
    out.push('');
  });
  return out.join('\n');
}
