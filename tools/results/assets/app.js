'use strict';
// Renders data/results.json. Every value is shown with textContent only: nothing from the data is parsed as markup.
const RANK = { fail: 0, report_only: 1, measured: 1, pass: 2 };
const WORD = { pass: 'passed', fail: 'FAILED', report_only: 'report only', measured: 'measured' };
const DESC = [['what_it_tested', 'What it tested'], ['what_happened', 'What happened'], ['what_changed_next', 'What changed next']];
function el(doc, tag, cls, text) {
  const e = doc.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function amount(b) {
  if (b.numerator === null || b.numerator === undefined) return String(b.value);
  return b.numerator + '/' + b.denominator + ' ' + b.meaning;
}
function barLine(b) {
  return b.name + ': ' + amount(b) + ' (bar: ' + b.bar + ') - ' + WORD[b.result];
}
function failedSection(doc, data) {
  const s = el(doc, 'section', 'failed');
  s.appendChild(el(doc, 'h2', '', 'Failed bars (' + data.summary.failed_bars + ')'));
  for (const r of data.rows) {
    for (const b of r.bars) {
      if (b.result === 'fail') s.appendChild(el(doc, 'div', 'failed-item', r.id + ' - ' + barLine(b)));
    }
  }
  return s;
}
function rowSection(doc, r) {
  const d = el(doc, 'section', 'row');
  d.setAttribute('data-id', r.id);
  d.appendChild(el(doc, 'h3', '', r.id + ': ' + r.title));
  if (r.parked) d.appendChild(el(doc, 'span', 'parked', (r.label || 'simulated') + ' - parked case study'));
  d.appendChild(el(doc, 'p', 'meta', 'Date: ' + (r.date || 'not stated') + '. Set size: ' + (r.set_size === null ? 'not stated' : r.set_size) + (r.set_size_note ? ' (' + r.set_size_note + ')' : '') + '.'));
  d.appendChild(el(doc, 'p', 'spent', r.set_spent ? 'Set spent: this set was run once and is never reused.' : 'Set not spent.'));
  if (r.verification_note) d.appendChild(el(doc, 'p', 'note', r.verification_note));
  if (r.notes) d.appendChild(el(doc, 'p', 'note', r.notes));
  // plain-English description above the bars; a row whose description was withheld (a number that is not in its bars) has none
  for (const [key, label] of DESC) {
    if (typeof r[key] === 'string' && r[key].length > 0) d.appendChild(el(doc, 'p', 'desc', label + ': ' + r[key]));
  }
  const bars = r.bars.map((b, i) => [b, i]).sort((x, y) => (RANK[x[0].result] - RANK[y[0].result]) || (x[1] - y[1])).map((x) => x[0]);
  for (const b of bars) {
    const line = el(doc, 'div', 'bar ' + b.result, barLine(b));
    if (b.note) line.appendChild(el(doc, 'div', 'note', b.note));
    d.appendChild(line);
  }
  if (r.set_flaws && r.set_flaws.length) {
    d.appendChild(el(doc, 'p', 'meta', 'Flaws in the set (not counted against the code):'));
    for (const f of r.set_flaws) d.appendChild(el(doc, 'div', 'flaw', f));
  }
  d.appendChild(el(doc, 'p', 'sources', 'Sources: ' + r.sources.map((s) => s.file + ' (' + s.type + ')').join('; ')));
  return d;
}
async function start(doc, fetchFn) {
  const data = await (await fetchFn('data/results.json')).json();
  doc.getElementById('label').textContent = data.label;
  const box = doc.getElementById('content');
  box.appendChild(failedSection(doc, data));
  const all = el(doc, 'section', 'all');
  all.appendChild(el(doc, 'h2', '', 'All results (' + data.summary.rows + ' runs, ' + data.summary.bars + ' bars)'));
  for (const r of data.rows) all.appendChild(rowSection(doc, r));
  box.appendChild(all);
}
if (typeof module !== 'undefined') {
  module.exports = { start };
} else {
  start(document, (u) => fetch(u)).catch(() => {
    document.getElementById('label').textContent = 'The data file could not be loaded.';
  });
}
