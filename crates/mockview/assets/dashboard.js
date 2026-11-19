'use strict';
// Static dashboard for a mock ledger. The numbers come from data/summary.json (computed when the page was generated) and are RECOMPUTED here from the record pages;
// if the two differ, a notice is shown. Every value is shown with textContent only: nothing is parsed as markup.
const MAX_DAYS = 60;
function el(doc, tag, cls, text) {
  const e = doc.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = String(text);
  return e;
}
function pageName(n) {
  return 'data/page-' + String(n).padStart(4, '0') + '.json';
}
function dayOf(ts) {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}
function bump(map, key) {
  map[key] = (map[key] || 0) + 1;
}
function sortedCopy(map) {
  const out = {};
  for (const k of Object.keys(map).sort()) out[k] = map[k];
  return out;
}
function recompute(pages) {
  const s = { records: 0, by_decision: {}, by_kind: {}, by_reason: {}, by_control: {}, by_label: {}, by_day: {} };
  for (const p of pages) {
    for (const r of p.records) {
      s.records += 1;
      bump(s.by_decision, r.decision);
      bump(s.by_kind, r.kind);
      bump(s.by_reason, r.reason);
      bump(s.by_control, r.control);
      bump(s.by_label, r.label);
      bump(s.by_day, dayOf(r.ts));
    }
  }
  for (const k of ['by_decision', 'by_kind', 'by_reason', 'by_control', 'by_label', 'by_day']) s[k] = sortedCopy(s[k]);
  // only the latest 60 days are listed; the earlier ones are one total (the same split as the generator)
  const dayKeys = Object.keys(s.by_day);
  s.earlier_days = { days: 0, records: 0 };
  for (const k of dayKeys.slice(0, Math.max(dayKeys.length - MAX_DAYS, 0))) {
    s.earlier_days.days += 1;
    s.earlier_days.records += s.by_day[k];
    delete s.by_day[k];
  }
  return s;
}
function same(a, b) {
  if (a.records !== b.records) return false;
  const ea = a.earlier_days || {};
  const eb = b.earlier_days || {};
  if (ea.days !== eb.days || ea.records !== eb.records) return false;
  for (const k of ['by_decision', 'by_kind', 'by_reason', 'by_control', 'by_label', 'by_day']) {
    const ka = Object.keys(a[k] || {}).sort();
    const kb = Object.keys(b[k] || {}).sort();
    if (ka.length !== kb.length) return false;
    for (let i = 0; i < ka.length; i++) {
      if (ka[i] !== kb[i] || a[k][ka[i]] !== b[k][kb[i]]) return false;
    }
  }
  return true;
}
function bars(doc, id, title, map, total) {
  const box = doc.getElementById(id);
  box.appendChild(el(doc, 'h2', '', title));
  for (const k of Object.keys(map)) {
    const row = el(doc, 'div', 'bar');
    row.appendChild(el(doc, 'span', 'name', k));
    const m = el(doc, 'meter', '');
    m.setAttribute('min', '0');
    m.setAttribute('max', String(total));
    m.setAttribute('value', String(map[k]));
    row.appendChild(m);
    row.appendChild(el(doc, 'span', 'count', map[k]));
    box.appendChild(row);
  }
}
async function start(doc, fetchFn) {
  const meta = await (await fetchFn('data/meta.json')).json();
  const summary = await (await fetchFn('data/summary.json')).json();
  doc.getElementById('label').textContent = meta.label;
  const pages = [];
  for (let n = 1; n <= meta.pages; n++) pages.push(await (await fetchFn(pageName(n))).json());
  const mine = recompute(pages);
  const ok = same(mine, summary) && summary.records === meta.records;
  doc.getElementById('mismatch').textContent = ok ? '' : 'The numbers on this page do not match the data files. Do not rely on them.';
  const t = doc.getElementById('totals');
  t.appendChild(el(doc, 'h2', '', 'Totals'));
  t.appendChild(el(doc, 'p', '', 'Records: ' + mine.records));
  t.appendChild(el(doc, 'p', 'mono', 'Head checkpoint: size ' + summary.head.size + ', root ' + summary.head.root));
  bars(doc, 'by_decision', 'Records by outcome', summary.by_decision, summary.records);
  bars(doc, 'by_kind', 'Records by kind', summary.by_kind, summary.records);
  bars(doc, 'by_reason', 'Records by reason', summary.by_reason, summary.records);
  bars(doc, 'by_control', 'Records by control', summary.by_control, summary.records);
  bars(doc, 'by_day', 'Records per day (UTC), latest 60 days', summary.by_day, summary.records);
  if (summary.earlier_days.records > 0) {
    doc.getElementById('by_day').appendChild(el(doc, 'p', 'muted', 'Earlier days: ' + summary.earlier_days.days + ' days, ' + summary.earlier_days.records + ' records'));
  }
  const nb = doc.getElementById('newest');
  nb.appendChild(el(doc, 'h2', '', 'Newest records'));
  for (const r of summary.newest) {
    const row = el(doc, 'div', 'newest-row');
    row.appendChild(el(doc, 'span', 'idx', '#' + r.index));
    row.appendChild(el(doc, 'span', '', r.plain));
    nb.appendChild(row);
  }
  const note = doc.getElementById('note');
  note.appendChild(el(doc, 'p', '', meta.not_claimed));
  note.appendChild(el(doc, 'code', 'mono', meta.verify_command));
  return { ok };
}
if (typeof module !== 'undefined') {
  module.exports = { start, recompute, same, dayOf };
} else {
  start(document, (u) => fetch(u)).catch(() => {
    document.getElementById('label').textContent = 'The data files could not be loaded.';
  });
}
