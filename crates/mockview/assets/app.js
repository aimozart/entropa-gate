'use strict';
// Static explorer for a mock ledger. Every value from the data files is shown with textContent only: nothing is parsed as markup.
function el(doc, tag, cls, text) {
  const e = doc.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = String(text);
  return e;
}
function pageNumber(search, pages) {
  const m = /(?:^|[?&])page=([0-9]{1,6})(?:&|$)/.exec(search || '');
  const n = m ? parseInt(m[1], 10) : 1;
  return Math.min(Math.max(n, 1), Math.max(pages, 1));
}
function pageName(n) {
  return 'data/page-' + String(n).padStart(4, '0') + '.json';
}
function pager(doc, where, n, pages) {
  const box = doc.getElementById(where);
  box.children = [];
  box.appendChild(el(doc, 'span', '', 'Page ' + n + ' of ' + pages));
  if (n > 1) {
    const a = el(doc, 'a', '', 'Previous');
    a.setAttribute('href', '?page=' + (n - 1));
    box.appendChild(a);
  }
  if (n < pages) {
    const a = el(doc, 'a', '', 'Next');
    a.setAttribute('href', '?page=' + (n + 1));
    box.appendChild(a);
  }
}
function about(doc, meta) {
  const box = doc.getElementById('about');
  box.appendChild(el(doc, 'h2', '', 'What is mock and what is real'));
  box.appendChild(el(doc, 'h3', '', 'Mock'));
  for (const t of meta.what_is_mock) box.appendChild(el(doc, 'p', '', t));
  box.appendChild(el(doc, 'h3', '', 'Real'));
  for (const t of meta.what_is_real) box.appendChild(el(doc, 'p', '', t));
  for (const t of meta.notes || []) box.appendChild(el(doc, 'p', 'note', t));
  const v = doc.getElementById('verify');
  v.appendChild(el(doc, 'h2', '', 'Verify it yourself'));
  v.appendChild(el(doc, 'p', '', 'Run this on your own machine against your own copy of the ledger directory:'));
  v.appendChild(el(doc, 'code', 'mono', meta.verify_command));
  v.appendChild(el(doc, 'p', '', 'Signer key id: ' + meta.key_id));
  v.appendChild(el(doc, 'p', 'mono', 'Public key: ' + meta.pubkey));
  v.appendChild(el(doc, 'p', 'mono', 'Head checkpoint: size ' + meta.checkpoint_head.size + ', root ' + meta.checkpoint_head.root));
  if (meta.ledger_tar) {
    const t = meta.ledger_tar;
    const a = el(doc, 'a', '', 'Download ' + t.file + ' (' + t.bytes + ' bytes, blake3 ' + t.blake3 + ')');
    a.setAttribute('href', t.file);
    const p = el(doc, 'p');
    p.appendChild(a);
    v.appendChild(p);
    v.appendChild(el(doc, 'p', '', t.how_to));
  }
  v.appendChild(el(doc, 'p', '', meta.not_claimed));
}
function row(doc, r) {
  const d = el(doc, 'div', 'row');
  d.appendChild(el(doc, 'div', 'idx', '#' + r.index));
  const body = el(doc, 'div', 'body');
  body.appendChild(el(doc, 'div', 'plain', r.plain));
  body.appendChild(el(doc, 'div', 'meta', [r.kind, r.label, r.decision, r.reason, r.control].join(' / ')));
  body.appendChild(el(doc, 'div', 'meta', 'subject ' + r.subject_hash));
  body.appendChild(el(doc, 'div', 'meta', 'checkpoint ' + r.checkpoint_size + ' root ' + r.checkpoint_root));
  d.appendChild(body);
  return d;
}
async function start(doc, fetchFn, search) {
  const meta = await (await fetchFn('data/meta.json')).json();
  doc.getElementById('label').textContent = meta.label;
  about(doc, meta);
  const n = pageNumber(search, meta.pages);
  const page = await (await fetchFn(pageName(n))).json();
  const box = doc.getElementById('records');
  for (const r of page.records) box.appendChild(row(doc, r));
  pager(doc, 'pager-top', n, meta.pages);
  pager(doc, 'pager', n, meta.pages);
}
if (typeof module !== 'undefined') {
  module.exports = { start, pageNumber, pageName };
} else {
  start(document, (u) => fetch(u), window.location.search).catch(() => {
    document.getElementById('label').textContent = 'The data files could not be loaded.';
  });
}
