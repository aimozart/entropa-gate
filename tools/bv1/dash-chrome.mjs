// DASH1: load the generated dashboard in headless Chrome from a local static server (the page's CSP allows connect-src 'self'), read what it rendered and when. Usage: node tools/bv1/dash-chrome.mjs BUNDLE_DIR TMPDIR
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
const [dir, tmp] = process.argv.slice(2);
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json" };
const srv = http.createServer((q, r) => { const p = path.join(dir, decodeURIComponent(q.url.split("?")[0]).replace(/^\/+/, "") || "index.html"); if (!p.startsWith(path.resolve(dir)) || !fs.existsSync(p)) { r.writeHead(404); r.end(); return; } r.writeHead(200, { "content-type": TYPES[path.extname(p)] || "application/octet-stream" }); r.end(fs.readFileSync(p)); });
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${srv.address().port}`;
const PORT = 9334;
const chrome = spawn("google-chrome", ["--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${path.join(tmp, "chrome-dash")}`, "--no-first-run", "--disable-gpu", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let tabs; for (let i = 0; i < 60; i++) { try { tabs = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); if (tabs.some((t) => t.type === "page")) break; } catch {} await sleep(250); }
const tab = tabs.find((t) => t.type === "page");
const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise((r) => (ws.onopen = r));
let id = 0; const waiting = new Map(); const logs = [];
ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } else if (m.method === "Log.entryAdded" || m.method === "Runtime.exceptionThrown") logs.push(JSON.stringify(m.params).slice(0, 240)); };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; waiting.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result.result.value;
await send("Page.enable"); await send("Runtime.enable"); await send("Log.enable");
const run = async (name, mutate) => {
  await send("Page.navigate", { url: `${base}/dashboard.html` });
  const t0 = Date.now();
  let st = "";
  for (let i = 0; i < 2400; i++) { await sleep(25); st = await ev(`document.querySelectorAll("#newest .newest-row").length`); if (st === 10) break; }
  const ms = Date.now() - t0;
  const info = await ev(`JSON.stringify({rows: document.querySelectorAll("#newest .newest-row").length, meters: document.querySelectorAll("meter").length, mismatch: document.getElementById("mismatch").textContent, label: document.getElementById("label").textContent, records: document.querySelector("#totals p").textContent})`);
  console.log(`${name}: render ${ms} ms; ${info}`);
  return JSON.parse(info);
};
const good = await run("matching data");
console.log(`console problems: ${logs.length}`);
// a wrong number: serve a changed summary.json
const sp = path.join(dir, "data/summary.json"); const orig = fs.readFileSync(sp);
const j = JSON.parse(orig); j.by_decision.allow += 1; fs.writeFileSync(sp, JSON.stringify(j));
const bad = await run("summary.json with one wrong number");
fs.writeFileSync(sp, orig);
ws.close(); chrome.kill(); srv.close();
const ok = good.mismatch === "" && good.rows === 10 && good.meters > 5 && bad.mismatch.includes("do not match") && logs.length === 0;
console.log(ok ? "DASH1 CHROME: PASS" : "DASH1 CHROME: FAIL");
process.exit(ok ? 0 : 1);
