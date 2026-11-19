// BV1: drive the REAL checker page in headless Chrome (DevTools protocol over node's WebSocket): choose each corpus file in the file input and compare the page's verdict with the frozen native verdict.
// Usage: node tools/bv1/chrome-run.mjs PAGE.html MANIFEST CORPUS_DIR TMPDIR
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
const [page, manifestPath, corpusDir, tmp] = process.argv.slice(2);
const PORT = 9333;
const CLASS = { ok: 0, Invalid: 1, Verify: 2, Limit: 3 };
const chrome = spawn("google-chrome", ["--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${path.join(tmp, "chrome-profile")}`, "--no-first-run", "--disable-gpu", "--allow-file-access-from-files", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let tabs;
for (let i = 0; i < 60; i++) { try { tabs = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); if (tabs.some((t) => t.type === "page")) break; } catch {} await sleep(250); }
const tab = tabs.find((t) => t.type === "page");
const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const waiting = new Map(); const console_ = [];
ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } else if (m.method === "Runtime.consoleAPICalled" || m.method === "Log.entryAdded") console_.push(JSON.stringify(m.params).slice(0, 200)); };
const send = (method, params = {}) => new Promise((r) => { const i = ++id; waiting.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true })).result.result.value;
await send("Page.enable"); await send("DOM.enable"); await send("Runtime.enable"); await send("Log.enable");
await send("Page.navigate", { url: "file://" + path.resolve(page) });
await sleep(1000);
const pick = async (file) => {
  const doc = (await send("DOM.getDocument")).result.root.nodeId;
  const node = (await send("DOM.querySelector", { nodeId: doc, selector: "#file" })).result.nodeId;
  await ev(`document.getElementById("result").setAttribute("data-code","")`);
  const t0 = Date.now();
  await send("DOM.setFileInputFiles", { files: [path.resolve(file)], nodeId: node });
  for (let i = 0; i < 4000; i++) { const c = await ev(`document.getElementById("result").getAttribute("data-code")`); if (c !== "") return { code: Number(c), ms: Date.now() - t0, counts: await ev(`Array.from(document.querySelectorAll("#counts dd")).map(d=>d.textContent).join(",")`), text: await ev(`document.getElementById("verdict").textContent`) }; await sleep(25); }
  return { code: -1, ms: -1, counts: "", text: "" };
};
const m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
let same = 0, differ = 0;
for (const c of m.cases) {
  let f = c.generate ? path.join(tmp, "oversize.json") : path.join(corpusDir, c.file);
  if (c.generate) fs.writeFileSync(f, `{"pad":"${"x".repeat(c.generate.pad_bytes)}"}`);
  const r = await pick(f);
  let ok = r.code === CLASS[c.verdict.class];
  if (ok && r.code === 0) ok = r.counts === ["records", "checkpoints", "receipts", "consistency", "witnesses", "signatures"].map((k) => c.verdict[k]).join(",");
  ok ? same++ : differ++;
  console.log(`${ok ? "SAME  " : "DIFFER"} ${c.id} native=${c.verdict.class} page=${r.code} ${r.ms} ms`);
}
const bigf = path.join(tmp, "big16.json"); fs.writeFileSync(bigf, `{"pad":"${"x".repeat(16 * 1024 * 1024)}"}`);
const b = await pick(bigf); console.log(`16 MiB file: page=${b.code} (3 = limit) ${b.ms} ms ${b.code === 3 ? "SAME" : "DIFFER"}`); b.code === 3 ? same++ : differ++;
const med = await pick(path.join(corpusDir, "valid-medium.json")); console.log(`valid-medium in Chrome: code ${med.code}, ${med.ms} ms, counts ${med.counts}`);
const csp = await ev(`document.querySelector('meta[http-equiv="Content-Security-Policy"]').content`); console.log("CSP: " + csp.replace(/'sha256-[^']*'/g, "'sha256-…'"));
const f1 = await ev(`fetch("data:text/plain,x").then(()=>"ALLOWED",()=>"BLOCKED")`); console.log(`fetch under the CSP: ${f1}`);
const f2 = await ev(`new Promise(r=>{try{var x=new XMLHttpRequest();x.open("GET","data:text/plain,x");x.onload=()=>r("ALLOWED");x.onerror=()=>r("BLOCKED");x.send();}catch(e){r("BLOCKED")}})`); console.log(`XMLHttpRequest under the CSP: ${f2}`);
console.log(`SUMMARY same=${same} differ=${differ} total=${same + differ}; csp checks: fetch ${f1}, xhr ${f2}`);
ws.close(); chrome.kill();
process.exit(differ || f1 !== "BLOCKED" || f2 !== "BLOCKED" ? 1 : 0);
