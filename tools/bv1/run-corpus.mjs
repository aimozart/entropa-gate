// BV1: run the browser verifier (the .wasm, plain WebAssembly API, no glue) over the browser corpus in node and compare every verdict with the frozen native verdict.
// Usage: node tools/bv1/run-corpus.mjs WASM MANIFEST CORPUS_DIR   (CORPUS_DIR written by `CORPUS_EXPORT=dir cargo test -p entropa-ledger --test bundle_corpus`). Prints one line per case, a summary and timings.
import fs from "node:fs";
import path from "node:path";
const [wasmPath, manifestPath, corpusDir] = process.argv.slice(2);
const CLASS = { ok: 0, Invalid: 1, Verify: 2, Limit: 3 };
const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmPath), {});
const x = instance.exports;
const dec = new TextDecoder();
export function verify(bytes) {
  const p = x.input_reserve(bytes.length);
  new Uint8Array(x.memory.buffer, p, bytes.length).set(bytes);
  const code = x.verify();
  const json = dec.decode(new Uint8Array(x.memory.buffer, x.output_ptr(), x.output_len()));
  return { code, json: JSON.parse(json) };
}
const m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
let same = 0, differ = 0;
for (const c of m.cases) {
  const bytes = c.generate ? new TextEncoder().encode(`{"pad":"${"x".repeat(c.generate.pad_bytes)}"}`) : fs.readFileSync(path.join(corpusDir, c.file));
  const want = CLASS[c.verdict.class];
  let got;
  try { got = verify(bytes); } catch (e) { got = { code: -1, json: { error: String(e) } }; }
  let ok = got.code === want;
  if (ok && want === 0) for (const k of ["records", "checkpoints", "receipts", "consistency", "witnesses", "signatures"]) ok = ok && got.json[k] === c.verdict[k];
  ok ? same++ : differ++;
  console.log(`${ok ? "SAME  " : "DIFFER"} ${c.id} native=${c.verdict.class} wasm=${got.code}`);
}
const big = new TextEncoder().encode(`{"pad":"${"x".repeat(16 * 1024 * 1024)}"}`);
const b = verify(big);
console.log(`16 MiB case: wasm=${b.code} (3 = limit) ${b.code === 3 ? "SAME" : "DIFFER"}`);
if (b.code !== 3) differ++; else same++;
// timing: repeated verification of the medium valid bundle until 10,000 records have been verified (a bundle is limited to 5 MiB, so 10,000 records are not one bundle)
const med = fs.readFileSync(path.join(corpusDir, "valid-medium.json"));
const r0 = verify(med).json.records;
let n = 0, t0 = performance.now();
while (n < 10000) { n += verify(med).json.records; }
const ms = performance.now() - t0;
console.log(`TIMING ${n} records verified (${Math.ceil(10000 / r0)} runs of valid-medium, ${r0} records each, ${med.length} bytes): ${ms.toFixed(0)} ms in node (${(ms / n).toFixed(2)} ms per record)`);
console.log(`SUMMARY same=${same} differ=${differ} total=${same + differ}`);
process.exit(differ ? 1 : 0);
