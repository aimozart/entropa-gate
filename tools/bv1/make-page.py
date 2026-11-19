#!/usr/bin/env python3
"""BV1: build the single self-contained checker page from the template, style, script and the .wasm. Usage: make-page.py WASM OUT.html
The page has a Content-Security-Policy with connect-src 'none' and script/style allowed only by their SHA-256 (plus wasm-unsafe-eval to compile the module)."""
import base64, hashlib, pathlib, sys
wasm_path, out = sys.argv[1:3]
w = pathlib.Path(__file__).resolve().parents[2] / "crates/bundle-verify/web"
wasm = pathlib.Path(wasm_path).read_bytes()
css = (w / "page.css").read_text()
js = (w / "page.js").read_text().replace("@WASM_B64@", base64.b64encode(wasm).decode())
h = lambda t: "'sha256-" + base64.b64encode(hashlib.sha256(t.encode()).digest()).decode() + "'"
page = (w / "page.template.html").read_text()
page = page.replace("@SCRIPT_HASH@", h(js)).replace("@STYLE_HASH@", h(css)).replace("@WASM_BYTES@", str(len(wasm))).replace("@WASM_SHA@", hashlib.sha256(wasm).hexdigest())
page = page.replace("@STYLE@", css).replace("@SCRIPT@", js)
pathlib.Path(out).write_text(page)
print(f"wrote {out}: {len(page)} bytes")
