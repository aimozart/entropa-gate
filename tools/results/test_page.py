"""Red tests for tools/results/make_page.py (a stage record (not published)). Standard library only; Node (installed) runs app.js against a fake DOM. Expectations are written here by hand."""
import json, os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOL = os.path.join(HERE, "make_page.py")
RESULTS = os.path.join(ROOT, "docs", "results", "results.json")
TMP = os.environ.get("TMPDIR", "/tmp")
CSP = ["default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "img-src 'none'", "base-uri 'none'", "form-action 'none'"]


def gen(results=RESULTS):
    out = os.path.join(tempfile.mkdtemp(prefix="page-test-", dir=TMP), "site")
    p = subprocess.run([sys.executable, TOOL, "--results", results, "--out", out], capture_output=True, text=True)
    return p.returncode, p.stderr, out


def files(d):
    res = {}
    for dp, _, fs in os.walk(d):
        for f in sorted(fs):
            full = os.path.join(dp, f)
            res[os.path.relpath(full, d)] = open(full, "rb").read()
    return res


def planted(mut):
    d = json.load(open(RESULTS))
    mut(d)
    f = tempfile.NamedTemporaryFile("w", suffix=".json", dir=TMP, delete=False)
    json.dump(d, f)
    f.close()
    return f.name


HARNESS = r"""
const fs = require('fs'); const dir = process.argv[2];
function el(tag){ return {tag, children:[], textContent:'', attrs:{}, setAttribute(k,v){this.attrs[k]=v;}, appendChild(c){this.children.push(c); return c;},
  set className(v){this.attrs.class=v;}, get className(){return this.attrs.class||'';}}; }
const doc = { createElement: el, getElementById: (id)=> (doc._ids[id] ||= el('div')), _ids:{} };
global.document = doc; global.window = { location: { search: '' } };
global.fetch = (u) => Promise.resolve({ ok:true, json: () => Promise.resolve(JSON.parse(fs.readFileSync(dir + '/' + u, 'utf8'))) });
require(dir + '/app.js').start(doc, fetch).then(() => {
  const all = []; (function walk(n, path){ all.push({tag:n.tag, cls:(n.attrs&&n.attrs.class)||'', text:n.textContent||'', id:(n.attrs&&n.attrs['data-id'])||'', path}); (n.children||[]).forEach((c,i)=>walk(c, path.concat([n.tag+':'+(n.attrs.class||'')]))); })(doc._ids['content'] || {children:[], attrs:{}}, []);
  console.log(JSON.stringify({label: doc._ids['label'] ? doc._ids['label'].textContent : null, nodes: all}));
}).catch(e => { console.log('ERR ' + e.message); process.exit(1); });
"""


def render(results=RESULTS):
    rc, err, out = gen(results)
    assert rc == 0, err
    h = os.path.join(out, "h.js")
    open(h, "w").write(HARNESS)
    p = subprocess.run(["node", h, out], capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    return json.loads(p.stdout)


class P(unittest.TestCase):
    def test_p1_the_page_is_four_static_files_with_the_label_and_the_csp(self):
        rc, err, out = gen()
        self.assertEqual(rc, 0, err)
        fs = files(out)
        self.assertEqual(sorted(fs), ["app.js", "data/results.json", "index.html", "llms.txt", "robots.txt", "sitemap.xml", "style.css"])
        html = fs["index.html"].decode()
        for part in CSP:
            self.assertIn(part, html)
        self.assertEqual(html.count("<script"), 1)
        self.assertIn('<script src="app.js"></script>', html)
        self.assertIn("tested against", html.lower())
        self.assertIn("failures are included", html.lower())
        self.assertNotIn("onclick", html.lower())

    def test_p2_hostile_text_in_the_data_never_becomes_markup(self):
        hostile = "<script>alert(1)</script> ‮\U0001F600 & \"q\" <img src=x onerror=alert(2)>"
        def m(d):
            d["rows"][0]["title"] = hostile
            d["rows"][0]["set_flaws"] = [hostile]
            d["rows"][0]["bars"][0]["note"] = hostile
        path = planted(m)
        rc, err, out = gen(path)
        self.assertEqual(rc, 0, err)
        j = open(os.path.join(out, "data", "results.json"), encoding="utf-8").read()
        for ch in "<>&":
            self.assertNotIn(ch, j, f"raw {ch!r} in the JSON")
        js = open(os.path.join(out, "app.js")).read()
        for bad in ("innerHTML", "outerHTML", "eval(", "new Function", "document.write", "insertAdjacentHTML"):
            self.assertNotIn(bad, js)
        data = render(path)
        texts = [n["text"] for n in data["nodes"]]
        self.assertTrue(any(hostile in t for t in texts), "the hostile text must appear as plain text")
        self.assertFalse(any(n["tag"] in ("script", "img", "iframe") for n in data["nodes"]))

    def test_p3_failures_come_first_and_all_17_are_listed(self):
        data = render()
        self.assertIn("tested against", data["label"].lower())
        nodes = data["nodes"]
        failed = [n for n in nodes if n["cls"] == "failed-item"]
        self.assertEqual(len(failed), 25)  # Test change (RESULTS-V3): 21 + 4
        first_failed = next(i for i, n in enumerate(nodes) if n["cls"] == "failed-item")
        first_row = next(i for i, n in enumerate(nodes) if n["cls"] == "row")
        self.assertLess(first_failed, first_row, "the failed list must precede the rows")
        rows = [n for n in nodes if n["cls"] == "row"]
        self.assertEqual(len(rows), 19)  # Test change (RESULTS-V3): 12 + 7 rows

    def test_p4_inside_a_row_failed_bars_precede_passed_bars_and_every_row_says_set_spent(self):
        nodes = render()["nodes"]
        order, cur = {}, None
        for n in nodes:
            if n["cls"] == "row":
                cur = n["id"]
                order[cur] = []
            elif n["cls"].startswith("bar ") and cur is not None:
                order[cur].append(n["cls"].split()[1])
        self.assertEqual(len(order), 19)  # Test change (RESULTS-V3): 12 + 7 rows
        rank = {"fail": 0, "report_only": 1, "measured": 1, "pass": 2}
        for title, results in order.items():
            self.assertEqual(results, sorted(results, key=lambda r: rank[r]), title)
        spent = [n for n in nodes if n["cls"] == "spent"]
        self.assertEqual(len(spent), 19)  # Test change (RESULTS-V3): 12 + 7 rows
        self.assertTrue(all("set spent" in n["text"].lower() for n in spent))

    def test_p5_wording_no_banned_words_no_paths_no_emails(self):
        rc, err, out = gen()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(files(out)), 7, "no files: the scan would prove nothing")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(files(out)), 7, "no files: the scan would prove nothing")
        for name, b in files(out).items():
            t = b.decode().lower().replace("convertto-securestring", "")
            for w in ("secure", "compliant", "certified"):
                self.assertNotIn(w, t, f"{name}: {w}")
            self.assertNotIn("/home/", t)
            self.assertNotRegex(t, r"[a-z0-9]@[a-z0-9]")

    def test_p6_deterministic_and_refusals_write_nothing(self):
        a, b = gen()[2], gen()[2]
        self.assertEqual(files(a), files(b))
        for name, mut in (
            ("wrong schema", lambda d: d.__setitem__("schema", "results-0")),
            ("no rows", lambda d: d.__setitem__("rows", [])),
            ("bar without result", lambda d: d["rows"][0]["bars"][0].pop("result")),
            ("row not spent", lambda d: d["rows"][0].__setitem__("set_spent", False)),
            ("summary mismatch", lambda d: d["summary"].__setitem__("failed_bars", 3)),
        ):
            rc, err, out = gen(planted(mut))
            self.assertEqual(rc, 1, name)
            self.assertFalse(os.path.exists(out), f"{name}: output written")

    def test_p7_unverified_and_parked_rows_are_marked_on_the_page(self):
        def m(d):
            d["rows"][-1]["numbers_verified"] = False
            d["rows"][-1]["verification_note"] = "NOT verified: test"
            d["summary"] = d["summary"]
        nodes = render(planted(m))["nodes"]
        self.assertTrue(any("NOT verified" in n["text"] for n in nodes))
        nodes = render()["nodes"]
        self.assertTrue(any(n["cls"] == "parked" and "simulated" in n["text"].lower() for n in nodes))


# ---- RESULTS-V2 (a stage record (not published)) ----
# Test change (RESULTS-V3): seven rows added (listed after EG-6 in the spec: LS3d RS1 INS-1 INS-2 INS-3 EG-7 EG-8; the later-listed row of a date first)
EXPECTED_ORDER = ["EG-8", "EG-7", "INS-3", "INS-2", "INS-1", "RS1", "LS3d", "EG-6", "EG-5", "AT4", "EG-4", "EG-3", "EG-2", "EG-1", "H1.1", "R3", "A4d", "R2", "A4c"]
LABELS = ("What it tested", "What happened", "What changed next")


class V2(unittest.TestCase):
    def test_v1_rows_appear_newest_first_in_the_rendered_page(self):
        rows = [n["id"] for n in render()["nodes"] if n["cls"] == "row"]
        self.assertEqual(rows, EXPECTED_ORDER)

    def test_v2_make_page_refuses_rows_that_are_not_newest_first(self):
        def swap(d):
            d["rows"][0], d["rows"][-1] = d["rows"][-1], d["rows"][0]
        rc, err, out = gen(planted(swap))
        self.assertEqual(rc, 1)
        self.assertIn("order", err)
        self.assertFalse(os.path.exists(out))

    def test_v3_descriptions_render_above_the_bars_as_plain_text(self):
        hostile = "<script>alert(1)</script> & \"q\" <img src=x onerror=alert(2)>"
        def m(d):
            d["rows"][0]["what_it_tested"] = hostile
            d["rows"][0]["what_happened"] = "it happened 5"
            d["rows"][0]["what_changed_next"] = "then this"
        data = render(planted(m))
        nodes = data["nodes"]
        start = next(i for i, n in enumerate(nodes) if n["cls"] == "row" and n["id"] == EXPECTED_ORDER[0])
        end = next(i for i, n in enumerate(nodes) if i > start and n["cls"] == "row")
        block = nodes[start:end]
        desc = [i for i, n in enumerate(block) if n["cls"] == "desc"]
        bars = [i for i, n in enumerate(block) if n["cls"].startswith("bar ")]
        self.assertEqual(len(desc), 3)
        self.assertTrue(bars)
        self.assertLess(max(desc), min(bars), "the description must come above the bar list")
        texts = [block[i]["text"] for i in desc]
        for label, t in zip(LABELS, texts):
            self.assertTrue(t.startswith(label), t)
        self.assertIn(hostile, texts[0])
        self.assertFalse(any(n["tag"] in ("script", "img", "iframe") for n in nodes))

    def test_v4_a_row_without_a_description_shows_none(self):
        nodes = render()["nodes"]
        # the stored data of this test (docs/results/results.json) may carry descriptions; a planted copy without them must show no desc nodes
        def strip(d):
            for r in d["rows"]:
                for f in ("what_it_tested", "what_happened", "what_changed_next"):
                    r.pop(f, None)
        self.assertEqual([n for n in render(planted(strip))["nodes"] if n["cls"] == "desc"], [])


if __name__ == "__main__":
    unittest.main()


class SEO(unittest.TestCase):
    """The search and sharing block of the live page (the reviewer's overlay of 2026-11-17) is part of the template, so the next deploy keeps it. Expectations are written here by hand."""

    def test_seo1_the_head_carries_title_description_canonical_and_open_graph_tags(self):
        rc, err, out = gen()
        self.assertEqual(rc, 0, err)
        html = files(out)["index.html"].decode()
        for part in (
            "<title>Results of record | Entropa Gate</title>",
            '<meta name="description" content="Measured results of sealed and held-out tests of Entropa Gate, newest first, with every failed bar listed.',
            '<link rel="canonical" href="https://results.entropa.space/">',
            '<meta property="og:title" content="Results of record | Entropa Gate">',
            '<meta property="og:description" content="Measured results of sealed and held-out tests, failures included.">',
            '<meta property="og:type" content="website">',
            '<meta property="og:url" content="https://results.entropa.space/">',
        ):
            self.assertIn(part, html)
        # the security policy of the page did not loosen: still one local script, nothing external
        for part in CSP:
            self.assertIn(part, html)
        self.assertEqual(html.count("<script"), 1)
        self.assertNotIn("http://", html)

    def test_seo2_robots_sitemap_and_llms_files_are_written_with_the_site_address(self):
        rc, err, out = gen()
        self.assertEqual(rc, 0, err)
        fs = {k: v.decode() for k, v in files(out).items()}
        self.assertIn("User-agent: *", fs["robots.txt"])
        self.assertIn("Allow: /", fs["robots.txt"])
        self.assertIn("Sitemap: https://results.entropa.space/sitemap.xml", fs["robots.txt"])
        self.assertTrue(fs["sitemap.xml"].startswith('<?xml version="1.0" encoding="UTF-8"?>'))
        self.assertIn("<loc>https://results.entropa.space/</loc>", fs["sitemap.xml"])
        self.assertTrue(fs["llms.txt"].startswith("# Results of record (Entropa Gate)"))
        for url in ("https://results.entropa.space/", "https://results.entropa.space/data/results.json", "https://entropa.space/", "https://docs.entropa.space/"):
            self.assertIn(url, fs["llms.txt"])
        self.assertIn("not a security claim", fs["llms.txt"])
