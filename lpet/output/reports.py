import html
import json
from pathlib import Path


def write_json(report, path):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_html(report, path):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    s = report["summary"]
    cards = " ".join(f"<span class='card'><b>{k.title()}</b><br>{s[k]}</span>"
                    for k in ("critical","high","medium","low","info"))
    rows = []
    for f in report["findings"]:
        refs = "<br>".join(html.escape(x) for x in f["references"])
        rows.append(
            "<tr>"
            f"<td><b>{html.escape(f['severity'])}</b></td>"
            f"<td>{html.escape(f['id'])}</td>"
            f"<td>{html.escape(f['category'])}</td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td>{html.escape(f['confidence'])}</td>"
            f"<td><pre>{html.escape(chr(10).join(f['evidence']))}</pre></td>"
            f"<td>{html.escape(f['impact'])}</td>"
            f"<td>{html.escape(f['remediation'])}<br><small>{refs}</small></td>"
            "</tr>"
        )

    sys = report["system"]
    page = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>LPET Security Exposure Report</title>
<style>
body{{font-family:Inter,Arial,sans-serif;margin:32px;background:#f7f8fa;color:#1f2937}}
header{{background:#111827;color:#fff;padding:28px;border-radius:12px}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:18px 0}}
.card{{background:#fff;padding:14px;border-radius:10px;border:1px solid #e5e7eb}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px}}
th,td{{border:1px solid #e5e7eb;padding:9px;vertical-align:top}}
th{{background:#f3f4f6;text-align:left}}
pre{{white-space:pre-wrap;max-width:420px}}
.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}
.meta div{{background:#fff;padding:12px;border:1px solid #e5e7eb;border-radius:8px}}
</style></head>
<body>
<header><h1>Linux Privilege Escalation Exposure Report</h1>
<p>LPET 2.0.0 · Detection-only security assessment</p>
<p>Scan ID: {html.escape(report['scan_id'])}</p></header>
<div class="grid">{cards}</div>
<h2>System Context</h2>
<div class="meta">
<div><b>Host</b><br>{html.escape(str(sys['hostname']))}</div>
<div><b>User / UID</b><br>{html.escape(str(sys['user']))} / {sys['uid']}</div>
<div><b>Kernel</b><br>{html.escape(str(sys['kernel']))}</div>
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>ID</th><th>Category</th><th>Title</th><th>Confidence</th><th>Evidence</th><th>Impact</th><th>Remediation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Assessment Notes</h2>
<p>Findings are indicators requiring validation. A detected configuration does not automatically
prove exploitability. Kernel/CVE applicability must be validated against the operating system
vendor's package build and security advisories.</p>
</body></html>"""
    p.write_text(page, encoding="utf-8")
