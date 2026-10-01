import html
import json
import os
from collections import Counter


def write_json(path, report):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def write_html(path, report):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    rows = []
    for f in report["findings"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(f['severity'])}</td>"
            f"<td>{html.escape(f['category'])}</td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td>{html.escape(f['confidence'])}</td>"
            f"<td><pre>{html.escape(f['evidence'])}</pre></td>"
            f"<td>{html.escape(f['mitigation'])}</td>"
            "</tr>"
        )

    system = report["system"]
    page = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Linux Privilege Escalation Audit Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:30px;line-height:1.4}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #bbb;padding:8px;vertical-align:top}}
th{{background:#eee}}
pre{{white-space:pre-wrap;max-width:500px}}
.badge{{display:inline-block;padding:6px 10px;border:1px solid #999;margin-right:6px}}
</style></head>
<body>
<h1>Linux Privilege Escalation Audit Report</h1>
<p><b>Detection only:</b> {report['detection_only']}</p>
<h2>System</h2>
<ul>
<li>User: {html.escape(str(system.get('username')))} (UID {system.get('uid')})</li>
<li>Root: {system.get('is_root')}</li>
<li>Hostname: {html.escape(str(system.get('hostname')))}</li>
<li>Kernel: {html.escape(str(system.get('kernel')))}</li>
<li>Architecture: {html.escape(str(system.get('architecture')))}</li>
</ul>
<h2>Summary</h2>
<p>
<span class="badge">Critical: {report['summary']['critical']}</span>
<span class="badge">High: {report['summary']['high']}</span>
<span class="badge">Medium: {report['summary']['medium']}</span>
<span class="badge">Low: {report['summary']['low']}</span>
<span class="badge">Info: {report['summary']['info']}</span>
</p>
<h2>Findings</h2>
<table><thead><tr>
<th>Severity</th><th>Category</th><th>Finding</th><th>Confidence</th><th>Evidence</th><th>Mitigation</th>
</tr></thead><tbody>
{''.join(rows)}
</tbody></table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


def print_summary(report):
    print("\n=== Audit Summary ===")
    print(f"Total findings : {report['summary']['total']}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"{sev:10}: {report['summary'][sev.lower()]}")
    print("\nTop findings:")
    for f in report["findings"][:10]:
        print(f" - [{f['severity']}] {f['category']}: {f['title']}")
