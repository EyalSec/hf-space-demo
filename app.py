#!/usr/bin/env python3
"""Same request, two runtimes: a Hugging Face Space about es-python.

Pick one of three flaws from the vulnerable-python demo app, edit the request,
and see two things side by side: what the vulnerable code does with it under
ordinary Python, and what the event es-python records about it looks like.

Nothing dangerous runs here. The SQL case runs against a throwaway in-memory
SQLite database that an authorizer limits to reading one table. The command
and file cases only build the string the vulnerable code would build; this
Space never runs a command and never opens a path you type.

Standard library only:  python3 app.py   (http://127.0.0.1:7860/)
"""
import html
import os
import posixpath
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlsplit

# Private Use Area markers around the attacker-controlled characters, so the
# page can highlight exactly which part of a value came from the request.
T_ON, T_OFF = "", ""

CASES = {
    "sqli": {
        "title": "SQL injection",
        "route": "GET /sqli?name=",
        "param": "name",
        "normal": "alice",
        "attack": "x' OR '1'='1",
        "code": (
            'name = request.args.get("name", "alice")\n'
            "query = (\"SELECT id, name, bio, secret FROM users \"\n"
            "         \"WHERE name = '\" + name + \"'\")\n"
            "rows = db.execute(query).fetchall()      # <-- the operation"
        ),
        "call": "sqlite3.Cursor.execute()",
        "sink": "sqlite execute",
        "category": "SQL injection",
        "happened": "Data that came in over the network was used to build a SQL query.",
        "impact": ("An attacker who can send data to this program over the network may use "
                   "this SQL injection to read or change data the query was never meant to reach."),
        "fix": "Pass the value as a query parameter: db.execute(\"... WHERE name = ?\", (name,)).",
    },
    "cmd": {
        "title": "Command injection",
        "route": "GET /cmd-subprocess?host=",
        "param": "host",
        "normal": "127.0.0.1",
        "attack": "127.0.0.1; id",
        "code": (
            'host = request.args.get("host", "127.0.0.1")\n'
            'cmd_str = "ping -c 1 " + host\n'
            "subprocess.run(cmd_str, shell=True)       # <-- the operation"
        ),
        "call": "subprocess.run(shell=True)",
        "sink": "subprocess shell",
        "category": "Command injection",
        "happened": "Data that came in over the network was used to run a command on the operating system.",
        "impact": ("An attacker who can send data to this program over the network may use this "
                   "command injection to run operating-system commands on the machine, as the user "
                   "this program runs as."),
        "fix": "Run the program without a shell and pass the value as one argument: "
               "subprocess.run([\"ping\", \"-c\", \"1\", host]), after checking it is a host name.",
    },
    "path": {
        "title": "Path traversal",
        "route": "GET /path?file=",
        "param": "file",
        "normal": "notes.txt",
        "attack": "../flag.txt",
        "code": (
            'name = request.args.get("file", "notes.txt")\n'
            "path = os.path.join(SAMPLE_DIR, name)\n"
            "return open(path).read()                  # <-- the operation"
        ),
        "call": "open()",
        "sink": "path traversal",
        "category": "File access and path traversal",
        "happened": "Data that came in over the network was used as the path of a file to open.",
        "impact": ("An attacker who can send data to this program over the network may use this "
                   "path traversal to read files outside the folder the program meant to serve."),
        "fix": "Resolve the path and refuse it unless it is still inside SAMPLE_DIR, "
               "or look the name up in a list of files you allow.",
    },
}

USERS = [
    (1, "alice", "demo user", "alice-password-hunter2"),
    (2, "bob", "demo user", "bob-api-token-abc123"),
    (3, "admin", "superuser", "admin-root-key-topsecret"),
]
SAMPLE_DIR = "/srv/vulnerable-python/sample"
PEER = "203.0.113.7"  # a documentation address, standing in for the attacker


def tainted(prefix, value, suffix=""):
    return prefix + T_ON + value + T_OFF + suffix


def run_sqli(name):
    query = tainted("SELECT id, name, bio, secret FROM users WHERE name = '", name, "'")
    plain = query.replace(T_ON, "").replace(T_OFF, "")
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, bio TEXT, secret TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", USERS)

    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}

    def authorizer(action, arg1, arg2, dbname, source):
        # Only reads of the demo table, and only harmless functions.
        if action == sqlite3.SQLITE_READ and arg1 != "users":
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and arg2 not in ("lower", "upper", "length", "substr",
                                                              "abs", "coalesce", "count", "max", "min"):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY

    db.set_authorizer(authorizer)
    db.set_progress_handler(lambda: 1, 200000)  # stop a runaway query
    try:
        rows = db.execute(plain).fetchmany(20)
        outcome = f"The query returned {len(rows)} row{'s' if len(rows) != 1 else ''}."
        table = rows
    except (sqlite3.Error, sqlite3.Warning) as exc:
        outcome = f"The database refused the query: {exc}."
        table = None
    finally:
        db.close()
    return query, outcome, table


def run_cmd(host):
    command = tainted("ping -c 1 ", host)
    extra = any(ch in host for ch in ";|&`$\n<>")
    if extra:
        outcome = ("The shell would run ping, then whatever follows the separator in your "
                   "input, as the app's user. This Space does not run it.")
    else:
        outcome = "The shell would run ping with your input as its arguments. This Space does not run it."
    return command, outcome, None


def run_path(name):
    joined = tainted(SAMPLE_DIR + "/", name)
    resolved = posixpath.normpath(posixpath.join(SAMPLE_DIR, name))
    inside = resolved == SAMPLE_DIR or resolved.startswith(SAMPLE_DIR + "/")
    if inside:
        outcome = f"open() would read {resolved}, inside the folder the route serves."
    else:
        outcome = (f"open() would read {resolved}, outside the folder the route serves. "
                   "This Space does not open it.")
    return joined, outcome, None


RUNNERS = {"sqli": run_sqli, "cmd": run_cmd, "path": run_path}


def mark(value):
    """HTML for a value, with the request-supplied characters highlighted."""
    out, i = [], 0
    while i < len(value):
        j = value.find(T_ON, i)
        if j < 0:
            out.append(html.escape(value[i:]))
            break
        k = value.find(T_OFF, j)
        out.append(html.escape(value[i:j]))
        out.append('<mark title="came from the request">' + html.escape(value[j + 1:k]) + "</mark>")
        i = k + 1
    return "".join(out)


STYLE = """
:root{--bg:#111310;--panel:#181a15;--border:#2a2c27;--ink:#f2f1ea;--body:#b6b8ad;--dim:#8f9187;
--signal:#e8b04b;--alarm:#d64545;--good:#8bbf6b;--mono:'IBM Plex Mono',ui-monospace,Menlo,monospace;
--sans:'IBM Plex Sans',system-ui,sans-serif;--disp:'Space Grotesk',system-ui,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--body);font:16px/1.55 var(--sans)}
main{max-width:1080px;margin:0 auto;padding:32px 16px 56px}
h1{font:600 clamp(28px,4vw,40px)/1.1 var(--disp);color:var(--ink);margin:0 0 10px;letter-spacing:-.01em}
h2{font:600 15px/1.3 var(--disp);color:var(--ink);margin:0 0 12px;text-transform:uppercase;letter-spacing:.06em}
p{margin:0 0 12px}
a{color:var(--signal)}
.lede{max-width:720px;font-size:17px}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:28px 0 18px}
nav a{padding:8px 14px;border:1px solid var(--border);border-radius:5px;color:var(--body);text-decoration:none;font:500 14px var(--sans)}
nav a[aria-current]{border-color:var(--signal);color:var(--ink)}
form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 8px}
label{font:500 14px var(--mono);color:var(--dim)}
input{flex:1 1 260px;min-width:0;background:var(--panel);color:var(--ink);border:1px solid var(--border);border-radius:5px;padding:10px 12px;font:15px var(--mono)}
button{background:var(--signal);color:#111310;border:0;border-radius:5px;padding:10px 18px;font:600 14px var(--sans);cursor:pointer}
.presets{font-size:14px;color:var(--dim);margin-bottom:24px}
.presets a{font-family:var(--mono)}
pre,code{font-family:var(--mono);font-size:14px}
pre{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:14px;overflow-x:auto;color:var(--ink);margin:0 0 16px;white-space:pre-wrap;word-break:break-word}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media (max-width:820px){.grid{grid-template-columns:1fr}}
.grid>section{min-width:0}
section.col{border-top:2px solid var(--border);padding-top:16px}
section.es{border-top-color:var(--signal)}
mark{background:rgba(214,69,69,.22);color:#ffb3a8;outline:1px solid rgba(214,69,69,.6);border-radius:2px;padding:0 1px}
table{border-collapse:collapse;width:100%;font:13px var(--mono);margin:0 0 16px}
td{border-bottom:1px solid var(--border);padding:6px 8px;color:var(--ink);word-break:break-all}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;margin:0 0 16px;font-size:14px}
dt{color:var(--dim);font-family:var(--mono)}
dd{margin:0;color:var(--ink)}
.note{font-size:13px;color:var(--dim)}
.verdict{color:var(--ink)}
footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--border);font-size:14px}
@media (max-width:560px){dl{grid-template-columns:1fr;gap:2px}dd{margin-bottom:10px}}
"""


def page(case_id, value):
    case = CASES[case_id]
    shown, outcome, rows = RUNNERS[case_id](value)
    nav = "".join(
        f'<a href="/?{urlencode({"case": cid})}"{" aria-current=page" if cid == case_id else ""}>'
        f'{html.escape(c["title"])}</a>' for cid, c in CASES.items())
    presets = " or ".join(
        f'<a href="/?{urlencode({"case": case_id, "value": v})}">{html.escape(v)}</a>'
        for v in (case["normal"], case["attack"]))
    table = ""
    if rows:
        table = "<table>" + "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows) + "</table>"
    raise_msg = f"RuntimeError: EyalSec: untrusted data from socket:{PEER}:51514 reached sink {case['sink']}"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Same request, two runtimes</title>
<meta name="description" content="Send an attack to vulnerable Python code and compare what ordinary Python does with what es-python records.">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500&family=Space+Grotesk:wght@600&display=swap" rel="stylesheet">
<style>{STYLE}</style></head>
<body><main>
<h1>Same request, two runtimes</h1>
<p class="lede">Logs, tests and scanners each show part of what a request does to a
Python service. Here is one more view: send a request to vulnerable code, then compare
what ordinary Python does with it and what <strong>es-python</strong>, the EyalSec
Python runtime, records about it.</p>
<nav aria-label="Flaw">{nav}</nav>
<form method="get" action="/">
<input type="hidden" name="case" value="{case_id}">
<label for="v">{html.escape(case["route"])}</label>
<input id="v" name="value" value="{html.escape(value)}" autocomplete="off" spellcheck="false">
<button type="submit">Send</button>
</form>
<p class="presets">Try {presets}.</p>
<pre>{html.escape(case["code"])}</pre>
<div class="grid">
<section class="col">
<h2>Ordinary Python</h2>
<p>The value the operation received:</p>
<pre>{mark(shown)}</pre>
<p class="verdict">{html.escape(outcome)}</p>
{table}
<p class="note">Nothing is written down beyond the access log line:
<code>"{html.escape(case["route"])}{html.escape(quote(value, safe="/.:"))} HTTP/1.1" 200</code></p>
</section>
<section class="col es">
<h2>es-python, network source on</h2>
<p>The same code, unchanged, reports an event like this one:</p>
<dl>
<dt>What happened</dt><dd><code>{html.escape(case["call"])}</code>: {html.escape(case["happened"])}</dd>
<dt>Category</dt><dd>{html.escape(case["category"])}</dd>
<dt>Source</dt><dd>socket (the HTTP request, from {PEER})</dd>
<dt>Value when it was used</dt><dd><pre>{mark(shown)}</pre></dd>
<dt>Why this is risky</dt><dd>{html.escape(case["impact"])}</dd>
<dt>What to do</dt><dd>{html.escape(case["fix"])}</dd>
</dl>
<p>With a Raise rule for this operation, the program gets an error at that line instead
of running it:</p>
<pre>{html.escape(raise_msg)}</pre>
<p class="note">An illustration of the event's fields, built by this page from the request
you sent. The highlighted characters are the ones that came from the request.</p>
</section>
</div>
<footer>
<p>The code above comes from <a href="https://github.com/EyalSec/vulnerable-python">vulnerable-python</a>,
an open-source demo app with one flaw per route. Run it yourself with
<code>docker run --rm -p 127.0.0.1:5000:5000 ghcr.io/eyalsec/vulnerable-python</code>.</p>
<p>To see es-python report these flows on a real app, <a href="https://eyalsec.com/contact">book a live demo</a>.
Read how it works at <a href="https://eyalsec.com/docs">eyalsec.com/docs</a>.</p>
</footer>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "eyalsec-demo"
    sys_version = ""

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/healthz":
            return self.send(200, "ok\n", "text/plain; charset=utf-8")
        if url.path != "/":
            return self.send(404, "not found\n", "text/plain; charset=utf-8")
        qs = parse_qs(url.query)
        case_id = qs.get("case", ["sqli"])[0]
        if case_id not in CASES:
            case_id = "sqli"
        value = qs.get("value", [CASES[case_id]["attack"]])[0][:300]
        value = value.replace(T_ON, "").replace(T_OFF, "")
        self.send(200, page(case_id, value), "text/html; charset=utf-8")

    def send(self, status, body, ctype):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "7860"))
    print(f"listening on http://{host}:{port}/", flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
