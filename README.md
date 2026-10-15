---
title: Same request, two runtimes
colorFrom: yellow
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Send an attack, compare plain Python with es-python
---

# Same request, two runtimes

A small web page for trying the idea behind [EyalSec](https://eyalsec.com) in a
browser, with nothing to install. It is published as a Hugging Face Space and
lives here as its source.

Pick one of three flaws taken from
[vulnerable-python](https://github.com/EyalSec/vulnerable-python) (SQL
injection, command injection, path traversal), edit the request, and see two
columns side by side:

| Column | What it shows |
|---|---|
| **Ordinary Python** | The value the vulnerable operation receives, with the characters that came from your request highlighted, and what the code does with it. The access log line is all that gets written down. |
| **es-python, network source on** | The fields of the event es-python records for the same request: the Python call that ran, where the data came from, the value when it was used, why it is risky and what to change. With a Raise rule, the `RuntimeError` the program gets instead. |

The right-hand column is an illustration built by the page from your request,
following the fields the event view shows; it is not a live es-python run. To
see es-python report these flows on a real app,
[book a live demo](https://eyalsec.com/contact).

## Nothing dangerous runs here

- The SQL case runs your query against a throwaway in-memory SQLite database
  holding three demo users, behind an authorizer that allows reading that one
  table and nothing else.
- The command case builds the command line the vulnerable code would run and
  stops there. No command is ever run.
- The path case resolves the path the vulnerable code would open and stops
  there. No file you name is ever opened.

`tests/test_app.py` checks all three, including that the command and path
cases never reach `subprocess`, `os.system` or `open`.

## Run it yourself

Standard library only:

```bash
python3 app.py                         # http://127.0.0.1:7860/
```

Or as the Space runs it:

```bash
docker build -t es-python-demo .
docker run --rm -p 127.0.0.1:7860:7860 es-python-demo
```

To attack the real app instead of reading about it:

```bash
docker run --rm -p 127.0.0.1:5000:5000 ghcr.io/eyalsec/vulnerable-python
```

## Publishing to Hugging Face

`.github/workflows/sync-to-hf.yml` pushes `main` to the Space on every change.
It stays inactive until the repository has an `HF_TOKEN` secret (a Hugging
Face token with write access to the Space). The Space it pushes to is the
`HF_SPACE` repository variable, `EyalSec/es-python-demo` when unset.

## License

MIT. See [LICENSE](LICENSE).
