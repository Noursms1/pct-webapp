# PCT — Portable Cybersecurity Toolkit

![Engine Tests](https://github.com/Noursms1/pct-webapp/actions/workflows/tests.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

PCT is a Python cybersecurity toolkit combining static code analysis, a TCP port scanner, OSINT/DNS reconnaissance, hash matching, a REST API, and an RTL web UI.

## Features

- Secure Code Reviewer with a hybrid SAST engine: regex rules for line-level patterns plus an AST taint analyzer that tracks tainted variables across statements and detects hidden SQLi, command injection, path traversal, deserialization, and SSRF.
- Multi-threaded TCP Network Scanner with fast, full, and custom modes, optional banners, and risky-port tagging.
- OSINT/DNS Recon with forward and reverse DNS, A/AAAA/MX/NS/TXT/CNAME records, HTTP header auditing, TLS certificate inspection, RFC 6125 SAN matching, robots.txt, security.txt, and Whois.
- Hash Matcher supporting hash identification, generation, and wordlist matching.
- Background jobs with progress, cancellation, and JSON history.

## Quick start

```bash
git clone https://github.com/Noursms1/pct-webapp.git
cd pct-webapp
python -m pip install -r requirements.txt
python selftest.py
python -m unittest discover -s tests -v
python server.py
```

Open `http://127.0.0.1:8000/` in a browser.

## Layout

```text
engine/                 Python engine modules
static/index.html       RTL Arabic web UI
tests/                  Offline deterministic unit tests
server.py               Flask API and web server
selftest.py             Engine smoke test
requirements.txt        Runtime dependencies
.github/workflows/      GitHub Actions CI
```

## API endpoints

- `GET /api/health`
- `GET /api/rules`
- `GET /api/stats`
- `POST /api/jobs`
- `GET /api/jobs` and `GET /api/jobs/<id>`
- `POST /api/jobs/<id>/cancel`
- `GET /api/history` and `GET /api/history/<id>`
- `DELETE /api/history`
- `POST /api/hash/generate`
- `POST /api/hash/identify`
- `POST /api/code/scan`

## Testing

```bash
python -m compileall -q engine tests server.py selftest.py
python selftest.py
python -m engine.osint_dns
python -m unittest discover -s tests -v
```

Tests are deterministic and avoid live network dependencies. CI runs on Ubuntu and Windows with Python 3.10, 3.11, and 3.12.

## Legal and ethical use

Use PCT only on systems you own or are explicitly authorized to test. Unauthorized scanning, reconnaissance, or exploitation may violate laws and policies.

## License

MIT License. See `LICENSE` for the full text.
