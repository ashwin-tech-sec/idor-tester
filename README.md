# IDOR Tester

A Python command-line tool for testing Insecure Direct Object Reference (IDOR) vulnerabilities in web applications — along with a deliberately vulnerable Flask app to safely demo and learn from.

> **Disclaimer:** Only use this tool on applications you own or have explicit written permission to test. Unauthorised testing is illegal.

---

## What Is IDOR?

Insecure Direct Object Reference (IDOR) occurs when an application uses user-controlled input to access objects without verifying whether the requesting user has permission. It is part of **OWASP A01:2021 — Broken Access Control**, the #1 vulnerability category in the OWASP Top 10.

**Example:**
```
GET /api/invoices/1042   ← your invoice
GET /api/invoices/1043   ← someone else's invoice (accessible due to IDOR)
```

---

## Contents

```
idor-tester/
├── idor_tester.py       ← Scanner tool
├── vulnerable_app.py    ← Intentionally vulnerable Flask app for local testing
├── requirements.txt
└── README.md
```

---

## Installation

```bash
git clone https://github.com/ashwin-tech-sec/idor-tester
cd idor-tester
pip install -r requirements.txt
```

---

## Usage — IDOR Tester

```
python idor_tester.py -u <url> -s <start_id> -e <end_id> [options]
```

### Options

| Flag | Description |
|---|---|
| `-u`, `--url` | Target URL — use `{id}` as placeholder e.g. `http://target.com/api/users/{id}` |
| `-s`, `--start` | Start of ID range |
| `-e`, `--end` | End of ID range |
| `-m`, `--method` | HTTP method (default: GET) |
| `-c`, `--cookies` | Session cookies e.g. `"session=abc123"` |
| `-t`, `--token` | Bearer token for Authorization header |
| `-H`, `--headers` | Custom headers e.g. `"X-User-ID: 5; Accept: application/json"` |
| `-T`, `--threads` | Number of threads (default: 10) |
| `-o`, `--output` | Output file — `.json` or `.csv` |
| `-v`, `--verbose` | Show all responses, not just accessible ones |

### Examples

**Basic scan:**
```bash
python idor_tester.py -u http://localhost:5000/vulnerable/invoices/{id} -s 100 -e 110
```

**With session cookie:**
```bash
python idor_tester.py -u http://localhost:5000/vulnerable/invoices/{id} -s 100 -e 110 -c "session=user2_session"
```

**Verbose output, save to JSON:**
```bash
python idor_tester.py -u http://localhost:5000/vulnerable/invoices/{id} -s 100 -e 110 -c "session=user2_session" -v -o results.json
```

**With Bearer token:**
```bash
python idor_tester.py -u http://target.com/api/orders/{id} -s 1 -e 500 -t "eyJhbGciOiJIUzI1NiJ9..." -T 20
```

---

## Demo — Vulnerable App

The included `vulnerable_app.py` is an intentionally vulnerable Flask application for safe local testing.

### Start the app

```bash
python vulnerable_app.py
```

The app runs at `http://127.0.0.1:5000`.

### Available sessions

| Cookie value | User | Role |
|---|---|---|
| `user2_session` | Bob Smith (ID 2) | user |
| `user3_session` | Carol Williams (ID 3) | user |
| `admin_session` | Alice Johnson (ID 1) | admin |

### Vulnerable endpoints (no ownership checks)

```
GET /vulnerable/users/{id}
GET /vulnerable/invoices/{id}
GET /vulnerable/orders/{id}
```

### Secure endpoints (with ownership checks)

```
GET /secure/users/{id}
GET /secure/invoices/{id}
GET /secure/orders/{id}
```

### Demo walkthrough

**Step 1 — Start the vulnerable app:**
```bash
python vulnerable_app.py
```

**Step 2 — Run the IDOR tester against the vulnerable endpoint:**
```bash
python idor_tester.py -u http://localhost:5000/vulnerable/invoices/{id} -s 100 -e 110 -c "session=user2_session" -v
```
You will see invoices belonging to other users returned — that's the IDOR.

**Step 3 — Run against the secure endpoint:**
```bash
python idor_tester.py -u http://localhost:5000/secure/invoices/{id} -s 100 -e 110 -c "session=user2_session" -v
```
Only Bob's own invoices (101, 104) are returned. Everything else returns 403.

**Step 4 — Compare the two routes in `vulnerable_app.py`** to see exactly what ownership check fixes the vulnerability.

---

## Output

Results are printed to the terminal and optionally saved:

```
[ACCESSIBLE] ID    101  →  http://localhost:5000/vulnerable/invoices/101  [200] [112 bytes]
[ACCESSIBLE] ID    102  →  http://localhost:5000/vulnerable/invoices/102  [200] [98 bytes]
```

Save to JSON:
```bash
-o results.json
```

Save to CSV:
```bash
-o results.csv
```

---

## Related

- [cybersecurity-writeups](https://github.com/ashwin-tech-sec/cybersecurity-writeups) — Write-up: OWASP A01 Broken Access Control
- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger — IDOR](https://portswigger.net/web-security/access-control/idor)

---

## Author

**Ashwin Hari** — Application Security Engineer  
[LinkedIn](https://www.linkedin.com/in/ashwin-hari-bb059815b/) · [GitHub](https://github.com/ashwin-tech-sec)
