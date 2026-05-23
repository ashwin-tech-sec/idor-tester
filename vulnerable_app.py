"""
Vulnerable Demo Application — IDOR Testing Target
Author: Ashwin Hari | Application Security Engineer

WARNING: This application is intentionally vulnerable.
Run it ONLY locally for security testing and learning purposes.
NEVER deploy this to a public server.
"""

from flask import Flask, jsonify, request, render_template_string
from functools import wraps

app = Flask(__name__)

# ─────────────────────────────────────────────
# Fake database
# ─────────────────────────────────────────────
USERS = {
    1: {"id": 1, "name": "Alice Johnson",  "email": "alice@example.com",  "role": "admin"},
    2: {"id": 2, "name": "Bob Smith",      "email": "bob@example.com",    "role": "user"},
    3: {"id": 3, "name": "Carol Williams", "email": "carol@example.com",  "role": "user"},
    4: {"id": 4, "name": "Dave Brown",     "email": "dave@example.com",   "role": "user"},
    5: {"id": 5, "name": "Eve Davis",      "email": "eve@example.com",    "role": "user"},
}

INVOICES = {
    101: {"id": 101, "user_id": 2, "amount": 1200.00, "description": "Security Audit",     "status": "paid"},
    102: {"id": 102, "user_id": 3, "amount":  450.50, "description": "Pentest Report",     "status": "pending"},
    103: {"id": 103, "user_id": 4, "amount": 3200.00, "description": "Consulting Fee",     "status": "paid"},
    104: {"id": 104, "user_id": 2, "amount":  899.99, "description": "Tool Licence",       "status": "overdue"},
    105: {"id": 105, "user_id": 5, "amount": 5000.00, "description": "Red Team Exercise",  "status": "paid"},
}

ORDERS = {
    201: {"id": 201, "user_id": 2, "product": "Security Camera",    "quantity": 2, "total": 299.98},
    202: {"id": 202, "user_id": 3, "product": "VPN Subscription",   "quantity": 1, "total":  99.99},
    203: {"id": 203, "user_id": 4, "product": "Firewall Appliance", "quantity": 1, "total": 899.00},
    204: {"id": 204, "user_id": 5, "product": "HSM Module",         "quantity": 3, "total": 4500.00},
}

SESSIONS = {
    "user2_session": 2,
    "user3_session": 3,
    "admin_session": 1,
}

# ─────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────
def get_current_user():
    session_token = request.cookies.get("session") or request.headers.get("X-Session-Token")
    if not session_token:
        return None
    user_id = SESSIONS.get(session_token)
    return USERS.get(user_id)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorised — provide a session cookie"}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# Landing page
# ─────────────────────────────────────────────
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>IDOR Vulnerable Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      min-height: 100vh;
      padding: 2rem 1rem;
    }
    .container { max-width: 860px; margin: 0 auto; }

    .banner {
      background: #ff000022;
      border: 1px solid #f85149;
      border-radius: 8px;
      padding: 0.75rem 1.25rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 14px;
      color: #f85149;
    }
    .banner span { font-size: 18px; }

    h1 { font-size: 26px; font-weight: 600; color: #e6edf3; margin-bottom: 0.25rem; }
    .subtitle { font-size: 14px; color: #8b949e; margin-bottom: 2rem; }
    .subtitle a { color: #58a6ff; text-decoration: none; }

    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 2rem; }

    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 10px;
      padding: 1.25rem;
    }
    .card-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 1rem;
    }
    .badge {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 20px;
      letter-spacing: 0.03em;
    }
    .badge-red   { background: #3d1a1a; color: #f85149; border: 1px solid #f8514940; }
    .badge-green { background: #1a2d1a; color: #3fb950; border: 1px solid #3fb95040; }

    .card h2 { font-size: 15px; font-weight: 600; color: #e6edf3; }

    .endpoint-list { list-style: none; display: flex; flex-direction: column; gap: 6px; }
    .endpoint-list li {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 8px 12px;
      font-size: 13px;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      color: #79c0ff;
    }
    .endpoint-list li .method {
      color: #56d364;
      margin-right: 8px;
      font-weight: 600;
    }

    .sessions-card { margin-bottom: 2rem; }
    .sessions-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .sessions-table th {
      text-align: left;
      padding: 8px 12px;
      color: #8b949e;
      font-weight: 500;
      border-bottom: 1px solid #21262d;
    }
    .sessions-table td {
      padding: 10px 12px;
      border-bottom: 1px solid #21262d;
      vertical-align: middle;
    }
    .sessions-table tr:last-child td { border-bottom: none; }
    code {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 4px;
      padding: 2px 7px;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 12px;
      color: #79c0ff;
    }
    .role-admin {
      background: #2d1a3d; color: #d2a8ff;
      border: 1px solid #d2a8ff40;
      border-radius: 20px; padding: 2px 8px;
      font-size: 11px; font-weight: 600;
    }
    .role-user {
      background: #1a2535; color: #58a6ff;
      border: 1px solid #58a6ff40;
      border-radius: 20px; padding: 2px 8px;
      font-size: 11px; font-weight: 600;
    }

    .usage-card { margin-bottom: 2rem; }
    .usage-block {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 12px 16px;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      font-size: 13px;
      color: #c9d1d9;
      margin-top: 0.75rem;
      line-height: 1.7;
      overflow-x: auto;
      white-space: pre;
    }
    .usage-label { font-size: 13px; color: #8b949e; margin-top: 1rem; }
    .usage-label:first-child { margin-top: 0; }

    .comment { color: #8b949e; }
    .cmd-green { color: #56d364; }
    .cmd-blue  { color: #79c0ff; }
    .cmd-orange { color: #e3b341; }

    footer {
      border-top: 1px solid #21262d;
      padding-top: 1rem;
      font-size: 12px;
      color: #8b949e;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    footer a { color: #58a6ff; text-decoration: none; }
  </style>
</head>
<body>
<div class="container">

  <div class="banner">
    <span>⚠️</span>
    <div>This application is <strong>intentionally vulnerable</strong>. Run locally only. Never deploy to a public server.</div>
  </div>

  <h1>🔐 IDOR Vulnerable Demo</h1>
  <p class="subtitle">A deliberate IDOR testing target for use with <a href="https://github.com/ashwin-tech-sec/idor-tester">idor-tester</a> · by <a href="https://github.com/ashwin-tech-sec">ashwin-tech-sec</a></p>

  <!-- Endpoints grid -->
  <div class="grid">
    <div class="card">
      <div class="card-header">
        <span class="badge badge-red">VULNERABLE</span>
        <h2>No ownership checks</h2>
      </div>
      <ul class="endpoint-list">
        <li><span class="method">GET</span>/vulnerable/users/{id}</li>
        <li><span class="method">GET</span>/vulnerable/invoices/{id}</li>
        <li><span class="method">GET</span>/vulnerable/orders/{id}</li>
      </ul>
    </div>
    <div class="card">
      <div class="card-header">
        <span class="badge badge-green">SECURE</span>
        <h2>With ownership checks</h2>
      </div>
      <ul class="endpoint-list">
        <li><span class="method">GET</span>/secure/users/{id}</li>
        <li><span class="method">GET</span>/secure/invoices/{id}</li>
        <li><span class="method">GET</span>/secure/orders/{id}</li>
      </ul>
    </div>
  </div>

  <!-- Sessions -->
  <div class="card sessions-card">
    <div class="card-header">
      <h2>Available sessions</h2>
    </div>
    <table class="sessions-table">
      <thead>
        <tr>
          <th>Cookie value</th>
          <th>User</th>
          <th>ID</th>
          <th>Role</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><code>user2_session</code></td>
          <td>Bob Smith</td>
          <td>2</td>
          <td><span class="role-user">user</span></td>
        </tr>
        <tr>
          <td><code>user3_session</code></td>
          <td>Carol Williams</td>
          <td>3</td>
          <td><span class="role-user">user</span></td>
        </tr>
        <tr>
          <td><code>admin_session</code></td>
          <td>Alice Johnson</td>
          <td>1</td>
          <td><span class="role-admin">admin</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <!-- Usage -->
  <div class="card usage-card">
    <div class="card-header">
      <h2>Quick start with idor-tester</h2>
    </div>
    <p class="usage-label">Scan the vulnerable endpoint (IDOR present):</p>
    <div class="usage-block"><span class="cmd-green">python</span> idor_tester.py <span class="cmd-blue">-u</span> <span class="cmd-orange">'http://localhost:5000/vulnerable/invoices/{id}'</span> <span class="cmd-blue">-s</span> 100 <span class="cmd-blue">-e</span> 110 <span class="cmd-blue">-c</span> <span class="cmd-orange">"session=user2_session"</span> <span class="cmd-blue">-v</span></div>
    <p class="usage-label">Scan the secure endpoint (IDOR fixed):</p>
    <div class="usage-block"><span class="cmd-green">python</span> idor_tester.py <span class="cmd-blue">-u</span> <span class="cmd-orange">'http://localhost:5000/secure/invoices/{id}'</span> <span class="cmd-blue">-s</span> 100 <span class="cmd-blue">-e</span> 110 <span class="cmd-blue">-c</span> <span class="cmd-orange">"session=user2_session"</span> <span class="cmd-blue">-v</span></div>
  </div>

  <footer>
    <span>IDOR Vulnerable Demo · local testing only</span>
    <a href="https://github.com/ashwin-tech-sec/idor-tester">github.com/ashwin-tech-sec/idor-tester</a>
  </footer>

</div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

# ─────────────────────────────────────────────
# Routes — VULNERABLE (no ownership checks)
# ─────────────────────────────────────────────

@app.route("/vulnerable/users/<int:user_id>", methods=["GET"])
@login_required
def get_user_vulnerable(user_id):
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user), 200

@app.route("/vulnerable/invoices/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice_vulnerable(invoice_id):
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return jsonify({"error": "Not found"}), 404
    return jsonify(invoice), 200

@app.route("/vulnerable/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order_vulnerable(order_id):
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify(order), 200

# ─────────────────────────────────────────────
# Routes — SECURE (with ownership checks)
# ─────────────────────────────────────────────

@app.route("/secure/users/<int:user_id>", methods=["GET"])
@login_required
def get_user_secure(user_id):
    current_user = get_current_user()
    if current_user["id"] != user_id and current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user), 200

@app.route("/secure/invoices/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice_secure(invoice_id):
    current_user = get_current_user()
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return jsonify({"error": "Not found"}), 404
    if invoice["user_id"] != current_user["id"] and current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(invoice), 200

@app.route("/secure/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order_secure(order_id):
    current_user = get_current_user()
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Not found"}), 404
    if order["user_id"] != current_user["id"] and current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(order), 200


if __name__ == "__main__":
    print("\n[!] WARNING: This app is intentionally vulnerable. Local use only.\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
