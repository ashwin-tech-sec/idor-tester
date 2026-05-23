"""
Vulnerable Demo Application — IDOR Testing Target
Author: Ashwin Hari | Application Security Engineer

WARNING: This application is intentionally vulnerable.
Run it ONLY locally for security testing and learning purposes.
NEVER deploy this to a public server.
"""

from flask import Flask, jsonify, request, abort
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
    101: {"id": 101, "user_id": 2, "amount": 1200.00, "description": "Security Audit",    "status": "paid"},
    102: {"id": 102, "user_id": 3, "amount":  450.50, "description": "Pentest Report",    "status": "pending"},
    103: {"id": 103, "user_id": 4, "amount": 3200.00, "description": "Consulting Fee",    "status": "paid"},
    104: {"id": 104, "user_id": 2, "amount":  899.99, "description": "Tool Licence",      "status": "overdue"},
    105: {"id": 105, "user_id": 5, "amount": 5000.00, "description": "Red Team Exercise", "status": "paid"},
}

ORDERS = {
    201: {"id": 201, "user_id": 2, "product": "Security Camera",    "quantity": 2, "total": 299.98},
    202: {"id": 202, "user_id": 3, "product": "VPN Subscription",   "quantity": 1, "total":  99.99},
    203: {"id": 203, "user_id": 4, "product": "Firewall Appliance", "quantity": 1, "total": 899.00},
    204: {"id": 204, "user_id": 5, "product": "HSM Module",         "quantity": 3, "total": 4500.00},
}

# Simple session store — in real apps this would be a DB
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
# Routes — VULNERABLE (no ownership checks)
# ─────────────────────────────────────────────

@app.route("/vulnerable/users/<int:user_id>", methods=["GET"])
@login_required
def get_user_vulnerable(user_id):
    """VULNERABLE: Returns any user's data — no ownership check."""
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user), 200


@app.route("/vulnerable/invoices/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice_vulnerable(invoice_id):
    """VULNERABLE: Returns any invoice — no ownership check."""
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        return jsonify({"error": "Not found"}), 404
    return jsonify(invoice), 200


@app.route("/vulnerable/orders/<int:order_id>", methods=["GET"])
@login_required
def get_order_vulnerable(order_id):
    """VULNERABLE: Returns any order — no ownership check."""
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
    """SECURE: Only returns the requesting user's own data."""
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
    """SECURE: Only returns invoices belonging to the requesting user."""
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
    """SECURE: Only returns orders belonging to the requesting user."""
    current_user = get_current_user()
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Not found"}), 404
    if order["user_id"] != current_user["id"] and current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(order), 200


# ─────────────────────────────────────────────
# Info route
# ─────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "app": "IDOR Vulnerable Demo — for local testing only",
        "sessions": {
            "user2_session": "Logs in as Bob (user, ID 2)",
            "user3_session": "Logs in as Carol (user, ID 3)",
            "admin_session": "Logs in as Alice (admin, ID 1)",
        },
        "vulnerable_endpoints": [
            "GET /vulnerable/users/{id}",
            "GET /vulnerable/invoices/{id}",
            "GET /vulnerable/orders/{id}",
        ],
        "secure_endpoints": [
            "GET /secure/users/{id}",
            "GET /secure/invoices/{id}",
            "GET /secure/orders/{id}",
        ],
        "usage": "Pass session cookie: -c 'session=user2_session'"
    }), 200


if __name__ == "__main__":
    print("\n[!] WARNING: This app is intentionally vulnerable. Local use only.\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
