"""agentic-security-demo.local, GOOD version.

The same endpoints, hardened. The scanner reports zero high findings here. The
diff between this file and app_bad.py *is* the control.

Endpoints: /api/campaigns  /api/customer-profile  /admin  /ai/prompt  /incident  /soc2
"""

import os
from functools import wraps

from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# FIX: secret comes from the environment / secrets manager, never the repo.
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")


def require_auth(fn):
    """Authn/z gate. Every protected route is wrapped with it."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "")
        if not _valid_token(token):
            abort(401)
        return fn(*args, **kwargs)
    return wrapper


@app.route("/api/campaigns")
@require_auth
def campaigns():
    return jsonify([{"id": 1, "brand": "Brand_X_Outreach"}])


@app.route("/api/customer-profile")
@require_auth
def customer_profile():
    # FIX: parameterized query, no string concatenation.
    customer_id = request.args.get("id")
    return run("SELECT * FROM customers WHERE id = %s", (customer_id,))


@app.route("/admin")
@require_auth
def admin():
    # FIX: authenticated; secret never returned to the client.
    return jsonify({"users": "all"})


@app.route("/ai/prompt", methods=["POST"])
@require_auth
def ai_prompt():
    # FIX: prompt goes through the governance guardrail before any model call.
    from agentic_security.governance import AIRequest, AgentHop, process_request
    prompt = request.json["prompt"]
    req = AIRequest(
        prompt=prompt,
        actor_chain=[AgentHop(_current_user(), "human", "ai request")],
        destination="amazon-bedrock",
        cost_center="eng-platform",
    )
    result = process_request(req, mode="good")
    if not result.allowed:
        return jsonify({"blocked": True, "audit": result.audit_record}), 403
    return jsonify({"sent": result.sanitized_prompt, "audit": result.audit_record})


@app.route("/incident")
@require_auth
def incident():
    return jsonify({"note": "incidents declared in an incident tracker with roles + timeline"})


@app.route("/soc2")
@require_auth
def soc2():
    return jsonify({"note": "evidence produced continuously by each control"})


def _valid_token(token):
    return token.startswith("Bearer ") and len(token) > 16


def _current_user():
    return "authenticated-user"


def run(query, params):
    return jsonify({"query": query, "params": list(params)})


if __name__ == "__main__":
    # FIX: debug disabled; bind explicitly.
    app.run(debug=False, host="127.0.0.1")
