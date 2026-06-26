"""agentic-security-demo.local, BAD version.

A deliberately insecure Flask app, used as a target for the scanner. Every issue
here is intentional and is caught by `agentic_security.scanner`. DO NOT deploy this.

Endpoints: /api/campaigns  /api/customer-profile  /admin  /ai/prompt  /incident  /soc2
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# ISSUE: hardcoded secret committed to the repo (AWS documented example key).
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


@app.route("/api/campaigns")
def campaigns():
    # ISSUE: no authentication on a data endpoint.
    return jsonify([{"id": 1, "brand": "Brand_X_Outreach"}])


@app.route("/api/customer-profile")
def customer_profile():
    # ISSUE: no auth + SQL built by string concatenation (injectable).
    customer_id = request.args.get("id")
    query = "SELECT * FROM customers WHERE id = '" + customer_id + "'"
    return run(query)


@app.route("/admin")
def admin():
    # ISSUE: admin surface with no authentication or authorization.
    return jsonify({"users": "all", "secret": AWS_SECRET_ACCESS_KEY})


@app.route("/ai/prompt", methods=["POST"])
def ai_prompt():
    # ISSUE: raw prompt forwarded to the model with no governance/classification.
    prompt = request.json["prompt"]
    return call_model(prompt, destination="public-llm-chatbot")


@app.route("/incident")
def incident():
    return jsonify({"note": "incidents handled ad hoc in Slack DMs"})


@app.route("/soc2")
def soc2():
    return jsonify({"note": "evidence collected manually at audit time"})


def run(query):
    return jsonify({"query": query})


def call_model(prompt, destination):
    return jsonify({"sent": prompt, "to": destination})


if __name__ == "__main__":
    # ISSUE: debug mode enabled (remote code execution via the debugger).
    app.run(debug=True, host="0.0.0.0")
