from flask import Flask, render_template, request, jsonify
from flask import Flask, jsonify, request

from app.core.security_engine import SecurityEngine


app = Flask(__name__)


security_engine = SecurityEngine()


# =========================================
# DASHBOARD
# =========================================

@app.route("/")
def dashboard():

    return render_template(
        "dashboard.html"
    )


# =========================================
# URL ANALYSIS
# =========================================

@app.route(
    "/api/analyze-url",
    methods=["POST"]
)
def analyze_url():

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get(
        "url",
        ""
    ).strip()

    if not url:

        return jsonify({
            "error": "URL is required"
        }), 400

    try:

        result = security_engine.analyze_url(
            url
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# FILE ANALYSIS
# =========================================

@app.route(
    "/api/analyze-file",
    methods=["POST"]
)
def analyze_file():

    data = request.get_json(
        silent=True
    ) or {}

    file_path = data.get(
        "file_path",
        ""
    ).strip()

    if not file_path:

        return jsonify({
            "error": "File path is required"
        }), 400

    try:

        result = security_engine.analyze_file(
            file_path
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================


# =========================================
# EMAIL / MESSAGE SECURITY ANALYSIS
# =========================================

@app.route(
    "/api/analyze-email",
    methods=["POST"]
)
def analyze_email():
    try:

        data = request.get_json(
            silent=True
        ) or {}

        message = data.get(
            "message",
            ""
        )

        subject = data.get(
            "subject",
            ""
        )

        if not message:
            return jsonify({
                "error": "message is required"
            }), 400

        result = security_engine.analyze_email_message(
            message,
            subject
        )

        return jsonify(
            result
        )

    except Exception as exc:

        return jsonify({
            "error": str(exc)
        }), 500


# PRIVACY CHECK
# =========================================

@app.route(
    "/api/privacy",
    methods=["GET"]
)
def privacy_check():

    try:

        result = security_engine.analyze_privacy()

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# SCAN HISTORY
# =========================================

@app.route(
    "/api/scan-history",
    methods=["GET"]
)
def scan_history():

    try:

        limit = request.args.get(
            "limit",
            20
        )

        result = security_engine.get_scan_history(
            limit
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# CLEAR SCAN HISTORY
# =========================================

@app.route(
    "/api/scan-history/clear",
    methods=["POST"]
)
def clear_scan_history():

    try:

        result = security_engine.clear_scan_history()

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# SECURITY ANALYTICS
# =========================================

@app.route(
    "/api/security-analytics",
    methods=["GET"]
)
def security_analytics():

    try:

        result = (
            security_engine
            .get_security_analytics()
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# AI STATUS
# =========================================

@app.route(
    "/api/ai/status",
    methods=["GET"]
)
def ai_status():

    try:

        result = (
            security_engine
            .get_ai_backend_status()
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500

# =========================================
# INCIDENTS
# =========================================

@app.route(
    "/api/incidents",
    methods=["GET"]
)
def get_incidents():

    try:

        limit = request.args.get(
            "limit",
            20
        )

        result = security_engine.incident_manager.get_incidents(
            limit
        )

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# INCIDENT DETAILS
# =========================================

@app.route(
    "/api/incidents/<int:incident_id>",
    methods=["GET"]
)
def get_incident(incident_id):

    try:

        incident = (
            security_engine
            .incident_manager
            .get_incident(incident_id)
        )

        if incident is None:

            return jsonify({
                "error": "Incident not found"
            }), 404

        return jsonify(incident)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# UPDATE INCIDENT STATUS
# =========================================

@app.route(
    "/api/incidents/<int:incident_id>/status",
    methods=["POST"]
)
def update_incident_status(incident_id):

    data = request.get_json(
        silent=True
    ) or {}

    status = data.get(
        "status",
        ""
    )

    if not status:

        return jsonify({
            "error": "Status is required"
        }), 400

    try:

        result = (
            security_engine
            .incident_manager
            .update_status(
                incident_id,
                status
            )
        )

        if result is None:

            return jsonify({
                "error": "Incident not found"
            }), 404

        if "error" in result:

            return jsonify(result), 400

        return jsonify(result)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500
# =========================================
# SET AI BACKEND
# =========================================

@app.route(
    "/api/ai/backend",
    methods=["POST"]
)
def set_ai_backend():

    data = request.get_json(
        silent=True
    ) or {}

    backend = data.get(
        "backend",
        "development"
    )

    if backend not in [
        "development",
        "qualcomm"
    ]:

        return jsonify({
            "error": (
                "Invalid backend. "
                "Use development or qualcomm."
            )
        }), 400

    try:

        security_engine.set_ai_backend(
            backend
        )

        return jsonify(
            security_engine
            .get_ai_backend_status()
        )

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# =========================================
# START VAJRA
# =========================================

if __name__ == "__main__":

    print(
        "\n===== VAJRA SECURITY DASHBOARD ====="
    )

    print(
        "Starting VAJRA Security Engine..."
    )

    print(
        "Dashboard: http://127.0.0.1:5000"
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )