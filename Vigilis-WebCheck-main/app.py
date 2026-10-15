
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
import io

from services.validation import normalize_input, ValidationError
from core.engine import run_assessment
from persistence import db
from reports import report_generator

app = Flask(__name__)
app.secret_key = "vigilis-dev-secret-key-change-in-production"

db.init_db()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200

@app.route("/scan", methods=["POST"])
def scan():
    raw_input = request.form.get("website", "")
    try:
        hostname = normalize_input(raw_input)
    except ValidationError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))

    result = run_assessment(hostname)
    scan_id = db.save_scan(result)
    return redirect(url_for("results", scan_id=scan_id))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    raw_input = (request.get_json(silent=True) or {}).get("website", "")
    try:
        hostname = normalize_input(raw_input)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    result = run_assessment(hostname)
    scan_id = db.save_scan(result)
    result["id"] = scan_id
    return jsonify(result)


@app.route("/results/<int:scan_id>")
def results(scan_id):
    result = db.get_scan(scan_id)
    if result is None:
        flash("That assessment could not be found.", "error")
        return redirect(url_for("index"))
    history = db.list_scans_for_host(result["hostname"])
    return render_template("results.html", result=result, history=history)


@app.route("/history")
def history():
    scans = db.list_scans()
    return render_template("history.html", scans=scans)


@app.route("/report/<int:scan_id>/<fmt>")
def download_report(scan_id, fmt):
    result = db.get_scan(scan_id)
    if result is None:
        flash("That assessment could not be found.", "error")
        return redirect(url_for("index"))

    filename_base = f"vigilis-report-{result['hostname']}-{scan_id}"

    if fmt == "txt":
        content = report_generator.generate_txt(result)
        return send_file(
            io.BytesIO(content), mimetype="text/plain",
            as_attachment=True, download_name=f"{filename_base}.txt",
        )
    if fmt == "html":
        content = report_generator.generate_html(result)
        return send_file(
            io.BytesIO(content), mimetype="text/html",
            as_attachment=True, download_name=f"{filename_base}.html",
        )
    if fmt == "pdf":
        try:
            content = report_generator.generate_pdf(result)
        except ImportError:
            flash("PDF generation is unavailable. Please install 'reportlab'.", "error")
            return redirect(url_for("results", scan_id=scan_id))
        return send_file(
            io.BytesIO(content), mimetype="application/pdf",
            as_attachment=True, download_name=f"{filename_base}.pdf",
        )

    flash("Unsupported report format.", "error")
    return redirect(url_for("results", scan_id=scan_id))


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", message="That page could not be found."), 404


@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html", message="Something went wrong on our end. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
