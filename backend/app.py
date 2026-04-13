from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
import psycopg2
import psycopg2.extras
import bcrypt
import json
import os
import subprocess
from datetime import datetime, timedelta

# ── App Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "cspm-super-secret-key-2024")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
jwt = JWTManager(app)

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
JAVA_DIR = os.path.join(BASE_DIR, "..", "java_engine")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

# ── DB Config ──────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "localhost"),
    "database": os.environ.get("DB_NAME",     "cspm_db"),
    "user":     os.environ.get("DB_USER",     "postgres"),
    "password": os.environ.get("DB_PASSWORD", "Amar100ni04"),
    "connect_timeout": 4,
}

def get_db():
    return psycopg2.connect(**DB_CONFIG)

# ── Severity / Recommendation helpers ─────────────────────────────────────
FINDING_META = {
    # S3
    "no versioning":              {"severity": "MEDIUM", "recommendation": "Enable S3 Versioning to protect against accidental deletion and overwrites."},
    "public access":              {"severity": "HIGH",   "recommendation": "Enable S3 Block Public Access; audit bucket ACLs and policies."},
    "no encryption":              {"severity": "HIGH",   "recommendation": "Enable server-side encryption (SSE-S3 or SSE-KMS) on all buckets."},
    "no logging":                 {"severity": "LOW",    "recommendation": "Enable S3 access logging and ship logs to a central audit bucket."},
    "permissive bucket policy":   {"severity": "MEDIUM", "recommendation": "Restrict the bucket policy to only allow specific IAM principals needed."},
    # IAM
    "no mfa":                     {"severity": "HIGH",   "recommendation": "Enforce MFA for all IAM users, especially privileged accounts."},
    "root account in use":        {"severity": "CRITICAL","recommendation": "Stop using the root account. Create individual IAM users with least-privilege roles."},
    "unused credentials":         {"severity": "MEDIUM", "recommendation": "Deactivate or delete IAM credentials inactive for 90+ days."},
    "password policy is too weak":{"severity": "HIGH",   "recommendation": "Set IAM password policy: min 14 chars, require uppercase, symbols, and disallow reuse."},
    "least privilege":            {"severity": "MEDIUM", "recommendation": "Audit IAM roles; replace wildcard (*) permissions with scoped resource-level policies."},
    # EC2
    "open ports":                 {"severity": "HIGH",   "recommendation": "Restrict Security Group ingress rules; allow only required ports from known CIDRs."},
    "public ip":                  {"severity": "MEDIUM", "recommendation": "Remove public IPs; route traffic through an Application Load Balancer or NAT Gateway."},
    "no security groups":         {"severity": "HIGH",   "recommendation": "Attach at least one Security Group with explicit deny-all default ingress."},
    "patch compliance":           {"severity": "HIGH",   "recommendation": "Enable AWS Systems Manager Patch Manager; patch all instances within 30 days of CVE disclosure."},
    "imdsv2 not enforced":        {"severity": "MEDIUM", "recommendation": "Enforce IMDSv2 (require session-oriented requests) to prevent SSRF token theft."},
    # RDS
    "publicly accessible rds":    {"severity": "HIGH",   "recommendation": "Set the RDS instance to not publicly accessible; use private subnets."},
    "no rds encryption":          {"severity": "HIGH",   "recommendation": "Enable encryption at rest for all RDS instances."},
    # VPC
    "no flow logs":               {"severity": "MEDIUM", "recommendation": "Enable VPC Flow Logs and ship to CloudWatch Logs or S3 for analysis."},
    "default vpc in use":         {"severity": "LOW",    "recommendation": "Avoid the default VPC; create a custom VPC with properly segmented subnets."},
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def enrich_finding(violation_text: str) -> dict:
    lower = violation_text.lower()
    for keyword, meta in FINDING_META.items():
        if keyword in lower:
            return {
                "description": violation_text,
                "severity":    meta["severity"],
                "recommendation": meta["recommendation"],
            }
    return {
        "description":    violation_text,
        "severity":       "INFO",
        "recommendation": "Review this finding manually and apply the principle of least privilege where possible.",
    }

def derive_resource(description: str) -> str:
    d = description.lower()
    if "s3" in d or "bucket" in d:
        return "S3"
    if "iam" in d or "mfa" in d or "root account" in d or "credential" in d or "password policy" in d or "least privilege" in d:
        return "IAM"
    if "ec2" in d or "instance" in d or "security group" in d or "patch" in d or "imds" in d or "open port" in d or "public ip" in d:
        return "EC2"
    if "rds" in d:
        return "RDS"
    if "vpc" in d or "flow log" in d:
        return "VPC"
    return "AWS"

def compute_score(findings: list) -> int:
    """Calculate score as percentage of PASS findings, weighted by severity."""
    if not findings:
        return 100
    weights = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 1}
    total_weight = sum(weights.get(f["severity"], 1) for f in findings)
    pass_weight  = sum(weights.get(f["severity"], 1) for f in findings if f["status"] == "PASS")
    return round((pass_weight / total_weight) * 100) if total_weight else 0

def build_findings(raw: dict) -> list:
    violations = raw.get("Violations", [])
    enriched   = [enrich_finding(v) for v in violations]
    findings   = []
    for idx, item in enumerate(enriched):
        resource = derive_resource(item["description"])
        status   = "FAIL"    if item["severity"] in ("HIGH", "CRITICAL") else \
                   "WARNING" if item["severity"] == "MEDIUM" else "PASS"
        findings.append({
            "id":             idx + 1,
            "resource":       resource,
            "check":          item["description"],
            "status":         status,
            "severity":       item["severity"],
            "recommendation": item["recommendation"],
        })
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings

# ── Root ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ── Auth: Register ─────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
            (username, email, pw_hash)
        )
        user_id = cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        token = create_access_token(identity=str(user_id))
        return jsonify({"message": "User registered", "token": token, "username": username}), 201
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Auth: Login ────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    try:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close(); conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=str(user["id"]))
    return jsonify({"token": token, "username": user["username"]}), 200

# ── Report ─────────────────────────────────────────────────────────────────
@app.route("/api/report")
@jwt_required(optional=True)
def report():
    report_path = os.path.join(DATA_DIR, "report.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "No report found. Run a scan first."}), 404

    with open(report_path, encoding="utf-8") as f:
        raw = json.load(f)

    findings = build_findings(raw)
    score    = compute_score(findings)

    failed   = sum(1 for f in findings if f["status"] == "FAIL")
    warnings = sum(1 for f in findings if f["status"] == "WARNING")
    passed   = sum(1 for f in findings if f["status"] == "PASS")

    return jsonify({
        "compliance_score": score,
        "total":   len(findings),
        "failed":  failed,
        "warnings": warnings,
        "passed":  passed,
        "high_risks":   sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL")),
        "medium_risks": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low_risks":    sum(1 for f in findings if f["severity"] == "LOW"),
        "findings": findings,
    })

# ── AWS Resources ──────────────────────────────────────────────────────────
@app.route("/api/resources")
@jwt_required(optional=True)
def resources():
    config_path = os.path.join(DATA_DIR, "aws_config.json")
    if not os.path.exists(config_path):
        return jsonify({"error": "aws_config.json not found"}), 404
    with open(config_path, encoding="utf-8") as f:
        return jsonify(json.load(f))

# ── Dashboard Stats ────────────────────────────────────────────────────────
@app.route("/api/dashboard/stats")
@jwt_required(optional=True)
def dashboard_stats():
    report_path = os.path.join(DATA_DIR, "report.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "No report found. Run a scan first."}), 404

    with open(report_path, encoding="utf-8") as f:
        raw = json.load(f)

    findings = build_findings(raw)
    score    = compute_score(findings)

    failed   = sum(1 for f in findings if f["status"] == "FAIL")
    warnings = sum(1 for f in findings if f["status"] == "WARNING")
    passed   = sum(1 for f in findings if f["status"] == "PASS")
    total    = len(findings) or 1

    service_breakdown  = {"S3": 0, "IAM": 0, "EC2": 0, "RDS": 0, "VPC": 0}
    severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for f in findings:
        svc = f["resource"]
        if svc in service_breakdown:
            service_breakdown[svc] = service_breakdown.get(svc, 0) + 1
        severity_breakdown[f["severity"]] = severity_breakdown.get(f["severity"], 0) + 1

    # Top 3 critical/high findings for "Recent Findings" widget
    critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:3]

    return jsonify({
        "total_checks":       total,
        "passed":             passed,
        "failed":             failed,
        "warnings":           warnings,
        "compliance_score":   score,
        "service_breakdown":  service_breakdown,
        "severity_breakdown": severity_breakdown,
        "recent_findings":    critical_high,
    })

# ── Scan History ───────────────────────────────────────────────────────────
@app.route("/api/scan-history")
@jwt_required(optional=True)
def scan_history():
    try:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT sh.id, u.username, sh.scan_type, sh.result, sh.status,
                   sh.scanned_at
            FROM scan_history sh
            LEFT JOIN users u ON sh.user_id = u.id
            ORDER BY sh.scanned_at DESC
            LIMIT 50
        """)
        rows = cur.fetchall()
        cur.close(); conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Delete One Scan ────────────────────────────────────────────────────────
@app.route("/api/scan-history/<int:scan_id>", methods=["DELETE"])
@jwt_required(optional=True)
def delete_scan(scan_id):
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("DELETE FROM scan_history WHERE id = %s", (scan_id,))
        deleted = cur.rowcount
        conn.commit(); cur.close(); conn.close()
        if deleted == 0:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify({"message": f"Scan #{scan_id} deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Delete All Scans ───────────────────────────────────────────────────────
@app.route("/api/scan-history/all", methods=["DELETE"])
@jwt_required(optional=True)
def delete_all_scans():
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("DELETE FROM scan_history")
        deleted = cur.rowcount
        conn.commit(); cur.close(); conn.close()
        return jsonify({"message": f"{deleted} scan(s) deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Trigger Scan ───────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
@jwt_required(optional=True)
def trigger_scan():
    user_id  = get_jwt_identity()
    jar_path = os.path.join(JAVA_DIR, "json-simple-1.1.1.jar")
    started  = datetime.now()

    # 1. Run the Java engine
    java_status = "failed"
    java_msg    = "Scan did not start."
    try:
        proc = subprocess.run(
            ["java", "-cp", f".{os.pathsep}{jar_path}", "ComplianceEngine"],
            cwd=JAVA_DIR,
            capture_output=True,
            timeout=60,
        )
        # Decode bytes; strip emoji/non-printable so we only keep clean ASCII
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raw_msg = stdout or stderr or "No output"
        java_msg = "".join(c for c in raw_msg if c.isprintable() or c in ("\n", "\r", "\t"))
        java_status = "completed" if proc.returncode == 0 else "failed"
    except FileNotFoundError:
        java_msg = "Java not found. Ensure JDK is installed and 'java' is on PATH."
    except subprocess.TimeoutExpired:
        java_msg = "Scan timed out after 60 seconds."
    except Exception as ex:
        java_msg = str(ex)

    # 2. Whether or not the Java engine ran, read the current report.json and
    #    build structured findings — this is what gets stored in scan_history.
    report_path = os.path.join(DATA_DIR, "report.json")
    result_payload: dict = {}

    if os.path.exists(report_path):
        try:
            with open(report_path, encoding="utf-8") as f:
                raw_report = json.load(f)

            findings = build_findings(raw_report)
            score    = compute_score(findings)
            failed   = sum(1 for fnd in findings if fnd["status"] == "FAIL")
            warnings = sum(1 for fnd in findings if fnd["status"] == "WARNING")
            passed   = sum(1 for fnd in findings if fnd["status"] == "PASS")

            result_payload = {
                "java_output": java_msg,
                "summary": {
                    "total":    len(findings),
                    "passed":   passed,
                    "failed":   failed,
                    "warnings": warnings,
                    "score":    score,
                },
                "findings": findings,
            }
        except Exception as parse_err:
            # report.json exists but couldn't be parsed — store raw java msg
            result_payload = {
                "java_output": java_msg,
                "error": f"Could not parse report.json: {parse_err}",
            }
    else:
        # Java didn't produce report.json (e.g. engine failed)
        result_payload = {
            "java_output": java_msg,
            "error": "report.json not found after scan. The Java engine may have failed.",
        }

    # Final status: completed only if java ran AND report was parsed
    status = "completed" if java_status == "completed" and "findings" in result_payload else "failed"

    # 3. Persist to DB — store the structured JSON as a string
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO scan_history (user_id, scan_type, result, status) VALUES (%s, %s, %s, %s)",
            (user_id, "compliance", json.dumps(result_payload), status)
        )
        conn.commit(); cur.close(); conn.close()
    except Exception:
        pass  # DB write failure must not block the response

    return jsonify({
        "status":     status,
        "output":     java_msg,
        "summary":    result_payload.get("summary", {}),
        "started":    started.isoformat(),
    }), (200 if status == "completed" else 500)


# ── Settings: DB Status ────────────────────────────────────────────────────
@app.route("/api/settings/status")
def settings_status():
    db_ok = False
    db_error = ""
    try:
        conn = get_db()
        conn.close()
        db_ok = True
    except Exception as e:
        db_error = str(e)

    # Java check: see if java binary exists
    java_ok = False
    try:
        r = subprocess.run(["java", "-version"], capture_output=True, timeout=5)
        java_ok = r.returncode == 0
    except Exception:
        pass

    # Load settings
    settings = {"aws_region": "us-east-1"}
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            settings = json.load(f)

    return jsonify({
        "db_connected": db_ok,
        "db_error":     db_error,
        "java_ok":      java_ok,
        "settings":     settings,
    })

# ── Settings: Save ────────────────────────────────────────────────────────
@app.route("/api/settings", methods=["POST"])
@jwt_required(optional=True)
def save_settings():
    data = request.get_json(silent=True) or {}
    allowed = {"aws_region"}
    settings = {}
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            settings = json.load(f)
    for key in allowed:
        if key in data:
            settings[key] = data[key]
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    return jsonify({"message": "Settings saved", "settings": settings})

# ── Entry Point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)