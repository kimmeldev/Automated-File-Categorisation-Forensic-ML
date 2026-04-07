from flask import Flask, render_template, request, send_file, session, redirect, url_for, send_from_directory
import os
import csv
import json
import subprocess
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from functools import wraps
from datetime import timedelta

import firebase_admin
from firebase_admin import credentials, auth, firestore

# ================= INIT =================

app = Flask(__name__)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.secret_key = "forensic_project"

cred = credentials.Certificate("firebase_key.json")
firebase_admin.initialize_app(cred)

db = firestore.client()

BASE_CASE_FOLDER = "cases"
USERS_FILE = "users.json"

# ================= DECORATORS =================

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get("role") != "admin":
            return "Access Denied", 403
        return f(*args, **kwargs)
    return wrap

# ================= USERS =================

def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({"admin@test.com": "admin"}, f)

    with open(USERS_FILE) as f:
        return json.load(f)

def get_user_role(email):
    return load_users().get(email, "worker")

# ================= LOGGING =================

def log_action(user, action, case_id="", filename=""):

    # ✅ save to CSV
    with open("logs.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            user,
            action,
            case_id,
            filename,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ])

    # ✅ save to Firebase
    try:
        db.collection("logs").add({
            "user": user,
            "action": action,
            "case_id": case_id,
            "filename": filename,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        print("🔥 Firebase log error:", e)

# ================= HELPERS =================

def list_cases(include_deleted=False):
    if not os.path.exists(BASE_CASE_FOLDER):
        os.makedirs(BASE_CASE_FOLDER)

    cases = []

    for c in os.listdir(BASE_CASE_FOLDER):
        if not c.startswith("CASE_"):
            continue

        info = get_case_info(c)

        if not include_deleted and info.get("status") == "DELETED":
            continue

        cases.append(c)

    return sorted(cases)

def get_case_info(case):
    path = os.path.join(BASE_CASE_FOLDER, case, "case_info.json")

    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)

    return {}

# ================= AUTH =================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        try:
            user = auth.get_user_by_email(email)

            if password == "admin123":
                session["user"] = user.uid
                session["email"] = email
                session["role"] = get_user_role(email)

                session.permanent = False

                log_action(email, "login")

                if session["role"] == "admin":
                    return redirect("/admin")
                return redirect("/")

            return "Invalid credentials"

        except:
            return "User not found"

    return render_template("login.html")

@app.route("/logout")
def logout():
    log_action(session.get("email"), "logout")
    session.clear()
    return redirect("/login")

# ================= DASHBOARD =================

@app.route("/")
@login_required
def index():

    case_list = list_cases()

    total_cases = len(case_list)
    total_files = 0
    total_suspicious = 0
    highest_risk = 0

    images = documents = videos = executables = 0

    # 🔥 NEW
    top_risk_files = []

    for case in case_list:
        report = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")

        if os.path.exists(report):
            with open(report, newline="") as f:
                for row in csv.DictReader(f):

                    total_files += 1
                    risk = int(row["risk_score"])
                    highest_risk = max(highest_risk, risk)

                    # 🔥 collect for top risk
                    top_risk_files.append({
                        "file": row["filename"],
                        "risk": risk,
                        "case": case
                    })

                    if row["status"] == "SUSPICIOUS":
                        total_suspicious += 1

                    if row["prediction"] == "images":
                        images += 1
                    elif row["prediction"] == "documents":
                        documents += 1
                    elif row["prediction"] == "videos":
                        videos += 1
                    elif row["prediction"] == "executables":
                        executables += 1

    # 🔥 sort top 3 highest risk
    top_risk_files = sorted(top_risk_files, key=lambda x: x["risk"], reverse=True)[:3]

    return render_template("index.html",
    title="Home",
    total_cases=total_cases,
    total_files=total_files,
    total_suspicious=total_suspicious,
    highest_risk=highest_risk,
    images=images,
    documents=documents,
    videos=videos,
    executables=executables,
    top_risk_files=top_risk_files
)

# ================= CASES =================

@app.route("/cases")
@login_required
def cases():

    if request.method == "GET":
        session.pop("case_id", None)

    case_data = []

    for case in list_cases():
        info = get_case_info(case)

        report = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")

        total = suspicious = 0

        if os.path.exists(report):
            with open(report, newline="") as f:
                for row in csv.DictReader(f):
                    total += 1
                    if row["status"] == "SUSPICIOUS":
                        suspicious += 1

        case_data.append({
            "name": case,
            "remark": info.get("remark"),
            "date": info.get("created_date"),
            "total": total,
            "suspicious": suspicious
        })

    return render_template("cases.html", title="Cases", cases=case_data)

# ================= EVIDENCE =================

@app.route("/evidence", methods=["GET", "POST"])
@login_required
def evidence():

    if request.method == "GET":
        session.pop("case_id", None)

    case_list = [{"name": c, "remark": get_case_info(c).get("remark")} for c in list_cases()]

    case_id = request.form.get("case")

    if case_id:
        session["case_id"] = case_id

    selected = session.get("case_id")
    results = []

    if selected:
        report = os.path.join(BASE_CASE_FOLDER, selected, "analysis_report.csv")
        if os.path.exists(report):
            with open(report, newline="") as f:
                results = list(csv.DictReader(f))

    return render_template("evidence.html",
        title="Evidence Explorer",
        cases=case_list,
        selected_case=selected,
        results=results
    )

# ================= TIMELINE =================

@app.route("/timeline", methods=["GET", "POST"])
@login_required
def timeline():

    if request.method == "GET":
        session.pop("case_id", None)

    case_list = [{"name": c, "remark": get_case_info(c).get("remark")} for c in list_cases()]

    case_id = request.form.get("case")

    if case_id:
        session["case_id"] = case_id

    selected = session.get("case_id")
    events = []

    if selected:
        report = os.path.join(BASE_CASE_FOLDER, selected, "analysis_report.csv")
        if os.path.exists(report):
            for row in csv.DictReader(open(report)):
                events.append({
                    "file": row["filename"],
                    "created": row["created_time"],
                    "modified": row["modified_time"],
                    "accessed": row["accessed_time"]
                })

    return render_template("timeline.html",
        title="Timeline",
        cases=case_list,
        case_id=selected,
        events=events
    )

# ================= REPORTS =================

@app.route("/reports", methods=["GET", "POST"])
@login_required
def reports():

    if request.method == "GET":
        session.pop("case_id", None)

    case_list = [{"name": c, "remark": get_case_info(c).get("remark")} for c in list_cases()]

    case_id = request.form.get("case")

    if case_id:
        session["case_id"] = case_id

    return render_template("reports.html",
        title="Reports",
        cases=case_list,
        selected_case=session.get("case_id")
    )

# ================= DOWNLOAD =================

@app.route("/download_csv")
@login_required
def download_csv():
    case = session.get("case_id")
    return send_file(os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv"), as_attachment=True)

@app.route("/download_pdf")
@login_required
def download_pdf():

    case = session.get("case_id")
    csv_file = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")
    pdf_file = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.pdf")

    rows = list(csv.DictReader(open(csv_file)))

    c = canvas.Canvas(pdf_file, pagesize=letter)
    y = 750

    for r in rows:
        c.drawString(30, y, r["filename"][:30])
        c.drawString(250, y, r["prediction"])
        c.drawString(350, y, r["confidence"])
        c.drawString(430, y, r["status"])
        c.drawString(500, y, r["risk_score"])
        y -= 18

    c.save()

    return send_file(pdf_file, as_attachment=True)

# ================= PREVIEW =================

@app.route("/preview/<case>/<filename>")
@login_required
def preview(case, filename):

    base = os.path.join(BASE_CASE_FOLDER, case, "processed")

    for root, _, files in os.walk(base):
        if filename in files:

            ext = filename.lower()

            # 🔥 allow inline preview for safe types
            if ext.endswith((".png", ".jpg", ".jpeg", ".gif", ".mp4", ".webm", ".pdf")):
                return send_from_directory(root, filename, as_attachment=False)

            # ⚠️ documents → force download
            return send_from_directory(root, filename, as_attachment=True)

    return "File not found"

# ================= ADMIN =================

@app.route("/admin")
@login_required
@admin_required
def admin():

    delete_requests = []

    for case in list_cases(include_deleted=True):

        report = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")

        if os.path.exists(report):
            with open(report, newline="") as f:
                for row in csv.DictReader(f):

                    if row.get("delete_request") == "YES":
                        delete_requests.append({
                            "case": case,
                            "file": row["filename"],
                            "reason": row.get("delete_reason"),
                            "user": row.get("requested_by")
                        })

    # load logs
    logs = []
    if os.path.exists("logs.csv"):
        with open("logs.csv") as f:
            logs = list(csv.reader(f))
            logs = logs[::-1]

    return render_template("admin.html",
        title="Admin Panel", 
        delete_requests=delete_requests,
        logs=logs
    )

@app.route("/request_delete", methods=["POST"])
@login_required
def request_delete():

    case = request.form["case"]
    filename = request.form["filename"]
    reason = request.form["reason"]

    report_path = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")

    rows = []

    with open(report_path, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames)

        # ensure new columns exist
        for col in ["delete_request", "delete_reason", "requested_by", "requested_at"]:
            if col not in fieldnames:
                fieldnames.append(col)

        for row in reader:

            if row["filename"] == filename:
                row["delete_request"] = "YES"
                row["delete_reason"] = reason
                row["requested_by"] = session.get("email")
                row["requested_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ✅ IMPORTANT: append EVERY row
            rows.append(row)

    # rewrite full CSV properly
    with open(report_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log_action(session.get("email"), "request_delete", case, filename)

    return redirect("/evidence")

@app.route("/approve_delete/<case>/<path:filename>")
@login_required
@admin_required
def approve_delete(case, filename):

    base_case = os.path.join(BASE_CASE_FOLDER, case)

    deleted = False

    for root, dirs, files in os.walk(base_case):
        for f in files:
            if f.strip() == filename.strip():
                file_path = os.path.join(root, f)
                os.remove(file_path)
                deleted = True
                print("🔥 Deleted file:", file_path)
                break
        if deleted:
            break

    if not deleted:
        print("⚠️ File not found on disk, removing from CSV only")

    # 🔥 ALWAYS REMOVE FROM CSV (IMPORTANT)
    report = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")

    rows = []

    with open(report, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

        for row in reader:
            if row["filename"] != filename:
                rows.append(row)

    with open(report, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log_action(session.get("email"), "approve_delete", case, filename)

    return redirect("/admin")

@app.route("/reject_delete/<case>/<path:filename>")
@login_required
@admin_required
def reject_delete(case, filename):

    report = os.path.join(BASE_CASE_FOLDER, case, "analysis_report.csv")

    rows = []

    with open(report, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

        for row in reader:
            if row["filename"] == filename:
                row["delete_request"] = ""
                row["delete_reason"] = ""
                row["requested_by"] = ""
                row["requested_at"] = ""
            rows.append(row)

    with open(report, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log_action(session.get("email"), "reject_delete", case, filename)

    return redirect("/admin")

# ================= CREATE CASE =================

@app.route("/create_case", methods=["POST"])
@login_required
def create_case():

    case_list = list_cases()

    if not case_list:
        next_case = "CASE_001"
    else:
        numbers = [int(c.split("_")[1]) for c in case_list]
        next_case = f"CASE_{max(numbers)+1:03d}"

    remark = request.form.get("remark")

    case_path = os.path.join(BASE_CASE_FOLDER, next_case)

    uploads = os.path.join(case_path, "uploads")
    processed = os.path.join(case_path, "processed")

    os.makedirs(uploads, exist_ok=True)
    os.makedirs(processed, exist_ok=True)

    case_info = {
        "case_id": next_case,
        "remark": remark,
        "created_date": datetime.now().strftime("%Y-%m-%d"),
        "created_by": session.get("email")  # 👈 we keep your new feature
    }

    db.collection("cases").document(next_case).set({
    "case_id": next_case,
    "remark": remark,
    "created_date": datetime.now().strftime("%Y-%m-%d"),
    "created_by": session.get("email")
    })

    with open(os.path.join(case_path, "case_info.json"), "w") as f:
        json.dump(case_info, f, indent=4)

    files = request.files.getlist("files")

    for file in files:
        if file.filename != "":
            file.save(os.path.join(uploads, file.filename))

        # 🔥 RESTORE ORIGINAL SORTER CALL
    subprocess.run(["python", "src/auto_sorter.py", next_case])

    # 🔥 SAVE FILE RESULTS TO FIREBASE
    report_path = os.path.join(BASE_CASE_FOLDER, next_case, "analysis_report.csv")

    if os.path.exists(report_path):
        with open(report_path, newline="") as f:
            for row in csv.DictReader(f):

                try:
                    db.collection("files").add({
                        "case_id": next_case,
                        "filename": row["filename"],
                        "category": row["prediction"],
                        "confidence": float(str(row["confidence"]).replace("%", "")),
                        "risk_score": int(row["risk_score"]),
                        "status": row["status"]
                    })
                except Exception as e:
                    print("🔥 Firebase file save error:", e)

    # 🔥 log after everything
    log_action(session.get("email"), "create_case", next_case, "")

    return redirect(url_for("cases"))

# ================= CREATE USER =================

@app.route("/create_user", methods=["POST"])
@login_required
@admin_required
def create_user():

    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = auth.create_user(
            email=email,
            password=password
        )

        # 🔥 ADD TO users.json
        users = load_users()
        users[email] = "worker"

        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

        log_action(session.get("email"), "create_user", "", email)

        print("✅ User created:", user.uid)

    except Exception as e:
        print("❌ Error creating user:", e)

    return redirect("/admin")

# ================= DELETE USER =================

@app.route("/delete_user", methods=["POST"])
@login_required
@admin_required
def delete_user():

    email = request.form.get("email")

    try:
        # 🔥 get user from Firebase
        user = auth.get_user_by_email(email)

        # 🔥 delete from Firebase
        auth.delete_user(user.uid)

        # 🔥 remove from users.json
        users = load_users()

        if email in users:
            del users[email]

            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)

        log_action(session.get("email"), "delete_user", "", email)

        print("✅ Deleted user:", email)

    except Exception as e:
        print("❌ Error deleting user:", e)

    return redirect("/admin")

 # ================= Model Info =================   

@app.route("/model")
def model():
    return render_template("model.html", title="Model Intelligence")

 # ================= Add Evidence =================  

@app.route("/add_evidence", methods=["POST"])
@login_required
def add_evidence():

    case = request.form.get("case")
    files = request.files.getlist("files")

    if not case:
        return "No case selected", 400

    case_path = os.path.join(BASE_CASE_FOLDER, case)
    uploads = os.path.join(case_path, "uploads")

    if not os.path.exists(uploads):
        return "Uploads folder not found", 404

    for file in files:
        if file and file.filename:
            file.save(os.path.join(uploads, file.filename))

    # 🔥 VERY IMPORTANT
    # re-run your ML processing so new files appear
    subprocess.run(["python", "src/auto_sorter.py", case])

    log_action(session.get("email"), "add_evidence", case, "")

    return redirect(url_for("evidence"))

# ================= RUN =================

if __name__ == "__main__":
    app.run(debug=True)