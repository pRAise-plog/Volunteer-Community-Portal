import hmac
import os
import re
import secrets
import sqlite3
from datetime import date
from functools import wraps
from pathlib import Path

import click
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
)
from werkzeug.security import generate_password_hash, check_password_hash

# ==========================================
# 1. CONFIGURATION
# ==========================================

app = Flask(__name__)

# Secret key for session security
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-me"
)

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Project directory
BASE_DIR = Path(__file__).resolve().parent

# Database location
# Local computer: database.db
# Render: /var/data/database.db
DATABASE = Path(
    os.environ.get(
        "DATABASE_PATH",
        str(BASE_DIR / "database.db")
    )
)

# Create database directory if it doesn't exist
DATABASE.parent.mkdir(parents=True, exist_ok=True)

# Volunteer hours target
HOURS_GOAL = 20


# ==========================================
# 2. DATABASE
# ==========================================

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    connection = get_db_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK (role IN ('volunteer', 'organization', 'admin')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS volunteer_profiles (
                user_id INTEGER PRIMARY KEY,
                phone TEXT NOT NULL,
                skills TEXT,
                availability TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                user_id INTEGER PRIMARY KEY,
                organization_name TEXT NOT NULL,
                contact_person TEXT NOT NULL,
                phone TEXT,
                purpose TEXT,
                approval_status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (approval_status IN ('pending', 'approved', 'rejected')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                location TEXT NOT NULL DEFAULT 'Keffi',
                event_date TEXT NOT NULL,
                event_time TEXT,
                hours INTEGER NOT NULL DEFAULT 2,
                FOREIGN KEY (organization_id)
                    REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS signups (
                user_id INTEGER NOT NULL,
                activity_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                attended INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, activity_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (activity_id)
                    REFERENCES activities(id) ON DELETE CASCADE
            )
        """)

        # Upgrade older databases that were created without "attended"
        columns = [r["name"] for r in
                   connection.execute("PRAGMA table_info(signups)")]
        if "attended" not in columns:
            connection.execute(
                "ALTER TABLE signups "
                "ADD COLUMN attended INTEGER NOT NULL DEFAULT 0"
            )

        connection.commit()
    finally:
        connection.close()


# ==========================================
# 3. ACCESS CONTROL
# ==========================================

def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You do not have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ==========================================
# 3b. CSRF PROTECTION
# ==========================================

CSRF_FORM = re.compile(
    r'(<form\b[^>]*\bmethod\s*=\s*["\']?post["\']?[^>]*>)', re.IGNORECASE
)


@app.before_request
def csrf_protect():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not hmac.compare_digest(sent, session["csrf_token"]):
            return bad_request(None)


@app.after_request
def add_csrf_fields(response):
    """Insert the hidden token field into every POST form on the page."""
    token = session.get("csrf_token")
    if (token
            and response.status_code == 200
            and response.mimetype == "text/html"
            and not response.direct_passthrough):
        field = f'<input type="hidden" name="csrf_token" value="{token}">'
        html = response.get_data(as_text=True)
        response.set_data(CSRF_FORM.sub(lambda m: m.group(1) + field, html))
    return response


@app.errorhandler(400)
def bad_request(error):
    flash("Your session expired or the form was invalid. "
          "Please try again.", "error")
    return redirect(url_for("home"))


# ==========================================
# 4. PUBLIC PAGES
# ==========================================

@app.route("/")
def home():
    today = date.today().isoformat()
    db = get_db_connection()
    try:
        activities = db.execute("""
            SELECT a.*, o.organization_name
            FROM activities a
            JOIN organizations o ON o.user_id = a.organization_id
            WHERE a.event_date >= ? AND o.approval_status = 'approved'
            ORDER BY a.event_date
            LIMIT 3
        """, (today,)).fetchall()

        stats = db.execute("""
            SELECT
              (SELECT COUNT(*) FROM users WHERE role='volunteer') AS volunteers,
              (SELECT COUNT(*) FROM organizations
               WHERE approval_status='approved') AS orgs,
              (SELECT COUNT(*) FROM activities) AS activities
        """).fetchone()
    finally:
        db.close()

    return render_template("index.html", activities=activities, stats=stats)


@app.route("/activities")
def activities():
    today = date.today().isoformat()
    db = get_db_connection()
    try:
        rows = db.execute("""
            SELECT a.*, o.organization_name,
                   (SELECT COUNT(*) FROM signups s
                    WHERE s.activity_id = a.id) AS volunteers
            FROM activities a
            JOIN organizations o ON o.user_id = a.organization_id
            WHERE a.event_date >= ? AND o.approval_status = 'approved'
            ORDER BY a.event_date
        """, (today,)).fetchall()

        joined = set()
        if session.get("role") == "volunteer":
            joined = {
                r["activity_id"] for r in db.execute(
                    "SELECT activity_id FROM signups WHERE user_id = ?",
                    (session["user_id"],),
                )
            }
    finally:
        db.close()

    return render_template("activities.html", activities=rows, joined=joined)


# ==========================================
# 5. REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        role = request.form.get("role", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if role not in ("volunteer", "organization"):
            flash("Please select a valid account type.", "error")
            return redirect(url_for("register"))

        if not full_name or not email or len(password) < 8:
            flash(
                "Enter your name and email, and use a password "
                "of at least 8 characters.", "error",
            )
            return redirect(url_for("register"))

        phone = request.form.get("phone", "").strip()
        skills = request.form.get("skills", "").strip()
        availability = request.form.get("availability", "").strip()

        organization_name = request.form.get("organization_name", "").strip()
        contact_person = request.form.get("contact_person", "").strip()
        organization_phone = request.form.get("organization_phone", "").strip()
        purpose = request.form.get("purpose", "").strip()

        if role == "volunteer" and not phone:
            flash("Please provide your phone number.", "error")
            return redirect(url_for("register"))

        if role == "organization" and (not organization_name or not contact_person):
            flash("Please provide your organization name and contact person.",
                  "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        connection = get_db_connection()

        try:
            cursor = connection.execute(
                "INSERT INTO users (full_name, email, password_hash, role) "
                "VALUES (?, ?, ?, ?)",
                (full_name, email, password_hash, role),
            )
            user_id = cursor.lastrowid

            if role == "volunteer":
                connection.execute(
                    "INSERT INTO volunteer_profiles "
                    "(user_id, phone, skills, availability) "
                    "VALUES (?, ?, ?, ?)",
                    (user_id, phone, skills, availability),
                )
            else:
                connection.execute(
                    "INSERT INTO organizations "
                    "(user_id, organization_name, contact_person, phone, purpose) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (user_id, organization_name, contact_person,
                     organization_phone, purpose),
                )

            connection.commit()

        except sqlite3.IntegrityError:
            connection.rollback()
            flash("That email address is already registered. "
                  "Please use another email.", "error")
            return redirect(url_for("register"))
        finally:
            connection.close()

        if role == "organization":
            flash("Registration successful! Your organization "
                  "is awaiting administrator approval.", "success")
        else:
            flash("Volunteer registration successful! You can now log in.",
                  "success")

        return redirect(url_for("login"))

    return render_template(
        "register.html",
        selected_role=request.args.get("role", "volunteer"),
    )


# ==========================================
# 6. LOGIN / LOGOUT
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_db_connection()
        try:
            user = connection.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
        finally:
            connection.close()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid email address or password.", "error")
            return redirect(url_for("login"))

        session.clear()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["full_name"] = user["full_name"]

        flash(f"Welcome back, {user['full_name']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("home"))


# ==========================================
# 7. DASHBOARD (volunteer / organization / admin)
# ==========================================

@app.route("/dashboard")
@login_required()
def dashboard():
    uid, role = session["user_id"], session["role"]
    today = date.today().isoformat()
    db = get_db_connection()

    ctx = {
        "org_status": None,
        "activities": [],
        "upcoming": [],
        "pending": [],
        "stats": {"activities": 0, "hours": 0},
    }

    try:
        if role == "volunteer":
            ctx["activities"] = db.execute("""
                SELECT a.id, a.title, a.category, a.location,
                       a.event_date AS activity_date,
                       CASE WHEN s.attended = 1 THEN 'attended'
                            WHEN a.event_date < ? THEN 'awaiting confirmation'
                            ELSE 'registered' END AS status
                FROM signups s
                JOIN activities a ON a.id = s.activity_id
                WHERE s.user_id = ?
                ORDER BY a.event_date DESC
            """, (today, uid)).fetchall()

            ctx["upcoming"] = db.execute("""
                SELECT a.id, a.title, a.location,
                       a.event_date AS activity_date
                FROM activities a
                JOIN organizations o ON o.user_id = a.organization_id
                WHERE a.event_date >= ? AND o.approval_status = 'approved'
                  AND a.id NOT IN (SELECT activity_id FROM signups
                                   WHERE user_id = ?)
                ORDER BY a.event_date
                LIMIT 3
            """, (today, uid)).fetchall()

            hours = db.execute("""
                SELECT COALESCE(SUM(a.hours), 0) AS total
                FROM signups s JOIN activities a ON a.id = s.activity_id
                WHERE s.user_id = ? AND s.attended = 1
            """, (uid,)).fetchone()["total"]

            completed = sum(1 for a in ctx["activities"]
                            if a["status"] == "attended")

            ctx["stats"] = {
                "activities": len(ctx["activities"]),
                "hours": hours,
                "completed": completed,
                "goal": HOURS_GOAL,
                "percent": min(100, round(hours * 100 / HOURS_GOAL)),
            }

        elif role == "organization":
            org = db.execute(
                "SELECT approval_status FROM organizations WHERE user_id = ?",
                (uid,),
            ).fetchone()
            ctx["org_status"] = org["approval_status"] if org else "pending"

            ctx["activities"] = db.execute("""
                SELECT a.id, a.title, a.category, a.location,
                       a.event_date AS activity_date,
                       (SELECT COUNT(*) FROM signups s
                        WHERE s.activity_id = a.id) || ' volunteers' AS status
                FROM activities a
                WHERE a.organization_id = ?
                ORDER BY a.event_date
            """, (uid,)).fetchall()

            hours = db.execute("""
                SELECT COALESCE(SUM(a.hours), 0) AS total
                FROM signups s JOIN activities a ON a.id = s.activity_id
                WHERE a.organization_id = ? AND s.attended = 1
            """, (uid,)).fetchone()["total"]

            ctx["stats"] = {"activities": len(ctx["activities"]),
                            "hours": hours}

        else:  # admin
            ctx["pending"] = db.execute("""
                SELECT o.*, u.email
                FROM organizations o
                JOIN users u ON u.id = o.user_id
                WHERE o.approval_status = 'pending'
            """).fetchall()

            row = db.execute("""
                SELECT
                  (SELECT COUNT(*) FROM activities) AS activities,
                  (SELECT COALESCE(SUM(a.hours), 0)
                   FROM signups s JOIN activities a ON a.id = s.activity_id
                   WHERE s.attended = 1) AS hours
            """).fetchone()
            ctx["stats"] = {"activities": row["activities"],
                            "hours": row["hours"]}
    finally:
        db.close()

    return render_template("dashboard.html", **ctx)


# ==========================================
# 8. VOLUNTEER: PROFILE, SIGN-UP, HOURS
# ==========================================

@app.route("/profile", methods=["GET", "POST"])
@login_required("volunteer")
def profile():
    uid = session["user_id"]
    db = get_db_connection()
    try:
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            phone = request.form.get("phone", "").strip()
            skills = request.form.get("skills", "").strip()
            availability = request.form.get("availability", "").strip()

            if not full_name or not phone:
                flash("Name and phone number are required.", "error")
                return redirect(url_for("profile"))

            db.execute("UPDATE users SET full_name = ? WHERE id = ?",
                       (full_name, uid))
            db.execute(
                "UPDATE volunteer_profiles "
                "SET phone = ?, skills = ?, availability = ? "
                "WHERE user_id = ?",
                (phone, skills, availability, uid),
            )
            db.commit()
            session["full_name"] = full_name
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile"))

        p = db.execute("""
            SELECT u.full_name, u.email, v.phone, v.skills, v.availability
            FROM users u
            JOIN volunteer_profiles v ON v.user_id = u.id
            WHERE u.id = ?
        """, (uid,)).fetchone()
    finally:
        db.close()

    return render_template("profile.html", name=session["full_name"],
                           role="volunteer", p=p)


@app.route("/activities/<int:activity_id>/join", methods=["POST"])
@login_required("volunteer")
def join_activity(activity_id):
    today = date.today().isoformat()
    db = get_db_connection()
    try:
        open_activity = db.execute("""
            SELECT a.id
            FROM activities a
            JOIN organizations o ON o.user_id = a.organization_id
            WHERE a.id = ? AND a.event_date >= ?
              AND o.approval_status = 'approved'
        """, (activity_id, today)).fetchone()

        if open_activity is None:
            flash("That activity is no longer available.", "error")
            return redirect(url_for("activities"))

        db.execute(
            "INSERT OR IGNORE INTO signups (user_id, activity_id) VALUES (?, ?)",
            (session["user_id"], activity_id),
        )
        db.commit()
    finally:
        db.close()
    flash("You have joined this activity. Thank you!", "success")
    return redirect(url_for("dashboard"))


@app.route("/activities/<int:activity_id>/leave", methods=["POST"])
@login_required("volunteer")
def leave_activity(activity_id):
    today = date.today().isoformat()
    db = get_db_connection()
    try:
        db.execute("""
            DELETE FROM signups
            WHERE user_id = ? AND activity_id = ?
              AND activity_id IN (SELECT id FROM activities
                                  WHERE event_date >= ?)
        """, (session["user_id"], activity_id, today))
        db.commit()
    finally:
        db.close()
    flash("You have left the activity.", "success")
    return redirect(url_for("dashboard"))


@app.route("/hours")
@login_required("volunteer")
def hours():
    db = get_db_connection()
    try:
        rows = db.execute("""
            SELECT a.title, a.event_date, a.hours, a.location,
                   o.organization_name
            FROM signups s
            JOIN activities a ON a.id = s.activity_id
            JOIN organizations o ON o.user_id = a.organization_id
            WHERE s.user_id = ? AND s.attended = 1
            ORDER BY a.event_date DESC
        """, (session["user_id"],)).fetchall()
    finally:
        db.close()

    total = sum(r["hours"] for r in rows)
    return render_template("hours.html", name=session["full_name"],
                           role="volunteer", rows=rows, total=total)


# ==========================================
# 9. ORGANIZATION: ACTIVITIES AND ATTENDANCE
# ==========================================

@app.route("/organization/activities/new", methods=["POST"])
@login_required("organization")
def new_activity():
    uid = session["user_id"]
    db = get_db_connection()
    try:
        org = db.execute(
            "SELECT approval_status FROM organizations WHERE user_id = ?", (uid,)
        ).fetchone()

        if org is None or org["approval_status"] != "approved":
            flash("Your organization must be approved first.", "error")
            return redirect(url_for("dashboard"))

        f = request.form
        title = f.get("title", "").strip()
        event_date = f.get("event_date", "").strip()

        if not title or not event_date:
            flash("Title and date are required.", "error")
            return redirect(url_for("dashboard"))

        try:
            hours_value = max(1, min(int(f.get("hours") or 2), 24))
        except ValueError:
            hours_value = 2

        db.execute("""
            INSERT INTO activities
              (organization_id, title, category, description,
               location, event_date, event_time, hours)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            uid, title, f.get("category", "outreach"),
            f.get("description", "").strip(),
            f.get("location", "").strip() or "Keffi",
            event_date, f.get("event_time", ""), hours_value,
        ))
        db.commit()
    finally:
        db.close()
    flash("Activity published.", "success")
    return redirect(url_for("dashboard"))


@app.route("/organization/activities/<int:activity_id>")
@login_required("organization")
def manage_activity(activity_id):
    today = date.today().isoformat()
    db = get_db_connection()
    try:
        activity = db.execute(
            "SELECT * FROM activities WHERE id = ? AND organization_id = ?",
            (activity_id, session["user_id"]),
        ).fetchone()

        if activity is None:
            flash("Activity not found.", "error")
            return redirect(url_for("dashboard"))

        roster = db.execute("""
            SELECT u.id, u.full_name, u.email, v.phone, v.skills, s.attended
            FROM signups s
            JOIN users u ON u.id = s.user_id
            LEFT JOIN volunteer_profiles v ON v.user_id = u.id
            WHERE s.activity_id = ?
            ORDER BY u.full_name
        """, (activity_id,)).fetchall()
    finally:
        db.close()

    return render_template(
        "manage_activity.html", name=session["full_name"],
        role="organization", activity=activity, roster=roster,
        can_mark=activity["event_date"] <= today,
    )


@app.route("/organization/activities/<int:activity_id>/attendance",
           methods=["POST"])
@login_required("organization")
def save_attendance(activity_id):
    today = date.today().isoformat()
    db = get_db_connection()
    try:
        activity = db.execute(
            "SELECT event_date FROM activities "
            "WHERE id = ? AND organization_id = ?",
            (activity_id, session["user_id"]),
        ).fetchone()

        if activity is None:
            flash("Activity not found.", "error")
            return redirect(url_for("dashboard"))

        if activity["event_date"] > today:
            flash("Attendance can only be recorded on or after the "
                  "activity date.", "error")
            return redirect(url_for("manage_activity", activity_id=activity_id))

        present = {int(x) for x in request.form.getlist("present")
                   if x.isdigit()}

        signed_up = db.execute(
            "SELECT user_id FROM signups WHERE activity_id = ?", (activity_id,)
        ).fetchall()

        for row in signed_up:
            db.execute(
                "UPDATE signups SET attended = ? "
                "WHERE user_id = ? AND activity_id = ?",
                (1 if row["user_id"] in present else 0,
                 row["user_id"], activity_id),
            )
        db.commit()
    finally:
        db.close()

    flash("Attendance saved. Volunteer hours have been updated.", "success")
    return redirect(url_for("manage_activity", activity_id=activity_id))


@app.route("/organization/activities/<int:activity_id>/delete",
           methods=["POST"])
@login_required("organization")
def delete_activity(activity_id):
    db = get_db_connection()
    try:
        db.execute(
            "DELETE FROM activities WHERE id = ? AND organization_id = ?",
            (activity_id, session["user_id"]),
        )
        db.commit()
    finally:
        db.close()
    flash("Activity deleted.", "success")
    return redirect(url_for("dashboard"))


# ==========================================
# 10. ADMIN
# ==========================================

@app.route("/admin/organizations/<int:org_id>/<action>", methods=["POST"])
@login_required("admin")
def review_organization(org_id, action):
    if action not in ("approve", "reject"):
        return redirect(url_for("dashboard"))

    status = "approved" if action == "approve" else "rejected"
    db = get_db_connection()
    try:
        db.execute(
            "UPDATE organizations SET approval_status = ? WHERE user_id = ?",
            (status, org_id),
        )
        db.commit()
    finally:
        db.close()
    flash(f"Organization {status}.", "success")
    return redirect(url_for("dashboard"))


# flask --app app create-admin "Your Name" you@email.com YourPassword
@app.cli.command("create-admin")
@click.argument("name")
@click.argument("email")
@click.argument("password")
def create_admin(name, email, password):
    db = get_db_connection()
    try:
        db.execute(
            "INSERT INTO users (full_name, email, password_hash, role) "
            "VALUES (?, ?, ?, 'admin')",
            (name, email.lower(), generate_password_hash(password)),
        )
        db.commit()
        print("Admin created.")
    finally:
        db.close()


# ==========================================
# 11. RUN
# ==========================================

initialize_database()

if __name__ == "__main__":
    # debug=True is for local testing only. Hosting services start the app
    # through their own WSGI file, so this line does not run online.
    app.run(debug=True)