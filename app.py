from datetime import datetime
from pathlib import Path
import random

from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database.db"


app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["UPLOAD_FOLDER"] = BASE_DIR / "uploads"


def generate_access_code():
    number = random.randint(10000, 99999)
    return "EDU" + str(number)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            access_code TEXT UNIQUE,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS parents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            student_id INTEGER,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pdf_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            pdf_name TEXT NOT NULL,
            total_pages INTEGER DEFAULT 0,
            pages_read INTEGER DEFAULT 0,
            reading_time INTEGER DEFAULT 0,
            progress REAL DEFAULT 0,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            opened_app TEXT NOT NULL,
            window_title TEXT,
            category TEXT NOT NULL,
            duration INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS quiz_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            pdf_name TEXT,
            score INTEGER DEFAULT 0,
            total_questions INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            study_duration INTEGER DEFAULT 0,
            pages_read INTEGER DEFAULT 0,
            total_pages INTEGER DEFAULT 0,
            educational_time INTEGER DEFAULT 0,
            entertainment_time INTEGER DEFAULT 0,
            game_time INTEGER DEFAULT 0,
            quiz_score TEXT,
            created_at TEXT NOT NULL
                    );
        """
    )

    db.commit()


@app.before_request
def setup_database():
    init_db()


@app.route("/")
def index():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        role = request.form["role"]
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        access_code = request.form.get("access_code", "").upper()

        password_hash = generate_password_hash(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        db = get_db()

        if role == "student":
            student_access_code = generate_access_code()

            db.execute(
                "INSERT INTO students (name, email, password_hash, access_code, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, password_hash, student_access_code, created_at)
            )

        else:
            student = db.execute(
                "SELECT * FROM students WHERE access_code = ?",
                (access_code,)
            ).fetchone()

            if student is None:
                message = "Invalid student access code."
                return render_template("register.html", message=message)

            db.execute(
                "INSERT INTO parents (name, email, password_hash, student_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (name, email, password_hash, student["id"], created_at)
            )

        try:
            db.commit()
            return redirect("/")

        except sqlite3.IntegrityError:
            message = "Email already registered. Please use another email."
            return render_template("register.html", message=message)

    return render_template("register.html", message=message)

def login_user(role):
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        table = "students" if role == "student" else "parents"

        db = get_db()
        user = db.execute(
            f"SELECT * FROM {table} WHERE email = ?",
            (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = role
            session["name"] = user["name"]

            if role == "parent":
                session["student_id"] = user["student_id"]
                return redirect("/parent")

            return redirect("/student")

    if role == "student":
        return render_template("student_login.html")
    else:
        return render_template("parent_login.html")


@app.route("/student-login", methods=["GET", "POST"])
def student_login():
    return login_user("student")


@app.route("/parent-login", methods=["GET", "POST"])
def parent_login():
    return login_user("parent")


@app.route("/student")
def student_dashboard():
    if session.get("role") != "student":
        return redirect("/student-login")

    db = get_db()
    student = db.execute(
        "SELECT * FROM students WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    return render_template(
        "student_dashboard.html",
        student_name=student["name"],
        access_code=student["access_code"]
    )


@app.route("/parent")
def parent_dashboard():
    if session.get("role") != "parent":
        return redirect("/parent-login")

    db = get_db()
    student = db.execute(
        "SELECT * FROM students WHERE id = ?",
        (session.get("student_id"),)
    ).fetchone()

    student_name = "No student linked"

    if student:
        student_name = student["name"]

    return render_template("parent_dashboard.html", student_name=student_name)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
