from flask import (
    Blueprint,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session
)
from app.models import User
from app.extensions import db
import random
from datetime import datetime, timedelta

main_bp = Blueprint('main', __name__)

# ------------------------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------------------------
@main_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"message": "TrustLease backend is running"})


# ------------------------------------------------------------------
# API ROUTES (Backend Testing / Demo)
# ------------------------------------------------------------------

@main_bp.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(username=username, role=role)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@main_bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=2)
        db.session.commit()

        return jsonify({
            "message": "OTP generated. Please verify.",
            "otp": otp   # demo only
        }), 200

    return jsonify({"error": "Invalid credentials"}), 401


@main_bp.route("/api/verify-otp", methods=["POST"])
def api_verify_otp():
    data = request.get_json()

    username = data.get("username")
    otp = data.get("otp")

    user = User.query.filter_by(username=username).first()

    if not user or not user.otp:
        return jsonify({"error": "OTP not generated"}), 400

    if user.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 401

    if datetime.utcnow() > user.otp_expiry:
        return jsonify({"error": "OTP expired"}), 401

    user.otp = None
    user.otp_expiry = None
    db.session.commit()

    return jsonify({
        "message": "MFA successful",
        "role": user.role
    }), 200


# ------------------------------------------------------------------
# UI ROUTES (Flask Templates + MFA Flow)
# ------------------------------------------------------------------

@main_bp.route("/", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=2)
            db.session.commit()

            session["username"] = username

            # Simulate email (demo purpose)
            print("OTP for demo:", otp)

            return redirect(url_for("main.otp_page"))

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@main_bp.route("/otp", methods=["GET", "POST"])
def otp_page():
    if "username" not in session:
        return redirect(url_for("main.login_page"))

    if request.method == "POST":
        otp = request.form.get("otp")
        user = User.query.filter_by(username=session["username"]).first()

        if (
            user
            and user.otp == otp
            and datetime.utcnow() <= user.otp_expiry
        ):
            user.otp = None
            user.otp_expiry = None
            db.session.commit()

            session["role"] = user.role
            return redirect(url_for("main.dashboard"))

        return render_template("otp.html", error="Invalid or expired OTP")

    return render_template("otp.html")


@main_bp.route("/dashboard")
def dashboard():
    if "role" not in session:
        return redirect(url_for("main.login_page"))

    return render_template("dashboard.html", role=session["role"])


@main_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login_page"))
