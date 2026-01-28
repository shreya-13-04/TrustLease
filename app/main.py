from flask import (
    Blueprint,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    abort
)
from app.crypto_utils import encrypt_data, decrypt_data
from app.models import User, SecureData
from app.extensions import db
import random
from datetime import datetime, timedelta
from functools import wraps

main_bp = Blueprint('main', __name__)

# ------------------------------------------------------------------
# AUTHORIZATION DECORATOR
# ------------------------------------------------------------------

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "role" not in session:
                return redirect(url_for("main.login_page"))

            if session["role"] != required_role:
                abort(403)

            return f(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------------------
# HEALTH CHECK
# ------------------------------------------------------------------

@main_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"message": "TrustLease backend is running"})


# ------------------------------------------------------------------
# API ROUTES
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

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=2)
        db.session.commit()

        return jsonify({
            "message": "OTP generated",
            "otp": otp
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

    if user.otp != otp or datetime.utcnow() > user.otp_expiry:
        return jsonify({"error": "Invalid or expired OTP"}), 401

    user.otp = None
    user.otp_expiry = None
    db.session.commit()

    return jsonify({"message": "MFA successful", "role": user.role}), 200


# ------------------------------------------------------------------
# UI ROUTES (LOGIN + MFA)
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

        if user and user.otp == otp and datetime.utcnow() <= user.otp_expiry:
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


# ------------------------------------------------------------------
# PHASE 5.5 – ENCRYPTED DATA STORAGE (NEW)
# ------------------------------------------------------------------

@main_bp.route("/secure-upload", methods=["POST"])
@role_required("owner")
def secure_upload():
    plaintext = request.form.get("data")

    encrypted = encrypt_data(plaintext)

    record = SecureData(
        owner=session["username"],
        encrypted_content=encrypted
    )

    db.session.add(record)
    db.session.commit()

    return "Data encrypted and securely stored"


@main_bp.route("/secure-view")
@role_required("owner")
def secure_view():
    records = SecureData.query.filter_by(owner=session["username"]).all()

    decrypted_data = [
        decrypt_data(r.encrypted_content) for r in records
    ]

    return jsonify(decrypted_data)


# ------------------------------------------------------------------
# PHASE 4 AUTHORIZED ROUTES
# ------------------------------------------------------------------

@main_bp.route("/upload")
@role_required("owner")
def upload_data():
    return "Secure data upload — OWNER only"


@main_bp.route("/grant")
@role_required("owner")
def grant_access():
    return "Granting time-bound access — OWNER only"


@main_bp.route("/view")
@role_required("delegate")
def view_shared_data():
    return "Viewing shared data — DELEGATE only"


@main_bp.route("/audit")
@role_required("admin")
def audit_logs():
    return "Audit logs — ADMIN only"


# ------------------------------------------------------------------
# LOGOUT
# ------------------------------------------------------------------

@main_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login_page"))


#----------------------------------------------------
@main_bp.route("/secure-upload-form", methods=["GET", "POST"])
@role_required("owner")
def secure_upload_form():
    if request.method == "POST":
        plaintext = request.form.get("data")
        encrypted = encrypt_data(plaintext)

        record = SecureData(
            owner=session["username"],
            encrypted_content=encrypted
        )

        db.session.add(record)
        db.session.commit()

        return redirect(url_for("main.secure_view"))

    return '''
    <form method="post">
        <input name="data" placeholder="Enter secret data" required>
        <button type="submit">Upload Securely</button>
    </form>
    '''
