from flask import (
    Blueprint, request, jsonify, render_template,
    redirect, url_for, session, abort
)
from datetime import datetime, timedelta
import random
import hashlib
from functools import wraps

from app.extensions import db
from app.models import User, Lease, SecureData, SignedData, AuditLog
from app.crypto_utils import encrypt_data, decrypt_data
from app.signature_utils import sign_data, verify_signature
from app.encoding_utils import encode_token, decode_token

main_bp = Blueprint("main", __name__)

# ==================================================
# HELPERS
# ==================================================

def log_event(username, action):
    log = AuditLog(
        username=username,
        action=action,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()


def hash_lease(owner, delegate, resource, start_time, end_time):
    payload = f"{owner}|{delegate}|{resource}|{start_time}|{end_time}"
    return hashlib.sha256(payload.encode()).hexdigest()


def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "role" not in session:
                return redirect(url_for("main.login_page"))

            if session["role"] != required_role:
                log_event(
                    session.get("username", "anonymous"),
                    "Unauthorized role access attempt"
                )
                abort(403)

            return f(*args, **kwargs)
        return wrapper
    return decorator

# ==================================================
# HEALTH CHECK
# ==================================================

@main_bp.route("/health")
def health():
    return jsonify({"message": "TrustLease backend is running"})

# ==================================================
# API ROUTES (TESTING)
# ==================================================

@main_bp.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(username=data["username"], role=data["role"])
    user.set_password(data["password"])

    db.session.add(user)
    db.session.commit()

    log_event(user.username, "User registered (API)")
    return jsonify({"message": "User registered"}), 201


@main_bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()

    if user and user.check_password(data["password"]):
        otp = str(random.randint(100000, 999999))
        user.otp = otp
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=2)

        db.session.commit()
        log_event(user.username, "API login successful (OTP generated)")

        return jsonify({"otp": otp}), 200

    log_event(data.get("username", "unknown"), "API login failed")
    return jsonify({"error": "Invalid credentials"}), 401


@main_bp.route("/api/verify-otp", methods=["POST"])
def api_verify_otp():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()

    if (
        user
        and user.otp == data["otp"]
        and datetime.utcnow() <= user.otp_expiry
    ):
        user.otp = None
        user.otp_expiry = None
        db.session.commit()

        log_event(user.username, "API OTP verified")
        return jsonify({"message": "MFA successful"}), 200

    log_event(data.get("username", "unknown"), "API OTP failed")
    return jsonify({"error": "OTP invalid"}), 401

# ==================================================
# REGISTRATION (UI)
# ==================================================

@main_bp.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")
        captcha_answer = request.form.get("captcha_answer")

        if not captcha_answer or int(captcha_answer) != session.get("captcha_result"):
            return render_template(
                "register.html",
                error="Invalid CAPTCHA",
                captcha_question=session.get("captcha_question")
            )

        if not username or not password or not role:
            return render_template("register.html", error="All fields are required")

        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="Username already exists")

        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must be at least 8 characters"
            )

        if role not in ["owner", "delegate"]:
            return render_template("register.html", error="Invalid role selected")

        user = User(username=username, role=role)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        log_event(username, "User registered (UI)")
        return redirect(url_for("main.login_page"))

    # CAPTCHA generation
    a, b = random.randint(1, 9), random.randint(1, 9)
    session["captcha_result"] = a + b
    session["captcha_question"] = f"{a} + {b}"

    return render_template(
        "register.html",
        captcha_question=session["captcha_question"]
    )

# ==================================================
# LOGIN + OTP (UI)
# ==================================================

@main_bp.route("/", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        user = User.query.filter_by(
            username=request.form.get("username")
        ).first()

        if user and user.check_password(request.form.get("password")):
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=2)

            db.session.commit()
            session["username"] = user.username

            log_event(user.username, "UI login successful (OTP generated)")
            print("OTP (demo):", otp)

            return redirect(url_for("main.otp_page"))

        log_event(request.form.get("username"), "UI login failed")
        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@main_bp.route("/otp", methods=["GET", "POST"])
def otp_page():
    if "username" not in session:
        return redirect(url_for("main.login_page"))

    user = User.query.filter_by(username=session["username"]).first()

    if request.method == "POST":
        if (
            user
            and user.otp == request.form.get("otp")
            and datetime.utcnow() <= user.otp_expiry
        ):
            user.otp = None
            user.otp_expiry = None
            db.session.commit()

            session["role"] = user.role
            log_event(user.username, "OTP verified (UI)")
            return redirect(url_for("main.dashboard"))

        log_event(session["username"], "OTP verification failed")
        return render_template("otp.html", error="Invalid or expired OTP")

    return render_template("otp.html")

# ==================================================
# DASHBOARD
# ==================================================

@main_bp.route("/dashboard")
def dashboard():
    if "role" not in session:
        return redirect(url_for("main.login_page"))

    return render_template("dashboard.html", role=session["role"])

# ==================================================
# PHASE 5 – SECURE DATA STORAGE
# ==================================================

@main_bp.route("/secure-upload", methods=["POST"])
@role_required("owner")
def secure_upload():
    encrypted = encrypt_data(request.form.get("data"))
    record = SecureData(
        owner=session["username"],
        encrypted_content=encrypted
    )
    db.session.add(record)
    db.session.commit()

    log_event(session["username"], "Encrypted data uploaded")
    return "Data encrypted and stored"


@main_bp.route("/secure-view")
@role_required("owner")
def secure_view():
    records = SecureData.query.filter_by(owner=session["username"]).all()
    decrypted = [decrypt_data(r.encrypted_content) for r in records]
    return jsonify(decrypted)

# ==================================================
# PHASE 7–9 – LEASE + TOKEN + SIGNATURE
# ==================================================
@main_bp.route("/create-lease", methods=["GET", "POST"])
@role_required("owner")
def create_lease():
    if request.method == "POST":
        delegate = request.form.get("delegate")
        resource = request.form.get("resource")
        duration = int(request.form.get("minutes"))

        start = datetime.utcnow()
        end = start + timedelta(minutes=duration)

        lease_hash = hash_lease(
            session["username"], delegate, resource, start, end
        )
        signature = sign_data(lease_hash)

        raw_token = f"{session['username']}|{delegate}|{resource}|{start}"
        encoded_token = encode_token(raw_token)

        lease = Lease(
            owner=session["username"],
            delegate=delegate,
            resource=resource,
            start_time=start,
            end_time=end,
            is_active=True,
            lease_hash=lease_hash,
            signature=signature,
            access_token=encoded_token
        )

        db.session.add(lease)
        db.session.commit()

        log_event(session["username"], f"Lease created for {delegate}")

        return render_template(
            "create_lease.html",
            success="Lease created successfully",
            token=encoded_token
        )

    # GET request → show form
    return render_template("create_lease.html")

@main_bp.route("/my-leases")
@role_required("owner")
def my_leases():
    leases = Lease.query.filter_by(owner=session["username"]).all()
    return render_template("my_leases.html", leases=leases)

@main_bp.route("/revoke-lease/<int:lease_id>")
@role_required("owner")
def revoke_lease(lease_id):
    lease = Lease.query.get_or_404(lease_id)
    lease.is_active = False
    db.session.commit()

    log_event(session["username"], f"Lease revoked ID {lease_id}")
    return redirect(url_for("main.my_leases"))

@main_bp.route("/lease/<int:lease_id>/document")
@role_required("owner")
def view_lease_document(lease_id):
    lease = Lease.query.get_or_404(lease_id)
    return render_template("lease_document.html", lease=lease)

def lease_canonical_text(lease):
    return f"""
    Owner:{lease.owner}
    Delegate:{lease.delegate}
    Resource:{lease.resource}
    Start:{lease.start_time}
    End:{lease.end_time}
    """

@main_bp.route("/lease/<int:lease_id>/sign", methods=["POST"])
@role_required("owner")
def sign_lease(lease_id):
    lease = Lease.query.get_or_404(lease_id)

    data = lease_canonical_text(lease)
    signature = sign_data(data)  # your existing crypto

    lease.signature = signature
    db.session.commit()

    log_event(session["username"], f"Lease {lease_id} signed")

    return redirect(url_for("main.view_lease_document", lease_id=lease_id))

@main_bp.route("/lease/<int:lease_id>/verify")
@role_required("delegate")
def verify_lease(lease_id):
    lease = Lease.query.get_or_404(lease_id)

    data = lease_canonical_text(lease)

    is_valid = verify_signature(data, lease.signature)

    return render_template(
        "verify_lease.html",
        lease=lease,
        is_valid=is_valid
    )
@main_bp.route("/access-resource", methods=["GET", "POST"])
@role_required("delegate")
def access_resource_page():
    if request.method == "POST":
        resource = request.form.get("resource")
        token = request.form.get("token")

        return redirect(
            url_for(
                "main.access_resource",
                resource=resource,
                token=token
            )
        )

    return render_template("access_resource.html")


@main_bp.route("/access-resource/<resource>/<token>")
@role_required("delegate")
def access_resource(resource, token):
    lease = Lease.query.filter_by(
        delegate=session["username"],
        resource=resource
    ).first()

    if not lease or not lease.is_active:
        log_event(session["username"], "Unauthorized access attempt")
        return "Access denied", 403

    decoded = decode_token(token)
    if decoded is None or lease.access_token != token:
        return "Invalid access token", 403

    expected_hash = hash_lease(
        lease.owner,
        lease.delegate,
        lease.resource,
        lease.start_time,
        lease.end_time
    )

    if expected_hash != lease.lease_hash:
        return "Lease tampered", 403

    if not verify_signature(lease.lease_hash, lease.signature):
        return "Invalid lease signature", 403

    log_event(session["username"], f"Accessed resource {resource}")
    return f"Access granted to resource: {resource}"

@main_bp.route("/verify-signature", methods=["GET", "POST"])
def verify_signature_page():
    result = None

    if request.method == "POST":
        data = request.form.get("data")
        signature = request.form.get("signature")

        try:
            signature_bytes = eval(signature)  # since stored as bytes repr
            is_valid = verify_signature(data, signature_bytes)

            result = "VALID" if is_valid else "INVALID"

            log_event(
                session.get("username", "anonymous"),
                f"Signature verification: {result}"
            )

        except Exception:
            result = "INVALID"

    return render_template("verify_signature.html", result=result)

@main_bp.route("/signed-data-history")
@role_required("owner")
def signed_data_history():
    records = SignedData.query.filter_by(
        owner=session["username"]
    ).order_by(SignedData.timestamp.desc()).all()

    return render_template("signed_data_history.html", records=records)

# ==================================================
# PHASE 10 – AUDIT LOGS
# ==================================================

@main_bp.route("/audit-logs")
@role_required("admin")
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return jsonify([
        {
            "user": l.username,
            "action": l.action,
            "time": l.timestamp.isoformat(),
            "ip": l.ip_address
        } for l in logs
    ])

# ==================================================
# LOGOUT
# ==================================================

@main_bp.route("/logout")
def logout():
    log_event(session.get("username"), "User logged out")
    session.clear()
    return redirect(url_for("main.login_page"))


@main_bp.route("/sign-data", methods=["GET", "POST"])
@role_required("owner")
def sign_data_page():
    signature = None

    if request.method == "POST":
        data = request.form.get("data")
        signature = sign_data(data)

        record = SignedData(
            owner=session["username"],
            data=data,
            signature=signature
        )
        db.session.add(record)
        db.session.commit()

        log_event(session["username"], "Data signed")

    return render_template("sign_data.html", signature=signature)
