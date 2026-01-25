from flask import Blueprint, request, jsonify
from app.models import User
from app.extensions import db   # ✅ correct import
import random
from datetime import datetime, timedelta


main_bp = Blueprint('main', __name__)

@main_bp.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "TrustLease backend is running"
    })


@main_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")
    role = data.get("role")

    if not username or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 409

    user = User(username=username, role=role)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@main_bp.route("/login", methods=["POST"])
def login():
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
            "otp": otp  # shown only for demo/testing
        }), 200

    return jsonify({"error": "Invalid credentials"}), 401

@main_bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()

    username = data.get("username")
    otp = data.get("otp")

    if not username or not otp:
        return jsonify({"error": "Missing OTP data"}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.otp:
        return jsonify({"error": "OTP not generated"}), 400

    if user.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 401

    if datetime.utcnow() > user.otp_expiry:
        return jsonify({"error": "OTP expired"}), 401

    # OTP is valid → clear it
    user.otp = None
    user.otp_expiry = None
    db.session.commit()

    return jsonify({
        "message": "MFA successful. Login complete.",
        "role": user.role
    }), 200
