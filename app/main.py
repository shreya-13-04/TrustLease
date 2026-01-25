from flask import Blueprint, request, jsonify
from app.models import User
from app.extensions import db   # ✅ correct import

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
        return jsonify({
            "message": "Login successful",
            "role": user.role
        }), 200

    return jsonify({"error": "Invalid credentials"}), 401
