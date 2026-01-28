from datetime import datetime
from app.extensions import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)   
class Lease(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    owner = db.Column(db.String(80), nullable=False)
    delegate = db.Column(db.String(80), nullable=False)
    resource = db.Column(db.String(120), nullable=False)

    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)

    is_active = db.Column(db.Boolean, default=True)

    # Phase 8 additions
    lease_hash = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    # Phase 9
    access_token = db.Column(db.String(255), nullable=False)

class SecureData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(80), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)

class SignedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(50))
    data = db.Column(db.Text)
    signature = db.Column(db.LargeBinary)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
