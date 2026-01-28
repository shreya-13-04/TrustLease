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


class SecureData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(80), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)

class SignedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner = db.Column(db.String(80), nullable=False)
    data = db.Column(db.Text, nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)

