from functools import wraps
from flask import session, redirect, url_for, abort

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
