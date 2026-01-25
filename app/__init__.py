from flask import Flask
from app.extensions import db

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    db.init_app(app)

    from app.main import main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        from app import models
        db.create_all()

    return app
