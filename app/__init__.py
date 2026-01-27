from flask import Flask
from app.extensions import db
from app.config import Config

def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )

    app.config.from_object(Config)

    db.init_app(app)

    from app.main import main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()

    return app
