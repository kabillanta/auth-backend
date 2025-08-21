import logging
import os
import re

from dotenv import load_dotenv
from email_validator import validate_email, EmailNotValidError
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from models import db, User

load_dotenv()  # load .env if present

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Database
    db.init_app(app)

    # JWT
    jwt = JWTManager(app)

    # Rate Limiter
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[app.config["RATELIMIT_DEFAULT"]],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    )

    # Logging
    gunicorn_logger = logging.getLogger("gunicorn.error")
    if gunicorn_logger.handlers:
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.setLevel(gunicorn_logger.level)
    else:
        logging.basicConfig(level=logging.INFO)

    # --- Helpers ---
    def validate_password_strength(pw: str):
        """
        Policy: >= 8 chars, at least 1 digit, 1 special, 1 uppercase, 1 lowercase
        """
        if len(pw) < 8:
            return "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", pw):
            return "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", pw):
            return "Password must contain at least one lowercase letter."
        if not re.search(r"\d", pw):
            return "Password must contain at least one digit."
        if not re.search(r"[!@#$%^&*()_\-+=\[{\]}\\|;:'\",<.>/?`~]", pw):
            return "Password must contain at least one special character."
        return None

    # --- Routes ---

    @app.get("/health")
    def health():
        return {"status": "ok"}, 200

    @app.post("/signup")
    @limiter.limit("5 per minute")  # extra protection on signup
    def signup():
        data = request.get_json(silent=True) or {}
        first_name = (data.get("first_name") or "").strip()
        last_name = (data.get("last_name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""
        confirm_password = data.get("confirm_password") or ""

        # Required fields
        if not all([first_name, last_name, email, password, confirm_password]):
            return jsonify({"error": "All fields are required."}), 400

        # Email validation
        try:
            validate_email(email, check_deliverability=False)
        except EmailNotValidError:
            return jsonify({"error": "Invalid email format."}), 400

        # Password match & policy
        if password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400
        pw_err = validate_password_strength(password)
        if pw_err:
            return jsonify({"error": pw_err}), 400

        # Duplicate check
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "An account with this email already exists."}), 409

        # Create user
        user = User(first_name=first_name, last_name=last_name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User registered successfully."}), 201

    @app.post("/login")
    @limiter.limit("10 per minute")  # anti brute-force
    def login():
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        if not email or not password:
            return jsonify({"error": "Email and password are required."}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            # Avoid leaking which field failed
            return jsonify({"error": "Invalid email or password."}), 401

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        return jsonify({
            "message": "Login successful.",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email
            }
        }), 200

    @app.post("/token/refresh")
    @jwt_required(refresh=True)
    def refresh_token():
        user_id = get_jwt_identity()
        new_access = create_access_token(identity=user_id)
        return jsonify({"access_token": new_access}), 200

    @app.get("/profile")
    @jwt_required()
    def profile():
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        return jsonify({
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email
        }), 200

    # --- Error Handlers ---
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({"error": "Too many requests"}), 429

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.exception("Unhandled exception: %s", e)
        return jsonify({"error": "Internal server error"}), 500

    return app


app = create_app()

if __name__ == "__main__":
    # Local dev only; in prod use Gunicorn
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
