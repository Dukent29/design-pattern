from __future__ import annotations

from typing import Any, Dict
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    jsonify,
    url_for,
)

from security.authentication import AuthenticatedUser, auth_enforcer
from security.authorization import current_user, require_permission, require_roles
from security.audit import audit_event
from security.validation import (
    ValidationResult,
    validate_login_form,
    validate_user_creation_payload,
)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me-in-production"

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';",
        )
        return response

    @app.context_processor
    def inject_current_user() -> Dict[str, Any]:
        return {"current_user": current_user()}

    @app.before_request
    def enforce_session_timeout() -> None:
        auth_enforcer.check_authentication()

    @app.route("/")
    def index():
        if current_user():
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            result: ValidationResult = validate_login_form(request.form)
            if not result.is_valid:
                for error in result.errors:
                    flash(error, "error")
                audit_event("login_validation_failed", result.data.get("username"))
                return render_template("login.html"), 400

            user: AuthenticatedUser | None = auth_enforcer.authenticate(
                result.data["username"],
                result.data["password"],
            )
            if not user:
                flash("Invalid username or password.", "error")
                return render_template("login.html"), 401

            flash("Successfully signed in.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        auth_enforcer.logout()
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    @app.errorhandler(403)
    def forbidden(exc):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(exc):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(exc):
        user = current_user()
        audit_event("server_error", user.get("username") if user else None)
        return render_template("errors/500.html"), 500

    @app.route("/dashboard")
    @require_permission("dashboard", "read")
    def dashboard(user):
        return render_template("dashboard.html", user=user)

    @app.route("/admin", methods=["GET", "POST"])
    @require_roles("admin")
    def admin_panel(user):
        if request.method == "POST":
            payload = {
                "username": request.form.get("username", ""),
                "password": request.form.get("password", ""),
                "role": request.form.get("role", ""),
            }
            result = validate_user_creation_payload(payload)
            if not result.is_valid:
                for error in result.errors:
                    flash(error, "error")
                audit_event(
                    "user_creation_failed",
                    user.get("username"),
                    {"errors": "|".join(result.errors), "source": "admin_form"},
                )
                return render_template("admin.html", user=user), 400

            try:
                created_user = auth_enforcer.create_user(
                    result.data["username"],
                    result.data["password"],
                    result.data["role"],
                )
            except ValueError as exc:
                flash(str(exc), "error")
                audit_event(
                    "user_creation_failed",
                    user.get("username"),
                    {"reason": str(exc), "source": "admin_form"},
                )
                return render_template("admin.html", user=user), 400

            flash(f"User '{created_user.username}' created successfully.", "success")
            audit_event(
                "user_creation_success",
                user.get("username"),
                {
                    "created_username": created_user.username,
                    "role": created_user.role,
                    "source": "admin_form",
                },
            )
            return redirect(url_for("admin_panel"))

        return render_template("admin.html", user=user)

    @app.route("/api/users", methods=["POST"])
    @require_roles("admin")
    def create_user_api(user):
        if not request.is_json:
            audit_event("user_creation_failed", user.get("username"), {"reason": "invalid_content_type"})
            return jsonify({"errors": ["Content-Type must be application/json"]}), 415

        payload = request.get_json(silent=True) or {}
        result = validate_user_creation_payload(payload)
        if not result.is_valid:
            audit_event(
                "user_creation_failed",
                user.get("username"),
                {"errors": "|".join(result.errors)},
            )
            return jsonify({"errors": result.errors}), 400

        try:
            created_user = auth_enforcer.create_user(
                result.data["username"],
                result.data["password"],
                result.data["role"],
            )
        except ValueError as exc:
            audit_event("user_creation_failed", user.get("username"), {"reason": str(exc)})
            return jsonify({"errors": [str(exc)]}), 400

        audit_event(
            "user_creation_success",
            user.get("username"),
            {"created_username": created_user.username, "role": created_user.role},
        )
        response_body = {
            "status": "created",
            "user": {
                "username": created_user.username,
                "role": created_user.role,
            },
        }
        return jsonify(response_body), 201

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
