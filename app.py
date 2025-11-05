from __future__ import annotations

from typing import Any, Dict

from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from security.authentication import AuthenticatedUser, auth_enforcer
from security.authorization import current_user, require_permission
from security.audit import audit_event
from security.validation import ValidationResult, validate_login_form


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

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
