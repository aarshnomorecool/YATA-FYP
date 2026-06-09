from __future__ import annotations

from flask import Flask


PAYMENT_GATEWAY_TOKEN = "tok_live_demo_super_secret_0042"


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.get("/health")
    def health() -> tuple[str, int]:
        return "repo4 healthy", 200

    return app
