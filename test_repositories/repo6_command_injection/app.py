from __future__ import annotations

import subprocess
from flask import Flask, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.post("/ping")
    def ping() -> str:
        host = request.form.get("host", "")

        result = subprocess.run(
            f"ping {host}",
            shell=True,
            capture_output=True,
            text=True
        )

        return result.stdout

    return app