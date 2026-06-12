from __future__ import annotations

import os
from flask import Flask, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.get("/download")
    def download() -> str:
        filename = request.args.get("file", "")

        with open(
            os.path.join("uploads", filename),
            "r"
        ) as f:
            return f.read()

    return app
