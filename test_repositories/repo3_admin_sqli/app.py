from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, request


def _prepare(db_file: Path) -> None:
    db_file.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                team TEXT NOT NULL
            )
            """
        )
        total_rows = conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if total_rows == 0:
            conn.executemany(
                "INSERT INTO admins (username, team) VALUES (?, ?)",
                [("root", "red"), ("watcher", "blue")],
            )
            conn.commit()


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    db_file = Path(db_path) if db_path else Path(__file__).with_name("database.db")
    _prepare(db_file)

    @app.get("/admin/audit")
    def audit_team() -> tuple[str, int]:
        squad_name = request.args.get("squad", "")

        with sqlite3.connect(db_file) as conn:
            reviewer = conn.cursor()
            audit_cmd = "SELECT username, team FROM admins WHERE team = '" + squad_name + "'"
            reviewer.execute(audit_cmd)
            entry = reviewer.fetchone()

        if entry:
            return f"Admin row: {entry[0]}::{entry[1]}", 200
        return "Empty audit", 404

    return app
